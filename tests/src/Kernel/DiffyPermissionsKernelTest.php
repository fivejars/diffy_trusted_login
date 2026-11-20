<?php

namespace Drupal\Tests\diffy_trusted_login\Kernel;

use Drupal\Core\PageCache\ChainRequestPolicy;
use Drupal\Core\Session\AnonymousUserSession;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login\PageCache\DenyDiffyRequests;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\diffy_trusted_login\Traits\DiffyRequestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the module wired into the real permission, cache and form systems.
 *
 * @group diffy_trusted_login
 */
#[Group('diffy_trusted_login')]
#[RunTestsInSeparateProcesses]
class DiffyPermissionsKernelTest extends KernelTestBase {

  use DiffyRequestTrait;
  use UserCreationTrait;

  /**
   * The token stored in State.
   */
  const TOKEN = 'kernel-test-token-0123456789';

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'diffy_trusted_login'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'diffy_trusted_login']);
    $this->container->get('state')->set(DiffyTokenManager::KEY, self::TOKEN);
    // Takes uid 1, which core grants every permission.
    $this->createUser([], 'admin');
  }

  /**
   * Login bypass permissions are granted on verified login requests only.
   */
  public function testLoginBypassPermissions(): void {
    $anonymous = new AnonymousUserSession();
    $cases = [
      'login page, valid token' => [self::TOKEN, 'user.login', TRUE],
      'login page, no token' => [NULL, 'user.login', FALSE],
      'login page, wrong token' => ['wrong', 'user.login', FALSE],
      'password page, valid token' => [self::TOKEN, 'user.pass', FALSE],
      'before routing, valid token' => [self::TOKEN, NULL, FALSE],
    ];
    foreach ($cases as $label => [$token, $route_name, $expected]) {
      $this->pushDiffyRequest($token, $route_name);
      $this->assertSame($expected, $anonymous->hasPermission('skip CAPTCHA'), $label);
      $this->assertSame($expected, $anonymous->hasPermission('bypass honeypot protection'), $label);
      $this->assertFalse($anonymous->hasPermission('protected from spambot scans'), $label);
    }
  }

  /**
   * With Diffy accounts set, only their login submissions are bypassed.
   */
  public function testLoginBypassLimitedToDiffyAccounts(): void {
    $this->createUser([], 'diffy', FALSE, ['mail' => 'diffy@example.com']);
    $this->createUser([], 'editor', FALSE, ['mail' => 'editor@example.com']);
    $this->config('diffy_trusted_login.settings')->set('accounts', ['diffy'])->save();
    $anonymous = new AnonymousUserSession();

    $cases = [
      'form display' => [NULL, TRUE],
      'Diffy account' => ['diffy', TRUE],
      'Diffy account, other case' => ['DIFFY', TRUE],
      // Core logs in by username only; email-login modules decorate user.auth.
      'Diffy account email, core' => ['diffy@example.com', FALSE],
      'other account' => ['editor', FALSE],
      'other account by email' => ['editor@example.com', FALSE],
      'unknown account' => ['nobody', FALSE],
    ];
    foreach ($cases as $label => [$login_name, $expected]) {
      $this->pushDiffyRequest(self::TOKEN, 'user.login', $login_name);
      $this->assertSame($expected, $anonymous->hasPermission('skip CAPTCHA'), $label);
    }
  }

  /**
   * The IP allowlist applies to the permission grant.
   */
  public function testLoginBypassRespectsAllowedIps(): void {
    $this->config('diffy_trusted_login.settings')->set('allowed_ips', ['192.0.2.0/24'])->save();
    $anonymous = new AnonymousUserSession();

    $this->pushDiffyRequest(self::TOKEN)->server->set('REMOTE_ADDR', '203.0.113.5');
    $this->assertFalse($anonymous->hasPermission('skip CAPTCHA'));

    $this->pushDiffyRequest(self::TOKEN)->server->set('REMOTE_ADDR', '192.0.2.10');
    $this->assertTrue($anonymous->hasPermission('skip CAPTCHA'));
  }

  /**
   * Diffy accounts are exempt from spambot scans, whoever is logged in.
   */
  public function testSpambotExemption(): void {
    $diffy = $this->createUser([], 'diffy');
    $editor = $this->createUser([], 'editor');
    $this->config('diffy_trusted_login.settings')->set('accounts', ['diffy'])->save();

    // As during cron: the scanned account isn't the current user.
    $this->setCurrentUser($editor);
    $this->assertTrue($diffy->hasPermission('protected from spambot scans'));
    $this->assertFalse($editor->hasPermission('protected from spambot scans'));
    $this->assertFalse($diffy->hasPermission('skip CAPTCHA'), 'No login bypass outside the login page.');

    $this->setCurrentUser(new AnonymousUserSession());
    $this->assertTrue($diffy->hasPermission('protected from spambot scans'));

    // Removing the account from the setting revokes the exemption.
    $this->config('diffy_trusted_login.settings')->set('accounts', [])->save();
    $this->assertFalse($diffy->hasPermission('protected from spambot scans'));
  }

  /**
   * The permissions hash differs, so cached output can't mix the two.
   */
  public function testPermissionsHashVaries(): void {
    $generator = $this->container->get('user_permissions_hash_generator');
    $anonymous = new AnonymousUserSession();

    $this->pushDiffyRequest(NULL);
    $normal = $generator->generate($anonymous);
    $this->pushDiffyRequest(self::TOKEN);
    $diffy = $generator->generate($anonymous);
    $this->pushDiffyRequest(self::TOKEN, 'user.pass');
    $diffy_elsewhere = $generator->generate($anonymous);

    $this->assertNotSame($normal, $diffy);
    $this->assertSame($normal, $diffy_elsewhere);
  }

  /**
   * The request policy is registered with the internal page cache.
   *
   * Its decisions are unit-tested; through the chain they can't be, since
   * core denies every CLI request.
   */
  public function testPageCacheRequestPolicy(): void {
    $rules = (new \ReflectionProperty(ChainRequestPolicy::class, 'rules'))->getValue($this->container->get('page_cache_request_policy'));
    $this->assertNotEmpty(array_filter($rules, fn($rule) => $rule instanceof DenyDiffyRequests));
  }

}
