<?php

namespace Drupal\Tests\diffy_trusted_login\Unit;

use Drupal\Core\Cache\Context\CacheContextsManager;
use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\Session\AccessPolicyInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\diffy_trusted_login\Access\DiffyAccessPolicy;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests which permissions the Diffy access policy grants, and when.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(DiffyAccessPolicy::class)]
#[Group('diffy_trusted_login')]
class DiffyAccessPolicyTest extends UnitTestCase {

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    new Settings([]);

    // Adding cache contexts validates them against the container.
    $cache_contexts_manager = $this->createMock(CacheContextsManager::class);
    $cache_contexts_manager->method('assertValidTokens')->willReturn(TRUE);
    $container = new ContainerBuilder();
    $container->set('cache_contexts_manager', $cache_contexts_manager);
    \Drupal::setContainer($container);
  }

  /**
   * Returns the permissions the policy grants in the given situation.
   */
  protected function calculate(bool $login_request, bool $diffy_account, bool $anonymous = TRUE): array {
    $token_manager = $this->createMock(DiffyTokenManager::class);
    $token_manager->method('isLoginRequest')->willReturn($login_request);
    $token_manager->method('isDiffyAccount')->willReturn($diffy_account);

    $policy = new DiffyAccessPolicy($token_manager);
    $account = $this->createMock(AccountInterface::class);
    $account->method('isAnonymous')->willReturn($anonymous);
    $calculated = $policy->calculatePermissions($account, AccessPolicyInterface::SCOPE_DRUPAL);

    $this->assertEqualsCanonicalizing(
      ['diffy_login_request', 'user.diffy_account', 'user.roles:anonymous'],
      $calculated->getCacheContexts(),
      'The result varies by both cache contexts.',
    );
    $item = $calculated->getItem();
    if ($item) {
      $this->assertFalse($item->isAdmin(), 'Never grants admin.');
    }
    return $item ? $item->getPermissions() : [];
  }

  /**
   * Tests the granted permissions per situation.
   *
   * @dataProvider providerPermissions
   */
  #[DataProvider('providerPermissions')]
  public function testPermissions(bool $login_request, bool $diffy_account, bool $anonymous, array $expected): void {
    $this->assertEqualsCanonicalizing($expected, $this->calculate($login_request, $diffy_account, $anonymous));
  }

  /**
   * Data provider for testPermissions().
   */
  public static function providerPermissions(): array {
    return [
      'neither' => [FALSE, FALSE, TRUE, []],
      'login request, anonymous visitor' => [TRUE, FALSE, TRUE, DiffyAccessPolicy::LOGIN_PERMISSIONS],
      'login request, some other account checked' => [TRUE, FALSE, FALSE, []],
      'Diffy account' => [FALSE, TRUE, FALSE, DiffyAccessPolicy::ACCOUNT_PERMISSIONS],
      'login request, Diffy account checked' => [TRUE, TRUE, FALSE, DiffyAccessPolicy::ACCOUNT_PERMISSIONS],
    ];
  }

  /**
   * Guards the permission lists against accidental admin-level grants.
   */
  public function testNoAdminPermissions(): void {
    foreach ([...DiffyAccessPolicy::LOGIN_PERMISSIONS, ...DiffyAccessPolicy::ACCOUNT_PERMISSIONS] as $permission) {
      $this->assertDoesNotMatchRegularExpression('/^(administer|access administration)/i', $permission);
    }
  }

  /**
   * Extra permissions from settings.php are added to login requests only.
   */
  public function testExtraPermissionsFromSettings(): void {
    new Settings(['diffy_trusted_login_extra_permissions' => ['bypass foo', 'skip CAPTCHA']]);

    $login = $this->calculate(TRUE, FALSE);
    $this->assertContains('bypass foo', $login);
    $this->assertCount(1, array_keys($login, 'skip CAPTCHA'), 'No duplicates.');

    $this->assertNotContains('bypass foo', $this->calculate(FALSE, TRUE));
  }

}
