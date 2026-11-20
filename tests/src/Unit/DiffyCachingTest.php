<?php

namespace Drupal\Tests\diffy_trusted_login\Unit;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\diffy_trusted_login\Cache\Context\DiffyAccountCacheContext;
use Drupal\diffy_trusted_login\Cache\Context\DiffyLoginRequestCacheContext;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login\PageCache\DenyDiffyRequests;
use Drupal\Tests\diffy_trusted_login\Traits\DiffyRequestTrait;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the page cache request policy and the cache contexts.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(DenyDiffyRequests::class)]
#[CoversClass(DiffyLoginRequestCacheContext::class)]
#[CoversClass(DiffyAccountCacheContext::class)]
#[Group('diffy_trusted_login')]
class DiffyCachingTest extends UnitTestCase {

  use DiffyRequestTrait;

  /**
   * Verified requests skip the page cache; all others are left alone.
   */
  public function testRequestPolicy(): void {
    $valid = static::createDiffyRequest('right');
    $invalid = static::createDiffyRequest('wrong');
    $token_manager = $this->createMock(DiffyTokenManager::class);
    $token_manager->method('isValidRequest')->willReturnMap([[$valid, TRUE], [$invalid, FALSE]]);

    $policy = new DenyDiffyRequests(fn() => $token_manager);
    $this->assertSame(RequestPolicyInterface::DENY, $policy->check($valid));
    $this->assertNull($policy->check($invalid), 'NULL keeps the page cache working for everyone else.');
  }

  /**
   * Requests without the header are left alone without building the manager.
   */
  public function testRequestPolicySkipsWithoutBuildingTheManager(): void {
    $policy = new DenyDiffyRequests(fn() => $this->fail('The token manager must not be built.'));
    $this->assertNull($policy->check(static::createDiffyRequest(NULL)), 'No header.');
    $this->assertNull($policy->check(static::createDiffyRequest(NULL, NULL, [], '/login')), 'No header, aliased path.');
  }

  /**
   * Verified requests are denied on any path.
   *
   * Before routing, the path can't tell whether the request reaches the login
   * route: routes match case-insensitively and through aliases.
   */
  public function testRequestPolicyDeniesAnyPath(): void {
    $token_manager = $this->createMock(DiffyTokenManager::class);
    $token_manager->method('isValidRequest')->willReturn(TRUE);
    $policy = new DenyDiffyRequests(fn() => $token_manager);
    foreach (['/user/login', '/user/login/', '/de/user/login', '/USER/LOGIN', '/login', '/node/1', '/user/login?destination=/node/1'] as $uri) {
      $this->assertSame(RequestPolicyInterface::DENY, $policy->check(static::createDiffyRequest('right', NULL, [], $uri)), $uri);
    }
  }

  /**
   * Tests that both contexts are only ever '1' or '0'.
   *
   * @dataProvider providerFlag
   */
  #[DataProvider('providerFlag')]
  public function testContextValues(bool $flag, string $expected): void {
    $user = $this->createMock(AccountInterface::class);
    $token_manager = $this->createMock(DiffyTokenManager::class);
    $token_manager->method('isLoginRequest')->willReturn($flag);
    $token_manager->method('isDiffyAccount')->with($user)->willReturn($flag);

    $this->assertSame($expected, (new DiffyLoginRequestCacheContext($token_manager))->getContext());
    $this->assertSame($expected, (new DiffyAccountCacheContext($user, $token_manager))->getContext());
  }

  /**
   * Data provider for testContextValues().
   */
  public static function providerFlag(): array {
    return [
      'yes' => [TRUE, '1'],
      'no' => [FALSE, '0'],
    ];
  }

  /**
   * The account context invalidates with the module's settings.
   */
  public function testAccountContextMetadata(): void {
    $context = new DiffyAccountCacheContext($this->createMock(AccountInterface::class), $this->createMock(DiffyTokenManager::class));
    $this->assertSame(['config:diffy_trusted_login.settings'], $context->getCacheableMetadata()->getCacheTags());
    $login_context = new DiffyLoginRequestCacheContext($this->createMock(DiffyTokenManager::class));
    $this->assertSame([], $login_context->getCacheableMetadata()->getCacheTags());
  }

}
