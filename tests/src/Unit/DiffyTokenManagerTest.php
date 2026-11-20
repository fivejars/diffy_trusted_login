<?php

namespace Drupal\Tests\diffy_trusted_login\Unit;

use Drupal\Core\Flood\FloodInterface;
use Drupal\Core\Flood\MemoryBackend;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\Tests\diffy_trusted_login\Traits\DiffyRequestTrait;
use Drupal\Tests\UnitTestCase;
use Drupal\user\UserAuthenticationInterface;
use Drupal\user\UserAuthInterface;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Tests the Diffy token manager: the security gate of the module.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(DiffyTokenManager::class)]
#[Group('diffy_trusted_login')]
class DiffyTokenManagerTest extends UnitTestCase {

  use DiffyRequestTrait;

  /**
   * The token stored in State by default.
   */
  const TOKEN = 'stored-token-0123456789abcdef';

  /**
   * In-memory State values.
   */
  protected array $stateValues = [];

  /**
   * The mocked State service.
   */
  protected StateInterface&MockObject $state;

  /**
   * The mocked logger.
   */
  protected LoggerInterface&MockObject $logger;

  /**
   * The mocked route match.
   */
  protected RouteMatchInterface&MockObject $routeMatch;

  /**
   * The request stack.
   */
  protected RequestStack $requestStack;

  /**
   * The in-memory flood service.
   */
  protected FloodInterface $flood;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    new Settings([]);
    $this->stateValues = [DiffyTokenManager::KEY => self::TOKEN];
    $this->state = $this->createMock(StateInterface::class);
    $this->state->method('get')->willReturnCallback(
      fn($key, $default = NULL) => $this->stateValues[$key] ?? $default,
    );
    $this->state->method('set')->willReturnCallback(
      function ($key, $value): void {
        $this->stateValues[$key] = $value;
      },
    );
    $this->state->method('delete')->willReturnCallback(
      function ($key): void {
        unset($this->stateValues[$key]);
      },
    );
    $this->logger = $this->createMock(LoggerInterface::class);
    $this->routeMatch = $this->createMock(RouteMatchInterface::class);
    $this->requestStack = new RequestStack();
    $this->flood = new MemoryBackend($this->requestStack);
  }

  /**
   * Creates the token manager with the given module settings.
   */
  protected function createManager(array $allowed_ips = [], array $accounts = []): DiffyTokenManager {
    return $this->createManagerWithConfig(['allowed_ips' => $allowed_ips, 'accounts' => $accounts]);
  }

  /**
   * Creates the token manager with raw module configuration.
   */
  protected function createManagerWithConfig(array $config, ?object $user_auth = NULL): DiffyTokenManager {
    return new DiffyTokenManager(
      $this->state,
      $this->requestStack,
      $this->getConfigFactoryStub(['diffy_trusted_login.settings' => $config]),
      fn() => $this->logger,
      $this->routeMatch,
      fn() => $user_auth ?? $this->createUserAuth(),
      fn() => $this->flood,
    );
  }

  /**
   * Creates a user.auth service that knows one account, 'Diffy'.
   *
   * Like core, it resolves the name case-insensitively; like an email-login
   * module, it also resolves diffy@example.com.
   */
  protected function createUserAuth(): UserAuthenticationInterface {
    $user = $this->createMock(UserInterface::class);
    $user->method('getAccountName')->willReturn('Diffy');
    $user->method('isAuthenticated')->willReturn(TRUE);
    $user_auth = $this->createMock(UserAuthenticationInterface::class);
    $user_auth->method('lookupAccount')->willReturnCallback(
      fn(string $identifier) => in_array(strtolower($identifier), ['diffy', 'diffy@example.com'], TRUE) ? $user : FALSE,
    );
    return $user_auth;
  }

  /**
   * Creates a request, optionally carrying the Diffy header.
   */
  protected function createRequest(?string $token, string $ip = '203.0.113.5', ?string $login_name = NULL): Request {
    return static::createDiffyRequest($token, $login_name, ['REMOTE_ADDR' => $ip], '/user/login?destination=/node/1');
  }

  /**
   * Pushes a request for the login page, or another route, as current.
   */
  protected function pushRequest(Request $request, ?string $route_name = 'user.login'): void {
    $this->routeMatch->method('getRouteName')->willReturn($route_name);
    $this->requestStack->push($request);
  }

  /**
   * Expects exactly one logged rejection with the given reason.
   */
  protected function expectRejection(string $reason, string ...$never_logged): void {
    $this->logger->expects($this->once())
      ->method('warning')
      ->with(
        $this->anything(),
        $this->callback(function (array $context) use ($reason, $never_logged): bool {
          $this->assertSame($reason, $context['@reason']);
          $this->assertSame('203.0.113.5', $context['@ip']);
          $this->assertSame('/user/login?destination=/node/1', $context['@uri']);
          foreach ($never_logged as $secret) {
            $this->assertStringNotContainsString($secret, serialize($context));
          }
          return TRUE;
        }),
      );
  }

  /**
   * A request without the header is rejected without reading the token.
   */
  public function testNoHeader(): void {
    $state = $this->createMock(StateInterface::class);
    $state->expects($this->never())->method('get');
    $this->state = $state;
    $this->logger->expects($this->never())->method($this->anything());

    $manager = $this->createManager();
    $this->assertFalse($manager->isValidRequest($this->createRequest(NULL)));
    $this->pushRequest($this->createRequest(NULL));
    $this->assertFalse($manager->isLoginRequest());
  }

  /**
   * The correct token is accepted when no IP allowlist is set.
   */
  public function testValidToken(): void {
    $this->logger->expects($this->never())->method($this->anything());
    $this->assertTrue($this->createManager()->isValidRequest($this->createRequest(self::TOKEN)));
  }

  /**
   * Tests rejected tokens and addresses; isValidRequest() itself never logs.
   *
   * @dataProvider providerRejections
   */
  #[DataProvider('providerRejections')]
  public function testValidationNeverLogs(array $allowed_ips, ?string $token, string $reason): void {
    if ($token === NULL) {
      $this->stateValues = [];
    }
    $this->logger->expects($this->never())->method($this->anything());
    $this->assertFalse($this->createManager($allowed_ips)->isValidRequest($this->createRequest($token ?? 'anything')));
  }

  /**
   * Rejections on the login page are logged, without the token.
   *
   * @dataProvider providerRejections
   */
  #[DataProvider('providerRejections')]
  public function testLoginPageRejectionsAreLogged(array $allowed_ips, ?string $token, string $reason): void {
    if ($token === NULL) {
      $this->stateValues = [];
    }
    $this->expectRejection($reason, $token ?? 'anything', self::TOKEN);
    $this->pushRequest($this->createRequest($token ?? 'anything'));
    $this->assertFalse($this->createManager($allowed_ips)->isLoginRequest());
  }

  /**
   * Data provider: rejected requests and the logged reason.
   */
  public static function providerRejections(): array {
    return [
      'wrong token' => [[], 'guessed-secret-value', 'invalid token'],
      'token prefix' => [[], substr(self::TOKEN, 0, 10), 'invalid token'],
      'no token configured' => [[], NULL, 'invalid token'],
      'IP not allowed' => [['192.0.2.1'], self::TOKEN, 'IP address not allowed'],
      'wrong token from a disallowed IP' => [['192.0.2.1'], 'wrong', 'invalid token'],
    ];
  }

  /**
   * Bad tokens on other pages grant nothing and aren't logged.
   *
   * Otherwise anyone could fill the log by sending the header anywhere.
   */
  public function testRejectionsElsewhereAreNotLogged(): void {
    $this->logger->expects($this->never())->method($this->anything());
    $this->pushRequest($this->createRequest('wrong'), 'entity.node.canonical');
    $this->assertFalse($this->createManager()->isLoginRequest());
  }

  /**
   * Rejection logging is limited per IP address; the requests stay rejected.
   */
  public function testRejectionLoggingIsFloodLimited(): void {
    $messages = [];
    $this->logger->method('warning')->willReturnCallback(
      function (string $message, array $context) use (&$messages): void {
        $messages[] = [$message, $context['@ip']];
      },
    );
    $manager = $this->createManager();
    for ($i = 0; $i < DiffyTokenManager::LOG_FLOOD_LIMIT + 5; $i++) {
      $this->requestStack->push($this->createRequest('wrong'));
      if ($i === 0) {
        $this->routeMatch->method('getRouteName')->willReturn('user.login');
      }
      $this->assertFalse($manager->isLoginRequest());
    }
    $this->assertCount(DiffyTokenManager::LOG_FLOOD_LIMIT, $messages);
    $this->assertStringNotContainsString('not logged', $messages[0][0]);
    $this->assertStringContainsString('Further rejections from this address are not logged', end($messages)[0]);

    // Another address has its own allowance.
    $this->requestStack->push($this->createRequest('wrong', '198.51.100.7'));
    $this->assertFalse($manager->isLoginRequest());
    $this->assertSame('198.51.100.7', end($messages)[1]);
  }

  /**
   * Submissions of other forms on the login page are never bypassed.
   *
   * @dataProvider providerOtherFormSubmission
   */
  #[DataProvider('providerOtherFormSubmission')]
  public function testOtherFormSubmission(array $accounts, ?string $form_id): void {
    $this->expectRejection('submission of a form other than the login form');
    $request = static::createDiffyRequest(self::TOKEN, 'Diffy', ['REMOTE_ADDR' => '203.0.113.5'], '/user/login?destination=/node/1', $form_id ?? '');
    if ($form_id === NULL) {
      $request->request->remove('form_id');
    }
    $this->pushRequest($request);
    $this->assertFalse($this->createManager([], $accounts)->isLoginRequest());
  }

  /**
   * Data provider for testOtherFormSubmission().
   */
  public static function providerOtherFormSubmission(): array {
    return [
      'other form, accounts set' => [['Diffy'], 'newsletter_form'],
      'other form, no accounts set' => [[], 'newsletter_form'],
      'no form ID' => [['Diffy'], NULL],
    ];
  }

  /**
   * Tests the IP allowlist.
   *
   * @dataProvider providerAllowedIps
   */
  #[DataProvider('providerAllowedIps')]
  public function testAllowedIps(array $allowed_ips, string $client_ip, bool $expected): void {
    $manager = $this->createManager($allowed_ips);
    $this->assertSame($expected, $manager->isValidRequest($this->createRequest(self::TOKEN, $client_ip)));
  }

  /**
   * Data provider for testAllowedIps().
   */
  public static function providerAllowedIps(): array {
    return [
      'exact match' => [['203.0.113.5'], '203.0.113.5', TRUE],
      'exact mismatch' => [['203.0.113.5'], '203.0.113.6', FALSE],
      'IPv4 CIDR match' => [['10.0.0.0/8'], '10.20.30.40', TRUE],
      'IPv4 CIDR mismatch' => [['10.0.0.0/8'], '11.0.0.1', FALSE],
      'IPv6 CIDR match' => [['2001:db8::/32'], '2001:db8::42', TRUE],
      'IPv6 CIDR mismatch' => [['2001:db8::/32'], '2001:db9::1', FALSE],
      'one of several' => [['192.0.2.1', '10.0.0.0/8'], '10.1.1.1', TRUE],
    ];
  }

  /**
   * Each request is decided and logged at most once.
   */
  public function testLoginDecisionIsMemoizedPerRequest(): void {
    $this->logger->expects($this->once())->method('warning');
    $manager = $this->createManager();
    $this->pushRequest($this->createRequest('wrong'));
    $this->assertFalse($manager->isLoginRequest());
    $this->assertFalse($manager->isLoginRequest());

    // A different request object is decided on its own.
    $this->requestStack->push($this->createRequest(self::TOKEN));
    $this->assertTrue($manager->isLoginRequest());
  }

  /**
   * Tests isLoginRequest() for each route situation.
   *
   * @dataProvider providerIsLoginRequest
   */
  #[DataProvider('providerIsLoginRequest')]
  public function testIsLoginRequest(?string $route_name, ?string $token, bool $expected): void {
    $this->pushRequest($this->createRequest($token), $route_name);
    $this->assertSame($expected, $this->createManager()->isLoginRequest());
  }

  /**
   * Data provider for testIsLoginRequest().
   */
  public static function providerIsLoginRequest(): array {
    return [
      'login page, valid token' => ['user.login', self::TOKEN, TRUE],
      'login page, no token' => ['user.login', NULL, FALSE],
      'login page, wrong token' => ['user.login', 'wrong', FALSE],
      'other page, valid token' => ['user.pass', self::TOKEN, FALSE],
      'before routing, valid token' => [NULL, self::TOKEN, FALSE],
    ];
  }

  /**
   * Tests which login submissions qualify when Diffy accounts are configured.
   *
   * @dataProvider providerLoginSubmission
   */
  #[DataProvider('providerLoginSubmission')]
  public function testLoginSubmission(array $accounts, ?string $login_name, bool $expected): void {
    if (!$expected && $accounts && $login_name !== NULL) {
      $this->expectRejection('login attempt for an account that is not a Diffy account', ...array_filter([trim($login_name)]));
    }
    else {
      $this->logger->expects($this->never())->method($this->anything());
    }
    $this->pushRequest($this->createRequest(self::TOKEN, '203.0.113.5', $login_name));

    $manager = $this->createManager([], $accounts);
    $this->assertSame($expected, $manager->isLoginRequest());
    $this->assertSame($expected, $manager->isLoginRequest(), 'Decided and logged once per request.');
  }

  /**
   * Data provider for testLoginSubmission().
   */
  public static function providerLoginSubmission(): array {
    return [
      'form display, accounts set' => [['Diffy'], NULL, TRUE],
      'no accounts set, any name' => [[], 'editor', TRUE],
      'Diffy account' => [['Diffy'], 'Diffy', TRUE],
      'Diffy account, other case' => [['Diffy'], 'dIFFY', TRUE],
      'configured in other case' => [['DIFFY'], 'diffy', TRUE],
      'Diffy account, surrounding spaces' => [['Diffy'], ' Diffy ', TRUE],
      'Diffy account by email' => [['Diffy'], 'diffy@example.com', TRUE],
      'one of several accounts' => [['other', 'Diffy'], 'diffy', TRUE],
      'other account' => [['Diffy'], 'editor', FALSE],
      'other account by email' => [['Diffy'], 'editor@example.com', FALSE],
      'unknown account' => [['Diffy'], 'nobody', FALSE],
      'empty name' => [['Diffy'], '', FALSE],
      'name containing a Diffy name' => [['Diffy'], 'Diffy2', FALSE],
    ];
  }

  /**
   * A non-string login name is a rejection, not an exception.
   */
  public function testLoginNameAsArray(): void {
    $this->expectRejection('login attempt for an account that is not a Diffy account');
    $request = $this->createRequest(self::TOKEN, '203.0.113.5', 'placeholder');
    $request->request->set('name', ['Diffy']);
    $this->pushRequest($request);
    $this->assertFalse($this->createManager([], ['Diffy'])->isLoginRequest());
  }

  /**
   * Without lookupAccount() (legacy user.auth), names match as usernames.
   */
  public function testLegacyUserAuthFallback(): void {
    $legacy_user_auth = $this->createMock(UserAuthInterface::class);
    $manager = $this->createManagerWithConfig(['accounts' => ['Diffy']], $legacy_user_auth);

    $this->pushRequest($this->createRequest(self::TOKEN, '203.0.113.5', 'diffy'));
    $this->assertTrue($manager->isLoginRequest());

    $this->requestStack->push($this->createRequest(self::TOKEN, '203.0.113.5', 'editor'));
    $this->assertFalse($manager->isLoginRequest());
  }

  /**
   * Tests isDiffyAccount().
   */
  public function testIsDiffyAccount(): void {
    $manager = $this->createManager([], ['diffy', 'Diffy2']);
    $this->assertSame(['diffy', 'Diffy2'], $manager->getAccounts());

    $this->assertTrue($manager->isDiffyAccount($this->createAccount('diffy')));
    $this->assertTrue($manager->isDiffyAccount($this->createAccount('DIFFY')), 'Case-insensitive.');
    $this->assertTrue($manager->isDiffyAccount($this->createAccount('diffy2')));
    $this->assertFalse($manager->isDiffyAccount($this->createAccount('editor')));
    $this->assertFalse($manager->isDiffyAccount($this->createAccount('diffy', FALSE)), 'Anonymous never matches.');
  }

  /**
   * Creates an account mock.
   */
  protected function createAccount(string $name, bool $authenticated = TRUE): AccountInterface {
    $account = $this->createMock(AccountInterface::class);
    $account->method('getAccountName')->willReturn($name);
    $account->method('isAuthenticated')->willReturn($authenticated);
    return $account;
  }

  /**
   * The settings.php override takes precedence over State.
   */
  public function testSettingsOverride(): void {
    new Settings([DiffyTokenManager::KEY => 'from-settings']);
    $manager = $this->createManager();
    $this->assertTrue($manager->hasSettingsOverride());
    $this->assertSame('from-settings', $manager->getToken());
    $this->assertTrue($manager->isValidRequest($this->createRequest('from-settings')));
    $this->assertFalse($manager->isValidRequest($this->createRequest(self::TOKEN)), 'The stored token is ignored.');
  }

  /**
   * An empty settings.php override falls back to State.
   */
  public function testEmptySettingsOverride(): void {
    new Settings([DiffyTokenManager::KEY => '']);
    $manager = $this->createManager();
    $this->assertFalse($manager->hasSettingsOverride());
    $this->assertSame(self::TOKEN, $manager->getToken());
  }

  /**
   * Tests token generation and regeneration.
   */
  public function testEnsureAndRegenerateToken(): void {
    $manager = $this->createManager();
    $this->assertSame(self::TOKEN, $manager->ensureToken(), 'An existing token is kept.');

    $this->stateValues = [];
    $generated = $manager->ensureToken();
    $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{43}$/', $generated, '32 random bytes, URL-safe base64.');
    $this->assertSame($generated, $this->stateValues[DiffyTokenManager::KEY]);
    $this->assertSame($generated, $manager->ensureToken(), 'Generated once.');

    $manager->regenerateToken();
    $this->assertNotSame($generated, $manager->getToken());

    $manager->deleteToken();
    $this->assertSame('', $manager->getToken());
  }

  /**
   * Regenerating stores a new token even while an override is active.
   *
   * The settings form says "a new stored token was generated" in that case,
   * so the stored token must actually change (and not just be deleted).
   */
  public function testRegenerateWithOverrideStoresNewToken(): void {
    new Settings([DiffyTokenManager::KEY => 'from-settings']);
    $manager = $this->createManager();
    $manager->regenerateToken();
    $this->assertNotSame(self::TOKEN, $this->stateValues[DiffyTokenManager::KEY]);
    $this->assertNotEmpty($this->stateValues[DiffyTokenManager::KEY]);
    $this->assertSame('from-settings', $manager->getToken());
  }

  /**
   * An empty allowlist in config means any address.
   */
  public function testGetAllowedIpsDefaultsToEmpty(): void {
    $manager = $this->createManagerWithConfig([]);
    $this->assertSame([], $manager->getAllowedIps());
    $this->assertSame([], $manager->getAccounts());
  }

}
