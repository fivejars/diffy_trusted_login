<?php

namespace Drupal\diffy_trusted_login;

use Drupal\Component\Utility\Crypt;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Routing\RouteMatchInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;
use Drupal\user\UserAuthenticationInterface;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Manages the Diffy token and decides which requests and accounts it covers.
 */
class DiffyTokenManager {

  /**
   * Key for both the State-stored token and the settings.php override.
   */
  const KEY = 'diffy_trusted_login_token';

  /**
   * Request header Diffy must send.
   */
  const HEADER = 'X-Diffy-Token';

  /**
   * The module's configuration object.
   */
  const CONFIG = 'diffy_trusted_login.settings';

  /**
   * The only route on which bot protections are bypassed.
   */
  const LOGIN_ROUTE = 'user.login';

  /**
   * The only form whose submissions are bypassed.
   */
  const LOGIN_FORM_ID = 'user_login_form';

  /**
   * Flood event that limits how many rejections are logged per IP address.
   */
  const LOG_FLOOD_EVENT = 'diffy_trusted_login.rejection_logged';

  /**
   * Rejections logged per IP address and window; further ones are dropped.
   */
  const LOG_FLOOD_LIMIT = 10;

  /**
   * The rejection logging window, in seconds.
   */
  const LOG_FLOOD_WINDOW = 3600;

  /**
   * Per-request token and IP check results.
   *
   * @var \WeakMap<\Symfony\Component\HttpFoundation\Request, bool>
   */
  protected \WeakMap $results;

  /**
   * Per-request login decisions, so each is made and logged at most once.
   *
   * @var \WeakMap<\Symfony\Component\HttpFoundation\Request, bool>
   */
  protected \WeakMap $loginResults;

  /**
   * Constructs the token manager.
   *
   * @param \Drupal\Core\State\StateInterface $state
   *   The State service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Closure $logger
   *   Returns the module's logger channel; only needed to log rejections.
   * @param \Drupal\Core\Routing\RouteMatchInterface $routeMatch
   *   The current route match.
   * @param \Closure $userAuth
   *   Returns the user.auth service; only needed for login submissions.
   * @param \Closure $flood
   *   Returns the flood service; only needed to log rejections.
   */
  public function __construct(
    protected StateInterface $state,
    protected RequestStack $requestStack,
    protected ConfigFactoryInterface $configFactory,
    protected \Closure $logger,
    protected RouteMatchInterface $routeMatch,
    protected \Closure $userAuth,
    protected \Closure $flood,
  ) {
    $this->results = new \WeakMap();
    $this->loginResults = new \WeakMap();
  }

  /**
   * Whether the current request is a verified Diffy request to the login page.
   *
   * FALSE before routing, so permission checks made earlier never bypass.
   * A submission only qualifies if it is of the login form itself, so other
   * forms shown on the login page keep their protections. When Diffy accounts
   * are configured, it must also be for one of them: any other login then has
   * to pass the protections it was shown without, and fails.
   *
   * Rejections are logged here, so only for the login page: elsewhere the
   * header grants nothing. Logging is also limited per IP address, so the
   * header can't be used to fill the log.
   */
  public function isLoginRequest(): bool {
    $request = $this->requestStack->getCurrentRequest();
    // The header check comes first: it is all normal traffic pays for.
    if (!$request?->headers->has(self::HEADER) || $this->routeMatch->getRouteName() !== self::LOGIN_ROUTE) {
      return FALSE;
    }
    return $this->loginResults[$request] ??= $this->checkLoginRequest($request);
  }

  /**
   * Makes the decision for isLoginRequest(); logs a rejection.
   */
  protected function checkLoginRequest(Request $request): bool {
    $reason = $this->getRejectionReason($request);
    if ($reason === NULL && $request->isMethod('POST')) {
      $values = $request->request->all();
      if (($values['form_id'] ?? NULL) !== self::LOGIN_FORM_ID) {
        $reason = 'submission of a form other than the login form';
      }
      elseif ($this->getAccounts()) {
        $name = $values['name'] ?? '';
        if (!is_string($name) || !$this->isDiffyLoginName(trim($name))) {
          $reason = 'login attempt for an account that is not a Diffy account';
        }
      }
    }
    if ($reason !== NULL) {
      $this->logRejection($request, $reason);
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Whether a submitted login name belongs to a Diffy account.
   *
   * The name is resolved the way the login form resolves it (user.auth), so
   * matching follows core, including modules that allow email logins.
   */
  protected function isDiffyLoginName(string $name): bool {
    if ($name === '') {
      return FALSE;
    }
    $user_auth = ($this->userAuth)();
    // Like core's login form: older user.auth decorators can't look up.
    if (!$user_auth instanceof UserAuthenticationInterface) {
      return $this->isDiffyAccountName($name);
    }
    $account = $user_auth->lookupAccount($name);
    return $account && $this->isDiffyAccount($account);
  }

  /**
   * Whether the account is one of the configured Diffy accounts.
   */
  public function isDiffyAccount(AccountInterface $account): bool {
    return $account->isAuthenticated() && $this->isDiffyAccountName($account->getAccountName());
  }

  /**
   * Whether a username is a configured Diffy account (case-insensitive).
   */
  protected function isDiffyAccountName(string $name): bool {
    return in_array(mb_strtolower($name), array_map('mb_strtolower', $this->getAccounts()), TRUE);
  }

  /**
   * Returns the usernames of the accounts Diffy logs in with.
   *
   * @return string[]
   *   The usernames.
   */
  public function getAccounts(): array {
    return $this->getSetting('accounts');
  }

  /**
   * Returns the IP addresses and CIDR ranges allowed to use the token.
   *
   * @return string[]
   *   The allowed addresses; empty means any address is allowed.
   */
  public function getAllowedIps(): array {
    return $this->getSetting('allowed_ips');
  }

  /**
   * Returns a list setting of the module's configuration.
   */
  protected function getSetting(string $key): array {
    return (array) $this->configFactory->get(self::CONFIG)->get($key);
  }

  /**
   * Whether the request carries a valid token from an allowed IP address.
   *
   * Memoized per request. Never logs; see isLoginRequest().
   */
  public function isValidRequest(Request $request): bool {
    return $this->results[$request] ??= $this->getRejectionReason($request) === NULL;
  }

  /**
   * Checks the token and the IP address.
   *
   * Requests without the header return early without reading the token.
   *
   * @return string|null
   *   Why the request is rejected, or NULL if it is valid.
   */
  protected function getRejectionReason(Request $request): ?string {
    $provided = (string) $request->headers->get(self::HEADER);
    if ($provided === '') {
      return 'no token';
    }
    $expected = $this->getToken();
    if ($expected === '' || !hash_equals($expected, $provided)) {
      return 'invalid token';
    }
    $allowed_ips = $this->getAllowedIps();
    if ($allowed_ips && !IpUtils::checkIp((string) $request->getClientIp(), $allowed_ips)) {
      return 'IP address not allowed';
    }
    return NULL;
  }

  /**
   * Logs a rejected request. The token and login name are never logged.
   *
   * At most LOG_FLOOD_LIMIT rejections are logged per IP address and window;
   * the last one says so. Rejections past the limit are still rejected.
   */
  protected function logRejection(Request $request, string $reason): void {
    $ip = $request->getClientIp() ?? 'unknown';
    $flood = ($this->flood)();
    if (!$flood->isAllowed(self::LOG_FLOOD_EVENT, self::LOG_FLOOD_LIMIT, self::LOG_FLOOD_WINDOW, $ip)) {
      return;
    }
    $flood->register(self::LOG_FLOOD_EVENT, self::LOG_FLOOD_WINDOW, $ip);
    $last = !$flood->isAllowed(self::LOG_FLOOD_EVENT, self::LOG_FLOOD_LIMIT, self::LOG_FLOOD_WINDOW, $ip);
    ($this->logger)()->warning('Rejected @header from @ip on @uri: @reason.' . ($last ? ' Further rejections from this address are not logged for an hour.' : ''), [
      '@header' => self::HEADER,
      '@ip' => $ip,
      '@uri' => $request->getRequestUri(),
      '@reason' => $reason,
    ]);
  }

  /**
   * Returns the effective token: the settings.php override, else State.
   *
   * @return string
   *   The token, or an empty string if none is set.
   */
  public function getToken(): string {
    return $this->hasSettingsOverride()
      ? (string) Settings::get(self::KEY)
      : (string) $this->state->get(self::KEY, '');
  }

  /**
   * Whether the token is defined in settings.php.
   */
  public function hasSettingsOverride(): bool {
    return (string) Settings::get(self::KEY, '') !== '';
  }

  /**
   * Returns the effective token, generating and storing one if none exists.
   */
  public function ensureToken(): string {
    $token = $this->getToken();
    if ($token === '') {
      $this->regenerateToken();
      $token = $this->getToken();
    }
    return $token;
  }

  /**
   * Stores a freshly generated token in State.
   */
  public function regenerateToken(): void {
    $this->state->set(self::KEY, Crypt::randomBytesBase64(32));
  }

  /**
   * Removes the stored token (used on uninstall).
   */
  public function deleteToken(): void {
    $this->state->delete(self::KEY);
  }

}
