<?php

namespace Drupal\diffy_trusted_login\Access;

use Drupal\Core\Session\AccessPolicyBase;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Session\CalculatedPermissionsItem;
use Drupal\Core\Session\RefinableCalculatedPermissionsInterface;
use Drupal\Core\Site\Settings;
use Drupal\diffy_trusted_login\DiffyTokenManager;

/**
 * Grants bot-protection bypass permissions to Diffy.
 *
 * Each protection module checks its own bypass permission before protecting a
 * form, so granting the permission skips the protection the supported way.
 * Permissions of modules that aren't installed are simply never checked.
 */
class DiffyAccessPolicy extends AccessPolicyBase {

  /**
   * Bypass permissions granted on verified Diffy login requests.
   *
   * Each is the module's own permission. See README.md for coverage.
   */
  const LOGIN_PERMISSIONS = [
    'skip CAPTCHA',
    'skip antibot',
    'bypass honeypot protection',
    'bypass simple_recaptcha',
  ];

  /**
   * Granted to the configured Diffy accounts at all times.
   *
   * Spambot's cron would otherwise block them: Diffy logs in from datacenter
   * addresses that StopForumSpam often lists.
   */
  const ACCOUNT_PERMISSIONS = [
    'protected from spambot scans',
  ];

  public function __construct(protected DiffyTokenManager $tokenManager) {}

  /**
   * {@inheritdoc}
   */
  public function calculatePermissions(AccountInterface $account, string $scope): RefinableCalculatedPermissionsInterface {
    $calculated_permissions = parent::calculatePermissions($account, $scope);
    $permissions = [];
    // Only the anonymous visitor submitting the login form needs the bypass,
    // not other accounts whose permissions happen to be checked meanwhile.
    if ($account->isAnonymous() && $this->tokenManager->isLoginRequest()) {
      $permissions = $this->getLoginPermissions();
    }
    if ($this->tokenManager->isDiffyAccount($account)) {
      $permissions = array_merge($permissions, static::ACCOUNT_PERMISSIONS);
    }
    if ($permissions) {
      $calculated_permissions->addItem(new CalculatedPermissionsItem($permissions));
    }
    return $calculated_permissions;
  }

  /**
   * {@inheritdoc}
   */
  public function getPersistentCacheContexts(): array {
    return ['diffy_login_request', 'user.diffy_account', 'user.roles:anonymous'];
  }

  /**
   * Returns the login permissions plus any added in settings.php.
   */
  protected function getLoginPermissions(): array {
    return array_merge(
      static::LOGIN_PERMISSIONS,
      (array) Settings::get('diffy_trusted_login_extra_permissions', []),
    );
  }

}
