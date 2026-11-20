<?php

namespace Drupal\diffy_trusted_login\Cache\Context;

use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Cache\Context\CacheContextInterface;
use Drupal\Core\Cache\Context\UserCacheContextBase;
use Drupal\Core\Session\AccountInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;

/**
 * Varies by whether the current user is one of the configured Diffy accounts.
 *
 * Cache context ID: 'user.diffy_account'. Being a 'user' child, it is folded
 * into 'user' when both are present, and core's permission processor switches
 * to the account being checked before evaluating it. The value is only '1' or
 * '0', so it doesn't split caches per user.
 */
class DiffyAccountCacheContext extends UserCacheContextBase implements CacheContextInterface {

  public function __construct(AccountInterface $user, protected DiffyTokenManager $tokenManager) {
    parent::__construct($user);
  }

  /**
   * {@inheritdoc}
   */
  public static function getLabel() {
    return t('Diffy account');
  }

  /**
   * {@inheritdoc}
   */
  public function getContext() {
    return $this->tokenManager->isDiffyAccount($this->user) ? '1' : '0';
  }

  /**
   * {@inheritdoc}
   */
  public function getCacheableMetadata() {
    return (new CacheableMetadata())->setCacheTags(['config:' . DiffyTokenManager::CONFIG]);
  }

}
