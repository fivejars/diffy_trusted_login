<?php

namespace Drupal\diffy_trusted_login\Cache\Context;

use Drupal\Core\Cache\CacheableMetadata;
use Drupal\Core\Cache\Context\CacheContextInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;

/**
 * Varies by whether the request is a verified Diffy request to the login page.
 *
 * Cache context ID: 'diffy_login_request'. The value is only '1' or '0', so
 * the secret token never ends up in a cache ID.
 */
class DiffyLoginRequestCacheContext implements CacheContextInterface {

  public function __construct(protected DiffyTokenManager $tokenManager) {}

  /**
   * {@inheritdoc}
   */
  public static function getLabel() {
    return t('Verified Diffy login request');
  }

  /**
   * {@inheritdoc}
   */
  public function getContext() {
    return $this->tokenManager->isLoginRequest() ? '1' : '0';
  }

  /**
   * {@inheritdoc}
   */
  public function getCacheableMetadata() {
    return new CacheableMetadata();
  }

}
