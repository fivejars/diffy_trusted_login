<?php

namespace Drupal\diffy_trusted_login\PageCache;

use Drupal\Core\PageCache\RequestPolicyInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Symfony\Component\HttpFoundation\Request;

/**
 * Keeps every verified Diffy request out of the page cache and edge caches.
 *
 * The internal page cache keys on the URL alone and answers before routing,
 * so the login route isn't known yet. The path can't stand in for it: routes
 * match case-insensitively and through aliases (e.g. /USER/LOGIN, /login).
 * Denying all verified requests is the only safe choice; it costs nothing for
 * other visitors, since only requests carrying the header pay for the check.
 * The same policy makes FinishResponseSubscriber mark the responses
 * 'no-cache, private', so an edge cache doesn't store them either.
 */
class DenyDiffyRequests implements RequestPolicyInterface {

  /**
   * Constructs the policy.
   *
   * @param \Closure $tokenManager
   *   Returns the token manager; only built for requests with the header.
   */
  public function __construct(protected \Closure $tokenManager) {}

  /**
   * {@inheritdoc}
   */
  public function check(Request $request) {
    return $request->headers->has(DiffyTokenManager::HEADER)
      && ($this->tokenManager)()->isValidRequest($request)
      ? self::DENY
      : NULL;
  }

}
