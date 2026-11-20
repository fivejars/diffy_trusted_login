<?php

namespace Drupal\Tests\diffy_trusted_login\Traits;

use Drupal\Core\Routing\RouteObjectInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Route;

/**
 * Builds requests as Diffy (or anyone else) would send them.
 */
trait DiffyRequestTrait {

  /**
   * Creates a request, optionally carrying the Diffy header.
   *
   * With a login name, it is a login POST submitting that name, unless a
   * different form ID is given.
   */
  protected static function createDiffyRequest(?string $token, ?string $login_name = NULL, array $server = [], string $uri = '/user/login', string $form_id = 'user_login_form'): Request {
    if ($token !== NULL) {
      $server['HTTP_X_DIFFY_TOKEN'] = $token;
    }
    $method = $login_name === NULL ? 'GET' : 'POST';
    $parameters = $login_name === NULL ? [] : ['form_id' => $form_id, 'name' => $login_name, 'pass' => 'secret'];
    return Request::create($uri, $method, $parameters, [], [], $server);
  }

  /**
   * Pushes a routed request onto a kernel test's request stack.
   *
   * Each pushed request stands for a new one, so the permissions hash, which
   * is cached statically per request, is reset.
   */
  protected function pushDiffyRequest(?string $token, ?string $route_name = 'user.login', ?string $login_name = NULL): Request {
    $request = static::createDiffyRequest($token, $login_name);
    if ($route_name) {
      $request->attributes->set(RouteObjectInterface::ROUTE_NAME, $route_name);
      $request->attributes->set(RouteObjectInterface::ROUTE_OBJECT, new Route('/' . $route_name));
    }
    $request_stack = $this->container->get('request_stack');
    $request->setSession($request_stack->getCurrentRequest()->getSession());
    $request_stack->push($request);
    $this->container->get('cache.memory')->deleteAll();
    return $request;
  }

}
