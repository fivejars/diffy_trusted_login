<?php

namespace Drupal\diffy_trusted_login\Drush\Commands;

use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drush\Attributes as CLI;
use Drush\Commands\DrushCommands;
use Drush\Exceptions\UserAbortException;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Drush commands to show and regenerate the Diffy token.
 */
final class DiffyTrustedLoginCommands extends DrushCommands {

  public function __construct(protected DiffyTokenManager $tokenManager) {
    parent::__construct();
  }

  /**
   * Creates the commands with their dependencies.
   */
  public static function create(ContainerInterface $container): self {
    return new self($container->get('diffy_trusted_login.token_manager'));
  }

  /**
   * Prints the Diffy token (generating one if none exists).
   */
  #[CLI\Command(name: 'diffy-trusted-login:token', aliases: ['diffy-token'])]
  #[CLI\Usage(name: 'drush diffy-token', description: 'Print the token to paste into Diffy as the X-Diffy-Token header.')]
  public function token(): string {
    return $this->tokenManager->ensureToken();
  }

  /**
   * Regenerates the Diffy token and prints the new one.
   */
  #[CLI\Command(name: 'diffy-trusted-login:regenerate', aliases: ['diffy-token-regenerate'])]
  #[CLI\Usage(name: 'drush diffy-token-regenerate -y', description: 'Rotate the token without a prompt.')]
  public function regenerate(): ?string {
    if ($this->tokenManager->hasSettingsOverride()) {
      throw new \RuntimeException(dt('The token is defined in settings.php ($settings[\'diffy_trusted_login_token\']). Change it there instead.'));
    }
    if (!$this->io()->confirm(dt('The current token stops working immediately and Diffy must be updated with the new one. Continue?'))) {
      throw new UserAbortException();
    }
    $this->tokenManager->regenerateToken();
    $this->logger()->success(dt('New token generated. Update the X-Diffy-Token header in Diffy.'));
    return $this->tokenManager->getToken();
  }

}
