<?php

namespace Drupal\diffy_trusted_login\Form;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Form\ConfirmFormBase;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Confirms regeneration of the Diffy token.
 */
class RegenerateTokenForm extends ConfirmFormBase {

  public function __construct(protected DiffyTokenManager $tokenManager) {}

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static($container->get('diffy_trusted_login.token_manager'));
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'diffy_trusted_login_regenerate';
  }

  /**
   * {@inheritdoc}
   */
  public function getQuestion() {
    return $this->t('Regenerate the Diffy token?');
  }

  /**
   * {@inheritdoc}
   */
  public function getDescription() {
    return $this->t('The current token stops working immediately. You must update the <code>X-Diffy-Token</code> header in Diffy with the new value, or Diffy will be blocked by bot protections again.');
  }

  /**
   * {@inheritdoc}
   */
  public function getConfirmText() {
    return $this->t('Regenerate');
  }

  /**
   * {@inheritdoc}
   */
  public function getCancelUrl() {
    return Url::fromRoute('diffy_trusted_login.settings');
  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->tokenManager->regenerateToken();
    $this->messenger()->addStatus($this->t('A new Diffy token has been generated. Update the X-Diffy-Token header in Diffy.'));
    $form_state->setRedirect('diffy_trusted_login.settings');
  }

  /**
   * Route access: closed while settings.php defines the token.
   *
   * Regenerating would then only rotate an unused stored token, which would
   * silently take effect once the override is removed.
   */
  public function access(): AccessResultInterface {
    return AccessResult::allowedIf(!$this->tokenManager->hasSettingsOverride())->setCacheMaxAge(0);
  }

}
