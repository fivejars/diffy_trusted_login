<?php

namespace Drupal\diffy_trusted_login_tfa;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormStateInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\user\Form\UserLoginForm;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;

/**
 * Login form submit handler for verified Diffy requests (TFA sites).
 */
class DiffyTfaLogin {

  public function __construct(
    protected DiffyTokenManager $tokenManager,
    protected EntityTypeManagerInterface $entityTypeManager,
    protected LoggerInterface $logger,
  ) {}

  /**
   * Static login form submit callback; delegates to the service.
   *
   * Form callbacks in the 'service:method' form need Drupal 11.3, so a static
   * method is used to support every core version the module declares.
   */
  public static function submitForm(array &$form, FormStateInterface $form_state): void {
    \Drupal::service('diffy_trusted_login_tfa.login')->submit($form, $form_state);
  }

  /**
   * Login form submit handler for verified Diffy requests.
   *
   * Diffy accounts are logged in by core's own login submit, without a second
   * factor. Everyone else goes through TFA.
   */
  public function submit(array &$form, FormStateInterface $form_state): void {
    if (empty($uid = $form_state->get('uid'))) {
      return;
    }
    $account = $this->entityTypeManager->getStorage('user')->load($uid);
    if (!$account instanceof UserInterface || !$this->tokenManager->isDiffyAccount($account)) {
      $form_state->getFormObject()->submitForm($form, $form_state);
      return;
    }

    $this->logger->notice('Diffy account @name logged in without a second factor.', [
      '@name' => $account->getAccountName(),
    ]);
    $this->submitAsCore($form, $form_state);
  }

  /**
   * Runs core's UserLoginForm::submitForm() on the TFA login form.
   *
   * TFA's form extends core's and overrides submitForm() to start the second
   * factor. Calling core's implementation directly logs the user in exactly
   * as core does (redirect, destination, session), without copying it.
   */
  protected function submitAsCore(array &$form, FormStateInterface $form_state): void {
    (new \ReflectionMethod(UserLoginForm::class, 'submitForm'))
      ->invokeArgs($form_state->getFormObject(), [&$form, $form_state]);
  }

}
