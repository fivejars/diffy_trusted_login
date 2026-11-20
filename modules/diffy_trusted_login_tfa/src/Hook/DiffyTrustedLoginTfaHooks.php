<?php

namespace Drupal\diffy_trusted_login_tfa\Hook;

use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Hook\Attribute\Hook;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login_tfa\DiffyTfaLogin;
use Drupal\tfa\Form\TfaLoginForm;

/**
 * Hook implementations for Diffy trusted login: TFA.
 */
class DiffyTrustedLoginTfaHooks {

  public function __construct(protected DiffyTokenManager $tokenManager) {}

  /**
   * Implements hook_form_FORM_ID_alter() for user_login_form.
   *
   * On verified Diffy login requests, swaps TFA's submit handler for one that
   * logs Diffy accounts straight in and hands every other login back to TFA.
   */
  #[Hook('form_user_login_form_alter')]
  public function formUserLoginFormAlter(array &$form, FormStateInterface $form_state, string $form_id): void {
    if (!$form_state->getFormObject() instanceof TfaLoginForm || !$this->tokenManager->isLoginRequest()) {
      return;
    }
    $key = array_search('::submitForm', $form['#submit'] ?? [], TRUE);
    if ($key !== FALSE) {
      // A static callable: 'service:method' strings only work from 11.3.
      $form['#submit'][$key] = [DiffyTfaLogin::class, 'submitForm'];
    }
  }

}
