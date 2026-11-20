<?php

namespace Drupal\Tests\diffy_trusted_login_tfa\Unit;

use Drupal\Core\Form\FormInterface;
use Drupal\Core\Form\FormState;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login_tfa\DiffyTfaLogin;
use Drupal\diffy_trusted_login_tfa\Hook\DiffyTrustedLoginTfaHooks;
use Drupal\Tests\UnitTestCase;
use Drupal\tfa\Form\TfaLoginForm;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests swapping TFA's login submit handler.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(DiffyTrustedLoginTfaHooks::class)]
#[Group('diffy_trusted_login')]
class DiffyTrustedLoginTfaHooksTest extends UnitTestCase {

  /**
   * Tests the alter for each situation.
   *
   * @dataProvider providerAlter
   */
  #[DataProvider('providerAlter')]
  public function testFormUserLoginFormAlter(bool $tfa_form, bool $login_request, array $submit, array $expected): void {
    $token_manager = $this->createMock(DiffyTokenManager::class);
    $token_manager->method('isLoginRequest')->willReturn($login_request);
    $form_object = $tfa_form ? $this->createMock(TfaLoginForm::class) : $this->createMock(FormInterface::class);

    $form = ['#submit' => $submit];
    (new DiffyTrustedLoginTfaHooks($token_manager))
      ->formUserLoginFormAlter($form, (new FormState())->setFormObject($form_object), 'user_login_form');
    $this->assertSame($expected, $form['#submit']);
  }

  /**
   * Data provider for testFormUserLoginFormAlter().
   */
  public static function providerAlter(): array {
    $tfa = ['::tfaLoginFormRedirect', '::submitForm'];
    $swapped = ['::tfaLoginFormRedirect', [DiffyTfaLogin::class, 'submitForm']];
    return [
      'TFA form, Diffy login request' => [TRUE, TRUE, $tfa, $swapped],
      'TFA form, other request' => [TRUE, FALSE, $tfa, $tfa],
      'core form, Diffy login request' => [FALSE, TRUE, $tfa, $tfa],
      'TFA form without its submit handler' => [TRUE, TRUE, ['::somethingElse'], ['::somethingElse']],
    ];
  }

}
