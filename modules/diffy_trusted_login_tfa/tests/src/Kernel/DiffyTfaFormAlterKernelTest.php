<?php

namespace Drupal\Tests\diffy_trusted_login_tfa\Kernel;

use Drupal\Core\Form\FormState;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login_tfa\DiffyTfaLogin;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\diffy_trusted_login\Traits\DiffyRequestTrait;
use Drupal\tfa\Form\TfaLoginForm;
use Drupal\user\Form\UserLoginForm;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the TFA login form alter wired into the real hook system.
 *
 * @group diffy_trusted_login
 */
#[Group('diffy_trusted_login')]
#[RunTestsInSeparateProcesses]
class DiffyTfaFormAlterKernelTest extends KernelTestBase {

  use DiffyRequestTrait;

  /**
   * The token stored in State.
   */
  const TOKEN = 'kernel-test-token-0123456789';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'key',
    'encrypt',
    'tfa',
    'diffy_trusted_login',
    'diffy_trusted_login_tfa',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['diffy_trusted_login']);
    $this->container->get('state')->set(DiffyTokenManager::KEY, self::TOKEN);
  }

  /**
   * Runs the login form alter hooks with the given form object and token.
   */
  protected function alterLoginForm(string $form_class, ?string $token): array {
    $this->pushDiffyRequest($token);

    // The form objects' constructors aren't needed to test the alter.
    $form_object = (new \ReflectionClass($form_class))->newInstanceWithoutConstructor();
    $form_state = (new FormState())->setFormObject($form_object);
    $form = ['#submit' => ['::tfaLoginFormRedirect', '::submitForm']];
    $form_id = 'user_login_form';
    $this->container->get('module_handler')->alter(['form', 'form_user_login_form'], $form, $form_state, $form_id);
    return $form['#submit'];
  }

  /**
   * TFA's submit handler is swapped on verified Diffy requests only.
   */
  public function testSubmitHandlerSwap(): void {
    $this->assertSame(
      ['::tfaLoginFormRedirect', [DiffyTfaLogin::class, 'submitForm']],
      $this->alterLoginForm(TfaLoginForm::class, self::TOKEN),
    );
    $this->assertSame(['::tfaLoginFormRedirect', '::submitForm'], $this->alterLoginForm(TfaLoginForm::class, NULL));
    $this->assertSame(['::tfaLoginFormRedirect', '::submitForm'], $this->alterLoginForm(TfaLoginForm::class, 'wrong'));
    $this->assertSame(
      ['::tfaLoginFormRedirect', '::submitForm'],
      $this->alterLoginForm(UserLoginForm::class, self::TOKEN),
      'Login forms that are not TFA\'s are left alone.',
    );
  }

  /**
   * The swapped-in handler is a plain callable that delegates to the service.
   *
   * A plain callable works on every supported core; 'service:method' strings
   * are only resolved by the form submitter from Drupal 11.3.
   */
  public function testSubmitHandlerDelegatesToService(): void {
    $this->assertTrue(is_callable([DiffyTfaLogin::class, 'submitForm']));
    $this->assertInstanceOf(DiffyTfaLogin::class, $this->container->get('diffy_trusted_login_tfa.login'));

    $form = [];
    $form_state = new FormState();
    $service = $this->createMock(DiffyTfaLogin::class);
    $service->expects($this->once())->method('submit')->with($form, $form_state);
    $this->container->set('diffy_trusted_login_tfa.login', $service);
    DiffyTfaLogin::submitForm($form, $form_state);
  }

}
