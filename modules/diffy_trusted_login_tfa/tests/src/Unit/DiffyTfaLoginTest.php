<?php

namespace Drupal\Tests\diffy_trusted_login_tfa\Unit;

use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\FormInterface;
use Drupal\Core\Form\FormState;
use Drupal\Core\Form\FormStateInterface;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login_tfa\DiffyTfaLogin;
use Drupal\Tests\UnitTestCase;
use Drupal\user\Form\UserLoginForm;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;

/**
 * Tests the TFA bypass decision for Diffy accounts.
 *
 * @group diffy_trusted_login
 */
#[CoversClass(DiffyTfaLogin::class)]
#[Group('diffy_trusted_login')]
class DiffyTfaLoginTest extends UnitTestCase {

  /**
   * The mocked token manager.
   */
  protected DiffyTokenManager&MockObject $tokenManager;

  /**
   * The mocked logger.
   */
  protected LoggerInterface&MockObject $logger;

  /**
   * The account the user storage returns for uid 5.
   */
  protected UserInterface&MockObject $account;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->tokenManager = $this->createMock(DiffyTokenManager::class);
    $this->logger = $this->createMock(LoggerInterface::class);
    $this->account = $this->createMock(UserInterface::class);
    $this->account->method('id')->willReturn(5);
    $this->account->method('getAccountName')->willReturn('diffy');
  }

  /**
   * Creates the service, with login finalization replaced by a mock.
   */
  protected function createService(): DiffyTfaLogin&MockObject {
    $storage = $this->createMock(EntityStorageInterface::class);
    $storage->method('load')->willReturnMap([[5, $this->account]]);
    $entity_type_manager = $this->createMock(EntityTypeManagerInterface::class);
    $entity_type_manager->method('getStorage')->with('user')->willReturn($storage);

    return $this->getMockBuilder(DiffyTfaLogin::class)
      ->setConstructorArgs([$this->tokenManager, $entity_type_manager, $this->logger])
      ->onlyMethods(['submitAsCore'])
      ->getMock();
  }

  /**
   * Creates a login form state whose form object is TFA's login form.
   */
  protected function createFormState(?int $uid, bool $expect_tfa_submit): FormState {
    $form_object = $this->createMock(FormInterface::class);
    $form_object->expects($expect_tfa_submit ? $this->once() : $this->never())->method('submitForm');
    $form_state = (new FormState())->setFormObject($form_object);
    if ($uid) {
      $form_state->set('uid', $uid);
    }
    return $form_state;
  }

  /**
   * A Diffy account is logged in by core's submit, without a second factor.
   */
  public function testDiffyAccountSkipsTfa(): void {
    $this->tokenManager->method('isDiffyAccount')->with($this->account)->willReturn(TRUE);
    $this->logger->expects($this->once())->method('notice')
      ->with($this->anything(), ['@name' => 'diffy']);
    $service = $this->createService();
    $form_state = $this->createFormState(5, FALSE);
    $service->expects($this->once())->method('submitAsCore')->with([], $form_state);

    $form = [];
    $service->submit($form, $form_state);
  }

  /**
   * Core's submit runs on the TFA form object, bypassing TFA's override.
   */
  public function testSubmitAsCoreSkipsTheOverride(): void {
    $tfa_like_form = (new \ReflectionClass(TfaLikeLoginForm::class))->newInstanceWithoutConstructor();
    $form_state = (new FormState())->setFormObject($tfa_like_form);
    $service = new DiffyTfaLogin($this->tokenManager, $this->createMock(EntityTypeManagerInterface::class), $this->logger);

    // Without a uid, core's submitForm() returns at once; the override throws.
    $form = [];
    (new \ReflectionMethod($service, 'submitAsCore'))->invokeArgs($service, [&$form, $form_state]);
    $this->assertSame([], $form);
  }

  /**
   * Any other account goes through TFA's own submit handler.
   */
  public function testOtherAccountGoesThroughTfa(): void {
    $this->tokenManager->method('isDiffyAccount')->willReturn(FALSE);
    $this->logger->expects($this->never())->method($this->anything());
    $service = $this->createService();
    $service->expects($this->never())->method('submitAsCore');

    $form = [];
    $service->submit($form, $this->createFormState(5, TRUE));
  }

  /**
   * An unknown user ID goes through TFA's own submit handler.
   */
  public function testUnknownAccountGoesThroughTfa(): void {
    $this->tokenManager->expects($this->never())->method('isDiffyAccount');
    $service = $this->createService();
    $service->expects($this->never())->method('submitAsCore');

    $form = [];
    $service->submit($form, $this->createFormState(99, TRUE));
  }

  /**
   * Without a validated user ID nothing happens, as in core.
   */
  public function testNoUid(): void {
    $service = $this->createService();
    $service->expects($this->never())->method('submitAsCore');

    $form = [];
    $service->submit($form, $this->createFormState(NULL, FALSE));
  }

}

/**
 * Stands in for TFA's login form: overrides core's submit.
 */
class TfaLikeLoginForm extends UserLoginForm {

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    throw new \LogicException('The override must not run.');
  }

}
