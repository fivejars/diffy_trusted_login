<?php

namespace Drupal\Tests\diffy_trusted_login\Kernel;

use Drupal\Core\Form\FormState;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login\Form\SettingsForm;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the settings form and the regenerate route.
 *
 * @group diffy_trusted_login
 */
#[Group('diffy_trusted_login')]
#[RunTestsInSeparateProcesses]
class DiffySettingsKernelTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'diffy_trusted_login'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'diffy_trusted_login']);
    // Takes uid 1, which core grants every permission.
    $this->createUser([], 'admin');
  }

  /**
   * Saves the settings form with the given values.
   */
  protected function submitSettings(string $allowed_ips, string $accounts): FormState {
    $form_state = (new FormState())->setValues(['allowed_ips' => $allowed_ips, 'accounts' => $accounts]);
    $this->container->get('form_builder')->submitForm(SettingsForm::class, $form_state);
    return $form_state;
  }

  /**
   * Both lists are saved cleaned up, and unknown accounts are kept.
   */
  public function testSaveKeepsUnknownAccounts(): void {
    $this->createUser([], 'diffy');
    $form_state = $this->submitSettings(" 10.0.0.0/8\n\n1.2.3.4\n1.2.3.4", "diffy\nnot-here-yet\n");

    $this->assertSame([], $form_state->getErrors());
    $config = $this->config(DiffyTokenManager::CONFIG);
    $this->assertSame(['10.0.0.0/8', '1.2.3.4'], $config->get('allowed_ips'));
    $this->assertSame(['diffy', 'not-here-yet'], $config->get('accounts'));

    $warnings = array_map('strval', $this->container->get('messenger')->messagesByType('warning'));
    $this->assertCount(1, $warnings);
    $this->assertStringContainsString('not-here-yet', $warnings[0]);
    $this->assertStringNotContainsString('diffy,', $warnings[0]);
  }

  /**
   * Existing accounts are found whatever the case, like at login.
   */
  public function testKnownAccountsMatchCaseInsensitively(): void {
    $this->createUser([], 'diffy');
    $this->createUser([], 'Bot%_two');
    $form_state = $this->submitSettings('', "DIFFY\nbot%_TWO\nbotx_two");

    $this->assertSame([], $form_state->getErrors());
    $warnings = array_map('strval', $this->container->get('messenger')->messagesByType('warning'));
    $this->assertCount(1, $warnings);
    $this->assertStringContainsString('botx_two', $warnings[0], 'LIKE wildcards in names are matched literally.');
    $this->assertStringNotContainsString('DIFFY', $warnings[0]);
    $this->assertStringNotContainsString('bot%_TWO', $warnings[0]);
  }

  /**
   * No account warning when the submission is rejected anyway.
   */
  public function testNoAccountWarningOnInvalidSubmission(): void {
    $form_state = $this->submitSettings('1.2.3.4/33', 'not-here-yet');
    $this->assertArrayHasKey('allowed_ips', $form_state->getErrors());
    $this->assertSame([], $this->container->get('messenger')->messagesByType('warning'));
  }

  /**
   * An invalid address is an error and nothing is saved.
   */
  public function testInvalidIpIsRejected(): void {
    $this->config(DiffyTokenManager::CONFIG)->set('allowed_ips', ['192.0.2.1'])->save();
    $form_state = $this->submitSettings("1.2.3.4/33", '');

    $this->assertArrayHasKey('allowed_ips', $form_state->getErrors());
    // Read storage: validation fills ConfigFormBase's in-memory copy.
    $stored = $this->container->get('config.storage')->read(DiffyTokenManager::CONFIG);
    $this->assertSame(['192.0.2.1'], $stored['allowed_ips']);
  }

  /**
   * The regenerate route is closed while settings.php defines the token.
   */
  public function testRegenerateRouteAccess(): void {
    $this->container->get('router.builder')->rebuild();
    $admin = $this->createUser(['administer site configuration']);
    $access_manager = $this->container->get('access_manager');

    $this->assertTrue($access_manager->checkNamedRoute('diffy_trusted_login.regenerate', [], $admin));
    $this->assertFalse($access_manager->checkNamedRoute('diffy_trusted_login.regenerate', [], $this->createUser()));

    $this->setSetting(DiffyTokenManager::KEY, 'from-settings');
    $this->assertFalse($access_manager->checkNamedRoute('diffy_trusted_login.regenerate', [], $admin));
    $this->assertTrue($access_manager->checkNamedRoute('diffy_trusted_login.settings', [], $admin), 'The settings page stays open.');
  }

}
