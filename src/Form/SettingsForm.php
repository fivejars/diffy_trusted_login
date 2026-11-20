<?php

namespace Drupal\diffy_trusted_login\Form;

use Drupal\Component\Utility\Html;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\ConfigTarget;
use Drupal\Core\Form\FormStateInterface;
use Drupal\Core\Url;
use Drupal\diffy_trusted_login\DiffyTokenManager;
use Drupal\diffy_trusted_login\IpList;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Shows the Diffy token and setup steps; configures allowed IPs and accounts.
 */
class SettingsForm extends ConfigFormBase {

  /**
   * The Diffy token manager.
   */
  protected DiffyTokenManager $tokenManager;

  /**
   * The entity type manager.
   */
  protected EntityTypeManagerInterface $entityTypeManager;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    $instance = parent::create($container);
    $instance->tokenManager = $container->get('diffy_trusted_login.token_manager');
    $instance->entityTypeManager = $container->get('entity_type.manager');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  public function getFormId() {
    return 'diffy_trusted_login_settings';
  }

  /**
   * {@inheritdoc}
   */
  protected function getEditableConfigNames() {
    return [DiffyTokenManager::CONFIG];
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    $from_settings = $this->tokenManager->hasSettingsOverride();

    $form['intro'] = [
      '#markup' => '<p>' . $this->t('Requests to the login page carrying this secret token skip the bot protections of the login form, so Diffy can log in. Submissions of other forms and other pages are not affected. Rejected attempts are logged.') . '</p>',
    ];

    $form['token'] = [
      '#type' => 'item',
      '#title' => $this->t('Diffy token'),
      '#markup' => '<code>' . Html::escape($this->tokenManager->ensureToken()) . '</code>',
      '#description' => $from_settings
        ? $this->t('Defined in settings.php, which overrides the stored token. Regeneration is unavailable until that override is removed.')
        : $this->t('Generated automatically and stored in State, never in exported config.'),
    ];

    if (!$from_settings) {
      $form['regenerate'] = [
        '#type' => 'link',
        '#title' => $this->t('Regenerate token'),
        '#url' => Url::fromRoute('diffy_trusted_login.regenerate'),
        '#attributes' => ['class' => ['button', 'button--danger']],
      ];
    }

    $form['diffy'] = [
      '#type' => 'details',
      '#title' => $this->t('Configure Diffy'),
      '#open' => TRUE,
      'list' => [
        '#theme' => 'item_list',
        '#list_type' => 'ol',
        '#items' => [
          $this->t('Open your project in Diffy and go to <strong>Settings → HTTP headers</strong>.'),
          $this->t('Add a header with name <code>X-Diffy-Token</code> and the token above as its value.'),
          $this->t('Behind an edge cache, also make Diffy skip it. On Pantheon, add the header <code>Cookie: NO_CACHE=1</code>.'),
        ],
      ],
    ];

    $form['allowed_ips'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Allowed IP addresses'),
      '#description' => $this->t("One IP address or CIDR range per line (IPv4 or IPv6), e.g. <code>203.0.113.10</code> or <code>203.0.113.0/24</code>. The token is only accepted from these addresses. Leave empty to accept it from any address. Behind a proxy or CDN, make sure Drupal sees the real client IP (<code>\$settings['reverse_proxy']</code>). Your current IP address is @ip.", [
        '@ip' => $this->getRequest()->getClientIp(),
      ]),
      '#config_target' => new ConfigTarget(
        DiffyTokenManager::CONFIG,
        'allowed_ips',
        [static::class, 'linesToText'],
        [IpList::class, 'parse'],
      ),
      '#rows' => 5,
    ];

    $form['accounts'] = [
      '#type' => 'textarea',
      '#title' => $this->t('Diffy accounts'),
      '#description' => $this->t("Usernames of the accounts Diffy logs in with, one per line. Once set, only these accounts get past the login protections with the token. See the README for their spambot and TFA exemptions. Kept as typed, so the setting deploys across environments even where an account doesn't exist yet."),
      '#config_target' => new ConfigTarget(
        DiffyTokenManager::CONFIG,
        'accounts',
        [static::class, 'linesToText'],
        [IpList::class, 'parse'],
      ),
      '#rows' => 3,
    ];

    // The page shows a secret that changes outside of config (State), so it
    // must never be served from cache.
    $form['#cache']['max-age'] = 0;

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validateForm(array &$form, FormStateInterface $form_state) {
    foreach (IpList::parse($form_state->getValue('allowed_ips')) as $ip) {
      if (!IpList::isValid($ip)) {
        $form_state->setErrorByName('allowed_ips', $this->t('%ip is not a valid IP address or CIDR range.', ['%ip' => $ip]));
      }
    }

    parent::validateForm($form, $form_state);

    // Unknown usernames are kept (they may exist on another environment),
    // but worth pointing out once the submission is otherwise valid.
    if (!$form_state->getErrors()) {
      $unknown = $this->getUnknownAccountNames(IpList::parse($form_state->getValue('accounts')));
      if ($unknown) {
        $this->messenger()->addWarning($this->t('No account exists on this site for: %names. They are saved anyway.', ['%names' => implode(', ', $unknown)]));
      }
    }
  }

  /**
   * Returns the given usernames that match no account, case-insensitively.
   *
   * Login matching is case-insensitive, so this must be too. One '='
   * condition per name: entity queries match those case-insensitively on
   * every database driver, unlike IN or loadByProperties().
   *
   * @param string[] $names
   *   The usernames to check.
   *
   * @return string[]
   *   The usernames, as given, that no account has.
   */
  protected function getUnknownAccountNames(array $names): array {
    if (!$names) {
      return [];
    }
    $storage = $this->entityTypeManager->getStorage('user');
    $query = $storage->getQuery()->accessCheck(FALSE);
    $group = $query->orConditionGroup();
    foreach ($names as $name) {
      $group->condition('name', $name);
    }
    $existing = array_map(
      fn($account) => mb_strtolower($account->getAccountName()),
      $storage->loadMultiple($query->condition($group)->execute()),
    );
    return array_values(array_filter($names, fn($name) => !in_array(mb_strtolower($name), $existing, TRUE)));
  }

  /**
   * Converts a list setting to textarea text, one entry per line.
   *
   * The reverse is IpList::parse(), which splits any such line list.
   *
   * @param string[] $lines
   *   The configured entries.
   */
  public static function linesToText(array $lines): string {
    return implode("\n", $lines);
  }

}
