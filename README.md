# Diffy trusted login

Lets [Diffy](https://diffy.website) (or any visual-regression crawler) log in to a Drupal site
whose login form is protected against bots.

It does **not** bypass authentication: Diffy still logs in with a real username and password. It
only switches off the bot challenges **on the login page**, and only for requests carrying a
secret `X-Diffy-Token` header (optionally only from allowed IP addresses). Other pages and forms
keep all their protections, for Diffy too.

## How it works

On a verified Diffy request to the login page (`user.login` route), a core access policy grants
the bypass permission that each protection module already checks before protecting a form:

| Module | Permission granted | Covers |
|---|---|---|
| [captcha](https://www.drupal.org/project/captcha) | `skip CAPTCHA` | Every CAPTCHA provider built on it: image CAPTCHA, reCAPTCHA, reCAPTCHA v3, Turnstile, hCaptcha, Friendly Captcha, ALTCHA, … |
| [antibot](https://www.drupal.org/project/antibot) | `skip antibot` | Antibot's JavaScript check |
| [honeypot](https://www.drupal.org/project/honeypot) | `bypass honeypot protection` | Hidden field and time limit |
| [simple_recaptcha](https://www.drupal.org/project/simple_recaptcha) | `bypass simple_recaptcha` | reCAPTCHA v2/v3 |

None of these modules is required; a permission of a module that isn't installed is never checked.
Only submissions of the login form itself are bypassed. Other forms on the login page (e.g. a
newsletter block) may be shown to Diffy without their protections, but submitting one with the
token is rejected and has to pass them.

When **Diffy accounts** are configured, the bypass on the login *submission* applies only to them.
The submitted name is resolved to an account the same way the login form does it (core's
`user.auth` service), so it matches case-insensitively and follows email-login modules. A
token-carrying login for any other account is logged and then has to pass the protections it was
shown without, so it fails. Without configured accounts, any login with a valid token is bypassed.

To cover another module that gates its protection on a bypass permission, add it in
`settings.php`:

```php
$settings['diffy_trusted_login_extra_permissions'] = ['bypass some_module protection'];
```

### Spambot

[Spambot](https://www.drupal.org/project/spambot) doesn't protect the login form, but its cron
scans existing accounts against StopForumSpam, including the IP addresses they log in from, and
can block them. Diffy logs in from datacenter addresses, which are often listed. The accounts
listed under **Diffy accounts** are therefore always granted `protected from spambot scans`, so
spambot never blocks them.

### TFA

The bundled **Diffy trusted login: TFA** submodule (`diffy_trusted_login_tfa`) lets the Diffy
accounts skip the [TFA](https://www.drupal.org/project/tfa) second factor on verified Diffy
requests, without an extra role. See `modules/diffy_trusted_login_tfa/README.md`.

### Caching

The unprotected login page is never served to anyone else, and Diffy never receives a cached,
protected one:

- Every verified Diffy request bypasses the internal page cache, which keys on the URL alone and
  answers before routing. The path can't be used to single out the login page, since routes also
  match case-insensitively and through aliases (`/USER/LOGIN`, `/login`). Requests without the
  header aren't affected.
- Everything else (render cache, dynamic page cache) already varies by `user.permissions`, which
  differs for Diffy login requests: calculated permissions vary by the `diffy_login_request` and
  `user.diffy_account` cache contexts. Their values are only `0` or `1`, so the token never
  appears in a cache ID and caches aren't split per user.

## Requirements

- Drupal 10.3 or 11
- PHP 8.1 or later

## Installation

```
composer require fivejars/diffy_trusted_login
drush en diffy_trusted_login -y
# Only if the site uses TFA:
drush en diffy_trusted_login_tfa -y
```

A token is generated automatically on install.

## Setup

1. Open **Admin → Configuration → Web services → Diffy trusted login**
   (`/admin/config/services/diffy-trusted-login`). This needs the *Administer site configuration*
   permission. Or use Drush:

   ```
   drush diffy-token                 # print the token
   drush diffy-token-regenerate -y   # rotate it and print the new one
   ```

   The token is read-only and stored in State (the database). It is not exported to config, so it
   never ends up in the repository. Use **Regenerate token** to rotate it.

   Optionally, set the token in `settings.php` instead. It then takes precedence over the stored
   one, and regeneration is disabled:

   ```php
   $settings['diffy_trusted_login_token'] = getenv('DIFFY_TOKEN');
   ```
2. In Diffy, open the project's **Settings → HTTP headers** and add:

   ```
   X-Diffy-Token: <the token from the settings page>
   ```

   After regenerating the token, update this header with the new value.
3. On the same settings page:
   - **Allowed IP addresses** (recommended): Diffy's IP addresses or CIDR ranges. The token is then
     rejected from anywhere else. Behind a proxy or CDN, set `$settings['reverse_proxy']` so
     Drupal sees the real client IP.
   - **Diffy accounts** (recommended): usernames of the accounts Diffy logs in with, one per line,
     matched case-insensitively. Once set, only these accounts get past the login protections.
     Also used by the spambot exemption and the TFA submodule. Names are kept even where no such
     account exists yet (the form warns), so the setting deploys across environments. Stored as usernames, so the setting deploys across environments.

   Both are regular config (`diffy_trusted_login.settings`) and can be exported.

## Edge caches (Pantheon and other CDNs)

Drupal sends Diffy's responses as `no-cache, private`, so an edge cache never stores the
unprotected version. An edge cache can still answer Diffy with a login page it cached for a
normal visitor, before the request reaches Drupal. Make Diffy skip the edge cache too:

- **Pantheon:** add a second header in Diffy, `Cookie: NO_CACHE=1`. Pantheon's Global CDN neither
  reads from nor writes to its cache for requests with that cookie.
- **Other CDNs or Varnish:** add a rule that bypasses the cache when `X-Diffy-Token` is present.

## Logging

On the `diffy_trusted_login` channel:

- Warnings for login-page requests that send `X-Diffy-Token` but are rejected (wrong token, an
  IP address that isn't allowed, or a login for an account that isn't a Diffy account), with the
  client IP and URL, once per request. Submissions of other forms on the login page with the token
  are rejected and logged too. The provided token and login name are never logged. At most 10
  rejections per IP address are logged per hour (via core's flood service), and bad tokens on
  other pages grant nothing and aren't logged, so the header can't be used to flood the log.
- Notices for each Diffy login that skipped the second factor (TFA submodule).

## Notes

- Serve the site over HTTPS only: the header is a bearer secret in transit.
- Fail-closed: with no token configured, nothing is bypassed.
- Removing the header in Diffy or rotating the token disables the bypass immediately.
- It does not get past a CDN's bot challenge (e.g. Cloudflare Managed Challenge). That needs an
  allowlist rule at the edge.

## Tests

Unit tests cover the token, IP and account checks, the granted permissions, the cache contexts,
the page cache policy and the TFA bypass decision. Kernel tests cover the wiring into core's
permission, cache, form and hook systems (they need `tfa`, `encrypt` and `key` for the submodule).

```
# Unit tests only:
vendor/bin/phpunit -c web/core web/modules/contrib/diffy_trusted_login/tests/src/Unit \
  web/modules/contrib/diffy_trusted_login/modules/diffy_trusted_login_tfa/tests/src/Unit
# Everything, including kernel tests:
SIMPLETEST_DB=sqlite://localhost//tmp/test.sqlite \
  vendor/bin/phpunit -c web/core web/modules/contrib/diffy_trusted_login
```
