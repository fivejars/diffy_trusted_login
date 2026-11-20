# Diffy trusted login: TFA

Lets the accounts Diffy logs in with skip the [TFA](https://www.drupal.org/project/tfa) second
factor, so Diffy can log in to sites where TFA is required for the roles it needs. No extra role
is required.

A login skips the second factor only when **all** of these hold:

1. The username and password are correct (normal login validation).
2. The request carries a valid `X-Diffy-Token` from an allowed IP address.
3. The account is listed under **Diffy accounts** on the Diffy trusted login settings page.

Everyone else, including Diffy's accounts when the token is missing, goes through TFA as usual.
Each skipped login is logged on the `diffy_trusted_login` channel.

It works whether or not TFA has been set up on the Diffy account, so the account never uses up
TFA's "skip setup" allowance.

## Setup

1. Enable the submodule.
2. At `/admin/config/services/diffy-trusted-login`, add the Diffy account under
   **Diffy accounts**. Also set **Allowed IP addresses**: with this submodule, the token and a
   password are all that stand in for the second factor.
