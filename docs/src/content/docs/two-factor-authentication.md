---
title: "Two-Factor Authentication"
description: "How to protect the linkding login with a code from an authenticator app"
---

linkding supports two-factor authentication (2FA) with time-based one-time passwords (TOTP). When 2FA is enabled, logging in with the login form requires a code from an authenticator app in addition to the password.

## Enable two-factor authentication

1. Go to *Settings > General* and find the *Two-factor authentication* section.
2. Click *Enable*.
3. Scan the QR code with an authenticator app, or enter the secret manually.
4. Enter the 6-digit code from the app and click *Confirm*.
5. Save the recovery codes that are shown. linkding shows them only once.

Two-factor authentication is only active after you confirm it with a valid code.

## Recovery codes

Each recovery code can be used once instead of a code from the authenticator app. Use one if you lose access to your authenticator app. You can enter a recovery code anywhere a code is requested, for example on the login page or to disable two-factor authentication.

## Disable two-factor authentication

Go to *Settings > General*, enter a code from your authenticator app or a recovery code, and click *Disable*.

## Failed attempts

After 5 failed codes, linkding locks the code step for that user for 15 minutes. Failed attempts on the login page and on the disable form count together, also across different browsers. Failed codes on the login page return HTTP status 401, the same as a wrong password, so tools like Fail2Ban can detect them.

## Reset two-factor authentication for a user

If a user lost access to the authenticator app and all recovery codes, an administrator can remove two-factor authentication for that user:

```shell
docker exec -it linkding python manage.py reset_mfa <username>
```

The user can then log in with the password only, and enable two-factor authentication again.

## What two-factor authentication does not cover

Two-factor authentication only protects the login form. These ways of authenticating are not affected:

- **REST API tokens**: An API token works without a code. Treat it like a password. You can only create a token while logged in, which requires the code when 2FA is enabled.
- **RSS feed tokens**: Feed URLs contain a token that gives read access to your bookmark feeds without a code.
- **OIDC login**: When you log in with OIDC, your identity provider is responsible for two-factor authentication.
- **Authentication proxy**: When you use `LD_ENABLE_AUTH_PROXY`, the proxy is responsible for two-factor authentication.

The admin app login redirects to the linkding login, so it also requires the code.

Enabling two-factor authentication does not end existing sessions, and does not revoke API tokens or feed tokens. If you enable 2FA because you think someone knows your password, also change your password and delete your API tokens after you enable it.

When `LD_DISABLE_LOGIN_FORM` is enabled, password login is off, and the *Two-factor authentication* section is hidden.
