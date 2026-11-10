# Authenticator password recovery

Implemented through `feature/authenticator-password-recovery` in CompAuthAPI, compgateway2, and compgateway-admin-cms, independently of `feature/eur-commission`. Application deployment is a separate rollout; this feature has not been deployed.

## User flow

1. Select Forgot password and enter **username or email** and a new six-digit code from the authenticator already enrolled for that account.
2. Verification returns a password-reset authorization valid for five minutes. The browser keeps this in component memory; it is never placed in a URL, browser persistent storage, or logs.
3. Enter and confirm the new password. The password must contain at least eight characters and fit BCrypt's 72-byte UTF-8 limit. The UI provides English/Arabic validation and recovery instructions.
4. A successful reset consumes the authorization, clears old email reset tokens, revokes active authentication and device sessions, and clears their refresh tokens. The authenticator secret and enrollment flag remain unchanged. A timed failed-password lock may be cleared; disabled or manually locked accounts cannot use this recovery path.
5. Return to login and use the new password with a **new** authenticator code. A code already accepted for login, setup, or recovery cannot be accepted again in its validity window.

Users without completed authenticator enrollment, or without access to that authenticator, must use verified support recovery. This flow does not generate a replacement QR code or disable 2FA.

## API contract

`POST /api/auth/password-recovery/verify`

```json
{ "login": "username-or-email", "code": "012345" }
```

Success: `{ "resetToken": "<64-character random authorization>", "expiresIn": 300 }`.

`POST /api/auth/password-recovery/complete`

```json
{ "resetToken": "<authorization>", "password": "<new password>", "confirmPassword": "<same password>" }
```

Success: HTTP 200 with `success: true`. Verification/completion failures return HTTP 400, and exhausted recovery attempt limits return HTTP 429. The API provides generic errors for missing, disabled, unenrolled, ambiguous, invalid-code, or replayed-code accounts and does not issue login tokens. These new routes bypass the legacy always-200 wrapper and use `Cache-Control: no-store`.

compgateway2 proxies only the two fixed paths under `/Companygw/api/auth/password-recovery/`. The CMS calls the configured Auth API directly. Both clients reject legacy-wrapped failures and malformed success responses.

## Persistence and security

Migration: **`20261110131728_AddAuthenticatorPasswordRecovery`**.

- `AuthenticatorActionGrants`: hashed 256-bit random tokens, purpose, user, password/secret fingerprints, creation/expiry, and consumption time. Tokens are bound to the account state and cannot be used after the password or authenticator changes. Setup grants and password-reset grants are purpose-separated.
- `AuthenticatorUsedSteps`: unique `(UserId, TimeStep)` receipts shared by setup, login, and password recovery to reject reused TOTP codes.
- `PasswordRecoveryThrottles`: hashed account/IP keys and attempt windows. Username and email aliases resolve to the same user limit. Limits are five recovery verification requests per account and thirty per source IP per fifteen minutes. Source IP is the address seen by Auth API; forwarded headers are not blindly trusted. Confirm trusted-proxy/WAF configuration and expected volume before later deployment.
- Grant/OTP decisions and consumption execute in serializable transactions using fresh contexts for SQL Server transient retries. SQL Server grant and throttle reads use update/range locks. Password reset and revocation commit together.
- Audit logs contain outcome and verified user ID only; no password, OTP, reset authorization, or secret is logged.

Expired grant/throttle/receipt retention should be included in the site's routine database housekeeping. Do not remove OTP receipts that are still within an accepted OTP time window.

## Enrollment prerequisite fixes

The web login response supplies a short-lived `setupToken` only after password verification for an unenrolled user. The web/CMS QR request must present it; completed enrollment cannot be overwritten through that endpoint. Refreshing an authorized pending setup reuses its pending secret instead of rotating it.

New QR images are returned inline (`qrCodeImageBase64`) rather than saved as public attachment files. Requests for legacy `/Attachments/*_2FA.png` files are blocked. Setup responses and the website login proxy are marked no-store. OTP/secret debug output was removed. Normal mobile setup remains supported through its existing signed password-issued challenge and device-policy checks.

The old `/api/auth/forgot-password`, `/customer-forgot-password`, and `/reset-password` implementations now return a failure directing callers to authenticator recovery; they no longer send email or accept old email codes. The unused repository implementations are closed too. Old mobile forgot-password screens therefore need an app/BFF update to use the new recovery flow; until then users can recover through the updated website. Normal mobile login/setup tests continue to pass.

## Database rollout completed; application deployment pending

Applied the reviewed single-migration SQL on 2026-11-10 to:

| Environment | Server | Database | Existing users/security rows |
|---|---|---|---:|
| UAT | 10.3.3.11 | CompAuthDb | 9 / 9 |
| Production | 10.1.1.205 | CompAuthDb | 106 / 106 |

Each transaction compared complete existing Users, UserSecurity, and Settings rows against server-side temporary snapshots and verified unrelated migration history unchanged. Sensitive records were never exported. Only the three empty recovery tables, their constraints/indexes, and this migration-history record were added. A fresh connection verified both migrations afterward. No password recovery was performed against a real user.

Reviewed SQL and result JSON: workspace `output/authenticator-password-recovery/`. SQL SHA-256: `3B273E32A7B07678D1CE57F42767EAD01758A4DF120006FB83DC2C97E054C06A`. The targeted helper is `tmp/authenticator-recovery-migration.ps1`; it is read-only without `-Apply`. Both migrations are already applied; do not repeat apply mode or run unrelated pending migrations.

Later deployment must include the updated **CompAuthAPI, compgateway2, and Admin CMS** together. Refresh existing web clients during rollout: older web QR setup cannot use the new password-issued setup authorization. Use the staging/production `comp-auth-api-20261110-153221-authenticator-recovery` packages, or build fresh packages from the merged source. Packages created before this feature do not include it. The running production/UAT applications continue using their existing code until deployment. CompGateApi and the EUR feature were not changed.

Validation: 85 Auth API tests, 12 company website tests, and 18 CMS tests passed. Both web projects passed TypeScript and changed-file ESLint checks. Coverage includes aliases, replay, throttles, expiration, single-use/concurrent completion, account-state binding, revocation, enrollment protection, disabled email routes, migration scope, and API/client success/error contracts.
