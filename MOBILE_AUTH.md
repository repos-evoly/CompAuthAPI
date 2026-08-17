# Mobile BFF authentication additions

The existing `/api/auth/*` routes and user-authentication implementation remain
unchanged. Mobile traffic uses an isolated, service-protected route group that
delegates to the existing password, lockout, 2FA, geofence, refresh-token, and
user-session handlers.

## Service token

The Mobile BFF obtains a short-lived RSA-signed service token from:

```http
POST /api/service-auth/token
Content-Type: application/json

{
  "client_id": "company-gateway-mobile-bff-uat",
  "client_secret": "<secret>",
  "scope": "company-gateway.mobile",
  "audience": "company-gateway-internal-apis-uat"
}
```

The token contains `token_type=service`, `client_id`, `scope`, and
`environment`. Signature, issuer, audience, lifetime, approved client, scope,
and environment are validated on every `/api/mobile-auth/*` request.

The signing key is separate from the existing user JWT key. Only CompAuthApi
receives the private key. Other internal APIs should receive the public key
when their service-token validation phase is implemented.

## Internal mobile routes

All routes require `X-Service-Authorization: Bearer <service-jwt>`:

```text
POST /api/mobile-auth/login
POST /api/mobile-auth/2fa/setup
POST /api/mobile-auth/2fa/verify
POST /api/mobile-auth/2fa/verify-initial
POST /api/mobile-auth/forgot-password
POST /api/mobile-auth/reset-password
POST /api/mobile-auth/refresh-token
```

Logout and heartbeat require both the service token and the existing user JWT:

```text
POST /api/mobile-auth/logout
POST /api/mobile-auth/session/heartbeat
```

The user JWT remains in `Authorization`. The service JWT is never placed in
that header and never represents a human user.

Approved-device notification-token management also requires both identities:

```text
PUT    /api/mobile-notifications/push-token
GET    /api/mobile-notifications/push-token/status?deviceId=<device-id>
DELETE /api/mobile-notifications/push-token/{deviceId}
```

The service-only `POST /api/mobile-notifications/targets/resolve` route returns
eligible Firebase targets for explicitly supplied CompAuth user IDs, and
`POST /api/mobile-notifications/push-token/invalidate` removes tokens Firebase
reports as unregistered. Neither route is exposed by the public BFF. Only
active users with approved devices are returned; user-facing responses never
contain registration tokens. Revoking a device deletes its push token.

After a valid password is supplied, logins requiring 2FA return a five-minute
challenge token. The 2FA routes require the challenge and bind it to the login,
device ID, purpose, and environment. This prevents the public BFF from exposing
the existing 2FA setup operation without proof of the preceding password check.

## Configuration

Use the placeholder templates in `deploy/`. UAT and Live require different:

- RSA service-token keypairs
- issuer and audience values
- service client IDs and secrets
- process environment and secret files

Generate an RSA keypair outside the repository, for example:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out service-token-private.pem
openssl rsa -pubout -in service-token-private.pem -out service-token-public.pem
```

Do not commit either environment's private key or client secret. The existing
committed user JWT key and database/email credentials were not changed by this
work, but they remain a security debt requiring coordinated rotation and
migration to protected configuration.
