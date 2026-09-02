# Orbita SSO Client Contract v1

This is the implementation contract for an application that consumes Orbita SSO. It complements
`API_CONTRACT.md`, which documents Orbita's complete API surface.

## 1. Configuration

The consuming application's **backend** owns these values. Do not expose its secret to a browser.

```env
ORBITA_SSO_BASE_URL=https://<orbita-backend>
ORBITA_SSO_CLIENT_ID=my-app
ORBITA_SSO_CLIENT_SECRET=<returned-once-during-registration>
ORBITA_SSO_REDIRECT_URI=https://<my-app-backend>/auth/orbita/callback
```

Fetch `GET /api/.well-known/orbita-configuration` during startup or on first use. Consumers must
require `contract_version: "1.0"` before using the advertised absolute endpoint URLs.

Use a separate Órbita registration and secret for development, staging and production. Sharing one
confidential client across environments expands the impact of a leaked secret and makes callback
governance harder. The launcher URL should point to an endpoint in the consuming backend that starts
this flow, not directly to Órbita's `/authorize` endpoint or to a frontend-only callback.

The configured base URL and every discovered endpoint must use HTTPS outside local development.
Validate that discovery comes from the expected Órbita origin; do not follow it to an arbitrary host.

## 2. Browser and backend responsibilities

1. The app backend generates a cryptographically-random, single-use `state` with at least 128 bits of
   entropy (minimum 16 characters), keeps it in a short-lived HTTP-only cookie or server-side session,
   then redirects the browser to the discovered
   `authorization_endpoint` with `client_id`, `redirect_uri` and `state`.
2. Orbita redirects back with `code` and the same `state`. The app must require both values, compare
   state in constant time, consume it once and reject unsolicited, expired or replayed callbacks.
3. The app backend posts `code`, its client credentials and the exact redirect URI to `token_endpoint`.
4. The app backend verifies the returned JWT using `jwks_uri`: RS256 signature, `aud == client_id`,
   expiration and required claims. It then creates its own local session with `HttpOnly`, `Secure` in
   production and a deliberate `SameSite` policy, and rotates any pre-login session identifier.

The browser never exchanges a code and never receives `client_secret`.

The callback must handle missing `code`, missing/mismatched `state`, provider/access errors and a
failed/timeout token exchange without creating a session. A code is valid for about 60 seconds and is
single-use. If the exchange result is uncertain or its response is lost, restart authorization rather
than repeatedly submitting the same code.

## 3. Token identity

The token is RS256 and contains at least:

```json
{
  "sub": "orbita-user-uuid",
  "email": "person@example.com",
  "name": "Person Name",
  "aud": "my-app",
  "roles": ["admin"],
  "jti": "token-id",
  "exp": 1234567890
}
```

`roles` contains stable **role keys** owned by the consuming app. The app maps those keys to its own
authorization rules. Orbita never interprets what a role permits inside an app.

Token verification must also:

- accept only the configured `RS256` algorithm and select the public key by `kid`;
- require `sub`, `email`, `name`, `aud`, `roles`, `jti` and `exp`, including expected types;
- reject an empty/unknown subject and unexpected role keys instead of granting a default privilege;
- allow only a small, explicit clock skew;
- refresh JWKS once when an unknown `kid` appears, then fail closed if it remains unknown;
- never log the raw token or place it in a URL.

The current v1 token does not carry `iss`, `iat` or `nbf`; do not invent validations for absent claims.
Environment separation therefore depends on distinct registration, trusted discovery origin, key set
and audience.

## 4. Role catalog ownership

Each SSO app declares its role catalog from its own backend or deployment pipeline using the discovered
`role_catalog_sync_endpoint`. It sends:

```json
{
  "client_secret": "server-side-only",
  "roles": [
    {"key": "admin", "display_name": "Administrator", "description": "Full access"}
  ]
}
```

`key` must be lowercase and stable; it is the exact string used in authorization checks and JWTs.
`display_name` and `description` are presentation metadata for Orbita administrators. Synchronization
upserts declared roles. A formerly synchronized role missing from the next manifest becomes inactive;
it is not deleted and its existing assignments are retained as history. Inactive roles cannot be
assigned or authorize SSO.

Send the complete desired catalog on every sync (0–100 unique entries), not a partial patch. Run it
from the consuming backend or deployment pipeline before assigning users. Removing a key is a breaking
authorization change: coordinate it, deploy code that no longer expects it and then remove it from the
manifest. Never recycle an old key with a different security meaning.

## 5. Reference adapters

- NestJS reference: `TeamLead-Backend/src/auth/orbita-sso.client.ts` and
  `npm run sso:roles:sync`.
- FastAPI reference: `clients/fastapi/orbita_sso.py` in this repository.

Adapters may keep a local session after the callback. Call the discovered `introspection_endpoint` when
recorded logout/expiry checks are required; otherwise JWT expiry remains the normal validity boundary.

The adapters are reference building blocks, not complete authentication middleware: the consuming app
still owns state storage/consumption, callback routes, local-user mapping, session cookies, CSRF,
logout, authorization checks, observability and error UX.

## 6. Introspection and local-session policy

`POST /api/auth/introspect` is server-to-server and requires the same client credentials. A consumer
may call it before sensitive actions or periodically while its local session is active. Treat transport
failure as a deliberate product decision: fail closed for high-risk operations; do not silently turn an
unavailable introspection service into approval.

Logout, user/app disabling, and role-assignment changes make an issued token inactive through
introspection. Consumers that do not call introspection must still bound their local session to the
JWT expiration (currently 30 minutes).

## 7. Error handling and secret operations

- `400` from `/token`: code invalid, expired, reused or bound to another redirect URI; restart login.
- `401`: invalid client credentials; alert operators without exposing the secret.
- An authenticated user without an active role for the app is redirected by the browser-facing
  authorization endpoint to Órbita's frontend with `error=sso_access_denied`; show an access-denied
  message and do not retry automatically. A direct API/client call may still receive `403`.
- `429`/`5xx`/network failure: show a recoverable error and use bounded retries only for requests known
  to be safe; never loop browser redirects.

Store `client_secret` in the consuming backend's secret manager. Restrict who can read it, never send
it to analytics/logs, and plan an incident response. Platform administrators can rotate it with
`POST /api/apps/{client_id}/rotate-secret`; the response returns the new value once and accepts the
previous secret for 15 minutes, so coordinate the consuming deployment before rotating a live credential.

## 8. Acceptance checklist for a new app

Before production registration is considered complete, demonstrate:

- successful login for an active user with one and with multiple app roles;
- denial for no role, inactive role, inactive user and disabled app;
- rejection of missing/mismatched/replayed `state` and an unsolicited callback;
- rejection of an unregistered/near-match `redirect_uri`, expired/reused code and wrong secret;
- rejection of wrong `aud`, unknown `kid`, invalid signature, expired token and malformed role claims;
- secure local cookie/session creation, CSRF protection and logout behavior;
- defined behavior when Órbita, token exchange, JWKS or introspection is unavailable;
- role-catalog sync is repeatable and removing a role deactivates it as expected;
- no token, code, password or client secret appears in browser storage, URLs, logs or error reporting.
