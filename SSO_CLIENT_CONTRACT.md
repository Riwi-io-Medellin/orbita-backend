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

## 2. Browser and backend responsibilities

1. The app backend generates a cryptographically-random `state` (minimum 16 characters), keeps it in
   a short-lived HTTP-only cookie or server-side session, then redirects the browser to the discovered
   `authorization_endpoint` with `client_id`, `redirect_uri` and `state`.
2. Orbita redirects back with `code` and the same `state`. The app must compare state in constant time.
3. The app backend posts `code`, its client credentials and the exact redirect URI to `token_endpoint`.
4. The app backend verifies the returned JWT using `jwks_uri`: RS256 signature, `aud == client_id`,
   expiration and required claims. It then creates its own local session.

The browser never exchanges a code and never receives `client_secret`.

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

## 5. Reference adapters

- NestJS reference: `TeamLead-Backend/src/auth/orbita-sso.client.ts` and
  `npm run sso:roles:sync`.
- FastAPI reference: `clients/fastapi/orbita_sso.py` in this repository.

Adapters may keep a local session after the callback. Call the discovered `introspection_endpoint` only
when immediate revocation is required; otherwise JWT expiry remains the normal validity boundary.
