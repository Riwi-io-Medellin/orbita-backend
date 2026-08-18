# Integrating your app with Orbita SSO

Orbita Backend is the central identity provider for all Riwi apps. Users log in once with an Orbita local account or Microsoft, and your app's backend receives a signed token proving who they are and what role they hold in *your* app specifically.

## 1. Get registered

Ask an Orbita platform admin to register your app (this cannot be self-served yet):

- A `client_id` (a slug, e.g. `my-app`)
- A `client_secret` (shown once at creation time — store it securely, e.g. as a server-side env var)
- The launcher tile (`slug`, name, description, icon and launch URL), created together with the SSO client
- One or more allow-listed `redirect_uri`s (one per environment: dev/staging/prod)
- The roles your app needs, and which users get which role

None of this is usable until at least one role is assigned to a user for your app — an authenticated user with zero roles for your app is refused at login (`403`).

## 2. Send users to Orbita to log in

Redirect the user's browser to:

```
GET https://<orbita-host>/api/auth/authorize
    ?client_id=<your client_id>
    &redirect_uri=<your registered redirect_uri>
    &state=<random per-request string, keep it and verify it on the way back>
```

- If the user already has an Orbita session, they're bounced straight back — no extra prompt.
- Otherwise they see Orbita's login page and may use their local password or Microsoft.
- Either way, if they're provisioned for your app, they land on your `redirect_uri` with `?code=...&state=...`.
- `redirect_uri` must match one of your registered URIs **exactly**, or the request is rejected (`400`) — this is what stops an unregistered site from hijacking the flow.

## 3. Exchange the code for a token (server-to-server)

From your backend, not the browser:

```
POST https://<orbita-host>/api/auth/token
Content-Type: application/json

{
  "code": "<code from the redirect>",
  "client_id": "<your client_id>",
  "client_secret": "<your client secret>",
  "redirect_uri": "<the same redirect_uri used in step 2>"
}
```

Response:

```json
{
  "access_token": "<RS256 JWT>",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

The code is single-use and expires ~60 seconds after issuance — exchange it immediately.

## 4. Verify the token locally

The `access_token` is a JWT signed with Orbita's RSA private key (`RS256`). Fetch Orbita's public key once (cache it) and verify locally — no need to call Orbita again per request:

```
GET https://<orbita-host>/api/.well-known/jwks.json
```

Verify:
- Signature, using the key matching the token's `kid` header.
- `exp` — token is valid for 30 minutes from issuance.
- `aud` — must equal your own `client_id`. Reject tokens issued for a different app.

Decoded payload:

```json
{
  "sub": "<Orbita user id>",
  "email": "user@example.com",
  "name": "User name",
  "aud": "your-app-client-id",
  "roles": ["admin"],
  "jti": "<unique token id>",
  "exp": 1234567890
}
```

Use `roles` to drive your app's own authorization. Mint your own app-local session/cookie from here — your backend does not need to talk to Orbita again for the rest of that session.

## 5. Logout and revocation

When a user logs out of Orbita, Orbita revokes every token it has issued on their behalf — but revocation is enforced server-side, not by invalidating the JWT's signature. A revoked token still decodes and verifies fine locally via JWKS; only Orbita's own record knows it's revoked. So:

- If your app **never checks revocation**, it keeps honoring the token until it naturally expires (≤30 minutes after issuance). That's fine for most cases and requires no extra work.
- If your app needs to know **immediately** (e.g. before a sensitive action, or on a periodic session check), call:

```
POST https://<orbita-host>/api/auth/introspect
Content-Type: application/json

{
  "token": "<the access_token you were issued>",
  "client_id": "<your client_id>",
  "client_secret": "<your client secret>"
}
```

Response:

```json
{ "active": true, "sub": "...", "email": "...", "roles": ["admin"], "exp": 1234567890 }
```

or, if revoked/expired/invalid:

```json
{ "active": false }
```

You can only introspect your own app's tokens — a token issued with `aud` for a different app always returns `active: false`, even with a valid `client_secret`.

## Notes

- Token lifetimes and the authorization-code TTL are currently fixed in code (30 min / 60 sec) — ask if you need them tuned.
- `/introspect` is opt-in — call it only where instant revocation actually matters to you. It's not required for every request.

## Orbita production variables

In addition to the existing database and Microsoft OAuth variables, Railway must define:

```env
ENVIRONMENT=production
FRONTEND_URL=https://<orbita-frontend>
MICROSOFT_REDIRECT_URI=https://<orbita-backend>/api/auth/callback

JWT_SECRET=<independent random secret for the server-side pending-login session>
JWT_ALGORITHM=RS256
JWT_EXPIRE_MINUTES=60
JWT_KID=orbita-prod-2026-08
JWT_PRIVATE_KEY=<PEM RSA private key>
JWT_PUBLIC_KEY=<PEM RSA public key>

PLATFORM_ADMIN_EMAILS=admin1@example.com,admin2@example.com
```

Keep `JWT_KID` stable while the key pair is unchanged. The private key must only exist in the Orbita backend; client applications use the public JWKS endpoint. `PLATFORM_ADMIN_EMAILS` bootstraps the first administrators and may be narrowed after normal administration is established.

Orbita runs Alembic migrations automatically during backend startup. Deploy the backend before registering SSO clients, then deploy each client app with its generated secret.
