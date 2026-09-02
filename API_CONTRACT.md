# Orbita API contract

Base URL: `https://<orbita-host>/api`. The executable contract is the OpenAPI document at
`/openapi.json` (Swagger at `/docs`). This document fixes the business rules that are easy to miss
when looking at individual routes.

## Authentication and response conventions

- **Public** endpoints do not need a credential.
- **Session** endpoints require Orbita's HTTP-only access cookie (`__Host-orbita_access` in production;
  `access_token` in development). Browser requests must use
  credentials so the cookie is sent.
- **Platform admin** endpoints additionally require `is_platform_admin=true` on that user.
- **Client credentials** endpoints are called server-to-server with `client_id` and `client_secret`
  in the JSON body; never expose a client secret to a browser.
- `204` responses have no body. HTTP errors use `{ "detail": "..." }`. Bulk responses report unknown
  ids in `not_found_ids` instead of silently discarding them.

## Application access policy

Every launcher `Application` exposes `access_policy` in its read models:

| Policy | Created by | How a user gets it in the launcher | How it authenticates |
| --- | --- | --- | --- |
| `catalog` | `POST /applications` | A linked global role or a direct user grant | It is only a launcher URL; Orbita does not issue an SSO token for it. |
| `sso_role` | `POST /apps` | At least one role assigned through `POST /apps/{client_id}/roles/{role_id}/assign` | The same app role is required by `/auth/authorize` and is embedded in the app JWT. |

Therefore, `POST /users/.../applications/...` and `POST /applications/.../roles/...` return `409`
for `sso_role` applications. They are catalog-only grants. Disabling a launcher application or its SSO
client changes both records atomically.

## System

| Method | Path | Access | Contract |
| --- | --- | --- | --- |
| GET | `/health` | Public | Liveness response: `{status:"ok", service:"orbita-backend"}`. |
| GET | `/.well-known/jwks.json` | Public | RSA public keys used to verify Orbita JWTs. |
| GET | `/.well-known/orbita-configuration` | Public | Discovery document for Orbita SSO Client Contract v1: version, endpoints, supported algorithms and claims. |

## Authentication and SSO

| Method | Path | Access | Contract |
| --- | --- | --- | --- |
| GET | `/auth/login` | Public | Starts Microsoft OAuth; `302` to Microsoft. |
| GET | `/auth/callback` | Public | Microsoft callback; establishes the central cookie and redirects to the frontend or pending SSO client. |
| GET | `/auth/providers` | Public | Returns which of Moodle, Microsoft and local login are currently available. Provider availability is enforced by the backend. |
| POST | `/auth/moodle/login` | Public | Body: `{username,password}`. Validates credentials through Moodle without persisting its password or token, resolves the canonical Orbita user, and sets the central cookie. Returns `429` for throttling and `503` when Moodle is disabled/unavailable. |
| POST | `/auth/moodle/password-reset` | Public | Body: `{identifier,identifier_type}` where `identifier_type` is `username` or `email`. Requests Moodle's password-reset flow through Orbita without a Moodle token and always returns a generic confirmation when accepted. |
| POST | `/auth/login` | Public | Local email/password login. Sets the central cookie. `401` invalid credentials; `403` inactive user. |
| GET | `/auth/csrf` | Session | Returns a short-lived, session-bound token for `X-CSRF-Token` on cookie-authenticated mutations. |
| GET | `/auth/me` | Session | Current profile and global roles. App-scoped roles are intentionally excluded. |
| POST | `/auth/logout` | Public/session | Clears the central cookie and revokes the caller's recorded app sessions. Always succeeds. |
| GET | `/auth/authorize` | Public/session | Starts an authorization-code SSO handoff. Query: `client_id`, exact registered `redirect_uri`, `state` (16–512 chars). Redirects with `code` and `state`; if an already authenticated user has no app role, redirects to the frontend with `error=sso_access_denied`. |
| GET | `/auth/resume` | Public/session | Continues the handoff saved by `/auth/authorize` after central login. |
| POST | `/auth/token` | Client credentials | Exchanges a single-use, ~60-second code for a 30-minute RS256 JWT. Body: `code`, `client_id`, `client_secret`, `redirect_uri`. |
| POST | `/auth/introspect` | Client credentials | Body: `token`, `client_id`, `client_secret`. Returns `200 {active:false}` for revoked, expired, wrong-audience, unavailable app/user, or changed roles. |
| POST | `/apps/{client_id}/rotate-secret` | Platform admin + CSRF | Returns the replacement secret once; the previous secret expires in 15 minutes. |

The token's `aud` equals `client_id`; clients must verify signature, expiration and audience using JWKS.

Existing-token semantics in v1: app-session records make expiry and central logout observable through
`/auth/introspect`. User/app deactivation and role assignment changes invalidate introspection
immediately. Consumers must bound local sessions to token
expiry unless a stronger revalidation policy is agreed. New token issuance must always enforce current
user, app and active-role state; any implementation that does not is a contract defect.

## Launcher and audit

| Method | Path | Access | Contract |
| --- | --- | --- | --- |
| GET | `/applications/` | Session | Current user's available launcher entries. Each includes `access_policy`. |
| POST | `/applications/{application_id}/access` | Session | Writes an `application.access` audit event only if the application is available to the user. |
| POST | `/applications/` | Platform admin | Creates a `catalog` (non-SSO) launcher application. |
| PATCH | `/applications/{application_id}/status` | Platform admin | Enables/disables a catalog tile and, if linked, its SSO client atomically. |
| GET | `/applications/global-roles` | Platform admin | Lists the fixed global roles. |
| POST | `/applications/{application_id}/roles/{global_role_id}` | Platform admin | Links a global role to a `catalog` app; idempotent. `409` for SSO apps. |
| DELETE | `/applications/{application_id}/roles/{global_role_id}` | Platform admin | Removes a catalog role-to-app link; idempotent. |
| GET | `/applications/audit` | Platform admin | Most-recent-first audit feed. Query: `limit` 1–250, `offset` ≥0. |

## SSO app registry and roles

All endpoints in this section require a platform-admin session, except the role-catalog synchronization
endpoint, which is server-to-server and accepts only the target app's client credentials.

| Method | Path | Contract |
| --- | --- | --- |
| POST | `/apps/` | Creates an `sso_role` launcher application and its SSO client in one transaction. Returns `client_secret` once only. |
| GET | `/apps/` | Lists SSO clients. Query: `limit` 1–250, `offset` ≥0, optional `is_active`. |
| PATCH | `/apps/{client_id}` | Enables/disables both the SSO client and linked launcher application atomically. |
| POST | `/apps/{client_id}/redirect-uris` | Registers one exact, fragment-free HTTP(S) callback URI. |
| POST | `/apps/{client_id}/roles` | Creates an app-scoped role. Role names are unique only within that app. |
| GET | `/apps/{client_id}/roles` | Lists roles defined for the SSO app. |
| DELETE | `/apps/{client_id}/roles/{role_id}` | Deletes a role and all of its user assignments. |
| POST | `/apps/{client_id}/roles/{role_id}/assign` | Assigns an app role to one user; this is the canonical SSO access grant. Idempotent. |
| DELETE | `/apps/{client_id}/roles/{role_id}/assign?user_id={user_id}` | Removes that one app-role assignment. |
| POST | `/apps/{client_id}/roles/{role_id}/assign/bulk` | Assigns one app role to 1–500 users. |
| POST | `/apps/{client_id}/roles/{role_id}/unassign/bulk` | Removes one app role from 1–500 users. |
| GET | `/apps/{client_id}/users` | Lists user-role rows for the app. Query: `limit` 1–250, `offset` ≥0. A user with several roles has several rows. |
| PUT | `/apps/{client_id}/role-catalog` | Server-to-server, authenticated by that app's `client_secret` in the body. Upserts its declared roles and deactivates missing previously synchronized roles without deleting assignments. |

## User administration

All endpoints in this section require a platform-admin session.

| Method | Path | Contract |
| --- | --- | --- |
| GET | `/users/` | Lists users. Query: `limit`, `offset`, optional `is_active`, `search`, `include_deleted`. |
| PATCH | `/users/{user_id}/status` | Enables/disables one user. An admin cannot deactivate themself. |
| DELETE | `/users/{user_id}` | Soft-deletes one user and disables it. An admin cannot delete themself. |
| PATCH | `/users/bulk/status` | Enables/disables 1–500 users. A bulk deactivation cannot include the caller. |
| POST | `/users/bulk/delete` | Soft-deletes 1–500 users. The caller cannot be included. |
| POST | `/users/{user_id}/global-roles/{role_id}` | Grants one global role. Applies only to catalog application access. |
| DELETE | `/users/{user_id}/global-roles/{role_id}` | Revokes one global role. |
| GET | `/users/{user_id}/global-roles` | Lists the global roles currently assigned to one user. |
| GET | `/users/{user_id}/external-identities` | Lists the external login providers linked to the canonical user. It returns provider name/code, provider-reported email and last activity; it never exposes external subjects or tenant identifiers. |
| POST | `/users/bulk/global-roles/{role_id}/grant` | Grants one global role to 1–500 users. |
| POST | `/users/bulk/global-roles/{role_id}/revoke` | Revokes one global role from 1–500 users. |
| POST | `/users/{user_id}/applications/{application_id}` | Directly grants one `catalog` app. `409` for an SSO app. |
| DELETE | `/users/{user_id}/applications/{application_id}` | Removes one direct catalog grant. |
| POST | `/users/bulk/applications/{application_id}/grant` | Directly grants a `catalog` app to 1–500 users. `409` for an SSO app. |
| POST | `/users/bulk/applications/{application_id}/revoke` | Removes direct catalog grants from 1–500 users. |
| GET | `/users/{user_id}/app-roles` | Lists all app-scoped roles a user holds, across SSO apps. |
| GET | `/users/{user_id}/applications` | Shows the user's resolved launcher, using the exact same policy as `GET /applications/`. |
