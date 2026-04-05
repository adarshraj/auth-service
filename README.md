# auth-service

Standalone authentication service for the personal app ecosystem. Runs on port **8703**.

## What it does

- Single shared user pool — one account works across all your apps
- Per-app access gates — apps can require explicit user grants before login is allowed
- Password login (bcrypt-compatible with finance-tracker hashes)
- Google and GitHub OAuth with browser-safe redirect flow
- JWT **ES256** tokens signed with a persisted EC P-256 key pair
- Public JWKS endpoint — consuming services verify tokens using the public key, no shared secret needed
- `aud` claim scoped to `appId` — a token issued for one app is rejected by any other app
- `groups` claim with the user's app-level role — consuming Quarkus/MP-JWT services can use `@RolesAllowed` directly
- Optional TOTP-based MFA — users opt-in; existing clients unaffected. Built with JDK crypto only (no external dependencies)
- SSO across your apps — a successful login sets an `HttpOnly` `auth_session` cookie on the auth-service domain; other apps exchange it for a JWT at `GET /auth/sso` with no password or OAuth hop

## API

### Auth endpoints (public)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Register (email + password); `X-App-Id` header optional |
| `POST` | `/auth/login` | Login → JWT; `X-App-Id` header optional |
| `POST` | `/auth/logout` | Revokes the SSO session cookie (client must also drop its JWT) |
| `POST` | `/auth/password` | Change password — requires current password (requires JWT) |
| `GET`  | `/auth/me` | Current user (requires `Authorization: Bearer <token>`) |
| `DELETE` | `/auth/account` | Delete own account (requires JWT) |
| `GET`  | `/auth/sso` | Exchange the SSO cookie for a code; `?app_id=&redirect_uri=` → redirects to `redirect_uri?code=` |
| `GET`  | `/auth/oauth/{provider}` | Redirect to Google or GitHub; optional `?redirect_uri=` and `X-App-Id` |
| `GET`  | `/auth/oauth/callback` | OAuth callback — issues a one-time code, redirects to `redirect_uri?code=` |
| `POST` | `/auth/token` | Exchange one-time code for a JWT (`application/x-www-form-urlencoded`, field: `code`) |
| `POST` | `/auth/mfa/setup` | Start MFA enrollment — returns TOTP secret, QR URI, recovery codes (requires JWT) |
| `POST` | `/auth/mfa/confirm` | Confirm MFA enrollment with a valid TOTP code (requires JWT) |
| `POST` | `/auth/mfa/verify` | Complete login with TOTP code or backup code (requires MFA token from login) |
| `POST` | `/auth/mfa/challenge` | Exchange a one-time MFA code (from OAuth redirect) for an MFA challenge token (`application/x-www-form-urlencoded`, field: `code`) |
| `POST` | `/auth/mfa/disable` | Disable MFA — requires valid TOTP or backup code (requires JWT) |
| `GET`  | `/.well-known/jwks.json` | Public key in JWK Set format for ES256 token verification |

### App management (admin — requires `X-Admin-Key`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/apps` | Register an app |
| `GET`  | `/auth/apps` | List apps |
| `DELETE` | `/auth/apps/{id}` | Delete an app |
| `GET`  | `/auth/apps/{appId}/access` | List users with explicit access |
| `POST` | `/auth/apps/{appId}/access/{userId}` | Grant access |
| `DELETE` | `/auth/apps/{appId}/access/{userId}` | Revoke access |

## MFA (two-factor authentication)

MFA is optional. Users who don't enable it see no changes to the login flow.

### Enabling MFA

1. Authenticate and call `POST /auth/mfa/setup` with your JWT. Response:
   ```json
   {
     "secret": "JBSWY3DPEHPK3PXP...",
     "otpauthUri": "otpauth://totp/AuthService:user@example.com?secret=...",
     "recoveryCodes": ["abc12345", "def67890", ...]
   }
   ```
2. Scan the `otpauthUri` as a QR code in any authenticator app (Google Authenticator, Authy, etc.).
3. Save the `recoveryCodes` — these are single-use backup codes in case you lose your authenticator.
4. Confirm by calling `POST /auth/mfa/confirm` with a valid 6-digit TOTP code from the app:
   ```json
   { "code": "123456" }
   ```

### Logging in with MFA

MFA is enforced across all login paths — password login, OAuth (JSON and redirect flows), and code exchange.

1. `POST /auth/login` (or OAuth callback / `POST /auth/token`). When MFA is enabled, the response changes:
   ```json
   { "mfaRequired": true, "mfaToken": "..." }
   ```
   For the OAuth redirect flow, the redirect URL fragment becomes `#mfa_required=true&mfa_code=...` instead of `?code=...`.
2. Prompt the user for their 6-digit TOTP code (or a backup code), then call:
   ```
   POST /auth/mfa/verify
   { "mfaToken": "...", "code": "123456" }
   ```
3. Response is the standard `{ token, user }`.

The `mfaToken` is valid for **5 minutes** and **single-use**. If it expires or is reused, the user must log in again.

### Disabling MFA

Call `POST /auth/mfa/disable` with a valid TOTP or backup code:
```json
{ "code": "123456" }
```

## OAuth browser flow

When a client app wants to log a user in via OAuth and receive a JWT:

1. Redirect the user to `GET /auth/oauth/{provider}?redirect_uri=https://yourapp.com/callback` with `X-App-Id: your-app`.
2. After the provider callback, auth-service redirects to `https://yourapp.com/callback?code=<one-time-code>`.
3. Your server (back-channel) POSTs the code:
   ```
   POST /auth/token
   Content-Type: application/x-www-form-urlencoded

   code=<one-time-code>
   ```
4. Response is `{ token, user }`. The code is valid for **60 seconds** and single-use.

The JWT is never placed in a URL or fragment — it only travels over the back-channel exchange.

**`redirect_uri` must be registered** for the app via `POST /auth/apps` (`redirectUris` field) before the flow will work. Redirect URIs are compared by `scheme://host:port/path` only — query strings and fragments are ignored during validation.

**If the user has MFA enabled**, step 2 redirects to `https://yourapp.com/callback#mfa_required=true&mfa_code=<code>` instead (in the URL fragment — never sent to servers, so not leaked via Referer or proxy logs). Client-side JS reads `window.location.hash`, then your server exchanges the code for an MFA challenge token, then completes the TOTP step:
```
POST /auth/mfa/challenge
Content-Type: application/x-www-form-urlencoded

code=<mfa-code>
```
Response is `{ mfaRequired, mfaToken }`. Then complete MFA via `POST /auth/mfa/verify`.

## SSO across your apps

Every successful auth (`/auth/login`, `/auth/register`, `/auth/mfa/verify`, `/auth/token`, OAuth callback) sets an `auth_session` cookie on the auth-service domain: `HttpOnly`, `SameSite=Strict`, `Max-Age=AUTH_SESSION_TTL_SECONDS` (default 7 days). The raw id lives only in the cookie; the server stores `HMAC(raw, token-pepper)` in `auth_sessions`.

**To log a user into a second app without a password prompt:**

1. From app B, redirect the browser to:
   ```
   GET https://auth.yourdomain.com/auth/sso?app_id=app-b&redirect_uri=https://app-b.yourdomain.com/cb
   ```
2. The browser sends `auth_session` (same-site as long as both apps share the parent domain). auth-service validates the session, enforces `requires_explicit_access` for `app-b`, issues a one-time code, and 302s to `redirect_uri?code=<code>`.
3. App B exchanges the code via `POST /auth/token` — same as the OAuth flow.

Fallbacks:
- No cookie / expired → `401 "No active session"`. Kick off the full login or OAuth flow.
- No access to the target app → `403 "You do not have access to this application"`.

**Scoping:**
- **Local dev** — leave `AUTH_SESSION_COOKIE_DOMAIN` empty; the browser scopes the cookie to the auth-service origin and sends it to all `localhost` ports (they're same-site).
- **Prod** — set `AUTH_SESSION_COOKIE_DOMAIN=yourdomain.com` and `AUTH_SESSION_COOKIE_SECURE=true`. Apps must live on sibling subdomains (`auth.yourdomain.com`, `app-a.yourdomain.com`, …) for the cookie to travel on the cross-subdomain redirect under `SameSite=Strict`.

**Logout.** `POST /auth/logout` deletes the session row matching the current cookie and clears the cookie on that client only. Sessions on other devices remain valid until their TTL expires (no "log out everywhere").

## Verifying tokens in consuming services

Fetch the public key once (or on a schedule) and cache it:

```
GET /.well-known/jwks.json
```

Verify the token signature using the EC P-256 public key (`alg: ES256`). Also validate:
- `iss` equals your known auth-service URL (e.g. `https://auth.example.com`)
- `aud` matches your app ID (prevents accepting tokens issued for other apps)
- `exp` is in the future

No shared secret is needed. If the key pair is rotated, the `kid` field changes — re-fetch JWKS when you encounter an unknown `kid`.

> **`aud` validation is mandatory.** A token issued for app A will be accepted by app B if `aud` is not checked. This is an account-isolation boundary — never skip it.

### JWT payload reference

| Claim | Always present | Description |
|-------|---------------|-------------|
| `sub` | Yes | userId |
| `userId` | Yes | Same as `sub`; kept for backward compatibility |
| `email` | Yes | User's email address |
| `iss` | Yes | Auth-service base URL |
| `aud` | When `X-App-Id` was passed | App ID the token is scoped to |
| `groups` | When `X-App-Id` was passed | `["user"]` or `["admin"]` — the user's role for this app |
| `kid` | Yes (JWT header) | Key ID; matches JWKS `kid` field |
| `iat` / `exp` | Yes | Issued-at and expiry timestamps |

`groups` is the standard claim read by Quarkus/MP-JWT for `@RolesAllowed`. Roles are managed via `POST /auth/apps/{appId}/access/{userId}` with a `{"role": "admin"}` body.

> **Tokens without `aud`:** Tokens issued without `X-App-Id` have no `aud` claim and are broadly usable. Always pass `X-App-Id` in login/register/OAuth flows to scope tokens to your app.

### Polymorphic responses (MFA)

`POST /auth/login`, `POST /auth/token`, and `GET /auth/oauth/callback` (JSON mode) return either `AuthResponse` or `MfaChallengeResponse` depending on whether the user has MFA enabled. Both are HTTP 200. Clients should check for the `mfaRequired` field:

```
// Pseudocode
response = POST /auth/login { email, password }
if response.mfaRequired:
    mfaCode = promptUser("Enter TOTP code")
    response = POST /auth/mfa/verify { mfaToken: response.mfaToken, code: mfaCode }
jwt = response.token
```

## Running locally

```bash
cd auth-service
./mvnw quarkus:dev
# Starts on http://localhost:8703
```

No env vars are required for local dev — all secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`, `AUTH_MFA_HMAC_SECRET`) have insecure dev defaults that are accepted in the `dev` profile (a warning is logged but startup is not blocked). Set `AUTH_ADMIN_KEY` only if you need the app management endpoints.

SQLite is used by default — no database setup needed. The EC key pair is generated on first boot and persisted to the DB.

## Production

All commands below run from the `auth-service/` directory (where `pom.xml` lives).

**Profile:** A packaged run uses Quarkus's **`prod`** profile. On startup, the service refuses to boot unless all four HMAC secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`, `AUTH_MFA_HMAC_SECRET`) are set to non-default values. Set `AUTH_ADMIN_KEY` if you need the `/auth/apps` admin API.

**EC key pair:** Generated automatically on first boot and stored in the database. Mount a persistent volume for the DB file so the key survives container restarts.

**Database:** SQLite is fine for small deployments — persist the file (set `AUTH_DB_FILE` to a path on a mounted volume). For PostgreSQL, set `QUARKUS_DATASOURCE_DB_KIND=postgresql`, the JDBC URL, username, password, and `QUARKUS_HIBERNATE_ORM_DIALECT=org.hibernate.dialect.PostgreSQLDialect` (see comments in `src/main/resources/application.yml`).

**OAuth:** Set `AUTH_BASE_URL` to your public origin (e.g. `https://auth.example.com`) and configure the Google/GitHub client env vars so callback URLs match your deployment.

### Run the JVM package (bare metal or VM)

```bash
cd auth-service
./mvnw package -DskipTests
export AUTH_KEY_HMAC_SECRET="your-hmac-secret-at-least-32-chars"
export AUTH_STATE_HMAC_SECRET="your-state-hmac-secret-at-least-32-chars"
export AUTH_TOKEN_PEPPER="your-token-pepper-at-least-32-chars"
export AUTH_ADMIN_KEY="your-admin-key"   # optional; omit to disable app management API
java -jar target/quarkus-app/quarkus-run.jar
```

The HTTP server listens on port **8703**. Terminate TLS at a reverse proxy or load balancer in front of the app.

### Docker (JVM image)

```bash
cd auth-service
./mvnw package -DskipTests
docker build -f src/main/docker/Dockerfile.jvm -t auth-service:latest .
docker run --rm -p 8703:8703 \
  -e AUTH_KEY_HMAC_SECRET="your-hmac-secret-at-least-32-chars" \
  -e AUTH_STATE_HMAC_SECRET="your-state-hmac-secret-at-least-32-chars" \
  -e AUTH_TOKEN_PEPPER="your-token-pepper-at-least-32-chars" \
  -e AUTH_ADMIN_KEY="your-admin-key" \
  -e AUTH_BASE_URL="https://auth.example.com" \
  -v /data/auth:/data \
  -e AUTH_DB_FILE=/data/authservice.db \
  auth-service:latest
```

Mount a volume (`/data/auth`) so the SQLite DB (and the persisted EC key pair) survive container restarts.

## Per-app access control

Apps registered with `requiresExplicitAccess: false` (default) let any registered user log in.
Apps registered with `requiresExplicitAccess: true` block login unless the user has been granted access via `POST /auth/apps/{appId}/access/{userId}`.

On first register/OAuth-login into a `requiresExplicitAccess: true` app, access is auto-granted for convenience. Use the admin API to revoke it.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AUTH_ADMIN_KEY` | For app mgmt | Key for `/auth/apps` endpoints |
| `AUTH_KEY_HMAC_SECRET` | Prod | HMAC secret for hashing the admin key; min 32 chars |
| `AUTH_STATE_HMAC_SECRET` | Prod | HMAC secret for signing OAuth state params (prevents open redirect / CSRF) |
| `AUTH_TOKEN_PEPPER` | Prod | HMAC pepper for storing auth tokens, OAuth codes, and MFA backup codes at rest; also AES key seed for MFA secret encryption |
| `AUTH_MFA_HMAC_SECRET` | Prod | HMAC secret for signing MFA challenge tokens (min 32 chars) |
| `AUTH_BASE_URL` | For OAuth | Base URL for OAuth callback redirect (e.g. `https://auth.example.com`) |
| `AUTH_JWT_EXPIRY_SECONDS` | No | Token TTL in seconds (default: 604800 = 7 days) |
| `AUTH_SESSION_TTL_SECONDS` | No | SSO cookie TTL in seconds (default: 604800 = 7 days) |
| `AUTH_SESSION_COOKIE_SECURE` | Prod | `true` to set the `Secure` cookie flag (default: false; localhost is exempt) |
| `AUTH_SESSION_COOKIE_DOMAIN` | Prod | Parent domain for the cookie (e.g. `yourdomain.com`) so all subdomains share it; leave empty for localhost |
| `AUTH_DB_FILE` | No | Path to SQLite DB file (default: `./authservice.db`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | For Google OAuth | |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | For GitHub OAuth | |
| `QUARKUS_DATASOURCE_JDBC_URL` | Prod/PostgreSQL | PostgreSQL JDBC URL |
| `QUARKUS_DATASOURCE_USERNAME` | Prod/PostgreSQL | DB username |
| `QUARKUS_DATASOURCE_PASSWORD` | Prod/PostgreSQL | DB password |

> `JWT_SECRET` is no longer used. Tokens are signed with an EC P-256 key pair stored in the database.

## Migrating finance-tracker users

finance-tracker uses bcrypt with cost factor 10 — same as this service. Export the `users` table and import directly; no re-hashing needed.

## Why ES256 and not RS256

RS256 (RSA + SHA-256) was considered but not implemented due to **performance concerns on a personal/low-resource server**:

| | ES256 (current) | RS256 |
|---|---|---|
| Algorithm | ECDSA P-256 | RSA 2048-bit |
| Signing speed | Fast | Slow (modular exponentiation) |
| Key generation | Fast | Slow (~100ms+ on low-end hardware) |
| Security level | 128-bit | 112-bit (2048-bit RSA) |
| Key size | ~200 bytes | ~1700 bytes |

ES256 provides stronger security with significantly less CPU cost at signing time. If requirements change, the switch is isolated to ~20 lines in `EcKeyService` — no API, DB schema, or consumer-side changes needed beyond updating the JWK type.

## Security model

| Mechanism | Detail |
|---|---|
| JWT signing | ES256 (ECDSA P-256); private key persisted in DB, never leaves the process |
| Token audience | `aud` claim set to `appId`; consuming services must validate to prevent cross-app reuse |
| Token issuer | `iss` set to `AUTH_BASE_URL` (trailing slash stripped); consuming services must validate |
| Token roles | `groups` claim set to `["user"]` or `["admin"]` from `user_app_access.role`; supports `@RolesAllowed` in Quarkus/MP-JWT |
| Auth tokens at rest | Password-reset / magic-link tokens and OAuth codes stored as `HMAC(value, AUTH_TOKEN_PEPPER)` — plaintext never written to DB |
| OAuth code exchange | Atomic `UPDATE ... WHERE used=false` marks the code used before returning it — eliminates the TOCTOU race where two concurrent requests could both redeem the same code |
| OAuth state | HMAC-signed (`payload~sig`) + single-use nonce stored server-side. Both layers must pass: signature prevents tampering, nonce prevents CSRF and state replay |
| Admin key | Stored as `HMAC(key, AUTH_KEY_HMAC_SECRET)`, compared constant-time; hash pre-computed at startup. All admin endpoints rate-limited at 20 RPM per IP |
| Rate limiting | Per-IP (configurable RPM) + per-account (10 RPM) on login; 20 RPM per IP on admin endpoints. In-memory — effective for single-instance deployments |
| Redirect URIs | HTTPS enforced; validated at registration and at use time; URI-normalized before comparison (lowercase host, default ports stripped) to prevent bypass via port variation |
| OAuth email verification | `emailVerified` reflects provider truth: Google reads `verified_email`; GitHub calls `/user/emails` for the `verified` field — never assumed `true` |
| OAuth account linking | Not automatic — requires authenticated link flow to prevent email-based account takeover |
| 5xx error responses | Internal error details never sent to the client — logged server-side only |
| OpenAPI/Swagger | Disabled in `prod` profile |
| Login error messages | Generic "Invalid email or password" for all failures — does not reveal whether email is registered or OAuth-only |
| Deleted-user guard | `POST /auth/token` rejects a valid code if the account was deleted after code issuance |
| MFA / TOTP | Optional per-user TOTP (RFC 6238) using JDK crypto only. Enforced across all login paths (password + OAuth). TOTP secret encrypted with AES-256-GCM at rest; backup codes stored as HMAC hashes. Single-use MFA challenge token (dedicated HMAC secret, nonce-based). Per-userId rate limit (5 RPM) on MFA verification |
| Audit logging | Critical events (login success/failure, account deletion, token exchange, admin auth failures, MFA enable/disable/verify) logged at INFO with an `AUDIT` prefix |

### By-design / operational notes

- **`/auth/me` and `/auth/account` are app-agnostic** — they return the global user identity and do not enforce `aud`. This is intentional: these routes serve any valid JWT regardless of which app issued it. If you need per-app identity binding on these routes, pass `X-App-Id` and validate `aud` in your own middleware.
- **Redirect URI normalization** — URIs are compared after lowercasing the host, stripping default ports (`:443` for https, `:80` for http), and trimming trailing slashes. `https://app/cb` and `https://app/cb/` are treated as the same URI.
- **JWT lifetime (7 days)** and **bcrypt cost 10** are policy choices tuned for a personal low-resource server. Tighten `AUTH_JWT_EXPIRY_SECONDS` or bcrypt cost if your threat model requires it.
- **No PKCE** — acceptable for confidential clients (server-to-server). Add PKCE before supporting mobile or SPA public clients.
- **OAuth state size** — grows with long `redirect_uri` values. All major providers tolerate the current size; no action needed unless you hit provider limits.
- **SQLite key material** — the EC private key and user data live in the DB file. Protect it with filesystem permissions, encrypted volumes, and off-site backups.
- **TLS, HSTS, CORS** — terminate TLS at the reverse proxy; set `AUTH_CORS_ORIGINS` explicitly in prod (default is empty — not `*`); add HSTS at the proxy.
- **Dependency CVEs** — no automated scanner is configured in-repo. Consider adding Dependabot or OSV-Scanner to the CI pipeline.

## Migrating consuming services from HS256

Services that previously verified JWTs using `JWT_SECRET` need to be updated:

1. Remove `JWT_SECRET` usage.
2. Fetch the public key from `GET /.well-known/jwks.json`.
3. Verify tokens using ES256 with the EC P-256 public key.
4. Validate `iss` equals your auth-service URL.
5. Validate `aud` matches your app ID.
