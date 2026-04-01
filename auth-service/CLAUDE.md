# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Standalone authentication service for the personal app ecosystem. Kotlin + Quarkus, port **8703**. Single shared user pool with optional per-app access gates. Issues **ES256** JWTs signed with a persisted EC P-256 key pair. Consuming services verify tokens using the public key from `GET /.well-known/jwks.json` — no shared secret required.

## Commands

All commands run from `auth-service/` (the inner directory with `pom.xml`):

```bash
# Dev mode (hot reload, SQLite, no DB setup needed)
./mvnw quarkus:dev

# Run tests
./mvnw test

# Build JAR
./mvnw package

# Run a single test class
./mvnw test -Dtest=AuthResourceTest

# Run a single test method
./mvnw test -Dtest=AuthResourceTest#login
```

**Required for dev:** Nothing — all secrets have insecure dev defaults that are accepted in the `dev` profile (warnings logged, startup not blocked). Optionally set `AUTH_ADMIN_KEY` to enable the app management endpoints:
```bash
export AUTH_ADMIN_KEY="your-admin-key"
```
All three HMAC secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`) **must** be set to non-default values in prod — `StartupGuard` throws on boot otherwise.

SQLite is used by default — no database setup needed for development.

## Architecture

Layered under `src/main/kotlin/com/authservice/`:

- **`api/`** — JAX-RS resources (`AuthResource`, `AppResource`, `VerifyResource`, `WellKnownResource`), DTOs, and exception mappers. Resources delegate all logic to services.
- **`service/`** — Business logic: `UserService` (registration, login, OAuth account linking, access management, auth tokens), `JwtService` (sign/verify ES256), `EcKeyService` (generate/persist/expose EC P-256 key pair), `PasswordService` (bcrypt), `OAuthService` (Google + GitHub flows), `TokenCleanupJob` (scheduled purge).
- **`domain/`** — JPA entities and Panache repositories: `UserEntity`, `AppEntity`, `UserAppAccessEntity` (composite PK), `AuthTokenEntity`, `RefreshTokenEntity`, `EcKeyEntity`, `OAuthCodeEntity`.
- **`security/`** — `JwtFilter` (protects `/auth/me` and `/auth/account`), `SessionCookieFilter` (sets/clears `platform_session` HttpOnly cookie on auth responses), `RateLimiter` (in-memory fixed-window), `OAuthNonceStore` (single-use nonce validation for OAuth CSRF protection), `ApiKeyHasher` (HMAC-SHA256 for admin key), `CallerContext` (request-scoped user identity), `StartupGuard` (validates required secrets on boot), `SecurityHeadersFilter` (adds X-Content-Type-Options, X-Frame-Options, CSP, HSTS, Referrer-Policy to all responses).
- **`config/`** — `RateLimitConfig` and `OAuthConfig` ConfigMapping interfaces.

### Key flows

**Login:** `AuthResource.login()` → `UserService.login()` (verify bcrypt, check app gate) → `JwtService.sign()` + `UserService.issueRefreshToken()` → `AuthResponse{token, refreshToken, user}`

**Token refresh:** `POST /auth/refresh` (form: `refresh_token=<token>`) → `UserService.rotateRefreshToken()` (atomically revokes old token, issues new one) → new `AuthResponse{token, refreshToken, user}`. Refresh tokens are single-use (rotation) with a 7-day TTL. Access tokens are short-lived (15 minutes by default).

**OAuth (browser flow with redirect_uri):**
1. `GET /auth/oauth/{provider}?redirect_uri=https://app.com/cb` (with `X-App-Id`)
2. 302 to provider → provider redirects to `GET /auth/oauth/callback`
3. `OAuthService.exchangeCode()` → `UserService.findOrCreateByOAuth()` → issue one-time code → 302 to `redirect_uri?code=<code>`
4. Client POSTs `POST /auth/token` (form: `code=<code>`) → JWT returned (code valid 60s, single-use)

**OAuth (API flow without redirect_uri):** Same as above but callback returns `AuthResponse` JSON directly.

**Per-app gate:** If `apps.requires_explicit_access = true`, login is blocked unless a `user_app_access` row exists. Auto-granted on first register/OAuth into that app.

**JWT verification in other services:** Fetch public key from `GET /.well-known/jwks.json`, verify ES256 signature, validate `aud` claim matches app ID. Token payload: `{sub, userId, email, groups, appId, aud, iat, exp}`.

### Database schema (Flyway migrations)

| Migration | Table | Purpose |
|-----------|-------|---------|
| V1 | `users` | Core user record — id, email, name, password_hash, avatar_url, oauth_provider, oauth_id, email_verified |
| V2 | `apps` | Registered apps — id (e.g. `finance-tracker`), name, requires_explicit_access |
| V3 | `user_app_access` | Per-user app grants — composite PK (user_id, app_id), role, granted_at |
| V4 | `auth_tokens` | One-time tokens — type (`password_reset`, `magic_link`, `email_verification`), expires_at, used (reserved for future endpoints) |
| V5 | `apps.redirect_uris` | Newline-separated allowed redirect URIs per app |
| V6 | `ec_keys` | Persisted EC P-256 key pair (single row, id=`primary`) |
| V7 | `oauth_codes` | Short-lived one-time codes for the OAuth browser redirect flow (60s TTL) |
| V8 | `refresh_tokens` | Revocable refresh tokens for access token rotation (7-day TTL, HMAC-hashed at rest) |

### Admin key security

The `X-Admin-Key` header value is never stored raw. The hash of the configured key is pre-computed once at startup (`AppResource.configuredKeyHash` lazy val). On each request `ApiKeyHasher.verify(provided, storedHash)` computes `HMAC(provided)` and compares via `MessageDigest.isEqual()` (constant-time). This prevents both timing attacks and repeated hashing overhead.

All admin endpoints are rate-limited at 20 RPM per IP (`AppResource.ADMIN_RPM`). Failed authentication attempts are logged with `AUDIT admin_auth_failed`.

**Admin API is disabled** (returns 501) if `AUTH_ADMIN_KEY` is not set. Apps still work — only the `/auth/apps` management endpoints are gated.

### Auth token, refresh token, and OAuth code security

`auth_tokens`, `refresh_tokens`, and `oauth_codes` are stored as `HMAC(value, AUTH_TOKEN_PEPPER)`, not plaintext. `UserService.createAuthToken()`, `UserService.issueRefreshToken()`, and `AuthResource.issueOAuthCode()` return the raw value to the caller and store only the hash; lookup hashes the incoming value before querying. A full DB dump does not expose redeemable tokens or codes.

All three token types use atomic `UPDATE ... WHERE used/revoked=false` claiming to eliminate TOCTOU races:
- `OAuthCodeRepository.claimCode()` — OAuth one-time codes
- `AuthTokenRepository.claimToken()` — password-reset / magic-link tokens
- `RefreshTokenRepository.claimToken()` — refresh tokens (single-use rotation)

Refresh tokens are single-use: exchanging one (`POST /auth/refresh`) atomically revokes the old token and issues a new one (rotation). All refresh tokens for a user are revoked on account deletion.

### Session cookie and forward auth

`SessionCookieFilter` is a JAX-RS `ContainerResponseFilter` that automatically sets a `platform_session` cookie on successful auth responses (login, register, refresh, token exchange) and clears it on logout. Cookie attributes:
- `HttpOnly` — not accessible to JavaScript (XSS protection)
- `Secure` — only sent over HTTPS
- `SameSite=Lax` — CSRF protection for top-level navigations
- `Domain` — set to `AUTH_SESSION_COOKIE_DOMAIN` (e.g. `.homelab.local` for cross-subdomain access); empty for localhost/dev
- `Max-Age` — matches `AUTH_JWT_EXPIRY_SECONDS` (15 minutes by default)
- `Path=/` — available to all paths

`VerifyResource` (`GET /auth/verify`) serves as a forward-auth endpoint for any reverse proxy (Traefik, nginx, Caddy, HAProxy, etc.). It accepts auth via:
1. `platform_session` cookie (browser access to admin UIs)
2. `Authorization: Bearer <token>` header (API access)

Returns 200 with `X-Auth-User-Id` and `X-Auth-User-Email` headers (forwarded to downstream services by the reverse proxy), or 401 with `X-Auth-Redirect: true` so middleware can redirect to login.

### OAuth state integrity and CSRF protection

The OAuth state parameter uses two independent layers of protection:

1. **HMAC signature** — `base64url(payload)~hmac_hex`. `AuthResource.buildOAuthState()` appends the signature; `parseOAuthState()` verifies it with constant-time comparison before decoding. Prevents an attacker from tampering with the `redirectUri`, `provider`, or `appId` fields in-flight.

2. **Single-use nonce** — A 16-byte random nonce is embedded in the state payload, registered in `OAuthNonceStore` when the OAuth flow starts, and consumed (removed) when the callback arrives. Even a valid HMAC-signed state can only be used once within its 10-minute TTL. This prevents CSRF and state-replay attacks.

### Rate limiting and reverse proxy

Rate limiting uses the **rightmost** `X-Forwarded-For` entry (set by the trusted reverse proxy) to prevent client-side IP spoofing. For this to be effective your reverse proxy must:
1. Strip any client-supplied `X-Forwarded-For` header before forwarding.
2. Append the real client IP itself.

Login is rate-limited twice: per-IP (global RPM from config) and per-account (hard-coded 10 RPM) to defend against distributed brute force from multiple IPs.

Admin endpoints are rate-limited at 20 RPM per IP independently of the auth rate limits.

**Known limitation:** The rate limiter is in-memory (`RateLimiter` uses `ConcurrentHashMap`). In a horizontally-scaled deployment with multiple instances, each instance tracks limits independently — the effective limit per IP is `RPM × instance count`. For single-instance deployments (the intended use case for a personal auth service) this is not a concern. If you scale horizontally, replace with a shared Redis-backed implementation.

### Redirect URI policy

Redirect URIs are validated at both registration time (`POST /auth/apps`) and use time (`GET /auth/oauth/{provider}?redirect_uri=`). Rules:
- Must be `https://` in production.
- `http://localhost` and `http://127.0.0.1` are allowed for local development.
- Compared after URI normalization: lowercase scheme + host, implicit default ports stripped (`:443` for https, `:80` for http), trailing slashes stripped. This prevents bypasses via port variation or case differences.

### emailVerified semantics for OAuth users

`users.email_verified` is set based on what the OAuth provider reports — not hardcoded `true`:

- **Google** — reads `verified_email` from `/oauth2/v2/userinfo`; defaults to `true` if the field is absent (all active Google accounts have a verified email).
- **GitHub** — always calls `/user/emails` to get the primary email's `verified` field. The `/user` endpoint does not expose verification status, and GitHub allows unverified email accounts.

Do not assume `emailVerified = true` for OAuth users without checking the provider.

### EC key pair lifecycle

`EcKeyService` observes `StartupEvent` and either loads the existing key pair from the `ec_keys` table or generates a new one (on first boot). The private key never leaves the process. `kid` is a random UUID stored alongside the key and included in each JWT header and JWKS response. If the DB is wiped, a new key pair is generated — all existing tokens will become invalid.

### Audit logging

Critical security events are logged at `INFO` level with an `AUDIT` prefix for easy grep/aggregation:

| Event | Log pattern |
|-------|-------------|
| Login success | `AUDIT login_success userId=… app=…` |
| Login failure | `AUDIT login_failed reason=… userId/email=… app=…` |
| Account deleted | `AUDIT account_deleted userId=… email=…` |
| OAuth token exchanged | `AUDIT token_exchanged userId=… app=…` |
| Token refreshed | `AUDIT token_refreshed userId=… app=…` |
| Admin auth failure | `AUDIT admin_auth_failed reason=… ip=…` |

To stream audit events: `grep AUDIT <logfile>` or configure your log aggregator to filter on `AUDIT`.

## Configuration

| Config path | Env var | Purpose |
|---|---|---|
| `auth.jwt.expiry-seconds` | `AUTH_JWT_EXPIRY_SECONDS` | Access token TTL (default 900 = 15 minutes) |
| `auth.refresh-token.expiry-seconds` | `AUTH_REFRESH_TOKEN_EXPIRY_SECONDS` | Refresh token TTL (default 604800 = 7 days) |
| `auth.admin-key` | `AUTH_ADMIN_KEY` | Key for `/auth/apps` endpoints (optional — disables app mgmt if unset) |
| `auth.key-hmac-secret` | `AUTH_KEY_HMAC_SECRET` | HMAC-SHA256 secret for admin key hashing (min 32 chars, required in prod) |
| `auth.state-hmac-secret` | `AUTH_STATE_HMAC_SECRET` | HMAC secret for signing OAuth state params (prevents open redirect / CSRF; required in prod) |
| `auth.token-pepper` | `AUTH_TOKEN_PEPPER` | HMAC pepper for storing auth tokens and OAuth codes at rest (required in prod) |
| `auth.session.cookie-domain` | `AUTH_SESSION_COOKIE_DOMAIN` | Cookie domain for `platform_session` (e.g. `.homelab.local`; empty for localhost) |
| `auth.rate-limit.enabled` | `AUTH_RATE_LIMIT_ENABLED` | Toggle rate limiting (default true) |
| `auth.rate-limit.requests-per-minute` | `AUTH_RATE_LIMIT_RPM` | Per-IP limit for auth endpoints (default 60) |
| `auth.oauth.google.client-id` | `GOOGLE_CLIENT_ID` | Google OAuth |
| `auth.oauth.google.client-secret` | `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `auth.oauth.github.client-id` | `GITHUB_CLIENT_ID` | GitHub OAuth |
| `auth.oauth.github.client-secret` | `GITHUB_CLIENT_SECRET` | GitHub OAuth |
| `auth.base-url` | `AUTH_BASE_URL` | Public base URL — used to build OAuth callback URLs |
| `quarkus.datasource.jdbc.url` | `QUARKUS_DATASOURCE_JDBC_URL` | DB connection string (prod: PostgreSQL JDBC URL) |
| `quarkus.datasource.username` | `QUARKUS_DATASOURCE_USERNAME` | DB username (prod only) |
| `quarkus.datasource.password` | `QUARKUS_DATASOURCE_PASSWORD` | DB password (prod only) |

**Dev profile:** SQLite at `./authservice-dev.db`. **Test profile:** In-memory SQLite, rate limiting disabled. **Prod profile:** SQLite by default — mount a persistent volume for the `.db` file. `StartupGuard` throws on boot if any of the three HMAC secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`) are at their default dev values. PostgreSQL is supported but optional.

**Note on dev secret defaults:** The JAR contains the dev default values for the three HMAC secrets. `StartupGuard` blocks prod startup if these defaults are detected, but a misconfigured deployment (missing env vars in prod) would use predictable secrets. Always verify env vars are set before promoting a build.

## Code patterns

**Adding a new protected endpoint:**
1. Add the path to `JwtFilter.PROTECTED` set.
2. In the resource method, cast `ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext` to get the caller identity.

**Adding a new public endpoint:**
- No changes needed — `JwtFilter` only blocks paths in `PROTECTED`. Everything else passes through without JWT checks.

**Adding a new auth token type:**
- Add a string constant for the type (e.g. `"email_verification"`).
- Call `userService.createAuthToken(userId, type, ttlHours)` to generate; call `userService.consumeAuthToken(token, type)` to validate and atomically mark used.
- `consumeAuthToken` uses `AuthTokenRepository.claimToken()` which atomically marks the token used via `UPDATE ... WHERE used=false` — safe against concurrent redemption.
- The `TokenCleanupJob` automatically purges tokens older than 30 days.
- Note: `auth_tokens` infrastructure exists in the DB (V4 migration) but no REST endpoints currently expose it — it is reserved for future password-reset / magic-link / email-verification flows.

**Exception handling:**
- Throw standard JAX-RS exceptions (`NotAuthorizedException`, `ForbiddenException`, `NotFoundException`, `BadRequestException`) from services — `NormalizedExceptionMappers` catches them and returns `{"error": "...", "message": "...", "status": N}`.
- Never return raw error strings from resources.
- 5xx responses return a generic `"An internal error occurred"` message to the client; the original message is logged server-side only.

## bcrypt compatibility

`PasswordService` uses `at.favre.lib:bcrypt` at cost factor 12, producing `$2a$12$...` hashes (upgraded from cost 10 per OWASP recommendation). Existing cost-10 hashes from finance-tracker remain verifiable — bcrypt encodes the cost factor in the hash string, so `BCrypt.verifyer()` handles both transparently. New registrations produce cost-12 hashes.

### Common password rejection

`PasswordService` loads `common-passwords.txt` at startup into an in-memory `Set`. Registration rejects passwords found in this list regardless of length. The list contains ~300 of the most commonly breached passwords.

## JWT format

`JwtService.sign()` sets the following in the payload:
- `sub` — userId; standard claim used by any JWT-aware service to identify the caller.
- `userId` — same as `sub`; custom claim for backward compatibility with finance-tracker.
- `email` — user's email address.
- `iss` — issuer, set to `auth.base-url` (e.g. `https://auth.example.com`). Consuming services should validate this.
- `aud` — set to `appId` when present. Consuming services **must** validate this to prevent cross-app token reuse. Tokens without `aud` are app-agnostic (issued without `X-App-Id`).
- `kid` — key ID in the JWT header; matches the `kid` field in the JWKS response. Re-fetch JWKS when you encounter an unknown `kid`.
- `groups` — list containing the user's role for the given app (e.g. `["user"]` or `["admin"]`). Only present when `appId` is set and the user has a `user_app_access` row. Consuming services using Quarkus/MP-JWT can use `@RolesAllowed` against this claim directly.
- `iat` / `exp` — issued-at and expiry timestamps.

Tokens are signed with ES256 (ECDSA P-256). Verify using the public key from `GET /.well-known/jwks.json`.

**Consuming services should validate:** `iss` equals their known auth-service URL, `aud` equals their app ID, `exp` is in the future, and `kid` matches a known key in the JWKS.

> **CRITICAL — aud validation is the consuming service's responsibility.** The auth-service correctly sets `aud` to the `appId`, but does not enforce that consuming services check it. A consuming service that skips `aud` validation will accept tokens issued for any other app. This is an account-isolation boundary — always validate `aud`.

**Note on tokens without `aud`:** Tokens issued via login/register without `X-App-Id` have no `aud` claim. They are broadly usable across any service that trusts this auth-service. Avoid issuing these in multi-tenant contexts — always pass `X-App-Id`.

## Why ES256 and not RS256

RS256 (RSA + SHA-256) was considered but not implemented due to **performance concerns on a personal/low-resource server**:

| | ES256 (current) | RS256 (alternative) |
|---|---|---|
| Algorithm | ECDSA P-256 | RSA 2048-bit |
| Key generation | Fast | Slow (~100ms+ on low-end hardware) |
| Signing | Fast | Slow (modular exponentiation) |
| Verification | Moderate | Fast (public exponent is small) |
| Key size on disk | ~200 bytes | ~1700 bytes |
| Security level | 128-bit | 112-bit (2048-bit RSA) |

ES256 provides **stronger security with significantly less CPU cost** at signing time, which matters on a personal server handling every login.

### What would need to change to switch to RS256

The change is isolated to `EcKeyService` and `JwtService` — no DB schema changes, no API changes.

1. **`EcKeyService`** — replace `KeyPairGenerator` algorithm from `"EC"` / `ECGenParameterSpec("secp256r1")` to `"RSA"` / `RSAKeyGenParameterSpec(2048, ...)`. Change `ECPrivateKey`/`ECPublicKey` types to `RSAPrivateKey`/`RSAPublicKey`. Update `publicKeyAsJwk()` to emit `"kty": "RSA"` with `n` (modulus) and `e` (exponent) instead of `x`/`y`/`crv`.

2. **`JwtService`** — no code change needed; `builder.signWith(ecKeyService.privateKey)` auto-detects the algorithm from the key type. jjwt will switch to RS256 automatically when given an `RSAPrivateKey`.

3. **`EcKeyEntity`** / **DB** — column names (`private_key_pkcs8`, `public_key_x509`) stay the same; only the stored bytes change. A DB wipe or migration to clear the old EC key row is needed so the new RSA key pair is generated on next boot.

That is the full scope — roughly 20 lines changed in `EcKeyService`.

## Change log

### groups/role claim in JWT (2026-03-30)

**Problem:** `@RolesAllowed("user")` in consuming Quarkus services requires a `groups` claim in the JWT. The auth-service was not emitting one.

**What was added:**
- `UserAppAccessRepository.findRole(userId, appId)` — looks up the user's role for an app.
- `UserService.getRole(userId, appId)` — exposes it to the resource layer.
- `JwtService.sign(..., role: String?)` — emits `"groups": [role]` when role is non-null.
- All four token-issuing paths in `AuthResource` (register, login, OAuth direct callback, token exchange) now look up the role and pass it to `sign()`.

Tokens issued without `X-App-Id` have no `groups` claim. Tokens with `X-App-Id` include `"groups": ["user"]` or `"groups": ["admin"]`.

### Security hardening (2026-03-30)

#### Critical fixes

**1. OAuth code TOCTOU race eliminated**
- `OAuthCodeRepository.claimCode()` — atomically marks the code used via `UPDATE ... WHERE used=false AND expiresAt > now` before returning the entity. If the UPDATE affects 0 rows, the code was already used or expired. `AuthResource.exchangeToken()` now calls `claimCode()` instead of the previous select-then-update pattern, which had a race where two concurrent requests could both exchange the same one-time code.

**2. Admin key brute-force protection**
- `AppResource` now injects `RateLimiter` and `ContainerRequestContext`.
- `checkAdmin()` rate-limits all admin endpoint requests at 20 RPM per IP (keyed `admin:ip:<ip>`), regardless of whether the key is correct. Failed auth attempts are logged with `AUDIT admin_auth_failed`.

**3. OAuth state nonce — single-use enforcement**
- New `OAuthNonceStore` (`security/OAuthNonceStore.kt`) — in-memory `ConcurrentHashMap<nonce, expiry>` with 10-minute TTL and 5-minute scheduled eviction.
- `buildOAuthState()` registers the nonce; `parseOAuthState()` consumes it. A state whose nonce is missing or expired is rejected even if the HMAC signature is valid. This closes the CSRF / state-replay vector.

#### High fixes

**4. OAuth `emailVerified` reflects provider truth**
- `OAuthService.OAuthUser` gained an `emailVerified: Boolean` field.
- Google: reads `verified_email` from `/oauth2/v2/userinfo` (defaults `true` if absent).
- GitHub: always calls `/user/emails` and reads the primary email's `verified` field. Previously `emailVerified` was hardcoded `true` for all OAuth users, which was incorrect for GitHub accounts with unverified emails.
- `UserService.findOrCreateByOAuth()` gained an `emailVerified` parameter; `AuthResource.oauthCallback()` passes `oauthUser.emailVerified`.

**5. Redirect URI comparison URI-normalized**
- `AuthResource.validateRedirectUri()` now normalizes both the incoming URI and all registered URIs before comparing: lowercase scheme + host, implicit ports stripped (443/https, 80/http), trailing slashes stripped.
- Prevents bypasses like `https://example.com:443/cb` vs `https://example.com/cb`.

#### Medium fixes

**6. 5xx responses no longer leak internal details**
- `WebApplicationExceptionMapper` returns `"An internal error occurred"` for any HTTP 5xx response; the original message is logged server-side. 4xx messages are unchanged (they are crafted by application code and intentionally user-facing).

**7. Audit logging added**
- Login success/failure (with reason), account deletion, OAuth token exchange, and admin auth failures are now logged with an `AUDIT` prefix at INFO level for easy filtering.

#### Documentation

**8. JWT `aud` validation warning**
- CLAUDE.md now contains a prominent CRITICAL note that consuming services are responsible for validating the `aud` claim. Skipping this check allows cross-app token reuse.

**9. Rate limiter single-instance limitation documented**
- Known limitation: in-memory rate limiter is not shared across instances in a horizontally-scaled deployment. Documented in CLAUDE.md; not a concern for the intended single-instance personal-use deployment.

**10. `auth_tokens` dead code documented**
- The `auth_tokens` table (V4 migration) and `UserService.createAuthToken/consumeAuthToken` exist for future password-reset / magic-link flows. No REST endpoints currently expose them. Documented as reserved.

### Security hardening phase 2 (2026-04-01)

#### Critical fixes

**1. `consumeAuthToken` TOCTOU race eliminated**
- Added `AuthTokenRepository.claimToken()` — atomically marks the token used via `UPDATE ... WHERE used=false AND type=? AND expiresAt > now` before returning the entity. Mirrors the `OAuthCodeRepository.claimCode()` pattern.
- `UserService.consumeAuthToken()` now uses the atomic method instead of the previous select-then-update pattern.
- This was a latent bug (no REST endpoints expose auth tokens yet) that would have become exploitable when password-reset or magic-link flows are added.

**2. Refresh token support with short-lived access tokens**
- Access token TTL reduced from 7 days to **15 minutes** (`AUTH_JWT_EXPIRY_SECONDS` default changed from 604800 to 900).
- New `refresh_tokens` table (V8 migration) — HMAC-hashed at rest, revocable, 7-day TTL.
- New `RefreshTokenEntity` + `RefreshTokenRepository` with atomic `claimToken()` (single-use rotation) and `revokeAllForUser()`.
- New `POST /auth/refresh` endpoint — accepts `refresh_token` form param, atomically revokes old token, issues new access + refresh token pair.
- All four token-issuing paths (register, login, OAuth callback, token exchange) now return `refreshToken` in the response.
- Account deletion revokes all refresh tokens via `UserService.revokeAllRefreshTokens()`.
- `TokenCleanupJob` purges expired refresh tokens older than 14 days.
- `AuthResponse` DTO gained a `refreshToken` field.

**3. Common password rejection**
- `PasswordService` loads `common-passwords.txt` (~300 entries) at startup into an in-memory `Set`.
- `PasswordService.isCommon(password)` checks against the list (case-insensitive).
- `UserService.register()` rejects common passwords with a clear error message before proceeding.

#### Medium fixes

**4. Registration timing side-channel fixed**
- `PasswordService.dummyHash()` performs a bcrypt hash to equalize response timing.
- Called on the duplicate-email registration failure path, so an attacker cannot distinguish "email already registered" from "new registration" by measuring response time.

**5. bcrypt cost factor increased from 10 to 12**
- Per OWASP recommendation. Cost 12 is ~4x slower to hash than cost 10, significantly increasing brute-force resistance.
- Existing cost-10 hashes from finance-tracker remain verifiable — bcrypt encodes the cost factor in the hash string.
- New registrations produce `$2a$12$...` hashes.

**6. Security response headers added**
- New `SecurityHeadersFilter` (JAX-RS `ContainerResponseFilter`) adds standard security headers to all responses:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
  - `X-XSS-Protection: 0` (disabled per modern best practice; CSP supersedes it)

**7. Login timing side-channel fixed**
- `PasswordService.dummyVerify()` performs a bcrypt verify against a pre-computed cost-12 hash.
- Called on both the unknown-email and no-password (OAuth-only) login failure paths, so response time is constant regardless of whether the email exists.

**8. Unknown app IDs rejected**
- `UserService.validateAppId(appId)` throws `BadRequestException` if `X-App-Id` does not match a registered app.
- Called in `AuthResource` for register, login, and OAuth redirect — prevents issuing JWTs with arbitrary `aud` claims.
- `checkAppAccess()` also rejects unknown app IDs instead of silently passing.

**9. Password required on public registration**
- `UserService.register()` now throws `BadRequestException("Password is required")` if password is null.
- Prevents email squatting where an attacker registers `victim@example.com` without a password to block the victim's OAuth-first signup (409 conflict).
- Passwordless accounts are still created via the OAuth flow (`findOrCreateByOAuth`), which does not go through `register()`.

**10. Production secret quality enforced**
- `StartupGuard` now enforces a minimum length of 32 characters for all three HMAC secrets in prod, in addition to checking they are not the dev defaults.
- Weak but non-default secrets (e.g. `"abc"`) are now rejected at boot.

### Known limitations and operational notes

#### Single-instance constraints
- **`OAuthNonceStore`** and **`RateLimiter`** are in-memory. With multiple instances, OAuth nonces are not shared (callbacks may fail if they hit a different instance than the redirect), and effective rate limits multiply by instance count. Use sticky sessions or a shared store (Redis) if scaling horizontally.

#### Stateless logout and incident response
- `POST /auth/logout` clears the `platform_session` cookie but does not revoke refresh tokens or block existing access JWTs. Access tokens remain valid until their 15-minute expiry.
- **Incident response playbook:** On compromise, rotate `AUTH_TOKEN_PEPPER` (invalidates all refresh tokens at rest) and wipe the `ec_keys` table (invalidates all access JWTs immediately since a new signing key is generated on next boot). The short access token TTL limits the window of exposure.

#### HSTS over HTTP
- `SecurityHeadersFilter` sends `Strict-Transport-Security` on all responses. Browsers ignore it over plain HTTP, so it is harmless but slightly noisy for local HTTP-only dev setups.

#### JWT PII considerations
- JWTs contain `email` in the payload. Consuming services should avoid logging raw tokens, as they become PII in log aggregators and caches. Log `userId` instead.

#### Refresh token rate limiting
- `POST /auth/refresh` is only rate-limited per-IP (no per-account bucket like login). Offline guessing is infeasible given the 256-bit token entropy, but per-account limiting would be defense-in-depth if needed.

#### Health and metrics endpoints
- `/q/health`, `/q/metrics`, and `/q/dev` are exposed by Quarkus. Ensure your reverse proxy does not expose these publicly if your network model requires it.

#### Dependency / CVE hygiene
- No automated SCA scanner is configured in-repo. Consider adding Dependabot or OSV-Scanner to the CI pipeline for `pom.xml` dependency monitoring.

### Consumer responsibilities (cannot be fixed inside this repo alone)

#### `aud` and `iss` validation
- `JwtService.verify()` requires `iss` but does not bind `aud`. The `/auth/me` and `/auth/account` endpoints are intentionally app-agnostic — they accept any valid JWT regardless of `aud`.
- **Consuming services must validate `aud` against their app ID and `iss` against this issuer**, or they may accept tokens minted for another app's audience string.

#### Post-deletion JWT validity
- After `DELETE /auth/account`, the user's access JWT remains cryptographically valid until expiry (up to 15 minutes). `/auth/me` returns 404, but other consuming services have no built-in way to know the account was deleted.
- If this becomes a concern, add optional revocation (e.g. check `iat` against a user-level `credentials_changed_at` timestamp, or maintain a short-lived revocation list keyed by `userId`).
