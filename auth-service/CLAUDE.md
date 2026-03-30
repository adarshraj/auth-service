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
All four HMAC secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`, `AUTH_MFA_HMAC_SECRET`) **must** be set to non-default values in prod — `StartupGuard` throws on boot otherwise.

SQLite is used by default — no database setup needed for development.

## Architecture

Layered under `src/main/kotlin/com/authservice/`:

- **`api/`** — JAX-RS resources (`AuthResource`, `AppResource`, `WellKnownResource`), DTOs, and exception mappers. Resources delegate all logic to services.
- **`service/`** — Business logic: `UserService` (registration, login, OAuth account linking, access management, auth tokens, MFA), `JwtService` (sign/verify ES256), `EcKeyService` (generate/persist/expose EC P-256 key pair), `PasswordService` (bcrypt), `OAuthService` (Google + GitHub flows), `TotpService` (TOTP generation/verification using JDK crypto), `TokenCleanupJob` (scheduled purge).
- **`domain/`** — JPA entities and Panache repositories: `UserEntity`, `AppEntity`, `UserAppAccessEntity` (composite PK), `AuthTokenEntity`, `EcKeyEntity`, `OAuthCodeEntity`.
- **`security/`** — `JwtFilter` (protects `/auth/me`, `/auth/account`, and `/auth/mfa/setup|confirm|disable`), `RateLimiter` (in-memory fixed-window), `OAuthNonceStore` (single-use nonce validation for OAuth CSRF protection), `ApiKeyHasher` (HMAC-SHA256 for admin key), `CallerContext` (request-scoped user identity), `StartupGuard` (validates required secrets on boot).
- **`config/`** — `RateLimitConfig` and `OAuthConfig` ConfigMapping interfaces.

### Key flows

**Login (without MFA):** `AuthResource.login()` → `UserService.login()` (verify bcrypt, check app gate) → `JwtService.sign()` → `AuthResponse{token, user}`

**Login (with MFA):** `AuthResource.login()` → `UserService.login()` → MFA enabled? → `MfaChallengeResponse{mfaRequired, mfaToken}` → client calls `POST /auth/mfa/verify` with TOTP code or backup code → `AuthResponse{token, user}`

**MFA enrollment:** `POST /auth/mfa/setup` (JWT required) → returns secret + QR URI + recovery codes → user scans QR → `POST /auth/mfa/confirm` with valid TOTP → MFA enabled

**OAuth (browser flow with redirect_uri):**
1. `GET /auth/oauth/{provider}?redirect_uri=https://app.com/cb` (with `X-App-Id`)
2. 302 to provider → provider redirects to `GET /auth/oauth/callback`
3. `OAuthService.exchangeCode()` → `UserService.findOrCreateByOAuth()` → issue one-time code → 302 to `redirect_uri?code=<code>`
4. Client POSTs `POST /auth/token` (form: `code=<code>`) → JWT returned (code valid 60s, single-use)
5. If MFA enabled: step 3 redirects to `redirect_uri?mfa_required=true&mfa_code=<code>` instead → client exchanges code via `POST /auth/mfa/challenge` (form: `code=<code>`) → receives `MfaChallengeResponse` → completes via `POST /auth/mfa/verify`

**OAuth (API flow without redirect_uri):** Same as above but callback returns `AuthResponse` or `MfaChallengeResponse` JSON directly.

### Polymorphic response types

Several endpoints return different response shapes depending on MFA state. Clients must check for the `mfaRequired` field to distinguish:

| Endpoint | Without MFA | With MFA |
|---|---|---|
| `POST /auth/login` | `AuthResponse { token, user }` | `MfaChallengeResponse { mfaRequired, mfaToken }` |
| `POST /auth/token` | `AuthResponse { token, user }` | `MfaChallengeResponse { mfaRequired, mfaToken }` |
| `GET /auth/oauth/callback` (no redirect) | `AuthResponse { token, user }` | `MfaChallengeResponse { mfaRequired, mfaToken }` |

All three return HTTP 200 in both cases. The presence of `mfaRequired: true` indicates the client must complete the MFA flow via `POST /auth/mfa/verify` before receiving a JWT.

> **Client implementation pattern:** Check if the response contains `mfaRequired`. If yes, prompt for TOTP and call `/auth/mfa/verify`. If no, the `token` field is the JWT. This branching logic is the only change required in existing clients to support MFA.

**Per-app gate:** If `apps.requires_explicit_access = true`, login is blocked unless a `user_app_access` row exists. Auto-granted on first register/OAuth into that app.

**JWT verification in other services:** Fetch public key from `GET /.well-known/jwks.json`, verify ES256 signature, validate `aud` claim matches app ID. Token payload: `{sub, userId, email, groups, appId, aud, iat, exp}`.

### Database schema (Flyway migrations)

| Migration | Table | Purpose |
|-----------|-------|---------|
| V1 | `users` | Core user record — id, email, name, password_hash, avatar_url, oauth_provider, oauth_id, email_verified |
| V2 | `apps` | Registered apps — id (e.g. `finance-tracker`), name, requires_explicit_access |
| V3 | `user_app_access` | Per-user app grants — composite PK (user_id, app_id), role, granted_at |
| V4 | `auth_tokens` | One-time tokens — type (`password_reset`, `magic_link`, `email_verification`, `mfa_challenge`), expires_at, used, app_id |
| V5 | `apps.redirect_uris` | Newline-separated allowed redirect URIs per app |
| V6 | `ec_keys` | Persisted EC P-256 key pair (single row, id=`primary`) |
| V7 | `oauth_codes` | Short-lived one-time codes for the OAuth browser redirect flow (60s TTL) |
| V8 | `users` (columns) | MFA fields — `mfa_enabled`, `mfa_secret`, `mfa_backup_codes` |
| V9 | `auth_tokens` (column) | `app_id` — binds token to originating app for MFA challenge flow |

### Admin key security

The `X-Admin-Key` header value is never stored raw. The hash of the configured key is pre-computed once at startup (`AppResource.configuredKeyHash` lazy val). On each request `ApiKeyHasher.verify(provided, storedHash)` computes `HMAC(provided)` and compares via `MessageDigest.isEqual()` (constant-time). This prevents both timing attacks and repeated hashing overhead.

All admin endpoints are rate-limited at 20 RPM per IP (`AppResource.ADMIN_RPM`). Failed authentication attempts are logged with `AUDIT admin_auth_failed`.

**Admin API is disabled** (returns 501) if `AUTH_ADMIN_KEY` is not set. Apps still work — only the `/auth/apps` management endpoints are gated.

### Auth token and OAuth code security

`auth_tokens` and `oauth_codes` are stored as `HMAC(value, AUTH_TOKEN_PEPPER)`, not plaintext. `UserService.createAuthToken()` and `AuthResource.issueOAuthCode()` return the raw value to the caller and store only the hash; lookup hashes the incoming value before querying. A full DB dump does not expose redeemable tokens or codes.

Both `OAuthCodeRepository.claimCode()` and `AuthTokenRepository.claimToken()` atomically mark codes/tokens as used via `UPDATE ... WHERE used=false` before returning the entity. This eliminates the TOCTOU race where two concurrent requests could both consume the same one-time code/token.

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

### MFA (TOTP)

Optional two-factor authentication using TOTP (RFC 6238). Implemented entirely with JDK crypto (`javax.crypto.Mac` / HMAC-SHA1) — no external libraries.

**Enrollment flow:**
1. Authenticated user calls `POST /auth/mfa/setup` → receives `secret` (base32), `otpauthUri` (for QR scanning), and 8 single-use `recoveryCodes`.
2. User scans the QR code with any authenticator app (Google Authenticator, Authy, etc.).
3. User calls `POST /auth/mfa/confirm` with a valid 6-digit TOTP code → MFA is enabled.

**Login flow with MFA:**
1. `POST /auth/login` returns `{ "mfaRequired": true, "mfaToken": "..." }` instead of a JWT.
2. Client calls `POST /auth/mfa/verify` with the `mfaToken` and a TOTP code (or backup code).
3. Response is the standard `AuthResponse { token, user }`.

**OAuth + MFA:** MFA is enforced across all login paths — password, OAuth JSON callback, and OAuth code exchange (`POST /auth/token`). When a user with MFA enabled completes OAuth, the response is an `MfaChallengeResponse` instead of a JWT. For the redirect flow, the client receives `?mfa_required=true&mfa_token=...` instead of `?code=...`.

**MFA challenge token:** HMAC-signed (`base64url(userId\nemail\nappId\nnonce\nexpiry)~hmac`), signed with `auth.mfa-hmac-secret` (dedicated secret, separate from OAuth state and token pepper), 5-minute TTL. Single-use — nonce is registered in `MfaNonceStore` and consumed on verification. Not a JWT — lightweight and single-purpose.

**Rate limiting on MFA verify:** Per-IP (global RPM) + per-userId (5 RPM) rate limits on `POST /auth/mfa/verify`. The per-userId limit prevents distributed brute force on 6-digit TOTP codes from multiple IPs.

**Backup codes:** 8 codes generated during setup (8 lowercase alphanumeric chars each). Stored as HMAC-SHA256 hashes in `users.mfa_backup_codes` (same pattern as auth tokens — a DB dump does not expose usable codes). Each code is consumed on use (hash removed from the list). Can be used in place of a TOTP code at `POST /auth/mfa/verify` or `POST /auth/mfa/disable`.

**Disabling MFA:** `POST /auth/mfa/disable` requires a valid TOTP or backup code. Clears `mfa_enabled`, `mfa_secret`, and `mfa_backup_codes`.

**Backward compatibility:** MFA is fully optional. Users who have not enabled MFA see no change in login behavior — the response is the same `AuthResponse { token, user }`. Clients only need to handle the MFA challenge flow if their users choose to enable MFA.

**MFA secret storage:** The TOTP secret is encrypted with AES-256-GCM using `SHA-256(AUTH_TOKEN_PEPPER)` as the key. Stored as `iv:ciphertext` in base64. A DB dump does not expose the raw TOTP secret. Backup codes are stored as HMAC hashes (not reversible).

### Redirect URI policy

Redirect URIs are validated at both registration time (`POST /auth/apps`) and use time (`GET /auth/oauth/{provider}?redirect_uri=`). Rules:
- Must be `https://` in production.
- `http://localhost` and `http://127.0.0.1` are allowed for local development.
- Compared after URI normalization: lowercase scheme + host, implicit default ports stripped (`:443` for https, `:80` for http), trailing slashes stripped. This prevents bypasses via port variation or case differences.
- **Query strings and fragments are ignored** during comparison — only `scheme://host:port/path` is compared. Registered redirect URIs must not rely on query parameters or fragments for identity. For example, `https://app.com/cb?v=1` and `https://app.com/cb?v=2` are treated as the same URI.

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
| Admin auth failure | `AUDIT admin_auth_failed reason=… ip=…` |
| MFA enabled | `AUDIT mfa_enabled userId=…` |
| MFA disabled | `AUDIT mfa_disabled userId=…` |
| MFA verify success | `AUDIT mfa_verify_success userId=…` |
| MFA verify failure | `AUDIT mfa_verify_failed userId=…` |
| MFA backup code used | `AUDIT mfa_backup_code_used userId=…` |

To stream audit events: `grep AUDIT <logfile>` or configure your log aggregator to filter on `AUDIT`.

## Configuration

| Config path | Env var | Purpose |
|---|---|---|
| `auth.jwt.expiry-seconds` | `AUTH_JWT_EXPIRY_SECONDS` | Token TTL (default 604800 = 7 days) |
| `auth.admin-key` | `AUTH_ADMIN_KEY` | Key for `/auth/apps` endpoints (optional — disables app mgmt if unset) |
| `auth.key-hmac-secret` | `AUTH_KEY_HMAC_SECRET` | HMAC-SHA256 secret for admin key hashing (min 32 chars, required in prod) |
| `auth.state-hmac-secret` | `AUTH_STATE_HMAC_SECRET` | HMAC secret for signing OAuth state params (prevents open redirect / CSRF; required in prod) |
| `auth.token-pepper` | `AUTH_TOKEN_PEPPER` | HMAC pepper for storing auth tokens, OAuth codes, and MFA backup codes at rest; also used as AES key seed for MFA secret encryption (required in prod) |
| `auth.mfa-hmac-secret` | `AUTH_MFA_HMAC_SECRET` | HMAC secret for signing MFA challenge tokens (separate from OAuth state; required in prod) |
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
- Call `userService.createAuthToken(userId, type, ttlHours)` to generate; call `userService.consumeAuthToken(token, type)` to validate and mark used.
- The `TokenCleanupJob` automatically purges tokens older than 30 days.
- Note: `auth_tokens` infrastructure exists in the DB (V4 migration) but no REST endpoints currently expose it — it is reserved for future password-reset / magic-link / email-verification flows.

**Exception handling:**
- Throw standard JAX-RS exceptions (`NotAuthorizedException`, `ForbiddenException`, `NotFoundException`, `BadRequestException`) from services — `NormalizedExceptionMappers` catches them and returns `{"error": "...", "message": "...", "status": N}`.
- Never return raw error strings from resources.
- 5xx responses return a generic `"An internal error occurred"` message to the client; the original message is logged server-side only.

## bcrypt compatibility

`PasswordService` uses `at.favre.lib:bcrypt` at cost factor 10, producing `$2a$10$...` hashes. This is byte-for-byte compatible with Node's `bcrypt` npm package at cost 10 — finance-tracker's existing user `password_hash` values can be imported directly into the `users` table without re-hashing.

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

### Optional MFA / TOTP support (2026-03-30)

**What was added:**
- `TotpService` — RFC 6238 TOTP implementation using only JDK `javax.crypto.Mac` (HMAC-SHA1). Generates base32 secrets, `otpauth://` URIs for QR codes, and 6-digit codes with ±30s skew tolerance. Also generates 8 single-use backup/recovery codes.
- `UserEntity` — three new columns: `mfa_enabled` (boolean), `mfa_secret` (base32 TOTP secret), `mfa_backup_codes` (comma-separated recovery codes).
- `UserService` — MFA lifecycle methods: `setupMfa()`, `confirmMfa()`, `disableMfa()`, `getMfaSecret()`, `consumeBackupCode()`, `isMfaEnabled()`.
- `AuthResource` — five new endpoints:
  - `POST /auth/mfa/setup` (JWT required) — starts enrollment, returns secret + QR URI + recovery codes.
  - `POST /auth/mfa/confirm` (JWT required) — verifies initial TOTP code, activates MFA.
  - `POST /auth/mfa/disable` (JWT required) — disables MFA (requires valid TOTP or backup code).
  - `POST /auth/mfa/verify` (public, MFA token required) — completes login with TOTP or backup code.
  - `POST /auth/login` — modified to return `MfaChallengeResponse` instead of `AuthResponse` when user has MFA enabled.
- `JwtFilter` — `/auth/mfa/setup`, `/auth/mfa/confirm`, `/auth/mfa/disable` added to `PROTECTED` set.
- `V8__mfa.sql` — Flyway migration adding MFA columns to `users` table.
- `MfaTest` — 11 tests covering setup, confirm, login challenge, TOTP verify, backup codes (single-use), disable, and backward compatibility.

**Design decisions:**
- MFA is optional — existing clients are unaffected unless users enable it.
- Zero external dependencies — TOTP uses JDK crypto only.
- MFA challenge token is HMAC-signed (not a JWT) with 5-minute TTL, using dedicated `auth.mfa-hmac-secret`.
- Backup codes are consumed on use — each can only be used once.

### MFA security hardening (2026-03-30)

Addressed findings from security audit:

**High — OAuth MFA bypass fixed:**
- OAuth callback (JSON branch), OAuth redirect flow, and `POST /auth/token` code exchange now check `isMfaEnabled()` and return `MfaChallengeResponse` instead of a JWT for MFA-enabled users.
- Redirect flow sends `?mfa_required=true&mfa_code=...` (opaque, single-use code) instead of `?code=...` when MFA is required. Client exchanges code via `POST /auth/mfa/challenge` for the actual `mfaToken` — token never appears in the URL.
- MFA now protects the account uniformly across all login paths (password, Google, GitHub).

**Medium fixes:**

1. **MFA token replay eliminated** — MFA challenge tokens now include a single-use nonce registered in `MfaNonceStore` (in-memory, same pattern as `OAuthNonceStore`). Token is consumed on first use; replay within TTL returns "MFA token already used or expired."

2. **Per-userId rate limit on /auth/mfa/verify** — Added 5 RPM per-userId rate limit (keyed `mfa:user:<userId>`) enforced after parsing the MFA token. Combined with per-IP limit, this prevents distributed brute force on 6-digit TOTP codes.

3. **Dedicated MFA HMAC secret** — New `auth.mfa-hmac-secret` / `AUTH_MFA_HMAC_SECRET` config. MFA challenge tokens are now signed with a separate secret from OAuth state (`auth.state-hmac-secret`). Compromise of one does not forge the other. `StartupGuard` validates it in prod.

4. **TOTP secrets encrypted at rest** — `mfa_secret` is now stored as AES-256-GCM ciphertext (`iv:ciphertext` in base64), encrypted with `SHA-256(AUTH_TOKEN_PEPPER)` as the key. A DB dump does not expose raw TOTP secrets.

5. **Backup codes hashed at rest** — Backup codes are stored as `HMAC-SHA256(code, AUTH_TOKEN_PEPPER)` hashes (same pattern as auth tokens and OAuth codes). Verification computes the hash and compares. A DB dump cannot recover usable backup codes.

### MFA follow-up fixes (2026-03-30)

**Medium — MFA token removed from redirect URL:**
- OAuth redirect flow for MFA-enabled users now sends an opaque `mfa_code` (60s, single-use, HMAC-hashed in DB via `auth_tokens` with type `mfa_challenge`) instead of the `mfaToken` in the query string.
- New endpoint `POST /auth/mfa/challenge` (form-encoded `code=...`) exchanges the code for an `MfaChallengeResponse` over HTTPS. The `mfaToken` never appears in browser history, Referer headers, or proxy logs.

**Low — Per-userId rate limit on /auth/mfa/confirm:**
- `POST /auth/mfa/confirm` now enforces the same 5 RPM per-userId rate limit as `/auth/mfa/verify`, preventing TOTP guessing with a stolen session.

**Low — confirmMfa no longer returns backup codes:**
- `POST /auth/mfa/confirm` response is now `{ "message": "MFA enabled" }` only. Recovery codes are returned exclusively by `POST /auth/mfa/setup` — the single point where users should save them. Previously, confirm returned the HMAC hashes of the codes (useless to the user).

**Documentation:**
- Redirect URI comparison explicitly documented as `scheme://host:port/path` only — query strings and fragments are ignored.
- Polymorphic response types documented for `POST /auth/login`, `POST /auth/token`, and `GET /auth/oauth/callback`: clients must check for `mfaRequired` to distinguish `AuthResponse` from `MfaChallengeResponse`.

### MFA challenge appId binding and atomic token consumption (2026-03-30)

**Medium — /auth/mfa/challenge now binds appId to the OAuth session:**
- `auth_tokens` table gained an `app_id` column (V9 migration).
- `createAuthToken()` accepts an optional `appId`, stored on the token row.
- `oauthCallback` passes `appId` when creating `mfa_challenge` tokens.
- `POST /auth/mfa/challenge` ignores client-supplied `X-App-Id` and uses the stored `app_id` from the token. An attacker with a leaked `mfa_code` cannot mint tokens for arbitrary apps.

**Medium — consumeAuthToken is now atomic (double-spend race eliminated):**
- `AuthTokenRepository.claimToken()` uses `UPDATE ... WHERE token = ? AND type = ? AND used = false AND expiresAt > ?` before SELECT (same pattern as `OAuthCodeRepository.claimCode()`).
- `UserService.consumeAuthToken()` now delegates to `claimToken()` — two concurrent requests with the same code cannot both succeed.
