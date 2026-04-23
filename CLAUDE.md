# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Overview

Standalone authentication service. Kotlin + Quarkus, port **8703**. Single shared user pool with optional per-app access gates. Issues **ES256** JWTs signed with a persisted EC P-256 key pair. Consuming services verify via the public key from `GET /.well-known/jwks.json`.

## Commands

All commands run from the project root (where `pom.xml` lives):

```bash
./mvnw quarkus:dev                              # Dev mode (hot reload, SQLite)
./mvnw test                                     # All tests
./mvnw test -Dtest=AuthResourceTest             # Single class
./mvnw test -Dtest=AuthResourceTest#login       # Single method
./mvnw package                                  # Build JAR
```

Dev has insecure defaults for all secrets (warnings logged, startup allowed). In prod, `StartupGuard` throws if any of `AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`, `AUTH_MFA_HMAC_SECRET` are at defaults or shorter than 32 chars. `AUTH_ADMIN_KEY` is optional — if unset, `/auth/apps` admin endpoints return 501.

## Architecture

Layered under `src/main/kotlin/com/authservice/`:

- **`api/`** — JAX-RS resources (`AuthResource`, `AppResource`, `VerifyResource`, `WellKnownResource`), DTOs, exception mappers. Resources delegate all logic to services.
- **`service/`** — `UserService`, `JwtService`, `EcKeyService`, `PasswordService`, `OAuthService`, `TotpService`, `TokenCleanupJob`, `EmailVerificationService`, `MailClient`.
- **`domain/`** — JPA entities + Panache repositories: `UserEntity`, `AppEntity`, `UserAppAccessEntity` (composite PK), `AuthTokenEntity`, `RefreshTokenEntity`, `EcKeyEntity`, `OAuthCodeEntity`.
- **`security/`** — `JwtFilter` (protects `/auth/me`, `/auth/account`, `/auth/mfa/setup|confirm|disable`), `SessionCookieFilter`, `RateLimiter`, `OAuthNonceStore`, `MfaNonceStore`, `ApiKeyHasher`, `CallerContext`, `StartupGuard`, `SecurityHeadersFilter`.
- **`config/`** — `RateLimitConfig`, `OAuthConfig` ConfigMapping interfaces.

## Key flows

**Login:** verify bcrypt → check app gate → if MFA enabled return `MfaChallengeResponse{mfaRequired, mfaToken}`; else return `AuthResponse{token, refreshToken, user}`.

**Refresh:** `POST /auth/refresh` (form `refresh_token=…`) atomically revokes old token, issues new access+refresh pair. Access TTL 15 min; refresh TTL 7 days, single-use rotation.

**OAuth browser flow:** `GET /auth/oauth/{provider}?redirect_uri=…` → provider → `GET /auth/oauth/callback` → issues one-time `oauth_code` (60s) → 302 to `redirect_uri?code=…` → client `POST /auth/token`. If MFA enabled, redirect carries `?mfa_required=true&mfa_code=…` instead; client exchanges via `POST /auth/mfa/challenge` for an `MfaChallengeResponse`, then `POST /auth/mfa/verify`.

**OAuth API flow (no redirect_uri):** callback returns `AuthResponse` or `MfaChallengeResponse` JSON directly.

**MFA enrollment:** `POST /auth/mfa/setup` returns secret + otpauth URI + 8 recovery codes → user scans QR → `POST /auth/mfa/confirm` with TOTP.

### Polymorphic response types

`POST /auth/login`, `POST /auth/token`, and `GET /auth/oauth/callback` (no-redirect branch) all return HTTP 200 with either `AuthResponse` or `MfaChallengeResponse`. Clients must branch on the presence of `mfaRequired`.

## JWT format

Payload: `sub` (userId), `userId` (duplicate for legacy clients), `email`, `iss` (= `auth.base-url`), `aud` (= appId when present), `kid` (header, matches JWKS), `groups` (`["user"]` or `["admin"]`, only when `appId` + `user_app_access` row exist), `iat`, `exp`.

**CRITICAL — `aud` validation is the consumer's responsibility.** This service sets `aud = appId` but does not enforce that downstream services check it. A consuming service that skips `aud` validation will accept tokens minted for any other app.

Tokens issued without `X-App-Id` have no `aud` or `groups` — avoid in multi-tenant contexts.

## Security primitives

**Token/code storage:** `auth_tokens`, `refresh_tokens`, `oauth_codes`, and MFA backup codes are stored as `HMAC(value, AUTH_TOKEN_PEPPER)`. Lookups hash the incoming value. A DB dump does not expose redeemable tokens.

**TOTP secrets:** `mfa_secret` is stored as AES-256-GCM ciphertext (`iv:ciphertext` base64), key = `SHA-256(AUTH_TOKEN_PEPPER)`.

**Atomic claim pattern:** all one-time tokens use `UPDATE … WHERE used=false AND expiresAt > now` before SELECT to eliminate TOCTOU races — `OAuthCodeRepository.claimCode()`, `AuthTokenRepository.claimToken()`, `RefreshTokenRepository.claimToken()`.

**OAuth state:** `base64url(payload)~hmac_hex` with 16-byte nonce registered in `OAuthNonceStore` (10-min TTL, single-use). HMAC tampering and state replay both blocked.

**MFA challenge token:** HMAC-signed `base64url(userId\nemail\nappId\nnonce\nexpiry)~hmac` with dedicated `AUTH_MFA_HMAC_SECRET`, 5-min TTL, single-use via `MfaNonceStore`. Not a JWT.

**Admin key:** hash pre-computed at boot (`AppResource.configuredKeyHash`); each request computes `HMAC(provided)` and compares with `MessageDigest.isEqual()`. Rate-limited at 20 RPM/IP independent of auth limits.

**Rate limiting:** in-memory `ConcurrentHashMap` (single-instance only). Uses **rightmost** `X-Forwarded-For` entry — reverse proxy must strip client-supplied values and append the real IP. Login is limited per-IP (global RPM) and per-account (10 RPM). MFA verify/confirm add per-userId (5 RPM).

**Security headers:** `SecurityHeadersFilter` sets `X-Content-Type-Options`, `X-Frame-Options: DENY`, `CSP: default-src 'none'; frame-ancestors 'none'`, `Referrer-Policy`, HSTS, `X-XSS-Protection: 0`.

**Redirect URI validation:** `https://` required in prod (`http://localhost`/`127.0.0.1` allowed for dev). Compared after normalization: lowercase scheme+host, strip default ports (`:443`/`:80`), strip trailing slash. **Query strings and fragments are ignored** — only `scheme://host:port/path` matters.

**Session cookie:** `SessionCookieFilter` sets `platform_session` (HttpOnly, Secure, SameSite=Lax, `Max-Age = AUTH_JWT_EXPIRY_SECONDS`) on auth success, clears on logout. Domain controlled by `AUTH_SESSION_COOKIE_DOMAIN`.

**Forward auth:** `GET /auth/verify` accepts `platform_session` cookie or `Authorization: Bearer`. Returns 200 with `X-Auth-User-Id`/`X-Auth-User-Email` headers, or 401 with `X-Auth-Redirect: true`.

**EC key lifecycle:** `EcKeyService` loads or generates on `StartupEvent`. `kid` is a random UUID stored alongside; private key never leaves process. Wiping `ec_keys` invalidates all existing tokens on next boot.

**bcrypt:** cost 12, `$2a$12$…`. Cost-10 legacy hashes still verify. `PasswordService.dummyHash()`/`dummyVerify()` equalize timing on duplicate-email and unknown-email paths. Common passwords (`common-passwords.txt`, ~300 entries) rejected at registration.

**OAuth `emailVerified`:** reflects provider truth — Google reads `verified_email`, GitHub always calls `/user/emails` (not hardcoded true).

## Database schema (Flyway)

| V | Table / change | Notes |
|---|---|---|
| V1 | `users` | id, email, name, password_hash, avatar_url, oauth_provider, oauth_id, email_verified |
| V2 | `apps` | id, name, requires_explicit_access |
| V3 | `user_app_access` | composite PK (user_id, app_id), role, granted_at |
| V4 | `auth_tokens` | type (`password_reset`/`magic_link`/`email_verification`/`mfa_challenge`), expires_at, used |
| V5 | `apps.redirect_uris` | newline-separated |
| V6 | `ec_keys` | single row, id=`primary` |
| V7 | `oauth_codes` | one-time codes for OAuth redirect flow (60s) |
| V8 | `refresh_tokens` | HMAC-hashed, revocable, 7-day TTL |
| V9 | `users` MFA cols | `mfa_enabled`, `mfa_secret`, `mfa_backup_codes` |
| V10 | `auth_tokens.app_id` | binds mfa_challenge token to originating app |

## Configuration

| Config | Env | Purpose |
|---|---|---|
| `auth.jwt.expiry-seconds` | `AUTH_JWT_EXPIRY_SECONDS` | Access TTL (default 900) |
| `auth.refresh-token.expiry-seconds` | `AUTH_REFRESH_TOKEN_EXPIRY_SECONDS` | Refresh TTL (default 604800) |
| `auth.admin-key` | `AUTH_ADMIN_KEY` | Admin key; unset disables `/auth/apps` |
| `auth.key-hmac-secret` | `AUTH_KEY_HMAC_SECRET` | Admin key hashing (≥32 chars in prod) |
| `auth.state-hmac-secret` | `AUTH_STATE_HMAC_SECRET` | OAuth state signing |
| `auth.token-pepper` | `AUTH_TOKEN_PEPPER` | Token HMAC + MFA AES key seed |
| `auth.mfa-hmac-secret` | `AUTH_MFA_HMAC_SECRET` | MFA challenge tokens |
| `auth.session.cookie-domain` | `AUTH_SESSION_COOKIE_DOMAIN` | e.g. `.homelab.local` |
| `auth.rate-limit.enabled` / `requests-per-minute` | `AUTH_RATE_LIMIT_ENABLED` / `AUTH_RATE_LIMIT_RPM` | default 60 |
| `auth.oauth.{google,github}.{client-id,client-secret}` | `{GOOGLE,GITHUB}_CLIENT_{ID,SECRET}` | |
| `auth.base-url` | `AUTH_BASE_URL` | Public URL used for OAuth callbacks + JWT `iss` |
| `quarkus.datasource.*` | `QUARKUS_DATASOURCE_*` | Prod DB connection (SQLite by default) |

**Profiles:** dev = SQLite file `./authservice-dev.db`. Test = in-memory SQLite, rate limiting disabled. Prod = SQLite by default (mount a volume); PostgreSQL supported.

## Code patterns

**New protected endpoint:** add path to `JwtFilter.PROTECTED`; in the resource, `ctx.getProperty(JwtFilter.PROP_CALLER) as? CallerContext`.

**New public endpoint:** no changes — only paths in `PROTECTED` are checked.

**New auth token type:** define a string constant; call `userService.createAuthToken(userId, type, ttlHours)` to issue (returns raw value, stores HMAC) and `userService.consumeAuthToken(token, type)` to atomically claim. `TokenCleanupJob` purges used/expired rows after 30 days.

**Exceptions:** throw `NotAuthorizedException`/`ForbiddenException`/`NotFoundException`/`BadRequestException` from services. `NormalizedExceptionMappers` returns `{error, message, status}`. 5xx responses return generic `"An internal error occurred"`; original is logged server-side.

## Audit logging

Events logged at INFO with `AUDIT` prefix: `login_success`, `login_failed`, `account_deleted`, `token_exchanged`, `token_refreshed`, `admin_auth_failed`, `mfa_enabled`, `mfa_disabled`, `mfa_verify_success`, `mfa_verify_failed`, `mfa_backup_code_used`. Stream with `grep AUDIT` or a log filter.

## Operational notes

- **Single-instance only:** `RateLimiter`, `OAuthNonceStore`, `MfaNonceStore` are in-memory. Scaling horizontally requires a shared store (Redis).
- **Incident response:** rotate `AUTH_TOKEN_PEPPER` (invalidates refresh tokens at rest) and wipe `ec_keys` (invalidates access JWTs on next boot). 15-min access TTL bounds the window.
- **Logout:** `POST /auth/logout?refresh_token=…` clears cookie + revokes the given refresh token. Access tokens remain valid until expiry (stateless).
- **Post-deletion JWTs:** valid until `exp` (≤15 min). `/auth/me` returns 404 but other services see a valid token unless they implement their own revocation check.
- **JWT PII:** payload contains `email`. Log `userId` instead of raw tokens.
- **Quarkus endpoints** `/q/health`, `/q/metrics`, `/q/dev` should not be publicly exposed.
