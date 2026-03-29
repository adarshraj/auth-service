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

**Required for dev:**
```bash
export AUTH_ADMIN_KEY="your-admin-key"
# HMAC secret defaults to a dev value — fine for local, not for prod
# JWT_SECRET is no longer used — key pair is generated and persisted to DB on first boot
```

SQLite is used by default — no database setup needed for development.

## Architecture

Layered under `src/main/kotlin/com/authservice/`:

- **`api/`** — JAX-RS resources (`AuthResource`, `AppResource`, `WellKnownResource`), DTOs, and exception mappers. Resources delegate all logic to services.
- **`service/`** — Business logic: `UserService` (registration, login, OAuth account linking, access management, auth tokens), `JwtService` (sign/verify ES256), `EcKeyService` (generate/persist/expose EC P-256 key pair), `PasswordService` (bcrypt), `OAuthService` (Google + GitHub flows), `TokenCleanupJob` (scheduled purge).
- **`domain/`** — JPA entities and Panache repositories: `UserEntity`, `AppEntity`, `UserAppAccessEntity` (composite PK), `AuthTokenEntity`, `EcKeyEntity`, `OAuthCodeEntity`.
- **`security/`** — `JwtFilter` (protects `/auth/me` and `/auth/account`), `RateLimiter` (in-memory fixed-window), `ApiKeyHasher` (HMAC-SHA256 for admin key), `CallerContext` (request-scoped user identity), `StartupGuard` (validates required secrets on boot).
- **`config/`** — `RateLimitConfig` and `OAuthConfig` ConfigMapping interfaces.

### Key flows

**Login:** `AuthResource.login()` → `UserService.login()` (verify bcrypt, check app gate) → `JwtService.sign()` → `AuthResponse{token, user}`

**OAuth (browser flow with redirect_uri):**
1. `GET /auth/oauth/{provider}?redirect_uri=https://app.com/cb` (with `X-App-Id`)
2. 302 to provider → provider redirects to `GET /auth/oauth/callback`
3. `OAuthService.exchangeCode()` → `UserService.findOrCreateByOAuth()` → issue one-time code → 302 to `redirect_uri?code=<code>`
4. Client POSTs `POST /auth/token` (form: `code=<code>`) → JWT returned (code valid 60s, single-use)

**OAuth (API flow without redirect_uri):** Same as above but callback returns `AuthResponse` JSON directly.

**Per-app gate:** If `apps.requires_explicit_access = true`, login is blocked unless a `user_app_access` row exists. Auto-granted on first register/OAuth into that app.

**JWT verification in other services:** Fetch public key from `GET /.well-known/jwks.json`, verify ES256 signature, validate `aud` claim matches app ID. Token payload: `{sub, userId, email, appId, aud, iat, exp}`.

### Database schema (Flyway migrations)

| Migration | Table | Purpose |
|-----------|-------|---------|
| V1 | `users` | Core user record — id, email, name, password_hash, avatar_url, oauth_provider, oauth_id, email_verified |
| V2 | `apps` | Registered apps — id (e.g. `finance-tracker`), name, requires_explicit_access |
| V3 | `user_app_access` | Per-user app grants — composite PK (user_id, app_id), role, granted_at |
| V4 | `auth_tokens` | One-time tokens — type (`password_reset`, `magic_link`, `email_verification`), expires_at, used |
| V5 | `apps.redirect_uris` | Newline-separated allowed redirect URIs per app |
| V6 | `ec_keys` | Persisted EC P-256 key pair (single row, id=`primary`) |
| V7 | `oauth_codes` | Short-lived one-time codes for the OAuth browser redirect flow (60s TTL) |

### Admin key security

The `X-Admin-Key` header value is never stored raw. The hash of the configured key is pre-computed once at startup (`AppResource.configuredKeyHash` lazy val). On each request `ApiKeyHasher.verify(provided, storedHash)` computes `HMAC(provided)` and compares via `MessageDigest.isEqual()` (constant-time). This prevents both timing attacks and repeated hashing overhead.

**Admin API is disabled** (returns 501) if `AUTH_ADMIN_KEY` is not set. Apps still work — only the `/auth/apps` management endpoints are gated.

### Auth token and OAuth code security

`auth_tokens` and `oauth_codes` are stored as `HMAC(value, AUTH_TOKEN_PEPPER)`, not plaintext. `UserService.createAuthToken()` and `AuthResource.issueOAuthCode()` return the raw value to the caller and store only the hash; lookup hashes the incoming value before querying. A full DB dump does not expose redeemable tokens or codes.

### OAuth state integrity

The OAuth state parameter is HMAC-signed: `base64url(payload)~hmac_hex`. `AuthResource.buildOAuthState()` appends the signature; `parseOAuthState()` verifies it with constant-time comparison before decoding. This prevents an attacker from swapping the `redirectUri` field in-flight (open redirect) or injecting a provider value.

### Rate limiting and reverse proxy

Rate limiting uses the **rightmost** `X-Forwarded-For` entry (set by the trusted reverse proxy) to prevent client-side IP spoofing. For this to be effective your reverse proxy must:
1. Strip any client-supplied `X-Forwarded-For` header before forwarding.
2. Append the real client IP itself.

Login is rate-limited twice: per-IP (global RPM from config) and per-account (hard-coded 10 RPM) to defend against distributed brute force from multiple IPs.

### Redirect URI policy

Redirect URIs are validated at both registration time (`POST /auth/apps`) and use time (`GET /auth/oauth/{provider}?redirect_uri=`). Rules:
- Must be `https://` in production.
- `http://localhost` and `http://127.0.0.1` are allowed for local development.
- Must exactly match a URI registered for the app — no prefix matching.

### EC key pair lifecycle

`EcKeyService` observes `StartupEvent` and either loads the existing key pair from the `ec_keys` table or generates a new one (on first boot). The private key never leaves the process. `kid` is a random UUID stored alongside the key and included in each JWT header and JWKS response. If the DB is wiped, a new key pair is generated — all existing tokens will become invalid.

## Configuration

| Config path | Env var | Purpose |
|---|---|---|
| `auth.jwt.expiry-seconds` | `AUTH_JWT_EXPIRY_SECONDS` | Token TTL (default 604800 = 7 days) |
| `auth.admin-key` | `AUTH_ADMIN_KEY` | Key for `/auth/apps` endpoints (optional — disables app mgmt if unset) |
| `auth.key-hmac-secret` | `AUTH_KEY_HMAC_SECRET` | HMAC-SHA256 secret for admin key hashing (min 32 chars, required in prod) |
| `auth.state-hmac-secret` | `AUTH_STATE_HMAC_SECRET` | HMAC secret for signing OAuth state params (prevents open redirect / CSRF; required in prod) |
| `auth.token-pepper` | `AUTH_TOKEN_PEPPER` | HMAC pepper for storing auth tokens and OAuth codes at rest (required in prod) |
| `auth.rate-limit.enabled` | `AUTH_RATE_LIMIT_ENABLED` | Toggle rate limiting (default true) |
| `auth.rate-limit.requests-per-minute` | `AUTH_RATE_LIMIT_RPM` | Per-IP limit (default 60) |
| `auth.oauth.google.client-id` | `GOOGLE_CLIENT_ID` | Google OAuth |
| `auth.oauth.google.client-secret` | `GOOGLE_CLIENT_SECRET` | Google OAuth |
| `auth.oauth.github.client-id` | `GITHUB_CLIENT_ID` | GitHub OAuth |
| `auth.oauth.github.client-secret` | `GITHUB_CLIENT_SECRET` | GitHub OAuth |
| `auth.base-url` | `AUTH_BASE_URL` | Public base URL — used to build OAuth callback URLs |
| `quarkus.datasource.jdbc.url` | `QUARKUS_DATASOURCE_JDBC_URL` | DB connection string (prod: PostgreSQL JDBC URL) |
| `quarkus.datasource.username` | `QUARKUS_DATASOURCE_USERNAME` | DB username (prod only) |
| `quarkus.datasource.password` | `QUARKUS_DATASOURCE_PASSWORD` | DB password (prod only) |

**Dev profile:** SQLite at `./authservice-dev.db`. **Test profile:** In-memory SQLite, rate limiting disabled. **Prod profile:** SQLite by default — mount a persistent volume for the `.db` file. `StartupGuard` throws on boot if any of the three HMAC secrets (`AUTH_KEY_HMAC_SECRET`, `AUTH_STATE_HMAC_SECRET`, `AUTH_TOKEN_PEPPER`) are at their default dev values. PostgreSQL is supported but optional.

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

**Exception handling:**
- Throw standard JAX-RS exceptions (`NotAuthorizedException`, `ForbiddenException`, `NotFoundException`, `BadRequestException`) from services — `NormalizedExceptionMappers` catches them and returns `{"error": "...", "message": "...", "status": N}`.
- Never return raw error strings from resources.

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
- `iat` / `exp` — issued-at and expiry timestamps.

Tokens are signed with ES256 (ECDSA P-256). Verify using the public key from `GET /.well-known/jwks.json`.

**Consuming services should validate:** `iss` equals their known auth-service URL, `aud` equals their app ID, `exp` is in the future, and `kid` matches a known key in the JWKS.

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
