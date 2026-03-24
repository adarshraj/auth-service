# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Standalone authentication service for the personal app ecosystem. Kotlin + Quarkus, port **8703**. Single shared user pool with optional per-app access gates. Issues HS256 JWTs that ai-wrap and any other service can verify without calling back to auth-service.

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
export JWT_SECRET="your-shared-secret-min-32-chars"
export AUTH_ADMIN_KEY="your-admin-key"
# HMAC secret defaults to a dev value — fine for local, not for prod
```

SQLite is used by default — no database setup needed for development.

## Architecture

Layered under `src/main/kotlin/com/authservice/`:

- **`api/`** — JAX-RS resources (`AuthResource`, `AppResource`), DTOs, and exception mappers. Resources delegate all logic to services.
- **`service/`** — Business logic: `UserService` (registration, login, OAuth account linking, access management, auth tokens), `JwtService` (sign/verify HS256), `PasswordService` (bcrypt), `OAuthService` (Google + GitHub flows), `TokenCleanupJob` (scheduled purge).
- **`domain/`** — JPA entities and Panache repositories: `UserEntity`, `AppEntity`, `UserAppAccessEntity` (composite PK), `AuthTokenEntity`.
- **`security/`** — `JwtFilter` (protects `/auth/me` and `/auth/account`), `RateLimiter` (in-memory fixed-window), `ApiKeyHasher` (HMAC-SHA256 for admin key), `CallerContext` (request-scoped user identity), `StartupGuard` (validates required secrets on boot).
- **`config/`** — `RateLimitConfig` and `OAuthConfig` ConfigMapping interfaces.

### Key flows

**Login:** `AuthResource.login()` → `UserService.login()` (verify bcrypt, check app gate) → `JwtService.sign()` → `AuthResponse{token, user}`

**OAuth:** `GET /auth/oauth/{provider}` → 302 to provider → provider redirects to `GET /auth/oauth/callback` → `OAuthService.exchangeCode()` → `UserService.findOrCreateByOAuth()` → `AuthResponse`

**Per-app gate:** If `apps.requires_explicit_access = true`, login is blocked unless a `user_app_access` row exists. Auto-granted on first register/OAuth into that app.

**JWT verification in other services:** Any service with the same `JWT_SECRET` can call `JwtService.verify(token)` locally — no HTTP call needed. Token payload: `{sub, userId, email, appId, iat, exp}`.

### Database schema (Flyway migrations)

| Migration | Table | Purpose |
|-----------|-------|---------|
| V1 | `users` | Core user record — id, email, name, password_hash, avatar_url, oauth_provider, oauth_id, email_verified |
| V2 | `apps` | Registered apps — id (e.g. `finance-tracker`), name, requires_explicit_access |
| V3 | `user_app_access` | Per-user app grants — composite PK (user_id, app_id), role, granted_at |
| V4 | `auth_tokens` | One-time tokens — type (`password_reset`, `magic_link`, `email_verification`), expires_at, used |

### Admin key security

The `X-Admin-Key` header value is never stored raw. Comparison works by hashing both the provided value and the configured value with the same HMAC secret, then comparing the hashes via `MessageDigest.isEqual()` (constant-time). This prevents timing attacks on key comparison.

**Admin API is disabled** (returns 501) if `AUTH_ADMIN_KEY` is not set. Apps still work — only the `/auth/apps` management endpoints are gated.

## Configuration

| Config path | Env var | Purpose |
|---|---|---|
| `auth.jwt.secret` | `JWT_SECRET` | HS256 signing key — must match all services that verify tokens |
| `auth.jwt.expiry-seconds` | `AUTH_JWT_EXPIRY_SECONDS` | Token TTL (default 604800 = 7 days) |
| `auth.admin-key` | `AUTH_ADMIN_KEY` | Key for `/auth/apps` endpoints (optional — disables app mgmt if unset) |
| `auth.key-hmac-secret` | `AUTH_KEY_HMAC_SECRET` | HMAC-SHA256 secret for admin key hashing (min 32 chars, required in prod) |
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

**Dev profile:** SQLite at `./authservice-dev.db`. **Test profile:** In-memory SQLite, rate limiting disabled, hardcoded secrets. **Prod profile:** SQLite by default (works fine for personal use — just mount a persistent volume for the `.db` file). `StartupGuard` throws on boot if JWT_SECRET is blank, < 32 chars, or HMAC secret is the default dev value. PostgreSQL is supported but optional — set `QUARKUS_DATASOURCE_DB_KIND=postgresql` and related env vars at runtime if needed.

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

## JWT compatibility

`JwtService.sign()` sets both `sub = userId` and `userId = userId` in the payload. This is intentional:
- `sub` is the standard claim that ai-wrap (and any other JWT-aware service) uses to identify the caller.
- `userId` is the custom claim finance-tracker reads for backward compatibility.

Any service holding the same `JWT_SECRET` can verify these tokens without calling auth-service.
