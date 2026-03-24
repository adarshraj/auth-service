# auth-service

Standalone authentication service for the personal app ecosystem. Runs on port **8703**.

## What it does

- Single shared user pool — one account works across all your apps
- Per-app access gates — apps can require explicit user grants before login is allowed
- Password login (bcrypt-compatible with finance-tracker hashes)
- Google and GitHub OAuth
- JWT HS256 tokens — same `JWT_SECRET` shared with ai-wrap, so tokens verified anywhere without network calls

## API

### Auth endpoints (public)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Register (email + password); `X-App-Id` header optional |
| `POST` | `/auth/login` | Login → JWT; `X-App-Id` header optional |
| `POST` | `/auth/logout` | Stateless — client drops the token |
| `GET`  | `/auth/me` | Current user (requires `Authorization: Bearer <token>`) |
| `DELETE` | `/auth/account` | Delete own account (requires JWT) |
| `GET`  | `/auth/oauth/{provider}` | Redirect to Google or GitHub (`X-App-Id` optional) |
| `GET`  | `/auth/oauth/callback` | OAuth callback → JWT |

### App management (admin — requires `X-Admin-Key`)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/apps` | Register an app |
| `GET`  | `/auth/apps` | List apps |
| `DELETE` | `/auth/apps/{id}` | Delete an app |
| `GET`  | `/auth/apps/{appId}/access` | List users with explicit access |
| `POST` | `/auth/apps/{appId}/access/{userId}` | Grant access |
| `DELETE` | `/auth/apps/{appId}/access/{userId}` | Revoke access |

## Running locally

```bash
cd auth-service
export JWT_SECRET="your-shared-secret-min-32-chars"
export AUTH_ADMIN_KEY="your-admin-key"
./mvnw quarkus:dev
# Starts on http://localhost:8703
```

SQLite is used by default — no database setup needed.

## Per-app access control

Apps registered with `requiresExplicitAccess: false` (default) let any registered user log in.
Apps registered with `requiresExplicitAccess: true` block login unless the user has been granted access via `POST /auth/apps/{appId}/access/{userId}`.

On first register/OAuth-login into an `requiresExplicitAccess: true` app, access is auto-granted for convenience. Use the admin API to revoke it.

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `JWT_SECRET` | Yes | HS256 signing key (share with ai-wrap and any service that verifies tokens) |
| `AUTH_ADMIN_KEY` | Yes (for app mgmt) | Key for `/auth/apps` endpoints |
| `AUTH_KEY_HMAC_SECRET` | Prod | HMAC secret for hashing the admin key; min 32 chars |
| `AUTH_BASE_URL` | For OAuth | Base URL for OAuth callback redirect (e.g. `https://auth.example.com`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | For Google OAuth | |
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | For GitHub OAuth | |
| `QUARKUS_DATASOURCE_JDBC_URL` | Prod | PostgreSQL JDBC URL |
| `QUARKUS_DATASOURCE_USERNAME` | Prod | DB username |
| `QUARKUS_DATASOURCE_PASSWORD` | Prod | DB password |

## Migrating finance-tracker users

finance-tracker uses bcrypt with cost factor 10 — same as this service. Export the `users` table and import directly; no re-hashing needed.
