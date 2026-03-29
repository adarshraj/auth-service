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

## Production

All commands below run from the `auth-service/` directory (where `pom.xml` lives).

**Profile:** A packaged run uses Quarkus’s **`prod`** profile (not `quarkus:dev`). On startup, the service refuses to boot in prod unless `JWT_SECRET` is set and at least 32 characters, and unless `AUTH_KEY_HMAC_SECRET` is set to something other than the default dev value. Set `AUTH_ADMIN_KEY` if you need the `/auth/apps` admin API.

**Database:** SQLite is fine for small deployments — persist the file (for example set `AUTH_DB_FILE` to a path on a mounted volume). For PostgreSQL, set `QUARKUS_DATASOURCE_DB_KIND=postgresql`, the JDBC URL, username, password, and `QUARKUS_HIBERNATE_ORM_DIALECT=org.hibernate.dialect.PostgreSQLDialect` (see comments in `src/main/resources/application.yml`).

**OAuth:** Set `AUTH_BASE_URL` to your public origin (for example `https://auth.example.com`) and configure the Google/GitHub client env vars so callback URLs match your deployment.

### Run the JVM package (bare metal or VM)

```bash
cd auth-service
./mvnw package -DskipTests
export JWT_SECRET="your-shared-secret-at-least-32-chars"
export AUTH_KEY_HMAC_SECRET="your-hmac-secret-at-least-32-chars"
export AUTH_ADMIN_KEY="your-admin-key"   # optional; omit to disable app management API
# Optional: listen on all interfaces (Dockerfile JVM image sets this for containers)
# export QUARKUS_HTTP_HOST=0.0.0.0
java -jar target/quarkus-app/quarkus-run.jar
```

The HTTP server listens on port **8703** (see `application.yml`). Terminate TLS at a reverse proxy or load balancer in front of the app.

### Docker (JVM image)

Build the runnable layout, then build and run the stock Quarkus JVM image:

```bash
cd auth-service
./mvnw package -DskipTests
docker build -f src/main/docker/Dockerfile.jvm -t auth-service:latest .
docker run --rm -p 8703:8703 \
  -e JWT_SECRET="your-shared-secret-at-least-32-chars" \
  -e AUTH_KEY_HMAC_SECRET="your-hmac-secret-at-least-32-chars" \
  -e AUTH_ADMIN_KEY="your-admin-key" \
  -e AUTH_BASE_URL="https://auth.example.com" \
  auth-service:latest
```

The generated `Dockerfile.jvm` comments still refer to port 8080 from the Quarkus template; **this service uses 8703**, so map `8703:8703`. For a persistent SQLite file inside the container, mount a volume and set `AUTH_DB_FILE` (or point `QUARKUS_DATASOURCE_JDBC_URL` at your SQLite path).

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
