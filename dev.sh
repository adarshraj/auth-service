#!/usr/bin/env bash
# dev.sh — Start auth-service in dev mode (Linux / macOS)
#
# Required:
#   JWT_SECRET          — HS256 signing key, min 32 chars.
#                         Must match the same value set in ai-wrap and any service
#                         that verifies tokens.
#
# Optional:
#   AUTH_ADMIN_KEY      — Key for /auth/apps admin endpoints. App management is
#                         disabled if not set (returns 501).
#   AUTH_BASE_URL       — Full public URL, used to build OAuth callback URLs.
#                         Default: http://localhost:8703
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   — Enable Google OAuth
#   GITHUB_CLIENT_ID  / GITHUB_CLIENT_SECRET  — Enable GitHub OAuth
#   AUTH_DB_FILE        — SQLite file path. Default: ./authservice-dev.db
#   AUTH_JWT_EXPIRY_SECONDS  — Token TTL in seconds. Default: 604800 (7 days)

set -euo pipefail

# ── Required secrets ──────────────────────────────────────────────────────────

if [[ -z "${JWT_SECRET:-}" ]]; then
  echo "ERROR: JWT_SECRET is not set."
  echo "  export JWT_SECRET=\"your-shared-secret-min-32-characters\""
  exit 1
fi

if [[ ${#JWT_SECRET} -lt 32 ]]; then
  echo "WARNING: JWT_SECRET is only ${#JWT_SECRET} chars — minimum 32 recommended."
fi

# ── Optional: load from .env if present ───────────────────────────────────────

if [[ -f ".env" ]]; then
  echo "Loading .env"
  # shellcheck disable=SC1091
  set -a; source .env; set +a
fi

# ── Start ─────────────────────────────────────────────────────────────────────

echo "Starting auth-service on http://localhost:8703 ..."
echo "  JWT_SECRET       = ${JWT_SECRET:0:8}... (${#JWT_SECRET} chars)"
echo "  AUTH_ADMIN_KEY   = ${AUTH_ADMIN_KEY:-(not set — admin API disabled)}"
echo "  AUTH_BASE_URL    = ${AUTH_BASE_URL:-http://localhost:8703}"

cd auth-service
./mvnw quarkus:dev
