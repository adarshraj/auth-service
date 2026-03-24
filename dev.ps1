# dev.ps1 — Start auth-service in dev mode (Windows PowerShell)
#
# Required:
#   JWT_SECRET          — HS256 signing key, min 32 chars.
#                         Must match the same value set in ai-wrap and any service
#                         that verifies tokens.
#
# Optional:
#   AUTH_ADMIN_KEY      — Key for /auth/apps admin endpoints. App management is
#                         disabled if not set (returns 501).
#   AUTH_BASE_URL       — Full public URL for OAuth callback URLs.
#                         Default: http://localhost:8703
#   GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET   — Enable Google OAuth
#   GITHUB_CLIENT_ID  / GITHUB_CLIENT_SECRET  — Enable GitHub OAuth

$ErrorActionPreference = "Stop"

# ── Required secrets ──────────────────────────────────────────────────────────

if (-not $env:JWT_SECRET) {
    Write-Error @"
ERROR: JWT_SECRET is not set.

Run in this shell before calling dev.ps1:
  `$env:JWT_SECRET = "your-shared-secret-min-32-characters"

Or set it permanently in System Properties > Environment Variables.
"@
    exit 1
}

if ($env:JWT_SECRET.Length -lt 32) {
    Write-Warning "JWT_SECRET is only $($env:JWT_SECRET.Length) chars — minimum 32 recommended."
}

# ── Optional: load from .env if present ───────────────────────────────────────

if (Test-Path ".env") {
    Write-Host "Loading .env"
    Get-Content ".env" | ForEach-Object {
        if ($_ -match "^\s*([^#=]+)=(.*)$") {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim().Trim('"').Trim("'")
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
}

# ── Start ─────────────────────────────────────────────────────────────────────

$adminKeyDisplay = if ($env:AUTH_ADMIN_KEY) { $env:AUTH_ADMIN_KEY } else { "(not set — admin API disabled)" }
$baseUrl = if ($env:AUTH_BASE_URL) { $env:AUTH_BASE_URL } else { "http://localhost:8703" }

Write-Host "Starting auth-service on http://localhost:8703 ..."
Write-Host "  JWT_SECRET       = $($env:JWT_SECRET.Substring(0, [Math]::Min(8, $env:JWT_SECRET.Length)))... ($($env:JWT_SECRET.Length) chars)"
Write-Host "  AUTH_ADMIN_KEY   = $adminKeyDisplay"
Write-Host "  AUTH_BASE_URL    = $baseUrl"

Set-Location auth-service
.\mvnw.cmd quarkus:dev
