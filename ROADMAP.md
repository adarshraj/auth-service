# Roadmap — gaps to industry-standard

auth-service today is a solid personal-scale auth server: shared user pool, ES256 JWTs via JWKS, OAuth (Google/GitHub), optional TOTP MFA, SSO cookie, per-app access gates. What follows is an honest list of what would need to change for it to stand in for Auth0 / Okta / Keycloak / Ory. **None of this is urgent for the current use case** — it's a parking lot for "one day."

---

## 1. Protocol / standards compliance (biggest gap)

We invented a custom flow instead of implementing established specs. Every item below means clients can't reuse off-the-shelf libraries.

- [ ] **OIDC** — publish `/.well-known/openid-configuration`, issue `id_token`, expose `/userinfo`, support standard scopes (`openid profile email`).
- [ ] **PKCE** (RFC 7636) — required for public clients (mobile, SPA).
- [ ] **Authorization-code grant** per OAuth2 spec (the current `/auth/token` exchange is close but not wire-compatible).
- [ ] **Refresh tokens** with rotation + reuse detection. Pairs with shorter access-token TTL.
- [ ] **Token introspection** (RFC 7662) — `/oauth2/introspect`.
- [ ] **Token revocation** (RFC 7009) — `/oauth2/revoke`.
- [ ] **Dynamic client registration** (RFC 7591).
- [ ] **SAML 2.0** — enterprise SSO table stakes.
- [ ] Consider replacing custom state/MFA/session tokens with standard signed JWTs/JWEs.

## 2. Missing features

### Identity & credentials
- [ ] **Email flows** — verification, password reset, magic link. DB infrastructure exists (`auth_tokens`, types reserved); no endpoints, no SMTP/Postmark/Resend integration.
- [ ] **Passkeys / WebAuthn** — modern MFA expectation, increasingly primary over passwords.
- [ ] **Account lockout** after N failed attempts (currently rate-limit only).
- [ ] **More federated providers** — Microsoft, Apple, Facebook, LinkedIn, generic OIDC/SAML IdP.
- [ ] **Consent screens** — "App X wants access to your profile" before granting.

### Session & key management
- [ ] **JWT signing key rotation.** Currently a single EC keypair forever. JWKS supports `kid`-based rotation — issue new key, keep old in JWKS until old tokens drain.
- [ ] **Server-side access-token revocation** — today only the SSO session is revocable; JWTs live until `exp`.
- [ ] **Device / session management UI** — user sees "logged in on N devices," can revoke individually.
- [ ] **"Log out everywhere"** — delete all `auth_sessions` rows for a user.

### Multi-tenancy & authorization
- [ ] **Tenants / organizations** — currently a flat user pool. Tenant-scoped users, apps, and roles.
- [ ] **Groups / teams** as role-bearing primitives (roles via team membership).
- [ ] **SCIM** (RFC 7644) — enterprise user provisioning API.

### Admin & end-user
- [ ] **Admin UI** — all management is curl today.
- [ ] **End-user account portal** — profile, sessions, MFA, connected providers, download data.
- [ ] **Anomaly / risk signals** — impossible travel, new-device email, suspicious-IP step-up.

## 3. Operational / scale

- [ ] **Shared state store** — `RateLimiter`, `OAuthNonceStore`, `MfaNonceStore` are all in-memory `ConcurrentHashMap`. Replace with Redis (or equivalent) to unblock horizontal scaling. Without this, a multi-instance deployment sees random 401s (nonce misses) and per-instance rate limits.
- [ ] **HA datastore** — SQLite default; prod-grade needs PostgreSQL with replicas, backups, DR runbook.
- [ ] **Deployment artifacts** — Helm chart, Terraform module, production Docker Compose profile, blue/green guidance.
- [ ] **Observability packs** — dashboards (Grafana), SLOs, alert rules, runbooks. OTel is wired but nothing ships on top.
- [ ] **Audit log sink** — stdout only today. Compliance wants queryable, retained, tamper-evident storage.
- [ ] **Load / soak tests** — no performance baseline exists.

## 4. Compliance & assurance

- [ ] Documented threat model.
- [ ] Third-party penetration test report.
- [ ] Vulnerability disclosure policy / security.txt.
- [ ] Bug bounty (if scope grows).
- [ ] SBOM, signed releases, reproducible builds.
- [ ] SOC 2 / ISO 27001 / HIPAA mode (only if the user base ever requires it).

---

## Suggested order if we ever start

Fastest path to "could replace Auth0 for a small SaaS":

1. **OIDC veneer** (`openid-configuration`, `id_token`, `/userinfo`, PKCE). Unlocks every OIDC client library instantly. ~1–2 weeks.
2. **Refresh tokens + rotation** with short access-token TTL. Closes the revocation gap for the common case.
3. **Email flows** (verify, reset, magic link) with pluggable provider.
4. **Redis-backed nonce + rate-limit stores** → horizontal scaling unblocked.
5. **JWT key rotation**.
6. **Passkeys (WebAuthn)**.
7. **Admin UI**.
8. **Tenants/orgs** primitive.

Roughly 6–12 months of focused work to match what the protocols and the market already defined. Until then: it's fine for what it is.
