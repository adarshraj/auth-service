-- Server-side SSO sessions. Identified by an opaque cookie `auth_session` set on the
-- auth-service domain. Enables "log into one app → the others auto-authenticate via
-- GET /auth/sso" without re-entering credentials.
-- The session id in the cookie is stored as HMAC(value, token-pepper) in this table —
-- a DB dump cannot be used to forge a cookie.
CREATE TABLE auth_sessions (
    id          TEXT NOT NULL PRIMARY KEY,
    user_id     TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_at  TEXT NOT NULL
);

CREATE INDEX idx_auth_sessions_user_id ON auth_sessions(user_id);
CREATE INDEX idx_auth_sessions_expires_at ON auth_sessions(expires_at);
