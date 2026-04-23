-- Refresh tokens for short-lived access token rotation.
-- Stored as HMAC(token, AUTH_TOKEN_PEPPER) — a DB dump cannot redeem tokens.
CREATE TABLE refresh_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT    NOT NULL UNIQUE,
    app_id     TEXT,
    expires_at TEXT    NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
CREATE INDEX idx_refresh_tokens_user  ON refresh_tokens(user_id);
