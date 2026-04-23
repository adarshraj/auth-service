-- Single-use tokens for password reset, magic link, email verification.
-- Ported from finance-tracker's AuthToken Prisma model.
CREATE TABLE auth_tokens (
    id         TEXT    NOT NULL PRIMARY KEY,
    user_id    TEXT    NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token      TEXT    NOT NULL UNIQUE,
    type       TEXT    NOT NULL,  -- 'password_reset' | 'magic_link' | 'email_verification'
    expires_at TEXT    NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);

CREATE INDEX idx_auth_tokens_token ON auth_tokens(token);
CREATE INDEX idx_auth_tokens_user  ON auth_tokens(user_id);
