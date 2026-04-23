-- Short-lived one-time codes issued after OAuth callback.
-- Client exchanges the code for a JWT via POST /auth/token within 60 seconds.
CREATE TABLE oauth_codes (
    id          TEXT NOT NULL PRIMARY KEY,
    code        TEXT NOT NULL UNIQUE,
    user_id     TEXT NOT NULL,
    email       TEXT NOT NULL,
    app_id      TEXT,
    expires_at  TEXT NOT NULL,
    used        BOOLEAN NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
