-- Per-app access grants. Only relevant when apps.requires_explicit_access = 1.
CREATE TABLE user_app_access (
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    app_id     TEXT NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'user',  -- 'user' | 'admin' (app-level role, not service-level)
    granted_at TEXT NOT NULL,
    PRIMARY KEY (user_id, app_id)
);

CREATE INDEX idx_user_app_access_app ON user_app_access(app_id);
