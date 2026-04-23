-- Apps that consume the auth service. Registered by admin via POST /auth/apps.
CREATE TABLE apps (
    id                       TEXT    NOT NULL PRIMARY KEY,  -- app identifier, e.g. 'finance-tracker'
    name                     TEXT    NOT NULL,
    -- If true, a user must be explicitly granted access before they can log in to this app.
    -- If false, any registered user can log in (good for personal/open apps).
    requires_explicit_access INTEGER NOT NULL DEFAULT 0,
    created_at               TEXT    NOT NULL
);
