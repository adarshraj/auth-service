-- Allowed redirect URIs per app, stored as a newline-separated list.
-- NULL means no redirect URIs are registered (OAuth will return JSON only).
ALTER TABLE apps ADD COLUMN redirect_uris TEXT;
