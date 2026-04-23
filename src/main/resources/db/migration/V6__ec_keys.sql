-- Persisted EC P-256 key pair for ES256 JWT signing.
-- Only ever contains one row (id = 'primary').
CREATE TABLE ec_keys (
    id              TEXT NOT NULL PRIMARY KEY,
    kid             TEXT NOT NULL,
    private_key_pkcs8 TEXT NOT NULL,
    public_key_x509   TEXT NOT NULL,
    created_at      TEXT NOT NULL
);
