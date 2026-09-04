-- 010_api_tokens.sql — REST API bearer tokens.
--
-- Tokens let scripts / SIEM tooling authenticate against the KSEC API as
-- a platform user. Only the SHA-256 of the token is stored; the plaintext
-- token is shown once at creation. Tokens can be revoked individually.

CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT '',
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);