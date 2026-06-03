-- Server-side opaque configuration blobs that must survive restarts.
-- Currently used for the handle-oracle anti-enumeration HMAC key (YELLOW-2).
-- Rows are operator-transparent: the key is a static ASCII label; value_bytes
-- is an opaque blob (never content, PII, or ciphertext).
CREATE TABLE server_config (
    key        TEXT        PRIMARY KEY,
    value_bytes BYTEA      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
