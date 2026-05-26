-- Add OPAQUE password file column to users.
-- The stored bytes are the serialized ServerRegistration<CS> (opaque-ke 3.x).
-- Server MUST NOT inspect or log these bytes (rule: no-plaintext-logging).
ALTER TABLE users ADD COLUMN IF NOT EXISTS opaque_password_file BYTEA NOT NULL DEFAULT '';

-- Enforce uniqueness of handle_hash to prevent concurrent duplicate registrations (Y-3).
CREATE UNIQUE INDEX IF NOT EXISTS users_handle_hash_unique ON users(handle_hash);
