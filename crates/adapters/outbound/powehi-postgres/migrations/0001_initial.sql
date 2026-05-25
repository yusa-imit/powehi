-- Users: handle stored only as SHA-256 hash — server never sees plaintext handle
CREATE TABLE IF NOT EXISTS users (
    id          UUID        PRIMARY KEY,
    handle_hash BYTEA       NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL
);

-- Devices: MLS credential bytes are opaque to the server
CREATE TABLE IF NOT EXISTS devices (
    id             UUID        PRIMARY KEY,
    user_id        UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    mls_credential BYTEA       NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS devices_user_id_idx ON devices(user_id);

-- Groups: epoch tracking; home_region for cross-region routing
CREATE TABLE IF NOT EXISTS groups (
    id          UUID        PRIMARY KEY,
    home_region TEXT        NOT NULL,
    epoch       BIGINT      NOT NULL DEFAULT 0,
    created_at  TIMESTAMPTZ NOT NULL
);

-- Group membership
CREATE TABLE IF NOT EXISTS group_members (
    group_id         UUID   NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id        UUID   NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    joined_at_epoch  BIGINT NOT NULL,
    PRIMARY KEY (group_id, device_id)
);

-- Envelopes: opaque E2EE delivery — server MUST NOT decrypt ciphertext.
-- No FK on group/sender/recipient: Welcome messages may precede group creation.
CREATE TABLE IF NOT EXISTS envelopes (
    id                  UUID        PRIMARY KEY,
    group_id            UUID        NOT NULL,
    sender_device_id    UUID        NOT NULL,
    recipient_device_id UUID,
    message_type        TEXT        NOT NULL,
    ciphertext          BYTEA       NOT NULL,
    epoch               BIGINT,
    created_at          TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS envelopes_recipient_created_idx
    ON envelopes(recipient_device_id, created_at);
CREATE INDEX IF NOT EXISTS envelopes_expires_idx
    ON envelopes(expires_at) WHERE expires_at IS NOT NULL;

-- KeyPackages: consumed exactly once via atomic SELECT FOR UPDATE
CREATE TABLE IF NOT EXISTS key_packages (
    id          UUID        PRIMARY KEY,
    device_id   UUID        NOT NULL,
    data        BYTEA       NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN     NOT NULL DEFAULT FALSE
);
CREATE INDEX IF NOT EXISTS key_packages_device_unconsumed_idx
    ON key_packages(device_id) WHERE NOT consumed;
