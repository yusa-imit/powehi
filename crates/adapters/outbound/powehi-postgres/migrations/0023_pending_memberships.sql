-- pending_memberships: server-side consent for group membership (8.11, prd §3.3/§6.3).
--
-- WHAT IT IS: (group_id, device_id, joined_at_epoch, created_at). Pure routing
-- metadata, no key material and no ciphertext. A member's `add_member` call
-- records a *pending* row here instead of a `group_members` row. Because every
-- fan-out / ACL / poll query reads `group_members` only, a pending device
-- receives nothing of the group (only its unicast Welcome, which is addressed
-- by recipient_device_id) until it calls accept; the exclusion is structural.
--
-- Both FKs cascade: a deleted group or device leaves no orphan row.
CREATE TABLE IF NOT EXISTS pending_memberships (
    group_id         UUID        NOT NULL REFERENCES groups(id)  ON DELETE CASCADE,
    device_id        UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    joined_at_epoch  BIGINT      NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, device_id)
);
CREATE INDEX IF NOT EXISTS pending_memberships_device_idx
    ON pending_memberships(device_id);
