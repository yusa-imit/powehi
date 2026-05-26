-- Media blob metadata: R2 object references + uploader audit.
-- Security invariant: only metadata stored here; actual ciphertext lives in R2.
-- The server generates pre-signed URLs so it never proxies ciphertext bytes.
-- Uploader tracked at device granularity (Phase 3: bearer token = DeviceId).
CREATE TABLE IF NOT EXISTS media_blobs (
    id                  UUID        PRIMARY KEY,
    uploader_device_id  UUID        NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    storage_key         TEXT        NOT NULL,
    content_type        TEXT        NOT NULL,
    size_bytes          BIGINT      NOT NULL,
    uploaded_at         TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS media_blobs_uploader_idx ON media_blobs(uploader_device_id);
CREATE INDEX IF NOT EXISTS media_blobs_expires_idx
    ON media_blobs(expires_at) WHERE expires_at IS NOT NULL;
