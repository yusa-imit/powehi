-- Append-only ledger of accepted media upload requests, backing the
-- per-device/per-day byte quota (`MediaService::request_upload`). Closes
-- the "delete resets usage" residual gap flagged by security-auditor in
-- cycle 361's `0014_media_blobs_device_uploaded_idx.sql`: the quota
-- previously summed live `media_blobs.size_bytes`, so `upload -> confirm ->
-- delete` in a loop let a device churn unbounded write ops/day within the
-- 24h window while never tripping the cap. Rows here are inserted once per
-- accepted `request_upload` call and are NEVER deleted or updated by any
-- code path (no FK to `media_blobs`, no CASCADE, no delete statement
-- anywhere in the codebase references this table) — deleting the
-- corresponding blob (`R2MediaAdapter::delete`) does not touch this table,
-- so a device's daily quota usage is now monotonic within the rolling
-- window regardless of how many uploads it also deletes.
--
-- `id` reuses the originating `media_blobs.id` 1:1 (one upload request, one
-- ledger row) purely so the existing `ON CONFLICT (id) DO NOTHING` insert
-- pattern makes the ledger write idempotent under retry, matching
-- `media_blobs`'s own insert. It is intentionally NOT a foreign key to
-- `media_blobs(id)`, since the ledger must outlive the blob being deleted.
--
-- KNOWN NON-BLOCKING GAP (security-auditor, cycle 362): unlike
-- `media_blobs`, this table has no GC/TTL sweep, so it grows unboundedly
-- forever — one small fixed-width row per accepted upload, across all
-- devices, indefinitely. The rolling-24h quota query only reads recent rows
-- via the index below, so this does not affect quota correctness or query
-- performance, only slow permanent storage/index growth. Worth a future
-- periodic trim job (e.g. delete rows older than N days, well past the 24h
-- quota window) — out of scope this cycle.
CREATE TABLE IF NOT EXISTS media_upload_ledger (
    id          UUID NOT NULL PRIMARY KEY,
    device_id   UUID NOT NULL,
    size_bytes  BIGINT NOT NULL CHECK (size_bytes > 0),
    uploaded_at TIMESTAMPTZ NOT NULL
);

-- Regular (non-CONCURRENTLY) index: the table is brand new and empty at
-- migration time, so there is no existing-row lock contention to avoid
-- (unlike 0011/0014's CONCURRENTLY builds on the pre-existing, actively
-- written `envelopes`/`media_blobs` tables) — safe to run inside sqlx's
-- default migration transaction.
CREATE INDEX IF NOT EXISTS media_upload_ledger_device_uploaded_idx
    ON media_upload_ledger(device_id, uploaded_at);
