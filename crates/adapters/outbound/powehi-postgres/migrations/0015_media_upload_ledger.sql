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
-- GC (closed cycle 363): a daily background sweep in bin/powehi-server/src/
-- main.rs calls `MediaRepository::trim_upload_ledger_older_than(now - 30
-- days)`, deleting rows well past the 24h quota window any live check could
-- still be reading — a large safety margin, same 30-day constant as media
-- blob GC (prd.md §11.4). Rows are still never touched by anything else
-- (no delete on confirm/blob-delete), so the quota's monotonic-within-window
-- guarantee is unaffected.
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
