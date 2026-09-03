use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    media::{MediaBlob, MediaId},
};

#[async_trait]
pub trait MediaRepository: Send + Sync {
    async fn save(&self, blob: &MediaBlob) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: &MediaId) -> Result<Option<MediaBlob>, DomainError>;
    async fn delete(&self, id: &MediaId) -> Result<(), DomainError>;
    async fn presigned_upload_url(
        &self,
        id: &MediaId,
        content_type: &str,
    ) -> Result<String, DomainError>;
    async fn presigned_download_url(&self, id: &MediaId) -> Result<String, DomainError>;

    /// Record that `device_id` has confirmed a verified download of `media_id`
    /// (an opaque consumption signal — no content, no plaintext). Callers must
    /// only invoke this once the transfer is actually confirmed complete, not
    /// merely once a download URL was granted (see `MediaUseCase::confirm_download`).
    /// Idempotent.
    async fn record_ack(&self, media_id: &MediaId, device_id: &DeviceId)
        -> Result<(), DomainError>;
    /// Devices that have acknowledged `media_id` so far.
    async fn list_ack_device_ids(&self, media_id: &MediaId) -> Result<Vec<DeviceId>, DomainError>;

    /// GC-eligible blob candidates only: a blob is a candidate when its
    /// `expires_at` is set and at or before `now`, or (when `expires_at` is
    /// unset) its `uploaded_at` is at or before `default_retention_cutoff`
    /// (`now - retention`). Keyset-paginated by `id` for bounded memory per
    /// call: pass the last returned blob's `id` as `after_id` to fetch the next
    /// page. Returns rows ordered by `id`, at most `limit` of them; fewer than
    /// `limit` rows means the candidate set is exhausted.
    ///
    /// The eligibility filter is pushed into SQL so the hourly GC sweep never
    /// loads non-eligible rows into memory (security-auditor cycle 289: the old
    /// unfiltered full-table scan was an OOM/DoS risk as `media_blobs` grows).
    async fn list_gc_candidates(
        &self,
        now: DateTime<Utc>,
        default_retention_cutoff: DateTime<Utc>,
        after_id: Option<MediaId>,
        limit: i64,
    ) -> Result<Vec<MediaBlob>, DomainError>;

    /// Total `size_bytes` of `device_id`'s uploads with `uploaded_at >= since`.
    /// Backs the per-device/per-day upload byte quota in `MediaService`
    /// (security-auditor cycle 359 residual finding) — the same fail-closed
    /// pattern as `KeyPackageRepository::count_available`, summing bytes
    /// instead of counting rows. Sums an append-only record of accepted
    /// upload requests, NOT currently-live blobs — deleting an upload must
    /// not reduce a device's counted usage within the window (cycle 362
    /// fix), otherwise `upload -> confirm -> delete` in a loop lets
    /// write-op churn bypass the cap.
    async fn sum_bytes_uploaded_since(
        &self,
        device_id: &DeviceId,
        since: DateTime<Utc>,
    ) -> Result<u64, DomainError>;

    /// Delete `media_upload_ledger` rows with `uploaded_at < cutoff`. The
    /// ledger is deliberately append-only for quota correctness (see
    /// `sum_bytes_uploaded_since`'s doc comment — deleting a row here must
    /// never happen inside the rolling 24h quota window a live quota check
    /// could still read), so callers must pass a `cutoff` with a large
    /// safety margin past that window. Closes the unbounded-growth gap
    /// flagged by security-auditor in cycle 362 (`0015_media_upload_ledger.sql`).
    /// Returns the number of rows deleted.
    async fn trim_upload_ledger_older_than(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DomainError>;

    /// Delete objects in the media bucket that have no matching
    /// `media_blobs.storage_key` row AND were last modified strictly before
    /// `older_than`. Returns the number of objects deleted.
    ///
    /// Closes the orphaned-object gap deferred across cycles 419-421:
    /// `delete()` (and the hourly `run_gc` that calls it) deletes the S3
    /// object, then removes the Postgres row (corrected cycle 424 — an
    /// earlier version of this comment had the order backwards). A client's
    /// presigned PUT stays valid for `r2_presign_upload_ttl_secs` after it
    /// was issued, independent of `delete()`'s own timeline — if that upload
    /// lands after `delete()` has already run to completion for that id, the
    /// PUT recreates the S3 object with no matching row, and `delete()` can
    /// never reach it again because a second call starts from `find_by_id`
    /// (`None` short-circuits the S3 delete). Nothing else ever enumerates
    /// the bucket, so without this sweep those objects are
    /// billable forever.
    ///
    /// `older_than` is a grace cutoff, not a retention policy: an object
    /// newer than it MUST NOT be deleted, because "no row yet" is the normal
    /// transient state of a legitimate in-flight upload (a presigned PUT
    /// still inside its TTL, or a `save()` whose row insert has not committed
    /// yet). Callers must pass a cutoff with a wide margin past the upload
    /// presign TTL plus any plausible clock skew — see
    /// `media_orphan_sweep_grace_hours`.
    async fn sweep_orphaned_storage_objects(
        &self,
        older_than: DateTime<Utc>,
    ) -> Result<u64, DomainError>;
}
