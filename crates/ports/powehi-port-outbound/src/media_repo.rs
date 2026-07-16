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

    /// Record that `device_id` has obtained a download URL for `media_id` (an
    /// opaque consumption signal — no content, no plaintext). Idempotent.
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
}
