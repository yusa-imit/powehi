use async_trait::async_trait;
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
    /// All blobs still present in storage (GC scan input).
    async fn list_undeleted(&self) -> Result<Vec<MediaBlob>, DomainError>;
}
