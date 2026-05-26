use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError, media::MediaId};

#[async_trait]
pub trait MediaUseCase: Send + Sync {
    /// Returns a pre-signed upload URL and the media ID.
    async fn request_upload(
        &self,
        uploader_device: &DeviceId,
        content_type: &str,
        size_bytes: u64,
    ) -> Result<(MediaId, String), DomainError>;

    async fn confirm_upload(&self, media_id: &MediaId) -> Result<(), DomainError>;

    /// Phase 3: requestor must be the uploader device.
    /// Phase 4 TODO: expand to group-member ACL check.
    async fn get_download_url(
        &self,
        media_id: &MediaId,
        requestor_device: &DeviceId,
    ) -> Result<String, DomainError>;

    async fn delete(
        &self,
        media_id: &MediaId,
        requestor_device: &DeviceId,
    ) -> Result<(), DomainError>;
}
