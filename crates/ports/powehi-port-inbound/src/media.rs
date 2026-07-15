use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError, group::GroupId, media::MediaId};

#[async_trait]
pub trait MediaUseCase: Send + Sync {
    /// Returns a pre-signed upload URL and the media ID.
    /// `group_id` — when set, group members may download the blob in addition to the uploader.
    async fn request_upload(
        &self,
        uploader_device: &DeviceId,
        content_type: &str,
        size_bytes: u64,
        group_id: Option<&GroupId>,
    ) -> Result<(MediaId, String), DomainError>;

    async fn confirm_upload(
        &self,
        media_id: &MediaId,
        confirmer_device: &DeviceId,
    ) -> Result<(), DomainError>;

    /// Uploader device always has access. When the blob was shared to an MLS group
    /// (`group_id` is set on the MediaBlob), any group member may also download.
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

    /// Delete blobs whose retention grace period has elapsed AND every
    /// required recipient (group members other than the uploader) has
    /// acknowledged a download. Returns the number of blobs deleted.
    async fn run_gc(&self) -> Result<usize, DomainError>;
}
