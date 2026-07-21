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
    /// Does NOT record a download ack — see `confirm_download`. Granting a URL
    /// only proves a download was authorized, not that the transfer completed.
    async fn get_download_url(
        &self,
        media_id: &MediaId,
        requestor_device: &DeviceId,
    ) -> Result<String, DomainError>;

    /// Records that `confirmer_device` actually received and verified the blob
    /// (called after a successful decrypt, not merely after a URL was granted —
    /// closes the "ack-on-grant" gap: a URL-grant alone doesn't prove transfer
    /// completed, so `run_gc` must not treat it as such). Same access rule as
    /// `get_download_url` (uploader or group member); the uploader's own ack is
    /// a no-op since `run_gc` never requires it. Unauthorized for anyone else.
    async fn confirm_download(
        &self,
        media_id: &MediaId,
        confirmer_device: &DeviceId,
    ) -> Result<(), DomainError>;

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
