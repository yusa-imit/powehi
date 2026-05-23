use async_trait::async_trait;
use powehi_domain::{error::DomainError, media::MediaId, user::UserId};

#[async_trait]
pub trait MediaUseCase: Send + Sync {
    /// Returns a pre-signed upload URL and the media ID.
    async fn request_upload(
        &self,
        uploader: &UserId,
        content_type: &str,
        size_bytes: u64,
    ) -> Result<(MediaId, String), DomainError>;

    async fn confirm_upload(
        &self,
        media_id: &MediaId,
    ) -> Result<(), DomainError>;

    async fn get_download_url(
        &self,
        media_id: &MediaId,
    ) -> Result<String, DomainError>;

    async fn delete(
        &self,
        media_id: &MediaId,
        requestor: &UserId,
    ) -> Result<(), DomainError>;
}
