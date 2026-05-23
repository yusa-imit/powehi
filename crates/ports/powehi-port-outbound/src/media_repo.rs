use async_trait::async_trait;
use powehi_domain::{error::DomainError, media::{MediaBlob, MediaId}};

#[async_trait]
pub trait MediaRepository: Send + Sync {
    async fn save(&self, blob: &MediaBlob) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: &MediaId) -> Result<Option<MediaBlob>, DomainError>;
    async fn delete(&self, id: &MediaId) -> Result<(), DomainError>;
    async fn presigned_upload_url(&self, id: &MediaId, content_type: &str) -> Result<String, DomainError>;
    async fn presigned_download_url(&self, id: &MediaId) -> Result<String, DomainError>;
}
