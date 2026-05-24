use std::sync::Arc;

use async_trait::async_trait;
use powehi_domain::{
    error::DomainError,
    media::{MediaBlob, MediaId},
    user::UserId,
};
use powehi_port_inbound::media::MediaUseCase;
use powehi_port_outbound::media_repo::MediaRepository;
use tracing::instrument;

pub struct MediaService {
    media_repo: Arc<dyn MediaRepository>,
}

impl MediaService {
    pub fn new(media_repo: Arc<dyn MediaRepository>) -> Self {
        Self { media_repo }
    }
}

#[async_trait]
impl MediaUseCase for MediaService {
    #[instrument(skip(self), fields(uploader = %uploader, content_type, size_bytes))]
    async fn request_upload(
        &self,
        uploader: &UserId,
        content_type: &str,
        size_bytes: u64,
    ) -> Result<(MediaId, String), DomainError> {
        let blob = MediaBlob {
            id: MediaId::new(),
            uploader: uploader.clone(),
            storage_key: format!("media/{}", uuid::Uuid::new_v4()),
            content_type: content_type.to_string(),
            size_bytes,
            uploaded_at: chrono::Utc::now(),
            expires_at: None,
        };
        let id = blob.id.clone();
        self.media_repo.save(&blob).await?;
        let url = self
            .media_repo
            .presigned_upload_url(&id, content_type)
            .await?;
        Ok((id, url))
    }

    #[instrument(skip(self), fields(media_id = %media_id))]
    async fn confirm_upload(&self, media_id: &MediaId) -> Result<(), DomainError> {
        self.media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;
        Ok(())
    }

    #[instrument(skip(self), fields(media_id = %media_id))]
    async fn get_download_url(&self, media_id: &MediaId) -> Result<String, DomainError> {
        self.media_repo.presigned_download_url(media_id).await
    }

    #[instrument(skip(self), fields(media_id = %media_id, requestor = %requestor))]
    async fn delete(&self, media_id: &MediaId, requestor: &UserId) -> Result<(), DomainError> {
        let blob = self
            .media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;
        if &blob.uploader != requestor {
            return Err(DomainError::Unauthorized);
        }
        self.media_repo.delete(media_id).await
    }
}
