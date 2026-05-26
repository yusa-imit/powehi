use std::sync::Arc;

fn size_bucket(bytes: u64) -> &'static str {
    match bytes {
        0..=1_024 => "<=1KB",
        1_025..=10_240 => "<=10KB",
        10_241..=102_400 => "<=100KB",
        102_401..=1_048_576 => "<=1MB",
        1_048_577..=10_485_760 => "<=10MB",
        _ => ">10MB",
    }
}

use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    media::{MediaBlob, MediaId},
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
    #[instrument(skip(self), fields(uploader_device = %uploader_device, size_bucket = size_bucket(size_bytes)))]
    async fn request_upload(
        &self,
        uploader_device: &DeviceId,
        content_type: &str,
        size_bytes: u64,
    ) -> Result<(MediaId, String), DomainError> {
        let blob = MediaBlob {
            id: MediaId::new(),
            uploader_device: uploader_device.clone(),
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
    async fn get_download_url(
        &self,
        media_id: &MediaId,
        requestor_device: &DeviceId,
    ) -> Result<String, DomainError> {
        let blob = self
            .media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;
        if &blob.uploader_device != requestor_device {
            return Err(DomainError::Unauthorized);
        }
        self.media_repo.presigned_download_url(media_id).await
    }

    #[instrument(skip(self), fields(media_id = %media_id, requestor_device = %requestor_device))]
    async fn delete(
        &self,
        media_id: &MediaId,
        requestor_device: &DeviceId,
    ) -> Result<(), DomainError> {
        let blob = self
            .media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;
        if &blob.uploader_device != requestor_device {
            return Err(DomainError::Unauthorized);
        }
        self.media_repo.delete(media_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use powehi_domain::media::MediaBlob;
    use std::sync::{Arc, Mutex};

    struct MockMediaRepo {
        saved: Mutex<Vec<MediaBlob>>,
        upload_url: String,
        download_url: String,
    }

    impl MockMediaRepo {
        fn new(upload_url: &str, download_url: &str) -> Self {
            Self {
                saved: Mutex::new(vec![]),
                upload_url: upload_url.into(),
                download_url: download_url.into(),
            }
        }
    }

    #[async_trait]
    impl MediaRepository for MockMediaRepo {
        async fn save(&self, blob: &MediaBlob) -> Result<(), DomainError> {
            self.saved.lock().unwrap().push(blob.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &MediaId) -> Result<Option<MediaBlob>, DomainError> {
            let locked = self.saved.lock().unwrap();
            Ok(locked.iter().find(|b| &b.id == id).cloned())
        }
        async fn delete(&self, id: &MediaId) -> Result<(), DomainError> {
            let mut locked = self.saved.lock().unwrap();
            locked.retain(|b| &b.id != id);
            Ok(())
        }
        async fn presigned_upload_url(
            &self,
            _id: &MediaId,
            _ct: &str,
        ) -> Result<String, DomainError> {
            Ok(self.upload_url.clone())
        }
        async fn presigned_download_url(&self, _id: &MediaId) -> Result<String, DomainError> {
            Ok(self.download_url.clone())
        }
    }

    #[tokio::test]
    async fn request_upload_saves_blob_and_returns_url() {
        let repo = Arc::new(MockMediaRepo::new("https://r2.example/upload", "unused"));
        let svc = MediaService::new(repo.clone());
        let device = DeviceId::new();
        let (id, url) = svc
            .request_upload(&device, "image/jpeg", 1024)
            .await
            .unwrap();
        assert_eq!(url, "https://r2.example/upload");
        let saved = repo.saved.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, id);
        assert_eq!(saved[0].uploader_device, device);
    }

    #[tokio::test]
    async fn confirm_upload_ok_when_blob_exists() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let svc = MediaService::new(repo.clone());
        let device = DeviceId::new();
        let (id, _) = svc.request_upload(&device, "image/png", 512).await.unwrap();
        svc.confirm_upload(&id).await.unwrap();
    }

    #[tokio::test]
    async fn confirm_upload_not_found_when_blob_missing() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let svc = MediaService::new(repo);
        let err = svc.confirm_upload(&MediaId::new()).await.unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn get_download_url_returns_url_for_uploader() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let svc = MediaService::new(repo.clone());
        let device = DeviceId::new();
        let (id, _) = svc
            .request_upload(&device, "video/mp4", 2048)
            .await
            .unwrap();
        let url = svc.get_download_url(&id, &device).await.unwrap();
        assert_eq!(url, "https://r2.example/download");
    }

    #[tokio::test]
    async fn get_download_url_by_different_device_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let svc = MediaService::new(repo.clone());
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let (id, _) = svc
            .request_upload(&uploader, "video/mp4", 2048)
            .await
            .unwrap();
        let err = svc.get_download_url(&id, &other).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn delete_by_uploader_succeeds() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let svc = MediaService::new(repo.clone());
        let device = DeviceId::new();
        let (id, _) = svc
            .request_upload(&device, "image/webp", 256)
            .await
            .unwrap();
        svc.delete(&id, &device).await.unwrap();
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_by_different_device_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let svc = MediaService::new(repo.clone());
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let (id, _) = svc
            .request_upload(&uploader, "audio/mpeg", 128)
            .await
            .unwrap();
        let err = svc.delete(&id, &other).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }
}
