use std::sync::Arc;

const MAX_MEDIA_BYTES: u64 = 100 * 1024 * 1024;

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
    group::GroupId,
    media::{MediaBlob, MediaId},
};
use powehi_port_inbound::media::MediaUseCase;
use powehi_port_outbound::{group_repo::GroupRepository, media_repo::MediaRepository};
use tracing::instrument;

pub struct MediaService {
    media_repo: Arc<dyn MediaRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl MediaService {
    pub fn new(media_repo: Arc<dyn MediaRepository>, group_repo: Arc<dyn GroupRepository>) -> Self {
        Self {
            media_repo,
            group_repo,
        }
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
        group_id: Option<&GroupId>,
    ) -> Result<(MediaId, String), DomainError> {
        // Defense-in-depth: validate size even though the REST handler already
        // checks. Non-REST callers (gRPC, tests) must not bypass this cap.
        if size_bytes == 0 || size_bytes > MAX_MEDIA_BYTES {
            return Err(DomainError::InvalidInput("size_bytes out of range".into()));
        }
        // Membership check: when a group_id is supplied, verify the uploader is
        // an actual member of that group before associating the blob with it.
        // Fail-closed: if no membership data exists (empty list), reject the
        // upload rather than silently accepting an unverifiable group claim.
        if let Some(gid) = group_id {
            let members = self.group_repo.list_members(gid).await?;
            if members.is_empty() {
                tracing::warn!(group_id = %gid, "request_upload fail-closed: no membership data");
                return Err(DomainError::Unauthorized);
            }
            if !members.iter().any(|m| &m.device_id == uploader_device) {
                return Err(DomainError::Unauthorized);
            }
        }
        let blob = MediaBlob {
            id: MediaId::new(),
            uploader_device: uploader_device.clone(),
            storage_key: format!("media/{}", uuid::Uuid::new_v4()),
            content_type: content_type.to_string(),
            size_bytes,
            uploaded_at: chrono::Utc::now(),
            expires_at: None,
            group_id: group_id.cloned(),
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
    async fn confirm_upload(
        &self,
        media_id: &MediaId,
        confirmer_device: &DeviceId,
    ) -> Result<(), DomainError> {
        let blob = self
            .media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;
        if &blob.uploader_device != confirmer_device {
            return Err(DomainError::Unauthorized);
        }
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

        // Uploader always has access.
        if &blob.uploader_device == requestor_device {
            return self.media_repo.presigned_download_url(media_id).await;
        }

        // Group members have access when the blob was shared to an MLS group.
        if let Some(gid) = &blob.group_id {
            let members = self.group_repo.list_members(gid).await?;
            if members.iter().any(|m| &m.device_id == requestor_device) {
                return self.media_repo.presigned_download_url(media_id).await;
            }
        }

        Err(DomainError::Unauthorized)
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
    use powehi_domain::{
        group::{Epoch, Group, GroupId, GroupMember},
        media::MediaBlob,
    };
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

    struct FakeGroupRepo {
        members: Mutex<Vec<(GroupId, DeviceId)>>,
    }

    impl FakeGroupRepo {
        fn empty() -> Arc<Self> {
            Arc::new(Self {
                members: Mutex::new(vec![]),
            })
        }
        fn with_member(group_id: GroupId, device_id: DeviceId) -> Arc<Self> {
            Arc::new(Self {
                members: Mutex::new(vec![(group_id, device_id)]),
            })
        }
        fn with_members(pairs: Vec<(GroupId, DeviceId)>) -> Arc<Self> {
            Arc::new(Self {
                members: Mutex::new(pairs),
            })
        }
    }

    #[async_trait]
    impl GroupRepository for FakeGroupRepo {
        async fn save(&self, _group: &Group) -> Result<(), DomainError> {
            Ok(())
        }
        async fn find_by_id(&self, _id: &GroupId) -> Result<Option<Group>, DomainError> {
            Ok(None)
        }
        async fn add_member(&self, _member: &GroupMember) -> Result<(), DomainError> {
            Ok(())
        }
        async fn remove_member(
            &self,
            _group_id: &GroupId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
            let locked = self.members.lock().unwrap();
            Ok(locked
                .iter()
                .filter(|(gid, _)| gid == group_id)
                .map(|(gid, did)| GroupMember {
                    group_id: gid.clone(),
                    device_id: did.clone(),
                    joined_at_epoch: Epoch(0),
                })
                .collect())
        }
        async fn list_groups_for_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Vec<GroupId>, DomainError> {
            let locked = self.members.lock().unwrap();
            Ok(locked
                .iter()
                .filter(|(_, did)| did == device_id)
                .map(|(gid, _)| gid.clone())
                .collect())
        }
    }

    fn svc(repo: Arc<MockMediaRepo>) -> MediaService {
        MediaService::new(repo, FakeGroupRepo::empty())
    }

    #[tokio::test]
    async fn request_upload_size_zero_returns_invalid_input() {
        let s = svc(Arc::new(MockMediaRepo::new("u", "d")));
        let err = s
            .request_upload(&DeviceId::new(), "image/jpeg", 0, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn request_upload_size_too_large_returns_invalid_input() {
        let s = svc(Arc::new(MockMediaRepo::new("u", "d")));
        let err = s
            .request_upload(&DeviceId::new(), "image/jpeg", MAX_MEDIA_BYTES + 1, None)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn request_upload_saves_blob_and_returns_url() {
        let repo = Arc::new(MockMediaRepo::new("https://r2.example/upload", "unused"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let (id, url) = s
            .request_upload(&device, "image/jpeg", 1024, None)
            .await
            .unwrap();
        assert_eq!(url, "https://r2.example/upload");
        let saved = repo.saved.lock().unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved[0].id, id);
        assert_eq!(saved[0].uploader_device, device);
        assert!(saved[0].group_id.is_none());
    }

    #[tokio::test]
    async fn request_upload_stores_group_id() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let device = DeviceId::new();
        let group = GroupId::new();
        // Uploader must be a member for the group association to be accepted.
        let s = MediaService::new(
            repo.clone(),
            FakeGroupRepo::with_member(group.clone(), device.clone()),
        );
        let (id, _) = s
            .request_upload(&device, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        let saved = repo.saved.lock().unwrap();
        assert_eq!(saved[0].id, id);
        assert_eq!(saved[0].group_id, Some(group));
    }

    #[tokio::test]
    async fn confirm_upload_ok_when_blob_exists() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let (id, _) = s
            .request_upload(&device, "image/png", 512, None)
            .await
            .unwrap();
        s.confirm_upload(&id, &device).await.unwrap();
    }

    #[tokio::test]
    async fn confirm_upload_not_found_when_blob_missing() {
        let s = svc(Arc::new(MockMediaRepo::new("u", "d")));
        let err = s
            .confirm_upload(&MediaId::new(), &DeviceId::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn confirm_upload_by_different_device_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let (id, _) = s
            .request_upload(&uploader, "image/png", 512, None)
            .await
            .unwrap();
        let err = s.confirm_upload(&id, &other).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn get_download_url_returns_url_for_uploader() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let (id, _) = s
            .request_upload(&device, "video/mp4", 2048, None)
            .await
            .unwrap();
        let url = s.get_download_url(&id, &device).await.unwrap();
        assert_eq!(url, "https://r2.example/download");
    }

    #[tokio::test]
    async fn get_download_url_by_different_device_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let s = svc(repo.clone());
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let (id, _) = s
            .request_upload(&uploader, "video/mp4", 2048, None)
            .await
            .unwrap();
        let err = s.get_download_url(&id, &other).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn get_download_url_by_group_member_succeeds() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        // Both uploader and member are in the group; uploader needs membership to
        // associate the blob with the group, member exercises the download ACL.
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        let url = s.get_download_url(&id, &member).await.unwrap();
        assert_eq!(url, "https://r2.example/download");
    }

    #[tokio::test]
    async fn get_download_url_by_non_member_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let non_member = DeviceId::new();
        let group = GroupId::new();
        // Uploader is a member (so upload succeeds), but non_member is not.
        let group_repo = FakeGroupRepo::with_member(group.clone(), uploader.clone());
        let s = MediaService::new(repo.clone(), group_repo);
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        let err = s.get_download_url(&id, &non_member).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn delete_by_uploader_succeeds() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let (id, _) = s
            .request_upload(&device, "image/webp", 256, None)
            .await
            .unwrap();
        s.delete(&id, &device).await.unwrap();
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_by_different_device_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let (id, _) = s
            .request_upload(&uploader, "audio/mpeg", 128, None)
            .await
            .unwrap();
        let err = s.delete(&id, &other).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn request_upload_with_group_id_member_succeeds() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let group = GroupId::new();
        let s = MediaService::new(
            repo.clone(),
            FakeGroupRepo::with_member(group.clone(), uploader.clone()),
        );
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 1024, Some(&group))
            .await
            .unwrap();
        let saved = repo.saved.lock().unwrap();
        assert_eq!(saved[0].id, id);
        assert_eq!(saved[0].group_id, Some(group));
    }

    #[tokio::test]
    async fn request_upload_with_group_id_non_member_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let other = DeviceId::new();
        let group = GroupId::new();
        // `other` is a member but `uploader` is not.
        let s = MediaService::new(
            repo.clone(),
            FakeGroupRepo::with_member(group.clone(), other.clone()),
        );
        let err = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        // No blob should have been saved.
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn request_upload_with_group_id_empty_membership_fails_closed() {
        // No membership data → fail-closed, upload rejected.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let group = GroupId::new();
        let s = MediaService::new(repo.clone(), FakeGroupRepo::empty());
        let err = s
            .request_upload(&DeviceId::new(), "image/jpeg", 512, Some(&group))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        assert!(repo.saved.lock().unwrap().is_empty());
    }
}
