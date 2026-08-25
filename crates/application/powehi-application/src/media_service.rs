use std::sync::Arc;

const MAX_MEDIA_BYTES: u64 = 100 * 1024 * 1024;

/// Per-device rolling-24h upload byte cap, summed over currently-live blobs
/// only. Closes the residual gap from cycle 359's security-auditor sweep:
/// binding `size_bytes` into the R2 presign signature made a single upload's
/// declared size trustworthy, but nothing bounded how many uploads a device
/// could request per day — only the shared per-IP `api_governor` rate limit
/// applied (~4TB/day/IP sustained-worst-case). 5GB/day comfortably covers
/// heavy real usage (dozens of photos/videos) while bounding worst-case R2
/// storage cost per device to a fixed ceiling.
///
/// One accepted residual gap (security-auditor sweep, cycle 361), not
/// blocking since storage itself stays bounded:
/// - **race window**: the count-then-insert check (below) is a soft cap, not
///   atomic — N concurrent requests from one device can all read the same
///   `used` before any commits. Bounded by the per-IP governor's burst (60),
///   so worst case is a one-shot ~2x-cap overshoot per window, not unbounded
///   drift (same shape as `KeyPackageService::upload`'s existing soft cap).
///
/// The other cycle-361 residual gap — `upload -> confirm -> delete` in a
/// loop resetting counted usage — was closed in cycle 362:
/// `sum_bytes_uploaded_since` now sums an append-only upload ledger instead
/// of currently-live blobs, so a device's counted usage is monotonic within
/// the rolling window regardless of deletes.
const MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY: u64 = 5 * 1024 * 1024 * 1024;

/// prd.md §9.4.3: blobs acknowledged by every recipient are deleted after N
/// days. This is also the fallback retention ceiling for blobs that are
/// never fully acknowledged (or have no recipients besides the uploader).
const GC_RETENTION_DAYS: i64 = 30;

/// Max GC candidates fetched per `list_gc_candidates` call. The hourly sweep
/// pages through candidates in keyset-paginated batches of this size so a large
/// `media_blobs` table can never be pulled fully into memory (security-auditor
/// cycle 289; prd.md §9.4.3).
const GC_BATCH_SIZE: i64 = 500;

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

/// RFC 6838 §4.2 restricted-name token: ALPHA / DIGIT / "!" / "#" / "$" / "&"
/// / "-" / "^" / "_" / "." / "+", non-empty.
fn is_valid_media_type_token(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "!#$&-^_.+".contains(c))
}

/// Validate a client-supplied `Content-Type` before it is persisted and
/// signed into the R2 presigned URL: must be a `type/subtype` pair (RFC 6838)
/// and capped well under typical MIME-type lengths. An unvalidated value here
/// is a weak trust boundary (security-auditor finding, cycle 260) — it isn't
/// logged or interpreted as a path/command, but nothing previously stopped an
/// arbitrary/oversized string from riding along into stored metadata and the
/// signed upload URL.
const MAX_CONTENT_TYPE_LEN: usize = 128;

fn is_valid_content_type(content_type: &str) -> bool {
    if content_type.is_empty() || content_type.len() > MAX_CONTENT_TYPE_LEN {
        return false;
    }
    match content_type.split_once('/') {
        Some((type_, subtype)) => {
            is_valid_media_type_token(type_) && is_valid_media_type_token(subtype)
        }
        None => false,
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

    /// GC sweep with an explicit candidate batch size. `run_gc` calls this with
    /// `GC_BATCH_SIZE`; tests pass a small size to exercise multi-page keyset
    /// pagination. Candidates arrive from the repo already filtered to the
    /// GC-eligible set (expires_at / retention cutoff pushed into SQL), so this
    /// loop only applies the per-blob all-recipients-acked check before deleting.
    async fn run_gc_batched(&self, limit: i64) -> Result<usize, DomainError> {
        let now = chrono::Utc::now();
        let retention = chrono::Duration::days(GC_RETENTION_DAYS);
        let default_retention_cutoff = now - retention;
        let mut deleted = 0usize;
        let mut after_id: Option<MediaId> = None;
        loop {
            let batch = self
                .media_repo
                .list_gc_candidates(now, default_retention_cutoff, after_id.clone(), limit)
                .await?;
            let batch_len = batch.len();
            // Advance the keyset cursor to the last id in the page BEFORE any
            // delete. A blob that stays (unacked recipients) must not be
            // re-fetched on the next page, which would loop forever.
            if let Some(last) = batch.last() {
                after_id = Some(last.id.clone());
            }
            for blob in batch {
                let required_ackers: Vec<DeviceId> = match &blob.group_id {
                    Some(gid) => self
                        .group_repo
                        .list_members(gid)
                        .await?
                        .into_iter()
                        .map(|m| m.device_id)
                        .filter(|d| d != &blob.uploader_device)
                        .collect(),
                    None => Vec::new(),
                };
                let all_acked = if required_ackers.is_empty() {
                    true
                } else {
                    let acked = self.media_repo.list_ack_device_ids(&blob.id).await?;
                    required_ackers.iter().all(|d| acked.contains(d))
                };
                if all_acked {
                    self.media_repo.delete(&blob.id).await?;
                    deleted += 1;
                }
            }
            // A short page means the candidate set is exhausted.
            if (batch_len as i64) < limit {
                break;
            }
        }
        Ok(deleted)
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
        if !is_valid_content_type(content_type) {
            return Err(DomainError::InvalidInput("content_type invalid".into()));
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
        // Soft cap, same count-then-insert race as `KeyPackageService::upload`
        // — see MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY's doc comment for the
        // bound (concurrency x MAX_MEDIA_BYTES, capped by the per-IP
        // governor's burst; a one-shot ~2x-cap overshoot per window, not
        // unbounded drift).
        let window_start = chrono::Utc::now() - chrono::Duration::days(1);
        let used = self
            .media_repo
            .sum_bytes_uploaded_since(uploader_device, window_start)
            .await?;
        if used.saturating_add(size_bytes) > MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY {
            return Err(DomainError::InvalidInput(
                "media_device_daily_quota_exceeded".into(),
            ));
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
        // Ack recording happens separately in `confirm_download`, once the
        // recipient has actually verified the transfer — a granted URL alone
        // doesn't prove the download completed.
        if let Some(gid) = &blob.group_id {
            let members = self.group_repo.list_members(gid).await?;
            if members.iter().any(|m| &m.device_id == requestor_device) {
                return self.media_repo.presigned_download_url(media_id).await;
            }
        }

        Err(DomainError::Unauthorized)
    }

    #[instrument(skip(self), fields(media_id = %media_id))]
    async fn confirm_download(
        &self,
        media_id: &MediaId,
        confirmer_device: &DeviceId,
    ) -> Result<(), DomainError> {
        let blob = self
            .media_repo
            .find_by_id(media_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;

        // Uploader's own download (e.g. re-fetching their own upload) is never
        // GC-required (`run_gc_batched` excludes the uploader from
        // `required_ackers`) — accept but skip the no-op write.
        if &blob.uploader_device == confirmer_device {
            return Ok(());
        }

        if let Some(gid) = &blob.group_id {
            let members = self.group_repo.list_members(gid).await?;
            if members.iter().any(|m| &m.device_id == confirmer_device) {
                // Best-effort: the caller already has the plaintext, so a
                // failure here must not surface as an error — it only delays
                // GC eligibility for this device.
                if let Err(e) = self.media_repo.record_ack(media_id, confirmer_device).await {
                    tracing::warn!(error_kind = "media_ack", error = %e, "record_ack failed");
                }
                return Ok(());
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

    #[instrument(skip(self))]
    async fn run_gc(&self) -> Result<usize, DomainError> {
        self.run_gc_batched(GC_BATCH_SIZE).await
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
        acks: Mutex<Vec<(MediaId, DeviceId)>>,
        // Mirrors `media_upload_ledger`: append-only, populated by `save()`,
        // NEVER pruned by `delete()` — models the real Postgres-backed
        // adapter's cycle-362 fix so in-memory unit tests can actually catch
        // a regression back to summing live `saved` rows.
        ledger: Mutex<Vec<(DeviceId, u64, chrono::DateTime<chrono::Utc>)>>,
        upload_url: String,
        download_url: String,
    }

    impl MockMediaRepo {
        fn new(upload_url: &str, download_url: &str) -> Self {
            Self {
                saved: Mutex::new(vec![]),
                acks: Mutex::new(vec![]),
                ledger: Mutex::new(vec![]),
                upload_url: upload_url.into(),
                download_url: download_url.into(),
            }
        }
    }

    #[async_trait]
    impl MediaRepository for MockMediaRepo {
        async fn save(&self, blob: &MediaBlob) -> Result<(), DomainError> {
            self.saved.lock().unwrap().push(blob.clone());
            self.ledger.lock().unwrap().push((
                blob.uploader_device.clone(),
                blob.size_bytes,
                blob.uploaded_at,
            ));
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
        async fn record_ack(
            &self,
            media_id: &MediaId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            let mut locked = self.acks.lock().unwrap();
            let key = (media_id.clone(), device_id.clone());
            if !locked.contains(&key) {
                locked.push(key);
            }
            Ok(())
        }
        async fn list_ack_device_ids(
            &self,
            media_id: &MediaId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            let locked = self.acks.lock().unwrap();
            Ok(locked
                .iter()
                .filter(|(mid, _)| mid == media_id)
                .map(|(_, did)| did.clone())
                .collect())
        }
        async fn list_gc_candidates(
            &self,
            now: chrono::DateTime<chrono::Utc>,
            default_retention_cutoff: chrono::DateTime<chrono::Utc>,
            after_id: Option<MediaId>,
            limit: i64,
        ) -> Result<Vec<MediaBlob>, DomainError> {
            // Mirror the SQL filter/keyset semantics in-memory so the service's
            // GC pagination logic is exercised the same way it is against Postgres.
            let mut rows: Vec<MediaBlob> = self
                .saved
                .lock()
                .unwrap()
                .iter()
                .filter(|b| {
                    let eligible = match b.expires_at {
                        Some(exp) => exp <= now,
                        None => b.uploaded_at <= default_retention_cutoff,
                    };
                    let after = after_id
                        .as_ref()
                        .map(|a| b.id.as_uuid() > a.as_uuid())
                        .unwrap_or(true);
                    eligible && after
                })
                .cloned()
                .collect();
            rows.sort_by_key(|b| b.id.as_uuid());
            rows.truncate(limit as usize);
            Ok(rows)
        }
        async fn sum_bytes_uploaded_since(
            &self,
            device_id: &DeviceId,
            since: chrono::DateTime<chrono::Utc>,
        ) -> Result<u64, DomainError> {
            let locked = self.ledger.lock().unwrap();
            Ok(locked
                .iter()
                .filter(|(d, _, at)| d == device_id && *at >= since)
                .map(|(_, bytes, _)| bytes)
                .sum())
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
        async fn upsert_members(
            &self,
            _group: &Group,
            _members: &[GroupMember],
        ) -> Result<(), DomainError> {
            Ok(())
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

    #[test]
    fn content_type_validation_accepts_common_mime_types() {
        for ct in [
            "image/jpeg",
            "image/png",
            "video/mp4",
            "audio/mpeg",
            "application/pdf",
        ] {
            assert!(is_valid_content_type(ct), "{ct} should be valid");
        }
    }

    #[test]
    fn content_type_validation_rejects_malformed_input() {
        for ct in [
            "",
            "no-slash",
            "/missing-type",
            "missing-subtype/",
            "too/many/slashes",
            "has space/x",
            "text/html\r\nX-Injected: 1",
        ] {
            assert!(!is_valid_content_type(ct), "{ct:?} should be rejected");
        }
    }

    #[test]
    fn content_type_validation_rejects_oversized_input() {
        let huge = format!("image/{}", "a".repeat(200));
        assert!(!is_valid_content_type(&huge));
    }

    #[tokio::test]
    async fn request_upload_invalid_content_type_returns_invalid_input() {
        let s = svc(Arc::new(MockMediaRepo::new("u", "d")));
        let err = s
            .request_upload(&DeviceId::new(), "not-a-mime-type", 1024, None)
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
    async fn request_upload_rejects_when_device_over_daily_byte_quota() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        // Prime the device's rolling-24h usage right up to the cap via a
        // synthetic already-saved blob (avoids looping thousands of real
        // MAX_MEDIA_BYTES-sized uploads just to reach 5GB).
        let priming = MediaBlob {
            id: MediaId::new(),
            uploader_device: device.clone(),
            storage_key: "media/priming".into(),
            content_type: "image/jpeg".into(),
            size_bytes: MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY,
            uploaded_at: chrono::Utc::now(),
            expires_at: None,
            group_id: None,
        };
        repo.save(&priming).await.unwrap();
        let err = s
            .request_upload(&device, "image/jpeg", 1, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidInput(ref s) if s.contains("media_device_daily_quota_exceeded")),
            "expected media_device_daily_quota_exceeded, got: {err:?}"
        );
        // No new blob saved past the priming one.
        assert_eq!(repo.saved.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn request_upload_accepts_when_at_exact_daily_quota_boundary() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let priming = MediaBlob {
            id: MediaId::new(),
            uploader_device: device.clone(),
            storage_key: "media/priming".into(),
            content_type: "image/jpeg".into(),
            size_bytes: MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY - 1,
            uploaded_at: chrono::Utc::now(),
            expires_at: None,
            group_id: None,
        };
        repo.save(&priming).await.unwrap();
        // Exactly at the cap must be accepted; only strictly over is rejected.
        s.request_upload(&device, "image/jpeg", 1, None)
            .await
            .unwrap();
        assert_eq!(repo.saved.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn request_upload_ignores_usage_outside_the_rolling_window() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let stale = MediaBlob {
            id: MediaId::new(),
            uploader_device: device.clone(),
            storage_key: "media/stale".into(),
            content_type: "image/jpeg".into(),
            size_bytes: MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY,
            uploaded_at: chrono::Utc::now() - chrono::Duration::days(2),
            expires_at: None,
            group_id: None,
        };
        repo.save(&stale).await.unwrap();
        // Stale usage from >24h ago must not count against today's quota.
        s.request_upload(&device, "image/jpeg", 1024, None)
            .await
            .unwrap();
        assert_eq!(repo.saved.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn request_upload_quota_survives_delete_upload_churn() {
        // Cycle 361's accepted residual gap, closed cycle 362: repeatedly
        // uploading then deleting must NOT reset counted usage, otherwise a
        // device could churn unbounded write ops/day while storage stays at
        // zero. Primes 3 synthetic uploads at 40% of the daily cap each
        // (single-request MAX_MEDIA_BYTES caps a real `request_upload` call
        // at 100MB, far below the 5GB daily cap, so priming via direct
        // `save`+`delete` — same technique the other daily-quota tests use
        // for the boundary case — is required to reach it), deleting each
        // one immediately after. The ledger must still show ~120% usage.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device = DeviceId::new();
        let chunk = MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY * 2 / 5;
        for _ in 0..3 {
            let blob = MediaBlob {
                id: MediaId::new(),
                uploader_device: device.clone(),
                storage_key: "media/churn".into(),
                content_type: "image/jpeg".into(),
                size_bytes: chunk,
                uploaded_at: chrono::Utc::now(),
                expires_at: None,
                group_id: None,
            };
            repo.save(&blob).await.unwrap();
            repo.delete(&blob.id).await.unwrap();
        }
        // No live blobs remain (all deleted), but the ledger has counted all
        // 3 uploads (~120% of the cap) — a real request_upload call must be
        // rejected despite live usage reading zero.
        assert!(repo.saved.lock().unwrap().is_empty());
        let err = s
            .request_upload(&device, "image/jpeg", 1, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidInput(ref s) if s.contains("media_device_daily_quota_exceeded")),
            "expected media_device_daily_quota_exceeded, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn request_upload_daily_quota_is_scoped_per_device() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let priming = MediaBlob {
            id: MediaId::new(),
            uploader_device: device_a.clone(),
            storage_key: "media/a-priming".into(),
            content_type: "image/jpeg".into(),
            size_bytes: MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY,
            uploaded_at: chrono::Utc::now(),
            expires_at: None,
            group_id: None,
        };
        repo.save(&priming).await.unwrap();
        // device_a is at its cap, but device_b's own quota is untouched.
        s.request_upload(&device_b, "image/jpeg", 1024, None)
            .await
            .unwrap();
        assert_eq!(repo.saved.lock().unwrap().len(), 2);
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

    fn old_blob(uploader: DeviceId, group_id: Option<GroupId>) -> MediaBlob {
        MediaBlob {
            id: MediaId::new(),
            uploader_device: uploader,
            storage_key: "media/gc-fixture".into(),
            content_type: "image/jpeg".into(),
            size_bytes: 1,
            uploaded_at: chrono::Utc::now() - chrono::Duration::days(GC_RETENTION_DAYS + 1),
            expires_at: None,
            group_id,
        }
    }

    #[tokio::test]
    async fn get_download_url_by_group_member_does_not_record_ack() {
        // Granting a URL only proves the download was authorized, not that the
        // transfer completed — the ack must wait for an explicit
        // `confirm_download` call (closes the cycle-289 ack-on-grant gap).
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        s.get_download_url(&id, &member).await.unwrap();
        let acked = repo.list_ack_device_ids(&id).await.unwrap();
        assert!(acked.is_empty());
    }

    #[tokio::test]
    async fn confirm_download_by_group_member_records_ack() {
        let repo = Arc::new(MockMediaRepo::new("u", "https://r2.example/download"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        s.confirm_download(&id, &member).await.unwrap();
        let acked = repo.list_ack_device_ids(&id).await.unwrap();
        assert_eq!(acked, vec![member]);
    }

    #[tokio::test]
    async fn confirm_download_by_uploader_is_a_noop() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        let uploader = DeviceId::new();
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, None)
            .await
            .unwrap();
        s.confirm_download(&id, &uploader).await.unwrap();
        assert!(repo.list_ack_device_ids(&id).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn confirm_download_by_non_member_returns_unauthorized() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let non_member = DeviceId::new();
        let group = GroupId::new();
        let group_repo = FakeGroupRepo::with_member(group.clone(), uploader.clone());
        let s = MediaService::new(repo.clone(), group_repo);
        let (id, _) = s
            .request_upload(&uploader, "image/jpeg", 512, Some(&group))
            .await
            .unwrap();
        let err = s.confirm_download(&id, &non_member).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn confirm_download_not_found_when_blob_missing() {
        let s = svc(Arc::new(MockMediaRepo::new("u", "d")));
        let err = s
            .confirm_download(&MediaId::new(), &DeviceId::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn run_gc_deletes_ungrouped_blob_past_retention() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let blob = old_blob(DeviceId::new(), None);
        repo.save(&blob).await.unwrap();
        let s = svc(repo.clone());
        let deleted = s.run_gc().await.unwrap();
        assert_eq!(deleted, 1);
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_gc_leaves_ungrouped_blob_within_retention() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let mut blob = old_blob(DeviceId::new(), None);
        blob.uploaded_at = chrono::Utc::now();
        repo.save(&blob).await.unwrap();
        let s = svc(repo.clone());
        let deleted = s.run_gc().await.unwrap();
        assert_eq!(deleted, 0);
        assert_eq!(repo.saved.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn run_gc_leaves_grouped_blob_with_unacked_recipient() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        let blob = old_blob(uploader.clone(), Some(group.clone()));
        repo.save(&blob).await.unwrap();
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let deleted = s.run_gc().await.unwrap();
        assert_eq!(deleted, 0, "member has not acked yet");
        assert_eq!(repo.saved.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn run_gc_deletes_grouped_blob_once_all_recipients_acked() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        let blob = old_blob(uploader.clone(), Some(group.clone()));
        repo.save(&blob).await.unwrap();
        repo.record_ack(&blob.id, &member).await.unwrap();
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let deleted = s.run_gc().await.unwrap();
        assert_eq!(deleted, 1);
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_gc_ignores_uploaders_own_ack_requirement() {
        // The uploader is never a "required" acker of their own upload — the
        // group has exactly one other member and that member has acked.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        let blob = old_blob(uploader.clone(), Some(group.clone()));
        repo.save(&blob).await.unwrap();
        repo.record_ack(&blob.id, &member).await.unwrap();
        // Only the member's ack is recorded, not the uploader's — must still GC.
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        assert_eq!(s.run_gc().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn run_gc_honors_explicit_expires_at_over_default_retention() {
        // expires_at set in the past, uploaded_at recent — explicit override wins.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let mut blob = old_blob(DeviceId::new(), None);
        blob.uploaded_at = chrono::Utc::now();
        blob.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        repo.save(&blob).await.unwrap();
        let s = svc(repo.clone());
        let deleted = s.run_gc().await.unwrap();
        assert_eq!(deleted, 1);
    }

    #[tokio::test]
    async fn run_gc_returns_zero_when_no_blobs_exist() {
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let s = svc(repo.clone());
        assert_eq!(s.run_gc().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn run_gc_batched_paginates_across_multiple_batches() {
        // More eligible candidates than one batch holds must ALL be GC'd, proving
        // the keyset cursor advances across pages without skipping rows.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        for _ in 0..5 {
            repo.save(&old_blob(DeviceId::new(), None)).await.unwrap();
        }
        let s = svc(repo.clone());
        // Batch size 2 over 5 candidates => pages of 2, 2, 1.
        let deleted = s.run_gc_batched(2).await.unwrap();
        assert_eq!(deleted, 5);
        assert!(repo.saved.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn run_gc_batched_does_not_loop_on_undeletable_blob() {
        // An eligible-but-undeletable blob (grouped, recipient hasn't acked) must
        // not stall the sweep: with batch size 1 the cursor still advances past it
        // so the run terminates and later deletable blobs are still collected.
        let repo = Arc::new(MockMediaRepo::new("u", "d"));
        let uploader = DeviceId::new();
        let member = DeviceId::new();
        let group = GroupId::new();
        repo.save(&old_blob(uploader.clone(), Some(group.clone())))
            .await
            .unwrap();
        repo.save(&old_blob(DeviceId::new(), None)).await.unwrap();
        let group_repo = FakeGroupRepo::with_members(vec![
            (group.clone(), uploader.clone()),
            (group.clone(), member.clone()),
        ]);
        let s = MediaService::new(repo.clone(), group_repo);
        let deleted = s.run_gc_batched(1).await.unwrap();
        assert_eq!(deleted, 1, "only the ungrouped blob is deletable");
        assert_eq!(
            repo.saved.lock().unwrap().len(),
            1,
            "the unacked grouped blob must remain"
        );
    }
}
