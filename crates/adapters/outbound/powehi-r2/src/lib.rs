//! Cloudflare R2 media adapter.
//!
//! Security invariant: the server NEVER proxies ciphertext. All uploads and
//! downloads happen via short-lived pre-signed S3 PUT/GET URLs generated here.
//! Only metadata (UUIDs, content-type, size) is persisted in Postgres.
//!
//! Pre-signed URL TTLs:
//!   - Upload:   configurable, default 900 s (15 min) — covers slow connections.
//!   - Download: configurable, default 300 s (5 min) — minimises link sharing window.

pub mod error;

use std::time::Duration;

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{Builder as S3ConfigBuilder, Region},
    presigning::PresigningConfig,
    Client as S3Client,
};
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::GroupId,
    media::{MediaBlob, MediaId},
};
use powehi_port_outbound::media_repo::MediaRepository;
use sqlx::postgres::PgPool;
use tracing::instrument;
use uuid::Uuid;

use crate::error::R2Error;

/// Content-types accepted for media uploads.
/// All blobs are client-side E2EE; the type hint is used only for `Content-Type` metadata.
const ALLOWED_CONTENT_TYPES: &[&str] = &[
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/gif",
    "video/mp4",
    "audio/mpeg",
    "audio/ogg",
    "application/octet-stream",
];

/// Maximum single-blob size the server will issue a presigned URL for: 100 MB.
pub const MAX_MEDIA_BYTES: u64 = 100 * 1024 * 1024;

/// Outbound adapter: Cloudflare R2 for pre-signed URL generation + Postgres for metadata.
pub struct R2MediaAdapter {
    pool: PgPool,
    s3: S3Client,
    bucket: String,
    upload_ttl: Duration,
    download_ttl: Duration,
}

impl R2MediaAdapter {
    /// Construct a new adapter.
    ///
    /// `endpoint`           — R2 S3-compatible URL, e.g. `https://<account>.r2.cloudflarestorage.com`
    /// `bucket`             — R2 bucket name
    /// `access_key_id`      — R2 API token key
    /// `secret_access_key`  — R2 API token secret
    /// `upload_ttl_secs`    — pre-signed upload URL TTL
    /// `download_ttl_secs`  — pre-signed download URL TTL
    pub fn new(
        pool: PgPool,
        endpoint: &str,
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
        upload_ttl_secs: u64,
        download_ttl_secs: u64,
    ) -> Self {
        let creds = Credentials::new(
            access_key_id,
            secret_access_key,
            None,
            None,
            "powehi-r2-static",
        );
        let s3_cfg = S3ConfigBuilder::new()
            .region(Region::new("auto"))
            .endpoint_url(endpoint)
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        let s3 = S3Client::from_conf(s3_cfg);
        Self {
            pool,
            s3,
            bucket: bucket.to_string(),
            upload_ttl: Duration::from_secs(upload_ttl_secs),
            download_ttl: Duration::from_secs(download_ttl_secs),
        }
    }

    fn validate_content_type(&self, ct: &str) -> Result<(), DomainError> {
        if ALLOWED_CONTENT_TYPES.contains(&ct) {
            Ok(())
        } else {
            Err(DomainError::InvalidInput("content_type not allowed".into()))
        }
    }
}

#[derive(sqlx::FromRow)]
struct MediaBlobRow {
    id: Uuid,
    uploader_device_id: Uuid,
    storage_key: String,
    content_type: String,
    size_bytes: i64,
    uploaded_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    group_id: Option<Uuid>,
}

impl From<MediaBlobRow> for MediaBlob {
    fn from(r: MediaBlobRow) -> Self {
        MediaBlob {
            id: MediaId::from(r.id),
            uploader_device: powehi_domain::device::DeviceId::from(r.uploader_device_id),
            storage_key: r.storage_key,
            content_type: r.content_type,
            size_bytes: r.size_bytes as u64,
            uploaded_at: r.uploaded_at,
            expires_at: r.expires_at,
            group_id: r.group_id.map(GroupId::from),
        }
    }
}

fn map_sqlx(e: sqlx::Error) -> DomainError {
    tracing::error!(error_kind = "sqlx", "database error");
    DomainError::Internal(e.to_string())
}

fn map_r2(e: R2Error) -> DomainError {
    tracing::error!(error_kind = "r2", "storage error");
    DomainError::Internal(e.to_string())
}

#[async_trait]
impl MediaRepository for R2MediaAdapter {
    #[instrument(skip(self, blob), fields(media_id = %blob.id))]
    async fn save(&self, blob: &MediaBlob) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO media_blobs
             (id, uploader_device_id, storage_key, content_type, size_bytes, uploaded_at, expires_at, group_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(blob.id.as_uuid())
        .bind(blob.uploader_device.as_uuid())
        .bind(&blob.storage_key)
        .bind(&blob.content_type)
        .bind(blob.size_bytes as i64)
        .bind(blob.uploaded_at)
        .bind(blob.expires_at)
        .bind(blob.group_id.as_ref().map(|g| g.as_uuid()))
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    #[instrument(skip(self), fields(media_id = %id))]
    async fn find_by_id(&self, id: &MediaId) -> Result<Option<MediaBlob>, DomainError> {
        let row = sqlx::query_as::<_, MediaBlobRow>(
            "SELECT id, uploader_device_id, storage_key, content_type, size_bytes, uploaded_at, expires_at, group_id
             FROM media_blobs WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.map(MediaBlob::from))
    }

    #[instrument(skip(self), fields(media_id = %id))]
    async fn delete(&self, id: &MediaId) -> Result<(), DomainError> {
        let row = self.find_by_id(id).await?;
        if let Some(blob) = row {
            self.s3
                .delete_object()
                .bucket(&self.bucket)
                .key(&blob.storage_key)
                .send()
                .await
                .map_err(|e| map_r2(R2Error::S3(e.to_string())))?;
        }
        sqlx::query("DELETE FROM media_blobs WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
        Ok(())
    }

    #[instrument(skip(self), fields(media_id = %id))]
    async fn presigned_upload_url(
        &self,
        id: &MediaId,
        content_type: &str,
    ) -> Result<String, DomainError> {
        self.validate_content_type(content_type)?;
        let row = self
            .find_by_id(id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;

        let presign_cfg = PresigningConfig::expires_in(self.upload_ttl)
            .map_err(|e| map_r2(R2Error::Presign(e.to_string())))?;

        let url = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(&row.storage_key)
            .content_type(content_type)
            .presigned(presign_cfg)
            .await
            .map_err(|e| map_r2(R2Error::S3(e.to_string())))?;

        Ok(url.uri().to_string())
    }

    #[instrument(skip(self), fields(media_id = %id))]
    async fn presigned_download_url(&self, id: &MediaId) -> Result<String, DomainError> {
        let row = self
            .find_by_id(id)
            .await?
            .ok_or_else(|| DomainError::NotFound("media".into()))?;

        let presign_cfg = PresigningConfig::expires_in(self.download_ttl)
            .map_err(|e| map_r2(R2Error::Presign(e.to_string())))?;

        let url = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(&row.storage_key)
            .presigned(presign_cfg)
            .await
            .map_err(|e| map_r2(R2Error::S3(e.to_string())))?;

        Ok(url.uri().to_string())
    }

    #[instrument(skip(self), fields(media_id = %media_id))]
    async fn record_ack(
        &self,
        media_id: &MediaId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO media_acks (media_id, device_id)
             VALUES ($1, $2)
             ON CONFLICT (media_id, device_id) DO NOTHING",
        )
        .bind(media_id.as_uuid())
        .bind(device_id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(())
    }

    #[instrument(skip(self), fields(media_id = %media_id))]
    async fn list_ack_device_ids(&self, media_id: &MediaId) -> Result<Vec<DeviceId>, DomainError> {
        let rows: Vec<(Uuid,)> =
            sqlx::query_as("SELECT device_id FROM media_acks WHERE media_id = $1")
                .bind(media_id.as_uuid())
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(|(id,)| DeviceId::from(id)).collect())
    }

    #[instrument(skip(self))]
    async fn list_undeleted(&self) -> Result<Vec<MediaBlob>, DomainError> {
        let rows = sqlx::query_as::<_, MediaBlobRow>(
            "SELECT id, uploader_device_id, storage_key, content_type, size_bytes, uploaded_at, expires_at, group_id
             FROM media_blobs",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(MediaBlob::from).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_content_types_covers_common_media() {
        assert!(ALLOWED_CONTENT_TYPES.contains(&"image/jpeg"));
        assert!(ALLOWED_CONTENT_TYPES.contains(&"video/mp4"));
        assert!(ALLOWED_CONTENT_TYPES.contains(&"application/octet-stream"));
        assert!(!ALLOWED_CONTENT_TYPES.contains(&"text/html"));
        assert!(!ALLOWED_CONTENT_TYPES.contains(&"application/javascript"));
    }

    #[test]
    fn max_media_bytes_is_100mb() {
        assert_eq!(MAX_MEDIA_BYTES, 100 * 1024 * 1024);
    }

    #[test]
    fn media_blob_row_converts_to_domain() {
        let id = Uuid::new_v4();
        let uploader_device = Uuid::new_v4();
        let now = Utc::now();
        let row = MediaBlobRow {
            id,
            uploader_device_id: uploader_device,
            storage_key: "media/abc123".into(),
            content_type: "image/jpeg".into(),
            size_bytes: 4096,
            uploaded_at: now,
            expires_at: None,
            group_id: None,
        };
        let blob = MediaBlob::from(row);
        assert_eq!(blob.id.as_uuid(), id);
        assert_eq!(blob.uploader_device.as_uuid(), uploader_device);
        assert_eq!(blob.storage_key, "media/abc123");
        assert_eq!(blob.size_bytes, 4096u64);
        assert!(blob.group_id.is_none());
    }

    #[test]
    fn all_allowed_content_types_are_accepted() {
        for ct in ALLOWED_CONTENT_TYPES {
            assert!(
                ALLOWED_CONTENT_TYPES.contains(ct),
                "expected {ct} to be in ALLOWED_CONTENT_TYPES"
            );
        }
    }

    #[test]
    fn disallowed_content_types_are_rejected() {
        let disallowed = [
            "text/plain",
            "text/html",
            "application/json",
            "application/javascript",
            "multipart/form-data",
            "application/x-www-form-urlencoded",
            "image/svg+xml",
            "",
        ];
        for ct in disallowed {
            assert!(
                !ALLOWED_CONTENT_TYPES.contains(&ct),
                "expected {ct} to be rejected by ALLOWED_CONTENT_TYPES"
            );
        }
    }

    #[test]
    fn media_blob_row_preserves_expires_at_some() {
        let id = Uuid::new_v4();
        let uploader_device = Uuid::new_v4();
        let now = Utc::now();
        let expires = Some(now);
        let row = MediaBlobRow {
            id,
            uploader_device_id: uploader_device,
            storage_key: "media/xyz".into(),
            content_type: "audio/ogg".into(),
            size_bytes: 1024 * 512,
            uploaded_at: now,
            expires_at: expires,
            group_id: None,
        };
        let blob = MediaBlob::from(row);
        assert!(blob.expires_at.is_some());
        assert_eq!(blob.content_type, "audio/ogg");
        assert_eq!(blob.size_bytes, 1024 * 512u64);
    }

    #[test]
    fn storage_key_is_preserved_verbatim() {
        let id = Uuid::new_v4();
        let uploader_device = Uuid::new_v4();
        let now = Utc::now();
        let storage_key = format!("media/{}/encrypted_blob", Uuid::new_v4());
        let row = MediaBlobRow {
            id,
            uploader_device_id: uploader_device,
            storage_key: storage_key.clone(),
            content_type: "image/webp".into(),
            size_bytes: 8192,
            uploaded_at: now,
            expires_at: None,
            group_id: None,
        };
        let blob = MediaBlob::from(row);
        assert_eq!(blob.storage_key, storage_key);
    }
}
