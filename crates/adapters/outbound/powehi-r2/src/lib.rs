//! Cloudflare R2 media adapter.
//!
//! Security invariant: the server NEVER proxies ciphertext. All uploads and
//! downloads happen via short-lived pre-signed S3 PUT/GET URLs generated here.
//! Only metadata (UUIDs, content-type, size) is persisted in Postgres.
//!
//! Pre-signed URL TTLs:
//!   - Upload:   configurable, default 900 s (15 min) — covers slow connections.
//!   - Download: configurable, default 300 s (5 min) — minimises link sharing window.
//!
//! The S3 client's own request timeout is separately configurable and distinct
//! from the presign TTLs above: presign TTL is the client-facing upload/download
//! window, while the request timeout bounds server-to-R2 call latency — currently
//! only `delete()` (used by the hourly media-blob GC job) makes a real R2 network
//! call; the daily ledger-trim job is Postgres-only and never touches R2.

pub mod error;

use std::time::Duration;

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{timeout::TimeoutConfig, Builder as S3ConfigBuilder, Region},
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

/// Row count per `DELETE` statement in `trim_upload_ledger_older_than`'s
/// keyset-batched sweep (cycle 364) — bounds lock hold time per statement
/// regardless of how many rows are past the cutoff.
const TRIM_LEDGER_BATCH_SIZE: i64 = 5_000;

/// Outbound adapter: Cloudflare R2 for pre-signed URL generation + Postgres for metadata.
pub struct R2MediaAdapter {
    pool: PgPool,
    s3: S3Client,
    bucket: String,
    upload_ttl: Duration,
    download_ttl: Duration,
}

/// Builds the S3-compatible client config used to talk to R2, including its
/// request-timeout policy. Pulled out of `R2MediaAdapter::new` so the timeout
/// wiring is unit-testable without needing a `PgPool`.
fn build_s3_config(
    endpoint: &str,
    access_key_id: &str,
    secret_access_key: &str,
    request_timeout_secs: u64,
) -> aws_sdk_s3::Config {
    let creds = Credentials::new(
        access_key_id,
        secret_access_key,
        None,
        None,
        "powehi-r2-static",
    );
    // A stalled single attempt must not consume the whole operation budget, or
    // the SDK's standard retry policy never gets a chance to try again — so the
    // attempt timeout is a third of the operation timeout (floored at 1s),
    // leaving room for the SDK's default 3-attempt retry budget.
    let attempt_timeout_secs = (request_timeout_secs / 3).max(1);
    S3ConfigBuilder::new()
        .region(Region::new("auto"))
        .endpoint_url(endpoint)
        .credentials_provider(creds)
        .force_path_style(true)
        .timeout_config(
            TimeoutConfig::builder()
                .operation_timeout(Duration::from_secs(request_timeout_secs))
                .operation_attempt_timeout(Duration::from_secs(attempt_timeout_secs))
                .build(),
        )
        .build()
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
    /// `request_timeout_secs` — bounds each R2 operation (whole retry loop) and,
    ///   at a third of that budget, each individual attempt within it — so a
    ///   stalled single attempt still leaves room for the SDK's standard retry
    ///   policy to try again, and a stalled R2 call can't hang the media-blob GC
    ///   job (or, transitively, the advisory lock guarding it) indefinitely
    // 8 plain construction params, each independently meaningful (creds,
    // endpoint/bucket, and three orthogonal TTL/timeout knobs) — a builder
    // would be more ceremony than value for a single-call adapter
    // constructor with no optional fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        endpoint: &str,
        bucket: &str,
        access_key_id: &str,
        secret_access_key: &str,
        upload_ttl_secs: u64,
        download_ttl_secs: u64,
        request_timeout_secs: u64,
    ) -> Self {
        let s3_cfg = build_s3_config(
            endpoint,
            access_key_id,
            secret_access_key,
            request_timeout_secs,
        );
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
        // Both inserts happen in one transaction: the ledger row must never
        // exist without a corresponding blob row (or vice versa), even
        // though the ledger deliberately outlives `delete()`. `id` reuses
        // `blob.id` 1:1 so the ledger insert is idempotent under retry via
        // the same `ON CONFLICT (id) DO NOTHING` pattern as `media_blobs`.
        let mut tx = self.pool.begin().await.map_err(map_sqlx)?;
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
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        sqlx::query(
            "INSERT INTO media_upload_ledger (id, device_id, size_bytes, uploaded_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(blob.id.as_uuid())
        .bind(blob.uploader_device.as_uuid())
        .bind(blob.size_bytes as i64)
        .bind(blob.uploaded_at)
        .execute(&mut *tx)
        .await
        .map_err(map_sqlx)?;
        tx.commit().await.map_err(map_sqlx)?;
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
            // Binds the size the client declared at request_upload time into the
            // SigV4 signature: R2 rejects a PUT whose actual body length differs
            // from this value, closing an unbounded-upload-size hole (the
            // `size_bytes` DB column was otherwise purely advisory).
            .content_length(row.size_bytes as i64)
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

    #[instrument(skip(self, now, default_retention_cutoff, after_id), fields(limit = %limit))]
    async fn list_gc_candidates(
        &self,
        now: DateTime<Utc>,
        default_retention_cutoff: DateTime<Utc>,
        after_id: Option<MediaId>,
        limit: i64,
    ) -> Result<Vec<MediaBlob>, DomainError> {
        // Eligibility is filtered in SQL and keyset-paginated by `id` so the
        // hourly GC sweep never loads non-eligible or already-scanned rows into
        // memory (security-auditor cycle 289; prd.md §9.4.3). Keyset (`id > $1`),
        // NOT OFFSET: run_gc deletes matching rows as it scans, so OFFSET would
        // skip or re-scan rows across pages.
        let rows = sqlx::query_as::<_, MediaBlobRow>(
            "SELECT id, uploader_device_id, storage_key, content_type, size_bytes, uploaded_at, expires_at, group_id
             FROM media_blobs
             WHERE ($1::uuid IS NULL OR id > $1)
               AND (
                 (expires_at IS NOT NULL AND expires_at <= $2)
                 OR (expires_at IS NULL AND uploaded_at <= $3)
               )
             ORDER BY id
             LIMIT $4",
        )
        .bind(after_id.map(|id| id.as_uuid()))
        .bind(now)
        .bind(default_retention_cutoff)
        .bind(limit)
        .fetch_all(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(rows.into_iter().map(MediaBlob::from).collect())
    }

    #[instrument(skip(self, since), fields(device_id = %device_id))]
    async fn sum_bytes_uploaded_since(
        &self,
        device_id: &DeviceId,
        since: DateTime<Utc>,
    ) -> Result<u64, DomainError> {
        // Sums the append-only `media_upload_ledger`, NOT live `media_blobs`
        // (cycle 362 fix): a device's daily quota usage must be monotonic
        // within the rolling window even if it deletes uploads in between,
        // otherwise `upload -> confirm -> delete` in a loop lets write-op
        // churn bypass the cap entirely while storage stays at zero.
        //
        // COALESCE: SUM over zero matching rows is SQL NULL, not 0. Explicit
        // ::BIGINT cast: Postgres's SUM(bigint) returns NUMERIC (only
        // SUM(integer) stays bigint), and this workspace's sqlx build has no
        // NUMERIC-decoding type (no bigdecimal/rust_decimal feature) — without
        // the cast, fetch_one would fail every call with a column-decode
        // error (security-auditor finding, cycle 361). size_bytes ≤
        // MAX_MEDIA_BYTES (100MB) per row makes overflow past i64::MAX
        // physically impossible regardless of row count.
        let row: (i64,) = sqlx::query_as(
            "SELECT COALESCE(SUM(size_bytes), 0)::BIGINT FROM media_upload_ledger
             WHERE device_id = $1 AND uploaded_at >= $2",
        )
        .bind(device_id.as_uuid())
        .bind(since)
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;
        Ok(row.0 as u64)
    }

    // Closed cycle 364 (security-auditor cycle 363 non-blocking finding):
    // batched via `media_upload_ledger_uploaded_at_idx` (migration 0016,
    // leads with `uploaded_at`) so each batch is an index range scan, not a
    // full table scan, and no single statement holds a lock over the whole
    // stale range — same keyset-batching intent as `list_gc_candidates`,
    // adapted to a delete-in-place loop since this method (unlike
    // `run_gc`'s repeated interval-tick calls) is invoked once per day and
    // must fully drain the stale range before returning.
    //
    // security-auditor cycle 364, non-blocking: with multiple server
    // replicas each running this daily sweep independently, a concurrent
    // sweep on another replica can delete rows out from under this loop's
    // next batch selection, making `affected` undercount and exit early
    // with stale rows left over. Bounded and self-healing regardless: any
    // leftovers are still >29 days past the 24h quota-read window (no
    // quota-correctness impact) and get swept on the next daily run.
    // Closed cycle 368: the background-job callers in main.rs now wrap this
    // (and `run_gc`) in a `powehi_postgres::leader_lock::PgLeaderLock`
    // Postgres advisory lock (moved off this adapter cycle 373 — it's a pure
    // Postgres primitive with no R2 dependency), so only one replica actually
    // executes the sweep per tick — this doc comment's race can now only
    // happen during the narrow window of a rolling deploy where an old and
    // new replica briefly overlap without both yet running the locked code
    // path.
    #[instrument(skip(self))]
    async fn trim_upload_ledger_older_than(
        &self,
        cutoff: DateTime<Utc>,
    ) -> Result<u64, DomainError> {
        let mut total: u64 = 0;
        loop {
            let result = sqlx::query(
                "DELETE FROM media_upload_ledger
                 WHERE id IN (
                     SELECT id FROM media_upload_ledger
                     WHERE uploaded_at < $1
                     ORDER BY uploaded_at
                     LIMIT $2
                 )",
            )
            .bind(cutoff)
            .bind(TRIM_LEDGER_BATCH_SIZE)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx)?;
            let affected = result.rows_affected();
            total += affected;
            if affected < TRIM_LEDGER_BATCH_SIZE as u64 {
                break;
            }
        }
        Ok(total)
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
    fn build_s3_config_attaches_operation_and_attempt_timeouts() {
        let cfg = build_s3_config(
            "https://example.r2.cloudflarestorage.com",
            "key",
            "secret",
            30,
        );
        let timeout_config = cfg
            .timeout_config()
            .expect("timeout_config must be attached to the built S3 client config");
        assert_eq!(
            timeout_config.operation_timeout(),
            Some(Duration::from_secs(30))
        );
        assert_eq!(
            timeout_config.operation_attempt_timeout(),
            Some(Duration::from_secs(10)),
            "attempt timeout must be a fraction of the operation timeout so a stalled \
             attempt doesn't consume the whole retry budget"
        );
    }

    #[test]
    fn build_s3_config_floors_attempt_timeout_at_one_second() {
        let cfg = build_s3_config(
            "https://example.r2.cloudflarestorage.com",
            "key",
            "secret",
            1,
        );
        let timeout_config = cfg
            .timeout_config()
            .expect("timeout_config must be attached");
        assert_eq!(
            timeout_config.operation_timeout(),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            timeout_config.operation_attempt_timeout(),
            Some(Duration::from_secs(1)),
            "1/3 of 1s rounds to 0 — must floor at 1s, not disable the attempt timeout"
        );
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
