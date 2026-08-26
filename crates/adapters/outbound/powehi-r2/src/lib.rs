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
    // (and `run_gc`) in an `R2MediaAdapter::try_gc_lock` Postgres advisory
    // lock, so only one replica actually executes the sweep per tick —
    // this doc comment's race can now only happen during the narrow window
    // of a rolling deploy where an old and new replica briefly overlap
    // without both yet running the locked code path.
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

/// Postgres advisory-lock keys guarding GC/trim background jobs (cycle 368) —
/// see `R2MediaAdapter::try_gc_lock` for why this exists and the locking
/// pattern it must follow. One key per job so the two jobs never block each
/// other, only concurrent runs of the *same* job across server replicas.
pub const GC_LOCK_MEDIA_BLOBS: i64 = 0x706f_7765_6869_0001;
pub const GC_LOCK_MEDIA_LEDGER: i64 = 0x706f_7765_6869_0002;

/// Holds a session-scoped Postgres advisory lock acquired via
/// `R2MediaAdapter::try_gc_lock`. `pg_advisory_lock`/`pg_advisory_unlock` are
/// tied to the underlying connection (session), not the query, so this guard
/// keeps a dedicated `PoolConnection` alive for its whole lifetime instead of
/// borrowing one per-query from the shared pool — returning it to the pool
/// between acquire and unlock would let some other caller's query run on
/// that same session and would leave the unlock call (issued from a
/// different pooled connection) unable to find the lock at all.
///
/// Deployment invariant: this only works against a real Postgres session —
/// a transaction-pooling proxy in front of the DB (PgBouncer/RDS Proxy in
/// transaction mode) would silently multiplex queries from this guard's
/// "session" across different real backends, breaking the lock with no
/// compile-time signal. None is deployed today (checked `infra/`); if one
/// is ever introduced, `try_gc_lock` needs a session-mode exception or a
/// different locking primitive (e.g. a plain row lock table).
#[must_use = "the advisory lock is released as soon as this guard is dropped — hold it for the job's duration, or call release() explicitly"]
pub struct GcLockGuard {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    key: i64,
}

impl GcLockGuard {
    /// Unlock and return the connection to the pool. Prefer this over
    /// letting the guard drop on the happy path.
    pub async fn release(mut self) {
        if let Some(mut conn) = self.conn.take() {
            match sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.key)
                .execute(&mut *conn)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    // Don't return a connection to the pool that might still
                    // hold the lock — fall back to the same detach-and-drop
                    // path Drop uses, which is guaranteed to release it.
                    tracing::warn!(error_kind = "gc_lock", error = %e, "gc.advisory_unlock_failed");
                    let _ = conn.detach();
                }
            }
        }
    }
}

impl Drop for GcLockGuard {
    fn drop(&mut self) {
        // release() wasn't called (early return / panic in the guarded job):
        // detach and drop the raw connection instead of returning it to the
        // pool. Ending the session server-side is what actually releases a
        // session-scoped advisory lock — an explicit unlock query issued
        // later from a *different* pooled connection would not find it.
        //
        // detach() (not a plain `drop(conn)`) is also what makes this safe
        // to call from a sync Drop impl at all: PoolConnection's own Drop
        // spawns an async task to return itself to the pool, which panics
        // if invoked while the Tokio runtime is shutting down. detach()
        // takes the connection out of pool bookkeeping first (decrementing
        // the pool's size permit, which the pool immediately backfills), so
        // the raw connection's drop that follows is just an fd close — no
        // spawn, runtime-agnostic. This relies on the pool's
        // `min_connections` being 0 (the default, and what `connect()` uses
        // today) — a nonzero `min_connections` would make even the
        // post-detach empty `PoolConnection` guard spawn on drop again.
        if let Some(conn) = self.conn.take() {
            let _ = conn.detach();
        }
    }
}

impl R2MediaAdapter {
    /// Attempt to acquire advisory lock `key` (one of the `GC_LOCK_*`
    /// constants) without blocking, guarding a GC/trim background job
    /// against multiple server replicas racing the same job concurrently —
    /// a benign but wasteful race documented on `run_gc` and
    /// `trim_upload_ledger_older_than` above (early exit can undercount and
    /// leave stale rows for the next scheduled tick, self-healing but
    /// avoidable). `Ok(None)` means another session already holds it —
    /// caller should skip this run.
    pub async fn try_gc_lock(&self, key: i64) -> Result<Option<GcLockGuard>, DomainError> {
        let mut conn = self.pool.acquire().await.map_err(map_sqlx)?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .map_err(map_sqlx)?;
        Ok(if acquired {
            Some(GcLockGuard {
                conn: Some(conn),
                key,
            })
        } else {
            None
        })
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
