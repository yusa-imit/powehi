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
//! window, while the request timeout bounds server-to-R2 call latency — `delete()`
//! (used by the hourly media-blob GC job) and `sweep_orphaned_storage_objects()`
//! (the 6-hourly orphan sweep) both make real R2 network calls; the daily
//! ledger-trim job is Postgres-only and never touches R2.

pub mod error;

use std::{collections::HashSet, time::Duration};

use async_trait::async_trait;
use aws_credential_types::Credentials;
use aws_sdk_s3::{
    config::{timeout::TimeoutConfig, Builder as S3ConfigBuilder, Region},
    error::ProvideErrorMetadata,
    presigning::PresigningConfig,
    primitives::ByteStream,
    types::{Delete, ObjectIdentifier},
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

/// Hard S3/R2 API limit on keys per `DeleteObjects` request. `list_objects_v2`
/// pages are already capped at 1000 keys, so in practice a page never exceeds
/// this — the chunking in `sweep_orphaned_storage_objects` is defence against
/// that assumption silently changing, not an expected path.
const DELETE_OBJECTS_MAX_KEYS: usize = 1_000;

/// Cumulative-ratio circuit breaker for `sweep_orphaned_storage_objects`: once
/// at least this many past-grace candidates have been examined across the
/// whole run, a very high orphan hit rate is treated as a signal that
/// `media_blobs` itself is untrustworthy for this run (wrong/empty database,
/// a PITR restore in progress, a bucket shared across regions) rather than as
/// evidence that legitimate storage is genuinely orphaned — and the sweep
/// stops deleting rather than trusting the reconciliation. A real orphan is a
/// rare row-less/PUT-timing race, not a bulk population, so a healthy sweep
/// should never come close to this threshold; kept low (below the minimum
/// sample size) so small buckets/test fixtures with a single legitimate
/// orphan never trip it.
const ORPHAN_RATIO_ABORT_MIN_SAMPLE: usize = 50;
// Lowered from an earlier 80 (security-auditor finding, cycle 424): two real,
// non-`local` deployments that share both a bucket AND a region_id (e.g. this
// repo's `staging`/`prod-eu` Helm overlays, both `region: eu-frankfurt`, both
// leaving `r2Bucket` unset today) would together produce close to a 50/50
// orphan rate from each side's point of view — the old 80% bar let that case
// sail through and quietly delete the other side's live media. 50% still
// leaves genuine legitimate-orphan runs (expected to be single-digit
// percent) with a wide margin.
const ORPHAN_RATIO_ABORT_THRESHOLD_PERCENT: u64 = 50;
/// Absolute cap on cumulative deletes while `aged_checked_total` is still
/// below `ORPHAN_RATIO_ABORT_MIN_SAMPLE` — i.e. before the ratio guard above
/// has enough evidence to evaluate at all. Without this, a run whose aged
/// candidates trickle in a few per page (rather than one large page) could
/// delete up to `ORPHAN_RATIO_ABORT_MIN_SAMPLE - 1` objects against a wrong or
/// empty database before the ratio guard ever gets a chance to trip
/// (security-auditor finding, cycle 424) — worst case for a small/new-region
/// bucket, which is exactly where a misconfiguration is least likely to have
/// been noticed yet. Kept well below the min sample size so a single
/// legitimate orphan in a small bucket/test fixture never trips it.
const ORPHAN_PRE_SAMPLE_MAX_DELETES: u64 = 5;

/// Key suffix (appended to `region_prefix`) of this environment's ownership
/// marker object — see `R2MediaAdapter::verify_region_ownership`. A leading
/// `.` keeps it lexically first in `list_objects_v2` pages and visually
/// distinct from real `{uuid}` media keys.
const OWNER_SENTINEL_KEY_SUFFIX: &str = ".owner";

/// Outbound adapter: Cloudflare R2 for pre-signed URL generation + Postgres for metadata.
pub struct R2MediaAdapter {
    pool: PgPool,
    s3: S3Client,
    bucket: String,
    upload_ttl: Duration,
    download_ttl: Duration,
    /// This deployment's region id. Scopes `sweep_orphaned_storage_objects`'s
    /// bucket-wide LIST to just this region's own storage keys (see
    /// `region_prefix`) — without it, a bucket shared or misconfigured across
    /// regions would let one region's sweep delete another region's live
    /// media (threat-model-checker RED finding, cycle 422).
    region_id: String,
    /// Blast-radius cap for `sweep_orphaned_storage_objects` — see that
    /// method's doc comment.
    max_deletes_per_run: u64,
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
    /// `region_id`            — this deployment's region id; scopes the orphan sweep's
    ///   bucket-wide LIST to this region's own storage keys (`region_prefix`)
    /// `max_deletes_per_run`  — blast-radius cap for the orphan sweep (see
    ///   `sweep_orphaned_storage_objects`)
    // 10 plain construction params, each independently meaningful (creds,
    // endpoint/bucket, and orthogonal TTL/timeout/scope/cap knobs) — a builder
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
        region_id: &str,
        max_deletes_per_run: u64,
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
            region_id: region_id.to_string(),
            max_deletes_per_run,
        }
    }

    fn validate_content_type(&self, ct: &str) -> Result<(), DomainError> {
        if ALLOWED_CONTENT_TYPES.contains(&ct) {
            Ok(())
        } else {
            Err(DomainError::InvalidInput("content_type not allowed".into()))
        }
    }

    /// The S3 key prefix scoping this adapter's orphan sweep to just this
    /// region's own objects. Storage keys are generated as
    /// `media/{region_id}/{uuid}` (`MediaService::request_upload`), so this
    /// prefix exactly covers every object this region could itself have
    /// created — and, structurally, nothing outside it — regardless of
    /// whether the bucket is (mis)configured to be shared across regions.
    fn region_prefix(&self) -> String {
        format!("media/{}/", self.region_id)
    }

    /// Verifies (and, on first run, claims) ownership of `region_prefix`
    /// before `sweep_orphaned_storage_objects` is allowed to delete anything
    /// under it.
    ///
    /// `region_prefix` only isolates *distinct* region ids sharing one
    /// bucket — it does nothing for two separate environments (e.g. staging
    /// and prod-eu) that are both misconfigured to share the same bucket
    /// AND region_id, since their storage keys would then collide under an
    /// identical prefix while each environment's own Postgres only knows
    /// about its own blobs (threat-model-checker RED finding, cycle 424;
    /// `AppConfig::validate()`'s dev-bucket-default guard narrows this to
    /// "forgot to set r2_bucket" but cannot catch "set two environments to
    /// the same real bucket on purpose or by mistake").
    ///
    /// This NARROWS that residual gap, it does not close it. Each
    /// environment generates a random owner id once, persists it in *its
    /// own* Postgres (`media_region_owner` — a different database per
    /// environment, so this value is never shared even when the bucket and
    /// region_id are), then races to claim `{region_prefix}.owner` in R2
    /// with a conditional (`If-None-Match: *`) write the first time it
    /// runs. Because the sweep is a periodic reconciliation job rather than
    /// a one-time boot check (see the impl-level doc comment above), every
    /// subsequent run re-reads that object and refuses to delete anything
    /// if the stored id doesn't match its own. This eliminates *mutual*
    /// destruction between two colliding environments (at most one of them
    /// can ever win the claim) and gives the losing side a loud, permanent
    /// `gc_orphan_owner_mismatch` signal instead of silent data loss — but
    /// it does **not** protect the winning side's victim: whichever
    /// environment's sweep claims the prefix first can still delete the
    /// other, still-live environment's media as "orphans" on every run
    /// thereafter, since the winner's Postgres genuinely has no row for
    /// them. Distinct real buckets per environment remain a hard
    /// requirement; this is a one-directional-protection-plus-detection
    /// mechanism, not full isolation (threat-model-checker + security-
    /// auditor, cycle 426 fresh review pass — see prd.md §9.4.3).
    ///
    /// The conditional write closes the naive GET-then-PUT sequence's own
    /// TOCTOU: without it, two environments racing to claim the same
    /// *empty* prefix on their respective first-ever runs could both
    /// observe "absent" and both unconditionally PUT, both concluding
    /// ownership in the same run (the exact mutual-destruction case this
    /// mechanism exists to prevent). `If-None-Match: *` makes the loser's
    /// write fail with a precondition error instead, and the loser then
    /// re-reads whatever the winner wrote to compare against.
    ///
    /// A benign multi-replica boot race within the *same* environment is
    /// resolved by the atomic Postgres upsert below (`RETURNING` always
    /// yields the one persisted value, regardless of which replica's
    /// `INSERT` actually won) before any replica touches R2, so replicas of
    /// the same environment always agree before racing for the R2 write.
    ///
    /// Returns `Ok(true)` if this run owns the prefix and may proceed,
    /// `Ok(false)` if ownership is contested (fail closed — the caller must
    /// not delete anything this run). Real S3/Postgres errors propagate as
    /// errors, same as every other guard in this adapter.
    async fn verify_region_ownership(&self, region_prefix: &str) -> Result<bool, DomainError> {
        // Atomic upsert-or-fetch: `DO UPDATE` (even as a no-op on the PK
        // itself) forces `RETURNING` to fire on a pre-existing row, unlike
        // `DO NOTHING`, which would leave a second query needed to read it
        // back — closing a benign-but-real gap where a fetch immediately
        // after a `DO NOTHING` insert could race a concurrent replica's
        // still-uncommitted insert (security-auditor F2, cycle 426 fresh
        // review pass).
        let local_owner_id: Uuid = sqlx::query_scalar(
            "INSERT INTO media_region_owner (region_id, owner_id)
             VALUES ($1, $2)
             ON CONFLICT (region_id) DO UPDATE SET region_id = EXCLUDED.region_id
             RETURNING owner_id",
        )
        .bind(&self.region_id)
        .bind(Uuid::new_v4())
        .fetch_one(&self.pool)
        .await
        .map_err(map_sqlx)?;

        self.verify_region_ownership_with_local_id(region_prefix, local_owner_id)
            .await
    }

    /// The R2-only half of `verify_region_ownership`, split out so its
    /// claim/self-verify/race-loss branches are unit-testable against a
    /// mocked `S3Client` (see the `mock_s3_client` test helper below)
    /// without needing a real Postgres pool — `local_owner_id` is normally
    /// sourced from the Postgres upsert above, but the R2 read/claim/verify
    /// logic itself never touches `self.pool`. Pure extraction, no behavior
    /// change.
    async fn verify_region_ownership_with_local_id(
        &self,
        region_prefix: &str,
        local_owner_id: Uuid,
    ) -> Result<bool, DomainError> {
        let owner_key = format!("{region_prefix}{OWNER_SENTINEL_KEY_SUFFIX}");
        if let Some(remote_owner_id) = self.read_owner_sentinel(&owner_key).await? {
            return Ok(self.owner_matches(local_owner_id, remote_owner_id));
        }

        match self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(&owner_key)
            .if_none_match("*")
            .body(ByteStream::from(local_owner_id.to_string().into_bytes()))
            .send()
            .await
        {
            Ok(_) => {
                // Self-verify rather than trust the 2xx: a non-conforming
                // S3-compatible endpoint that silently ignores
                // `If-None-Match` would otherwise let two racing claimants
                // both observe success and both conclude ownership — the
                // exact mutual-destruction case this mechanism exists to
                // prevent (security-auditor Y1, cycle 426). R2 itself is
                // conformant, but the sweep is written against the
                // `S3Client` port, not R2 specifically, so this guard is
                // cheap and load-bearing for any future S3-compatible
                // adapter swap.
                match self.read_owner_sentinel(&owner_key).await? {
                    Some(remote_owner_id) => {
                        Ok(self.owner_matches(local_owner_id, remote_owner_id))
                    }
                    // The object we just wrote is already gone (e.g. a
                    // concurrent external deletion) — fail closed rather
                    // than assume the claim still holds.
                    None => Ok(false),
                }
            }
            Err(e) => {
                // `PreconditionFailed` is the code most S3-compatible
                // endpoints (including R2) return for a failed
                // `If-None-Match`; `ConditionalRequestConflict` is AWS S3's
                // own newer name for the same condition. Matching both
                // keeps the fail-closed generic-error branch below reserved
                // for genuinely unexpected errors rather than a known,
                // benign claim-race loss (security-auditor Y3, cycle 426).
                let lost_the_claim_race = e.as_service_error().is_some_and(|se| {
                    matches!(
                        se.code(),
                        Some("PreconditionFailed") | Some("ConditionalRequestConflict")
                    )
                });
                if !lost_the_claim_race {
                    return Err(map_r2(R2Error::S3(e.to_string())));
                }
                // Another environment's concurrent first claim won this
                // race — re-read whatever it wrote rather than assuming we
                // simply lost; either way this run fails closed.
                match self.read_owner_sentinel(&owner_key).await? {
                    Some(remote_owner_id) => {
                        Ok(self.owner_matches(local_owner_id, remote_owner_id))
                    }
                    None => Ok(false),
                }
            }
        }
    }

    /// Reads `owner_key`'s content as a `Uuid`, or `None` if the object
    /// doesn't exist (yet). Any other S3 error propagates.
    async fn read_owner_sentinel(&self, owner_key: &str) -> Result<Option<Uuid>, DomainError> {
        match self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(owner_key)
            .send()
            .await
        {
            Ok(out) => {
                let bytes = out
                    .body
                    .collect()
                    .await
                    .map_err(|e| map_r2(R2Error::S3(e.to_string())))?
                    .into_bytes();
                Ok(std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|s| Uuid::parse_str(s.trim()).ok()))
            }
            Err(e) => {
                if e.as_service_error().is_some_and(|se| se.is_no_such_key()) {
                    Ok(None)
                } else {
                    Err(map_r2(R2Error::S3(e.to_string())))
                }
            }
        }
    }

    /// Compares this environment's own owner id against the value read from
    /// R2, logging a diagnosable mismatch. Both ids are server-generated
    /// random v4 UUIDs with no linkage to users, devices, keys, or
    /// ciphertext, so logging them is not a plaintext/PII leak (rule:
    /// `no-plaintext-logging`) — and doing so is the only way this failure
    /// mode is diagnosable at all (security-auditor F3, cycle 426 fresh
    /// review pass).
    fn owner_matches(&self, local_owner_id: Uuid, remote_owner_id: Uuid) -> bool {
        let owned = local_owner_id == remote_owner_id;
        if !owned {
            tracing::error!(
                error_kind = "gc_orphan_owner_mismatch",
                local_owner_id = %local_owner_id,
                remote_owner_id = %remote_owner_id,
                "media.orphan_sweep_owner_mismatch_refusing_sweep"
            );
        }
        owned
    }

    /// Bulk-delete up to `DELETE_OBJECTS_MAX_KEYS` keys in one `DeleteObjects`
    /// call, returning how many were actually removed. Per-key failures are
    /// reported by S3 in the response body rather than as a call error, so
    /// they are counted out of the total and logged as a bare count under an
    /// error category — never the keys themselves (rule: no-plaintext-logging).
    async fn delete_object_batch(&self, keys: &[String]) -> Result<u64, DomainError> {
        let mut identifiers = Vec::with_capacity(keys.len());
        for key in keys {
            identifiers.push(
                ObjectIdentifier::builder()
                    .key(key)
                    // Fixed category string, not the builder error's message:
                    // that message can echo the offending field back into a
                    // log line, and this error surfaces through DomainError
                    // into the sweep job's `error = %e` field.
                    .build()
                    .map_err(|_| map_r2(R2Error::S3("object identifier build failed".into())))?,
            );
        }
        let delete = Delete::builder()
            .set_objects(Some(identifiers))
            // Quiet mode: suppress the per-key success list in the response
            // (we only need the count and the failures), keeping the response
            // body small and free of any key echo on the happy path.
            .quiet(true)
            .build()
            .map_err(|_| map_r2(R2Error::S3("delete request build failed".into())))?;
        let out = self
            .s3
            .delete_objects()
            .bucket(&self.bucket)
            .delete(delete)
            .send()
            .await
            .map_err(|e| map_r2(R2Error::S3(e.to_string())))?;
        let failed = out.errors().len();
        if failed > 0 {
            tracing::warn!(
                error_kind = "r2_bulk_delete",
                failed = failed,
                "media.orphan_sweep_batch_partial_failure"
            );
        }
        Ok(keys.len().saturating_sub(failed) as u64)
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

    // Orphan sweep (closes the cycle 419-421 deferred finding; see the trait
    // doc comment on `sweep_orphaned_storage_objects` for the race itself).
    // Deliberately a periodic reconciliation rather than an upload-confirmation
    // transaction: the sweep is adapter-only and reuses the existing
    // leader-lock/interval background-job pattern, whereas making the object
    // and the row commit atomically would mean reworking the client upload API
    // contract (the client PUTs straight to R2 without ever calling back).
    //
    // Bucket enumeration is the only place in this adapter that touches
    // objects it has no row for, so it is also the only place that could leak
    // a key into a log line — the whole method logs nothing but counts and
    // error categories.
    #[instrument(skip(self, older_than))]
    async fn sweep_orphaned_storage_objects(
        &self,
        older_than: DateTime<Utc>,
    ) -> Result<u64, DomainError> {
        // Compared in epoch seconds against S3's own `LastModified`, avoiding a
        // fallible smithy-DateTime -> chrono conversion in a path that must not
        // panic. Second-granularity truncation is irrelevant against a grace
        // period measured in hours, and rounds toward NOT deleting.
        let cutoff_epoch_secs = older_than.timestamp();
        let region_prefix = self.region_prefix();

        // Ownership gate: refuse to delete anything if another environment
        // has already claimed this exact region_prefix (see
        // `verify_region_ownership`'s doc comment) — fail closed rather than
        // trust a bucket-wide LIST that could belong to someone else.
        if !self.verify_region_ownership(&region_prefix).await? {
            return Ok(0);
        }
        let owner_key = format!("{region_prefix}{OWNER_SENTINEL_KEY_SUFFIX}");

        let mut continuation: Option<String> = None;
        let mut deleted_total: u64 = 0;
        // Budget consumption is tracked by keys *attempted*, not keys
        // actually deleted — `deleted_total` alone would let a run where
        // every `DeleteObjects` call fails (e.g. a transient R2 outage) never
        // advance the cap, issuing bulk-delete calls for the entire
        // `media_orphan_sweep_timeout_secs` budget instead of backing off
        // (security-auditor finding, cycle 424).
        let mut attempted_deletes_total: u64 = 0;
        // Cumulative across the whole run (not per-page): feeds the ratio
        // circuit breaker below, which must judge the run as a whole, not
        // reset its judgement every 1000-key page.
        let mut aged_checked_total: usize = 0;
        let mut orphans_found_total: usize = 0;

        'paginate: loop {
            let page = self
                .s3
                .list_objects_v2()
                .bucket(&self.bucket)
                // Region scope (see `region_prefix`): structurally prevents
                // this replica from ever enumerating — let alone deleting —
                // another region's objects, even if the bucket itself is
                // shared or misconfigured across regions.
                .prefix(&region_prefix)
                .set_continuation_token(continuation.take())
                .send()
                .await
                .map_err(|e| map_r2(R2Error::S3(e.to_string())))?;

            // Only past-grace objects are candidates. An object with no
            // `LastModified` at all is skipped rather than swept: unknown age
            // must fail closed, since deleting a live in-flight upload is
            // unrecoverable while leaving an orphan another 6 hours is not.
            let aged_keys: Vec<String> = page
                .contents()
                .iter()
                // Never treat this adapter's own ownership marker as a
                // candidate: it has no `media_blobs` row by design, so
                // without this it would eventually age past the grace
                // period and get swept away by the very mechanism it gates.
                .filter(|obj| obj.key() != Some(owner_key.as_str()))
                .filter(|obj| {
                    obj.last_modified()
                        .is_some_and(|t| t.secs() < cutoff_epoch_secs)
                })
                .filter_map(|obj| obj.key().map(str::to_string))
                .collect();

            if !aged_keys.is_empty() {
                aged_checked_total += aged_keys.len();
                // One `= ANY($1)` per page, not one query per key: a bucket
                // sweep is O(objects) and an N+1 here would put a query per
                // stored blob on the DB every 6 hours.
                let known: Vec<String> = sqlx::query_scalar(
                    "SELECT storage_key FROM media_blobs WHERE storage_key = ANY($1)",
                )
                .bind(&aged_keys)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx)?;
                let known: HashSet<String> = known.into_iter().collect();
                let orphans: Vec<String> = aged_keys
                    .into_iter()
                    .filter(|key| !known.contains(key))
                    .collect();
                orphans_found_total += orphans.len();

                // Circuit breaker: a suspiciously high cumulative orphan rate
                // means `media_blobs` itself is the untrustworthy party this
                // run (wrong/empty database, cross-region bucket collision),
                // not that storage is genuinely full of orphans — stop before
                // deleting anything from this page or any further one.
                if aged_checked_total >= ORPHAN_RATIO_ABORT_MIN_SAMPLE
                    && (orphans_found_total as u64) * 100
                        >= (aged_checked_total as u64) * ORPHAN_RATIO_ABORT_THRESHOLD_PERCENT
                {
                    tracing::warn!(
                        error_kind = "gc_orphan_ratio_guard",
                        aged_checked = aged_checked_total,
                        orphans_found = orphans_found_total,
                        deleted_before_abort = deleted_total,
                        "media.orphan_sweep_ratio_guard_triggered"
                    );
                    break 'paginate;
                }

                // Below the ratio guard's minimum sample size, there isn't
                // enough evidence yet to trust a low orphan ratio, so this
                // run's effective budget is the small pre-sample cap instead
                // of the full configured `max_deletes_per_run` — see
                // `ORPHAN_PRE_SAMPLE_MAX_DELETES`.
                let effective_cap = if aged_checked_total < ORPHAN_RATIO_ABORT_MIN_SAMPLE {
                    ORPHAN_PRE_SAMPLE_MAX_DELETES.min(self.max_deletes_per_run)
                } else {
                    self.max_deletes_per_run
                };
                for chunk in orphans.chunks(DELETE_OBJECTS_MAX_KEYS) {
                    // Blast-radius cap: never delete past the configured
                    // per-run budget (or, pre-sample, the smaller
                    // `effective_cap`) regardless of how many more orphans
                    // this or a later page finds. A truncated run is not
                    // lossy — whatever's left is still row-checked and
                    // re-evaluated next tick.
                    let remaining_budget = effective_cap.saturating_sub(attempted_deletes_total);
                    if remaining_budget == 0 {
                        tracing::warn!(
                            error_kind = "gc_max_deletes_cap",
                            cap = effective_cap,
                            pre_sample = aged_checked_total < ORPHAN_RATIO_ABORT_MIN_SAMPLE,
                            "media.orphan_sweep_max_deletes_reached"
                        );
                        break 'paginate;
                    }
                    let take = (chunk.len() as u64).min(remaining_budget) as usize;
                    attempted_deletes_total += take as u64;
                    deleted_total += self.delete_object_batch(&chunk[..take]).await?;
                }
            }

            // Deleting keys already returned by an earlier page is safe:
            // `list_objects_v2` continuation is key-ordered, so a removed key
            // can never shift an unvisited one out of a later page.
            continuation = page.next_continuation_token().map(str::to_string);
            if continuation.is_none() {
                break;
            }
        }
        Ok(deleted_total)
    }
}

#[cfg(test)]
mod tests {
    use aws_smithy_http_client::test_util::{ReplayEvent, StaticReplayClient};
    use aws_smithy_types::body::SdkBody;

    use super::*;

    /// Builds an `S3Client` whose HTTP transport is a `StaticReplayClient`
    /// returning `responses` in order regardless of the actual request sent —
    /// lets `verify_region_ownership_with_local_id`'s claim/self-verify/
    /// race-loss branches (including the mismatch/vanished-on-success paths
    /// no real S3-compatible backend will deterministically reproduce) be
    /// unit-tested without Docker/MinIO.
    fn mock_s3_client(responses: Vec<http::Response<SdkBody>>) -> S3Client {
        let dummy_request = || {
            http::Request::builder()
                .uri("https://example.test/")
                .body(SdkBody::empty())
                .expect("static request builds")
        };
        let events = responses
            .into_iter()
            .map(|resp| ReplayEvent::new(dummy_request(), resp))
            .collect::<Vec<_>>();
        let cfg = S3ConfigBuilder::new()
            .region(Region::new("auto"))
            .endpoint_url("https://example.test")
            .credentials_provider(Credentials::new(
                "key",
                "secret",
                None,
                None,
                "powehi-r2-test",
            ))
            .force_path_style(true)
            .http_client(StaticReplayClient::new(events))
            .build();
        S3Client::from_conf(cfg)
    }

    fn owner_sentinel_adapter(s3: S3Client) -> R2MediaAdapter {
        R2MediaAdapter {
            pool: PgPool::connect_lazy("postgres://localhost/unused")
                .expect("lazy pool never connects"),
            s3,
            bucket: "bucket".into(),
            upload_ttl: Duration::from_secs(900),
            download_ttl: Duration::from_secs(300),
            region_id: "eu-central-1".into(),
            max_deletes_per_run: 500,
        }
    }

    fn no_such_key_response() -> http::Response<SdkBody> {
        http::Response::builder()
            .status(404)
            .header("content-type", "application/xml")
            .body(SdkBody::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <Error><Code>NoSuchKey</Code>\
                 <Message>The specified key does not exist.</Message>\
                 <Key>x</Key><RequestId>req</RequestId><HostId>host</HostId></Error>",
            ))
            .expect("static response builds")
    }

    fn owner_body_response(id: Uuid) -> http::Response<SdkBody> {
        http::Response::builder()
            .status(200)
            .body(SdkBody::from(id.to_string()))
            .expect("static response builds")
    }

    fn put_ok_response() -> http::Response<SdkBody> {
        http::Response::builder()
            .status(200)
            .body(SdkBody::empty())
            .expect("static response builds")
    }

    fn precondition_failed_response() -> http::Response<SdkBody> {
        http::Response::builder()
            .status(412)
            .header("content-type", "application/xml")
            .body(SdkBody::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <Error><Code>PreconditionFailed</Code>\
                 <Message>At least one of the pre-conditions you specified did not hold.</Message>\
                 <RequestId>req</RequestId><HostId>host</HostId></Error>",
            ))
            .expect("static response builds")
    }

    #[tokio::test]
    async fn verify_region_ownership_already_claimed_matches() {
        let local_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![owner_body_response(local_id)]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(owned, "matching remote owner id must be treated as owned");
    }

    #[tokio::test]
    async fn verify_region_ownership_already_claimed_mismatch_fails_closed() {
        let local_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![owner_body_response(other_id)]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(!owned, "a foreign remote owner id must fail closed");
    }

    #[tokio::test]
    async fn verify_region_ownership_claims_when_absent_and_self_verify_matches() {
        let local_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![
            no_such_key_response(),        // initial read: sentinel absent
            put_ok_response(),             // conditional claim PUT succeeds
            owner_body_response(local_id), // self-verify re-read matches
        ]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(
            owned,
            "a self-verified successful claim must be treated as owned"
        );
    }

    /// security-auditor Y1 (cycle 426): the claim-success path must not
    /// trust the SDK's 2xx blindly. A non-conforming S3-compatible endpoint
    /// that silently ignores `If-None-Match: *` could let two racing
    /// claimants both observe a "successful" PUT — this reproduces that
    /// exact scenario (PUT reports success, but the self-verify re-read
    /// shows a different id already stored) deterministically, which no
    /// real MinIO/R2 backend will do since both honor the conditional
    /// header correctly.
    #[tokio::test]
    async fn verify_region_ownership_self_verify_mismatch_fails_closed() {
        let local_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![
            no_such_key_response(),
            put_ok_response(),
            owner_body_response(other_id), // self-verify sees someone else's id
        ]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(
            !owned,
            "a non-conforming endpoint that let the PUT through despite a losing race \
             must fail closed on self-verify mismatch, not trust the 2xx"
        );
    }

    /// security-auditor Y1 (cycle 426), the other self-verify failure mode:
    /// the object we just wrote is already gone by the time we re-read it
    /// (e.g. a concurrent external delete) — must fail closed rather than
    /// assume the claim still holds.
    #[tokio::test]
    async fn verify_region_ownership_self_verify_vanished_fails_closed() {
        let local_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![
            no_such_key_response(),
            put_ok_response(),
            no_such_key_response(), // self-verify: sentinel vanished
        ]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(
            !owned,
            "the sentinel vanishing between the claim write and the self-verify read \
             must fail closed, not assume the claim still holds"
        );
    }

    /// security-auditor Y3 (cycle 426): `PreconditionFailed` on the claim PUT
    /// is a genuine claim-race loss, not an error — the losing side must
    /// re-read and compare against whatever the winner wrote, not assume
    /// loss without checking.
    #[tokio::test]
    async fn verify_region_ownership_claim_race_loss_precondition_failed_reads_winner() {
        let local_id = Uuid::new_v4();
        let winner_id = Uuid::new_v4();
        let adapter = owner_sentinel_adapter(mock_s3_client(vec![
            no_such_key_response(),
            precondition_failed_response(),
            owner_body_response(winner_id),
        ]));
        let owned = adapter
            .verify_region_ownership_with_local_id("media/eu-central-1/", local_id)
            .await
            .expect("no S3 error");
        assert!(
            !owned,
            "losing the claim race means the winner's id, not ours, is stored remotely"
        );
    }

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
    fn delete_objects_max_keys_matches_s3_api_limit() {
        assert_eq!(DELETE_OBJECTS_MAX_KEYS, 1_000);
    }

    #[tokio::test]
    async fn region_prefix_is_scoped_under_media_and_region_id() {
        let adapter = R2MediaAdapter {
            pool: PgPool::connect_lazy("postgres://localhost/unused")
                .expect("lazy pool never connects"),
            s3: S3Client::from_conf(build_s3_config(
                "http://localhost:9000",
                "key",
                "secret",
                30,
            )),
            bucket: "bucket".into(),
            upload_ttl: Duration::from_secs(900),
            download_ttl: Duration::from_secs(300),
            region_id: "eu-central-1".into(),
            max_deletes_per_run: 500,
        };
        assert_eq!(adapter.region_prefix(), "media/eu-central-1/");
    }

    #[test]
    fn orphan_ratio_guard_thresholds_are_sane() {
        // Min sample stays below what a small test bucket/fixture set would
        // ever hit, and the threshold stays high enough that a real (rare)
        // orphan alongside normal traffic never trips it, while low enough to
        // catch a ~50/50 orphan rate (two deployments sharing both a bucket
        // and a region_id) rather than only a near-total mismatch.
        assert_eq!(ORPHAN_RATIO_ABORT_MIN_SAMPLE, 50);
        assert_eq!(ORPHAN_RATIO_ABORT_THRESHOLD_PERCENT, 50);
        assert!(ORPHAN_PRE_SAMPLE_MAX_DELETES < ORPHAN_RATIO_ABORT_MIN_SAMPLE as u64);
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
