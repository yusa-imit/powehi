//! Testcontainers integration tests for powehi-r2 `R2MediaAdapter`.
//!
//! `R2MediaAdapter` straddles two backends, so each test spins up BOTH:
//!   - an ephemeral Postgres container (media_blobs metadata rows), migrated
//!     via `powehi_postgres::run_migrations`, and
//!   - an ephemeral MinIO container (S3-compatible object store) for real
//!     pre-signed PUT/GET URL generation.
//!
//! No mocks — this exercises behaviour a fake could never validate:
//!   - `save` -> `find_by_id` metadata round-trip (group_id Some AND None).
//!   - `find_by_id` on a missing id returns `Ok(None)`.
//!   - `save` idempotency (INSERT ... ON CONFLICT (id) DO NOTHING).
//!   - `presigned_upload_url` rejects a disallowed content-type BEFORE touching S3,
//!     and returns a URL for an allowed type against a real row.
//!   - `presigned_upload_url`/`presigned_download_url` NotFound for an absent row.
//!   - `presigned_download_url` embeds the bucket + storage_key.
//!   - `delete` removes BOTH the S3 object and the Postgres row; delete of an
//!     absent id is a no-op (not an error).
//!   - full upload->download round-trip through the pre-signed URLs (reqwest PUT/GET).
//!
//! Uses postgres:16-alpine explicitly (the modules default 11-alpine is EOL) and
//! minio/minio:RELEASE.2022-02-07T08-17-33Z (the modules default) which serves the
//! S3 API on container port 9000, ready once stdout contains `"API:"`.
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers).
//! Run them in CI via: `cargo nextest run -p powehi-r2 --run-ignored all
//!                       -E 'binary(r2_media_it)'`
//!
//! SECURITY: every fixture below is metadata only (opaque UUID storage keys,
//! content-type hints, byte sizes) plus test-authored opaque bytes for the
//! upload round-trip — never real message plaintext or PII. This asserts
//! STORAGE-KEY LIFECYCLE correctness; the server-never-sees-plaintext invariant
//! (rule: `no-plaintext-logging`) is unaffected by this change.

use aws_credential_types::Credentials;
use aws_sdk_s3::config::{Builder as S3ConfigBuilder, Region};
use aws_sdk_s3::Client as S3Client;
use chrono::Utc;
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    group::{Group, GroupId},
    media::{MediaBlob, MediaId},
    region::RegionId,
    user::{User, UserId},
};
use powehi_port_outbound::{
    device_repo::DeviceRepository, group_repo::GroupRepository, media_repo::MediaRepository,
    user_repo::UserRepository,
};
use powehi_postgres::{PgDeviceRepository, PgGroupRepository, PgUserRepository};
use powehi_r2::R2MediaAdapter;
use sqlx::PgPool;
use testcontainers::{runners::AsyncRunner, ContainerAsync, ImageExt};
use testcontainers_modules::{minio::MinIO, postgres::Postgres};
use uuid::Uuid;

// ── Constants ─────────────────────────────────────────────────────────────────

/// MinIO default credentials (image `minio/minio:RELEASE.2022-02-07T08-17-33Z`).
const MINIO_ACCESS_KEY: &str = "minioadmin";
/// MinIO default secret credential (the modules image ships this static value).
const MINIO_SECRET: &str = "minioadmin";
/// Bucket the adapter and fixtures share, created before `R2MediaAdapter::new`.
const TEST_BUCKET: &str = "powehi-media-test";
const UPLOAD_TTL_SECS: u64 = 900;
const DOWNLOAD_TTL_SECS: u64 = 300;
/// Bounds each R2 operation (and each individual attempt) issued by the adapter.
const REQUEST_TIMEOUT_SECS: u64 = 30;

// ── Container setup ───────────────────────────────────────────────────────────

/// Everything a test needs, with both containers kept alive for its duration.
struct Harness {
    _pg: ContainerAsync<Postgres>,
    _minio: ContainerAsync<MinIO>,
    adapter: R2MediaAdapter,
    pool: PgPool,
    /// A raw S3 client (same endpoint/creds/bucket) for bucket setup + assertions.
    s3: S3Client,
}

/// Build an S3 client identical in config to the one `R2MediaAdapter` builds
/// internally: path-style addressing, static creds, endpoint at the MinIO port.
fn build_s3_client(endpoint: &str) -> S3Client {
    let creds = Credentials::new(MINIO_ACCESS_KEY, MINIO_SECRET, None, None, "powehi-r2-it");
    let cfg = S3ConfigBuilder::new()
        .region(Region::new("us-east-1"))
        .endpoint_url(endpoint)
        .credentials_provider(creds)
        .force_path_style(true)
        .build();
    S3Client::from_conf(cfg)
}

/// Start a throwaway Postgres + MinIO pair, migrate the DB, create the bucket,
/// and return a ready `R2MediaAdapter` plus handles for fixtures and assertions.
/// Caller must keep the returned containers alive for the duration of the test.
async fn setup() -> Harness {
    // Postgres (16-alpine — the modules default 11-alpine is EOL).
    let pg = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("Postgres container started");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg host port");
    let db_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");
    let pool = powehi_postgres::connect(&db_url, 10)
        .await
        .expect("connect pg");
    powehi_postgres::run_migrations(&pool)
        .await
        .expect("migrations");

    // MinIO (S3 API on port 9000, ready once stdout has "API:").
    let minio = MinIO::default()
        .start()
        .await
        .expect("MinIO container started");
    let minio_port = minio
        .get_host_port_ipv4(9000)
        .await
        .expect("minio host port");
    let endpoint = format!("http://127.0.0.1:{minio_port}");

    // Create the bucket BEFORE constructing the adapter (mirrors minio_buckets).
    let s3 = build_s3_client(&endpoint);
    s3.create_bucket()
        .bucket(TEST_BUCKET)
        .send()
        .await
        .expect("create bucket");

    let adapter = R2MediaAdapter::new(
        pool.clone(),
        &endpoint,
        TEST_BUCKET,
        MINIO_ACCESS_KEY,
        MINIO_SECRET,
        UPLOAD_TTL_SECS,
        DOWNLOAD_TTL_SECS,
        REQUEST_TIMEOUT_SECS,
    );

    Harness {
        _pg: pg,
        _minio: minio,
        adapter,
        pool,
        s3,
    }
}

// ── Fixture helpers ───────────────────────────────────────────────────────────

/// Insert a user + device and return the device id. media_blobs.uploader_device_id
/// is a NOT NULL FK to devices(id), so a blob needs a real device row first.
/// Random UUIDs keep the handle_hash / mls_credential unique per call.
async fn insert_device(pool: &PgPool) -> DeviceId {
    let h1 = Uuid::new_v4();
    let h2 = Uuid::new_v4();
    let handle_hash = [h1.as_bytes().as_slice(), h2.as_bytes().as_slice()].concat();
    let user = User::new(UserId::new(), handle_hash);
    PgUserRepository::new(pool.clone())
        .save(&user)
        .await
        .expect("insert user");

    let cred_uuid = Uuid::new_v4();
    let mut cred = [0u8; 32];
    cred[..16].copy_from_slice(cred_uuid.as_bytes());
    let device = Device::new(DeviceId::new(), user.id, cred.to_vec());
    PgDeviceRepository::new(pool.clone())
        .save(&device)
        .await
        .expect("insert device");
    device.id
}

/// Insert a group and return its id (media_blobs.group_id FKs groups(id)).
async fn insert_group(pool: &PgPool) -> GroupId {
    let group = Group::new(GroupId::new(), RegionId::new("eu-de-1"));
    PgGroupRepository::new(pool.clone())
        .save(&group)
        .await
        .expect("insert group");
    group.id
}

/// A realistic media-blob fixture. `storage_key` is an opaque object reference,
/// `content_type` a metadata hint — never actual (decrypted) content.
fn media_fixture(uploader: DeviceId, group_id: Option<GroupId>) -> MediaBlob {
    MediaBlob {
        id: MediaId::new(),
        uploader_device: uploader,
        storage_key: format!("media/{}/blob", Uuid::new_v4()),
        content_type: "image/jpeg".to_string(),
        size_bytes: 4096,
        uploaded_at: Utc::now(),
        expires_at: None,
        group_id,
    }
}

/// List object keys under `prefix` in the test bucket (for delete assertions).
async fn list_keys(s3: &S3Client, prefix: &str) -> Vec<String> {
    s3.list_objects_v2()
        .bucket(TEST_BUCKET)
        .prefix(prefix)
        .send()
        .await
        .expect("list_objects_v2")
        .contents()
        .iter()
        .filter_map(|o| o.key().map(str::to_string))
        .collect()
}

// ── save / find_by_id round-trip ──────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn save_then_find_by_id_round_trips_without_group() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let blob = media_fixture(device, None);

    h.adapter.save(&blob).await.expect("save");
    let got = h
        .adapter
        .find_by_id(&blob.id)
        .await
        .expect("find_by_id")
        .expect("must be Some after save");

    assert_eq!(got.id, blob.id);
    assert_eq!(got.uploader_device, blob.uploader_device);
    assert_eq!(got.storage_key, blob.storage_key);
    assert_eq!(got.content_type, blob.content_type);
    assert_eq!(got.size_bytes, blob.size_bytes);
    assert!(got.group_id.is_none(), "group_id must round-trip as None");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn save_then_find_by_id_round_trips_with_group() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let group_id = insert_group(&h.pool).await;
    let blob = media_fixture(device, Some(group_id.clone()));

    h.adapter.save(&blob).await.expect("save");
    let got = h
        .adapter
        .find_by_id(&blob.id)
        .await
        .expect("find_by_id")
        .expect("must be Some after save");

    assert_eq!(
        got.group_id,
        Some(group_id),
        "group_id Some(..) must round-trip verbatim"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_by_id_returns_none_for_unknown_id() {
    let h = setup().await;
    let got = h
        .adapter
        .find_by_id(&MediaId::from(Uuid::new_v4()))
        .await
        .expect("find_by_id");
    assert!(got.is_none(), "unknown media id must return Ok(None)");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn save_is_idempotent_on_conflict() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let mut blob = media_fixture(device, None);
    let original_key = blob.storage_key.clone();

    h.adapter.save(&blob).await.expect("first save");

    // Second save with the SAME id but mutated fields must be a no-op
    // (ON CONFLICT (id) DO NOTHING) — no error, original row survives.
    blob.storage_key = format!("media/{}/overwrite-attempt", Uuid::new_v4());
    blob.content_type = "video/mp4".to_string();
    h.adapter
        .save(&blob)
        .await
        .expect("second save must be idempotent, not error");

    let got = h
        .adapter
        .find_by_id(&blob.id)
        .await
        .expect("find_by_id")
        .expect("row must still exist");
    assert_eq!(
        got.storage_key, original_key,
        "DO NOTHING must preserve the first writer's storage_key"
    );
    assert_eq!(
        got.content_type, "image/jpeg",
        "DO NOTHING must preserve the first writer's content_type"
    );
}

// ── presigned_upload_url ──────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_url_returns_url_for_allowed_type() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let blob = media_fixture(device, None);
    h.adapter.save(&blob).await.expect("save");

    let url = h
        .adapter
        .presigned_upload_url(&blob.id, "image/png")
        .await
        .expect("presigned_upload_url for allowed type");
    assert!(url.contains(TEST_BUCKET), "url must target the bucket");
    assert!(
        url.contains(&blob.storage_key),
        "url must reference the row's storage_key"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_url_rejects_body_larger_than_declared_size_bytes() {
    // Regression test: `size_bytes` used to be purely advisory (never reached the
    // SigV4 signature), so a client could declare a tiny size then PUT an
    // arbitrarily large body to the same URL — unbounded R2 storage/egress cost
    // regardless of the server-side MAX_MEDIA_BYTES check on request_upload.
    // `presigned_upload_url` now signs `content-length`, so R2 must reject any
    // PUT whose actual body length differs from the declared `size_bytes`.
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let mut blob = media_fixture(device, None);
    blob.size_bytes = 8; // declare a tiny upload
    h.adapter.save(&blob).await.expect("save");

    let upload_url = h
        .adapter
        .presigned_upload_url(&blob.id, &blob.content_type)
        .await
        .expect("presigned_upload_url");

    // Attempt to PUT far more than the signed 8 bytes.
    let oversized_body = vec![0xABu8; 4096];
    let client = reqwest::Client::new();
    let resp = client
        .put(&upload_url)
        .header("content-type", &blob.content_type)
        .body(oversized_body)
        .send()
        .await
        .expect(
            "PUT request must complete (rejection is an HTTP error status, not a transport error)",
        );

    assert!(
        !resp.status().is_success(),
        "a PUT body larger than the signed content-length must be rejected, got {}",
        resp.status()
    );
    assert!(
        list_keys(&h.s3, &blob.storage_key).await.is_empty(),
        "a rejected oversized upload must not leave an object in S3"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_url_rejects_body_smaller_than_declared_size_bytes() {
    // Same signature-binding mechanism, opposite direction: an undersized body
    // must also be rejected (content-length is exact-match, not a ceiling).
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let mut blob = media_fixture(device, None);
    blob.size_bytes = 4096;
    h.adapter.save(&blob).await.expect("save");

    let upload_url = h
        .adapter
        .presigned_upload_url(&blob.id, &blob.content_type)
        .await
        .expect("presigned_upload_url");

    let undersized_body = vec![0xCDu8; 8];
    let client = reqwest::Client::new();
    let resp = client
        .put(&upload_url)
        .header("content-type", &blob.content_type)
        .body(undersized_body)
        .send()
        .await
        .expect(
            "PUT request must complete (rejection is an HTTP error status, not a transport error)",
        );

    assert!(
        !resp.status().is_success(),
        "a PUT body smaller than the signed content-length must be rejected, got {}",
        resp.status()
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_url_rejects_disallowed_content_type() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let blob = media_fixture(device, None);
    h.adapter.save(&blob).await.expect("save");

    // validate_content_type runs BEFORE any S3 call, so a disallowed type
    // must fail even though the row exists.
    let err = h
        .adapter
        .presigned_upload_url(&blob.id, "text/html")
        .await
        .expect_err("text/html must be rejected");
    assert!(
        matches!(err, DomainError::InvalidInput(_)),
        "disallowed content-type must be InvalidInput, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_url_not_found_for_missing_row() {
    let h = setup().await;
    let err = h
        .adapter
        .presigned_upload_url(&MediaId::from(Uuid::new_v4()), "image/jpeg")
        .await
        .expect_err("missing row must error");
    assert!(
        matches!(err, DomainError::NotFound(_)),
        "missing media row must be NotFound, got {err:?}"
    );
}

// ── presigned_download_url ────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_download_url_not_found_for_missing_row() {
    let h = setup().await;
    let err = h
        .adapter
        .presigned_download_url(&MediaId::from(Uuid::new_v4()))
        .await
        .expect_err("missing row must error");
    assert!(
        matches!(err, DomainError::NotFound(_)),
        "missing media row must be NotFound, got {err:?}"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_download_url_contains_bucket_and_key() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let blob = media_fixture(device, None);
    h.adapter.save(&blob).await.expect("save");

    let url = h
        .adapter
        .presigned_download_url(&blob.id)
        .await
        .expect("presigned_download_url");
    assert!(url.contains(TEST_BUCKET), "url must target the bucket");
    assert!(
        url.contains(&blob.storage_key),
        "url must reference the row's storage_key"
    );
}

// ── delete ────────────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn delete_removes_s3_object_and_row() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let body = b"opaque-ciphertext-bytes".to_vec();
    let mut blob = media_fixture(device, None);
    // size_bytes is now bound into the presigned URL's signature (content-length) —
    // it must equal the actual PUT body length or the upload is rejected.
    blob.size_bytes = body.len() as u64;
    h.adapter.save(&blob).await.expect("save");

    // Put a real object at the key via the pre-signed upload URL so we can
    // prove delete removes it from S3 (not just the metadata row).
    let upload_url = h
        .adapter
        .presigned_upload_url(&blob.id, &blob.content_type)
        .await
        .expect("presigned_upload_url");
    let client = reqwest::Client::new();
    let resp = client
        .put(&upload_url)
        .header("content-type", &blob.content_type)
        .body(body)
        .send()
        .await
        .expect("PUT to presigned url");
    assert!(resp.status().is_success(), "upload PUT must succeed");
    assert_eq!(
        list_keys(&h.s3, &blob.storage_key).await,
        vec![blob.storage_key.clone()],
        "object must exist in S3 before delete"
    );

    h.adapter.delete(&blob.id).await.expect("delete");

    assert!(
        list_keys(&h.s3, &blob.storage_key).await.is_empty(),
        "delete must remove the S3 object"
    );
    assert!(
        h.adapter
            .find_by_id(&blob.id)
            .await
            .expect("find_by_id after delete")
            .is_none(),
        "delete must remove the Postgres row"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn delete_nonexistent_id_is_a_noop() {
    let h = setup().await;
    // delete's impl short-circuits the S3 call when find_by_id is None and the
    // DELETE affects zero rows — must not error.
    h.adapter
        .delete(&MediaId::from(Uuid::new_v4()))
        .await
        .expect("delete of unknown id must be a no-op, not an error");
}

// ── full pre-signed upload -> download round-trip ─────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn presigned_upload_then_download_round_trips_bytes() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    // Opaque, test-authored bytes — stands in for client-side E2EE ciphertext.
    let payload = b"\x00\x01\x02opaque-e2ee-ciphertext\xfe\xff".to_vec();
    let mut blob = media_fixture(device, None);
    // size_bytes is now bound into the presigned URL's signature (content-length) —
    // it must equal the actual PUT body length or the upload is rejected.
    blob.size_bytes = payload.len() as u64;
    h.adapter.save(&blob).await.expect("save");

    let client = reqwest::Client::new();

    let upload_url = h
        .adapter
        .presigned_upload_url(&blob.id, &blob.content_type)
        .await
        .expect("presigned_upload_url");
    let put = client
        .put(&upload_url)
        .header("content-type", &blob.content_type)
        .body(payload.clone())
        .send()
        .await
        .expect("PUT to presigned url");
    assert!(put.status().is_success(), "upload PUT must succeed");

    let download_url = h
        .adapter
        .presigned_download_url(&blob.id)
        .await
        .expect("presigned_download_url");
    let got = client
        .get(&download_url)
        .send()
        .await
        .expect("GET presigned url")
        .bytes()
        .await
        .expect("read body");
    assert_eq!(
        got.as_ref(),
        payload.as_slice(),
        "downloaded bytes must equal the uploaded bytes"
    );
}

// ── media_acks (GC bookkeeping) ────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn record_ack_then_list_ack_device_ids_round_trips() {
    let h = setup().await;
    let uploader = insert_device(&h.pool).await;
    let recipient = insert_device(&h.pool).await;
    let blob = media_fixture(uploader, None);
    h.adapter.save(&blob).await.expect("save");

    assert!(
        h.adapter
            .list_ack_device_ids(&blob.id)
            .await
            .expect("list_ack_device_ids")
            .is_empty(),
        "no acks recorded yet"
    );

    h.adapter
        .record_ack(&blob.id, &recipient)
        .await
        .expect("record_ack");

    let acked = h
        .adapter
        .list_ack_device_ids(&blob.id)
        .await
        .expect("list_ack_device_ids");
    assert_eq!(acked, vec![recipient]);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn record_ack_is_idempotent_on_conflict() {
    let h = setup().await;
    let uploader = insert_device(&h.pool).await;
    let recipient = insert_device(&h.pool).await;
    let blob = media_fixture(uploader, None);
    h.adapter.save(&blob).await.expect("save");

    h.adapter
        .record_ack(&blob.id, &recipient)
        .await
        .expect("first record_ack");
    h.adapter
        .record_ack(&blob.id, &recipient)
        .await
        .expect("second record_ack must not error (ON CONFLICT DO NOTHING)");

    let acked = h
        .adapter
        .list_ack_device_ids(&blob.id)
        .await
        .expect("list_ack_device_ids");
    assert_eq!(acked.len(), 1, "duplicate ack must not create a second row");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn record_ack_for_unknown_media_id_is_rejected() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let unknown = MediaId::from(Uuid::new_v4());
    let err = h
        .adapter
        .record_ack(&unknown, &device)
        .await
        .expect_err("media_id FK must reject an unknown blob id");
    assert!(matches!(err, DomainError::Internal(_)));
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn list_gc_candidates_filters_paginates_and_keysets() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;

    let now = Utc::now();
    let cutoff = now - chrono::Duration::days(30);

    // Three GC-eligible blobs (uploaded past the 30-day retention window, no
    // explicit expiry) ...
    let mut eligible: Vec<MediaId> = Vec::new();
    for _ in 0..3 {
        let mut b = media_fixture(device.clone(), None);
        b.uploaded_at = now - chrono::Duration::days(31);
        h.adapter.save(&b).await.expect("save eligible");
        eligible.push(b.id);
    }
    // ... and one too-recent blob that must be excluded from candidates.
    let mut recent = media_fixture(device.clone(), None);
    recent.uploaded_at = now;
    h.adapter.save(&recent).await.expect("save recent");

    // Full candidate set: exactly the 3 eligible rows, never the recent one,
    // ordered by id ascending (the keyset invariant).
    let all = h
        .adapter
        .list_gc_candidates(now, cutoff, None, 100)
        .await
        .expect("list_gc_candidates");
    assert_eq!(all.len(), 3, "only eligible blobs are candidates");
    assert!(
        all.iter().all(|blob| blob.id != recent.id),
        "too-recent blob must be excluded"
    );
    for id in &eligible {
        assert!(
            all.iter().any(|blob| &blob.id == id),
            "each eligible blob must appear"
        );
    }
    assert!(
        all.windows(2)
            .all(|w| w[0].id.as_uuid() < w[1].id.as_uuid()),
        "candidates must be ordered by id ascending"
    );

    // LIMIT caps the page size ...
    let page1 = h
        .adapter
        .list_gc_candidates(now, cutoff, None, 2)
        .await
        .expect("page1");
    assert_eq!(page1.len(), 2, "LIMIT must cap the page size");

    // ... and keyset pagination from the last id returns the remaining rows
    // with no repeats and no skips.
    let last = page1.last().expect("page1 not empty").id.clone();
    let page2 = h
        .adapter
        .list_gc_candidates(now, cutoff, Some(last), 2)
        .await
        .expect("page2");
    assert_eq!(
        page2.len(),
        1,
        "exactly one eligible blob remains after page1"
    );

    let mut seen: Vec<MediaId> = page1
        .iter()
        .chain(page2.iter())
        .map(|blob| blob.id.clone())
        .collect();
    seen.sort_by_key(MediaId::as_uuid);
    seen.dedup();
    assert_eq!(
        seen.len(),
        3,
        "the two pages must be disjoint and cover every eligible blob"
    );
    for id in &eligible {
        assert!(
            seen.contains(id),
            "every eligible blob must appear exactly once across pages"
        );
    }
}

// ── sum_bytes_uploaded_since (per-device daily media quota) ───────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn sum_bytes_uploaded_since_sums_only_matching_device_and_window() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let other_device = insert_device(&h.pool).await;
    let now = Utc::now();
    let window_start = now - chrono::Duration::days(1);

    let mut in_window = media_fixture(device.clone(), None);
    in_window.size_bytes = 1_000;
    in_window.uploaded_at = now;
    h.adapter.save(&in_window).await.expect("save in_window");

    let mut stale = media_fixture(device.clone(), None);
    stale.size_bytes = 999_999;
    stale.uploaded_at = now - chrono::Duration::days(2);
    h.adapter.save(&stale).await.expect("save stale");

    let mut other = media_fixture(other_device, None);
    other.size_bytes = 555;
    other.uploaded_at = now;
    h.adapter.save(&other).await.expect("save other device");

    let sum = h
        .adapter
        .sum_bytes_uploaded_since(&device, window_start)
        .await
        .expect("sum_bytes_uploaded_since");
    assert_eq!(
        sum, 1_000,
        "must count only this device's in-window blob, not the stale or other-device ones"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn sum_bytes_uploaded_since_returns_zero_for_device_with_no_uploads() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let sum = h
        .adapter
        .sum_bytes_uploaded_since(&device, Utc::now() - chrono::Duration::days(1))
        .await
        .expect("sum_bytes_uploaded_since");
    assert_eq!(sum, 0, "COALESCE must turn SQL NULL into 0, not error");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn sum_bytes_uploaded_since_survives_delete_against_real_postgres() {
    // Cycle 362 fix: `sum_bytes_uploaded_since` must sum the append-only
    // `media_upload_ledger`, not live `media_blobs` — deleting an upload
    // must not reduce counted usage within the window. Proven against a
    // real Postgres instance (unlike the in-memory mock in
    // `media_service.rs`, this exercises the actual `save()` transaction
    // that writes both tables and the actual `DELETE FROM media_blobs`
    // that must NOT touch `media_upload_ledger`).
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let now = Utc::now();
    let window_start = now - chrono::Duration::days(1);

    let mut blob = media_fixture(device.clone(), None);
    blob.size_bytes = 12_345;
    blob.uploaded_at = now;
    h.adapter.save(&blob).await.expect("save");
    h.adapter.delete(&blob.id).await.expect("delete");

    assert!(
        h.adapter
            .find_by_id(&blob.id)
            .await
            .expect("find_by_id")
            .is_none(),
        "blob must actually be gone from media_blobs"
    );
    let sum = h
        .adapter
        .sum_bytes_uploaded_since(&device, window_start)
        .await
        .expect("sum_bytes_uploaded_since");
    assert_eq!(
        sum, 12_345,
        "deleting the blob must not reduce the device's counted ledger usage"
    );
}

// ── trim_upload_ledger_older_than (cycle 363: closes cycle 362's unbounded ──
// ── ledger growth gap) ──────────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn trim_upload_ledger_older_than_deletes_only_rows_past_cutoff() {
    let h = setup().await;
    let device = insert_device(&h.pool).await;
    let now = Utc::now();

    let mut stale = media_fixture(device.clone(), None);
    stale.size_bytes = 1_000;
    stale.uploaded_at = now - chrono::Duration::days(31);
    h.adapter.save(&stale).await.expect("save stale");

    let mut fresh = media_fixture(device.clone(), None);
    fresh.size_bytes = 2_000;
    fresh.uploaded_at = now;
    h.adapter.save(&fresh).await.expect("save fresh");

    let cutoff = now - chrono::Duration::days(30);
    let trimmed = h
        .adapter
        .trim_upload_ledger_older_than(cutoff)
        .await
        .expect("trim_upload_ledger_older_than");
    assert_eq!(trimmed, 1, "only the stale row is past the cutoff");

    // The fresh row must still count toward a live quota check.
    let sum = h
        .adapter
        .sum_bytes_uploaded_since(&device, now - chrono::Duration::days(1))
        .await
        .expect("sum_bytes_uploaded_since");
    assert_eq!(sum, 2_000);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn trim_upload_ledger_older_than_does_not_touch_media_blobs() {
    // The ledger and `media_blobs` are deliberately independent tables (no
    // FK) — trimming the ledger must never delete a still-live blob.
    let h = setup().await;
    let blob = media_fixture(insert_device(&h.pool).await, None);
    h.adapter.save(&blob).await.expect("save");

    let far_future_cutoff = Utc::now() + chrono::Duration::days(365);
    h.adapter
        .trim_upload_ledger_older_than(far_future_cutoff)
        .await
        .expect("trim_upload_ledger_older_than");

    assert!(
        h.adapter
            .find_by_id(&blob.id)
            .await
            .expect("find_by_id")
            .is_some(),
        "trimming the ledger must not delete the corresponding media_blobs row"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn trim_upload_ledger_older_than_drains_multiple_batches() {
    // Cycle 364: `trim_upload_ledger_older_than` deletes in fixed-size
    // batches (`TRIM_LEDGER_BATCH_SIZE` = 5,000) via a keyset-paginated loop
    // rather than one unbatched statement (closes the cycle-363 non-blocking
    // finding). Bulk-insert straight to Postgres — no FK on `device_id` in
    // this table (migration 0015) — to prove the loop fully drains a stale
    // range spanning multiple batches (12,001 rows = 2 full batches + 1
    // partial) without needing 12k slow `save()` round-trips.
    let h = setup().await;
    let now = Utc::now();
    let stale_at = now - chrono::Duration::days(31);
    let device = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO media_upload_ledger (id, device_id, size_bytes, uploaded_at)
         SELECT gen_random_uuid(), $1, 1, $2
         FROM generate_series(1, 12001)",
    )
    .bind(device)
    .bind(stale_at)
    .execute(&h.pool)
    .await
    .expect("bulk insert stale ledger rows");

    // One fresh row that must survive the trim.
    sqlx::query(
        "INSERT INTO media_upload_ledger (id, device_id, size_bytes, uploaded_at)
         VALUES (gen_random_uuid(), $1, 1, $2)",
    )
    .bind(device)
    .bind(now)
    .execute(&h.pool)
    .await
    .expect("insert fresh ledger row");

    let cutoff = now - chrono::Duration::days(30);
    let trimmed = h
        .adapter
        .trim_upload_ledger_older_than(cutoff)
        .await
        .expect("trim_upload_ledger_older_than");
    assert_eq!(
        trimmed, 12_001,
        "all stale rows across every batch must be deleted"
    );

    let (remaining,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM media_upload_ledger")
        .fetch_one(&h.pool)
        .await
        .expect("count remaining");
    assert_eq!(remaining, 1, "only the fresh row must survive");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn trim_upload_ledger_older_than_returns_zero_when_nothing_stale() {
    let h = setup().await;
    let blob = media_fixture(insert_device(&h.pool).await, None);
    h.adapter.save(&blob).await.expect("save");

    let cutoff = Utc::now() - chrono::Duration::days(30);
    let trimmed = h
        .adapter
        .trim_upload_ledger_older_than(cutoff)
        .await
        .expect("trim_upload_ledger_older_than");
    assert_eq!(trimmed, 0);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn deleting_a_blob_cascades_its_acks() {
    let h = setup().await;
    let uploader = insert_device(&h.pool).await;
    let recipient = insert_device(&h.pool).await;
    let blob = media_fixture(uploader, None);
    h.adapter.save(&blob).await.expect("save");
    h.adapter
        .record_ack(&blob.id, &recipient)
        .await
        .expect("record_ack");

    h.adapter.delete(&blob.id).await.expect("delete");

    let acked = h
        .adapter
        .list_ack_device_ids(&blob.id)
        .await
        .expect("list_ack_device_ids after delete");
    assert!(
        acked.is_empty(),
        "ON DELETE CASCADE must remove orphaned acks"
    );
}

// ── GC advisory lock (cycle 368) ────────────────────────────────────────────
// `try_gc_lock` guards the background GC/trim jobs against multiple server
// replicas racing the same job. Session-scoped Postgres advisory locks can't
// be exercised by any mock (the whole point is real per-connection session
// state), so this is testcontainers-only coverage.

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_returns_none_when_already_held() {
    let h = setup().await;
    let key = 0x7000_0000_0000_0001i64;

    let guard1 = h
        .adapter
        .try_gc_lock(key)
        .await
        .expect("try_gc_lock first")
        .expect("lock must be free on first attempt");

    let second = h
        .adapter
        .try_gc_lock(key)
        .await
        .expect("try_gc_lock second");
    assert!(
        second.is_none(),
        "a second session must not acquire a lock already held by the first"
    );

    guard1.release().await;

    let third = h
        .adapter
        .try_gc_lock(key)
        .await
        .expect("try_gc_lock third")
        .expect("lock must be free again after release()");
    third.release().await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_distinct_keys_do_not_block_each_other() {
    let h = setup().await;

    let guard_a = h
        .adapter
        .try_gc_lock(0x7000_0000_0000_0002)
        .await
        .expect("try_gc_lock a")
        .expect("lock a must be free");
    let guard_b = h
        .adapter
        .try_gc_lock(0x7000_0000_0000_0003)
        .await
        .expect("try_gc_lock b")
        .expect("a different key must not be blocked by lock a");

    guard_a.release().await;
    guard_b.release().await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_dropped_without_release_still_frees_the_lock() {
    let h = setup().await;
    let key = 0x7000_0000_0000_0004i64;

    let guard = h
        .adapter
        .try_gc_lock(key)
        .await
        .expect("try_gc_lock first")
        .expect("lock must be free on first attempt");
    drop(guard); // simulates an early return / panic in the guarded job — no explicit release()

    // GcLockGuard's Drop impl detaches and closes the raw connection instead
    // of returning it to the pool — that's what actually releases a
    // session-scoped advisory lock server-side — but TCP teardown is async,
    // so poll briefly instead of asserting the very next instant.
    let mut reacquired = None;
    for _ in 0..20 {
        if let Some(g) = h.adapter.try_gc_lock(key).await.expect("try_gc_lock poll") {
            reacquired = Some(g);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    reacquired
        .expect("dropping the guard without release() must eventually free the lock")
        .release()
        .await;
}
