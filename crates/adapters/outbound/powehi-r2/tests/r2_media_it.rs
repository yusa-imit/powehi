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
    let pool = PgPool::connect(&db_url).await.expect("connect pg");
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
    let blob = media_fixture(device, None);
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
        .body(b"opaque-ciphertext-bytes".to_vec())
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
    let blob = media_fixture(device, None);
    h.adapter.save(&blob).await.expect("save");

    // Opaque, test-authored bytes — stands in for client-side E2EE ciphertext.
    let payload = b"\x00\x01\x02opaque-e2ee-ciphertext\xfe\xff".to_vec();
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
