//! Testcontainers integration tests for powehi-postgres.
//!
//! Each test spins up an ephemeral Postgres container, runs all sqlx migrations,
//! and verifies security invariants that depend on real SQL semantics:
//!   - Broadcast-envelope scoping: non-members receive zero broadcasts.
//!   - Group-membership scoping: `list_groups_for_device` is device-local.
//!   - KeyPackage single-use: `fetch_one` is atomic and marks consumed.
//!   - `mark_consumed` double-consume prevention (CAS gRPC ConsumeKeyPackage).
//!   - TTL enforcement: expired envelopes are filtered at the DB layer.
//!   - `add_member` ON CONFLICT DO NOTHING idempotency.
//!   - `server_config` round-trip and first-boot race convergence (DO NOTHING).
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers).
//! Run them in CI via: `cargo nextest run -p powehi-postgres --run-ignored all
//!                       -E 'binary(pg_security_it)'`

use chrono::Utc;
use powehi_domain::{
    device::{Device, DeviceId},
    envelope::{Envelope, EnvelopeId, MessageType},
    group::{Epoch, Group, GroupId, GroupMember},
    key_package::{ConsumeResult, KeyPackage, KeyPackageId},
    region::RegionId,
    user::{User, UserId},
};
use powehi_port_outbound::{
    device_repo::DeviceRepository, envelope_repo::EnvelopeRepository, group_repo::GroupRepository,
    key_package_repo::KeyPackageRepository, server_config_repo::ServerConfigRepository,
    user_repo::UserRepository,
};
use powehi_postgres::{
    PgDeviceRepository, PgEnvelopeRepository, PgGroupRepository, PgKeyPackageRepository,
    PgServerConfigRepository, PgUserRepository,
};
use sqlx::PgPool;
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::postgres::Postgres;
use uuid::Uuid;

// ── Container setup ───────────────────────────────────────────────────────────

/// Start a throwaway Postgres container, run all migrations, return the pool.
/// Caller must keep the returned container alive for the duration of the test.
///
/// Uses postgres:16-alpine explicitly — the testcontainers-modules default
/// (11-alpine) is EOL since 2023-11 and its Docker Hub layers are unstable.
async fn setup() -> (testcontainers::ContainerAsync<Postgres>, PgPool) {
    let container = Postgres::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("Postgres container started");
    let port = container.get_host_port_ipv4(5432).await.expect("host port");
    let url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let pool = PgPool::connect(&url).await.expect("connect");
    powehi_postgres::run_migrations(&pool)
        .await
        .expect("migrations");
    (container, pool)
}

// ── Fixture helpers ───────────────────────────────────────────────────────────

async fn insert_user(pool: &PgPool) -> UserId {
    // Use two random UUIDs to form a unique 32-byte handle_hash per call,
    // avoiding violations of the users_handle_hash_unique constraint when
    // insert_user is called multiple times within the same test database.
    let h1 = Uuid::new_v4();
    let h2 = Uuid::new_v4();
    let handle_hash = [h1.as_bytes().as_slice(), h2.as_bytes().as_slice()].concat();
    let user = User::new(UserId::new(), handle_hash);
    PgUserRepository::new(pool.clone())
        .save(&user)
        .await
        .expect("insert user");
    user.id
}

async fn insert_device(pool: &PgPool, user_id: UserId) -> DeviceId {
    // Use a random UUID to form a unique 32-byte mls_credential per call,
    // guarding against potential future UNIQUE constraints on that column.
    let cred_uuid = Uuid::new_v4();
    let mut cred = [0u8; 32];
    cred[..16].copy_from_slice(cred_uuid.as_bytes());
    let device = Device::new(DeviceId::new(), user_id, cred.to_vec());
    PgDeviceRepository::new(pool.clone())
        .save(&device)
        .await
        .expect("insert device");
    device.id
}

async fn insert_group(pool: &PgPool) -> GroupId {
    let group = Group::new(GroupId::new(), RegionId::new("eu-de-1"));
    PgGroupRepository::new(pool.clone())
        .save(&group)
        .await
        .expect("insert group");
    group.id
}

async fn join_group(pool: &PgPool, group_id: GroupId, device_id: DeviceId) {
    let member = GroupMember {
        group_id,
        device_id,
        joined_at_epoch: Epoch(0),
    };
    PgGroupRepository::new(pool.clone())
        .add_member(&member)
        .await
        .expect("add member");
}

// ── Security-invariant tests ──────────────────────────────────────────────────

/// SECURITY: a device must only see the groups it belongs to.
/// `list_groups_for_device` must never return another device's groups.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn list_groups_for_device_returns_only_own_groups() {
    let (_c, pool) = setup().await;

    let device_a = insert_device(&pool, insert_user(&pool).await).await;
    let device_b = insert_device(&pool, insert_user(&pool).await).await;
    let group_a = insert_group(&pool).await;
    let group_b = insert_group(&pool).await;

    join_group(&pool, group_a.clone(), device_a.clone()).await;
    join_group(&pool, group_b.clone(), device_b.clone()).await;

    let repo = PgGroupRepository::new(pool);

    let a_groups = repo
        .list_groups_for_device(&device_a)
        .await
        .expect("query a");
    assert_eq!(a_groups, vec![group_a], "device_a must only see group_a");

    let b_groups = repo
        .list_groups_for_device(&device_b)
        .await
        .expect("query b");
    assert_eq!(b_groups, vec![group_b], "device_b must only see group_b");
}

/// SECURITY: a non-member must receive ZERO group broadcast envelopes.
/// Validates the cycle-74 SQL fix: `recipient_device_id IS NULL AND group_id IN
/// (SELECT group_id FROM group_members WHERE device_id = $1)` evaluates to FALSE
/// when device_id has no membership rows — fail-closed invariant confirmed
/// against real Postgres semantics.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_broadcast_excluded_for_non_member() {
    let (_c, pool) = setup().await;

    let sender = insert_device(&pool, insert_user(&pool).await).await;
    let non_member = insert_device(&pool, insert_user(&pool).await).await;

    // Broadcast to a group that `non_member` is NOT in (no FK on envelopes)
    let group_id = GroupId::from(Uuid::new_v4());
    let broadcast = Envelope {
        id: EnvelopeId::new(),
        group_id,
        sender: sender.clone(),
        recipient: None, // broadcast — recipient_device_id IS NULL
        message_type: MessageType::Application,
        ciphertext: vec![0xff; 32], // opaque bytes — server must not inspect
        epoch: Some(Epoch(1)),
        created_at: Utc::now(),
        expires_at: None,
    };
    let repo = PgEnvelopeRepository::new(pool);
    repo.save(&broadcast).await.expect("save");

    let pending = repo
        .find_pending(&non_member, None)
        .await
        .expect("find_pending");
    assert!(
        pending.is_empty(),
        "non-member must receive zero broadcasts; got {} envelope(s)",
        pending.len()
    );
}

/// A group member MUST receive broadcast envelopes for their group.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_broadcast_included_for_member() {
    let (_c, pool) = setup().await;

    let sender = insert_device(&pool, insert_user(&pool).await).await;
    let member = insert_device(&pool, insert_user(&pool).await).await;
    let group_id = insert_group(&pool).await;
    join_group(&pool, group_id.clone(), sender.clone()).await;
    join_group(&pool, group_id.clone(), member.clone()).await;

    let broadcast = Envelope {
        id: EnvelopeId::new(),
        group_id,
        sender: sender.clone(),
        recipient: None,
        message_type: MessageType::Application,
        ciphertext: vec![0xab; 32],
        epoch: Some(Epoch(1)),
        created_at: Utc::now(),
        expires_at: None,
    };
    let repo = PgEnvelopeRepository::new(pool);
    repo.save(&broadcast).await.expect("save");

    let pending = repo
        .find_pending(&member, None)
        .await
        .expect("find_pending");
    assert_eq!(pending.len(), 1, "member must receive the group broadcast");
    assert_eq!(pending[0].id, broadcast.id);
}

/// TTL enforcement: expired envelopes must not be returned by `find_pending`.
/// The SQL guard `expires_at IS NULL OR expires_at > NOW()` is evaluated
/// by Postgres — this test confirms real DB semantics (not just in-memory fake).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_excludes_expired_envelopes() {
    let (_c, pool) = setup().await;

    let device = insert_device(&pool, insert_user(&pool).await).await;
    let past = Utc::now() - chrono::Duration::seconds(120);

    let env = Envelope {
        id: EnvelopeId::new(),
        group_id: GroupId::from(Uuid::new_v4()),
        sender: device.clone(),
        recipient: Some(device.clone()),
        message_type: MessageType::Application,
        ciphertext: vec![0x00; 16],
        epoch: None,
        created_at: past,
        expires_at: Some(past), // already expired
    };
    let repo = PgEnvelopeRepository::new(pool);
    repo.save(&env).await.expect("save");

    let pending = repo
        .find_pending(&device, None)
        .await
        .expect("find_pending");
    assert!(
        pending.is_empty(),
        "expired envelope must not be returned by find_pending"
    );
}

/// SECURITY: `fetch_one` atomically marks the KeyPackage consumed.
/// After a single fetch the KP count drops to 0 and a second call returns None.
/// Enforces MLS KeyPackage single-use (forward-secrecy prerequisite).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn key_package_fetch_one_atomically_marks_consumed() {
    let (_c, pool) = setup().await;

    let device = insert_device(&pool, insert_user(&pool).await).await;
    let repo = PgKeyPackageRepository::new(pool);

    let kp = KeyPackage {
        id: KeyPackageId::new(),
        device_id: device.clone(),
        data: vec![0xde; 64], // opaque MLS KeyPackage bytes
        uploaded_at: Utc::now(),
        consumed: false,
    };
    repo.save(&kp).await.expect("save");
    assert_eq!(repo.count_available(&device).await.expect("count"), 1);

    let fetched = repo.fetch_one(&device).await.expect("fetch_one");
    assert!(fetched.is_some(), "first fetch_one must return the KP");
    assert_eq!(fetched.unwrap().id, kp.id);

    assert_eq!(
        repo.count_available(&device).await.expect("count after"),
        0,
        "count must drop to 0 after fetch_one"
    );
    let second = repo.fetch_one(&device).await.expect("second fetch_one");
    assert!(
        second.is_none(),
        "KP must be single-use — second fetch_one must return None"
    );
}

/// SECURITY: `mark_consumed` prevents double-consumption (CAS invariant).
/// First call returns `Consumed`; a second call returns `AlreadyConsumed`.
/// Guards the cross-region gRPC `ConsumeKeyPackage` RPC.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mark_consumed_prevents_double_consume() {
    let (_c, pool) = setup().await;

    let device = insert_device(&pool, insert_user(&pool).await).await;
    let repo = PgKeyPackageRepository::new(pool);

    let kp = KeyPackage {
        id: KeyPackageId::new(),
        device_id: device,
        data: vec![0xbe; 64],
        uploaded_at: Utc::now(),
        consumed: false,
    };
    repo.save(&kp).await.expect("save");

    assert_eq!(
        repo.mark_consumed(&kp.id).await.expect("first"),
        ConsumeResult::Consumed,
        "first mark_consumed must return Consumed"
    );
    assert_eq!(
        repo.mark_consumed(&kp.id).await.expect("second"),
        ConsumeResult::AlreadyConsumed,
        "second mark_consumed must return AlreadyConsumed"
    );
}

/// `mark_consumed` on an unknown ID returns `NotFound` (not Internal error).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn mark_consumed_not_found_for_unknown_id() {
    let (_c, pool) = setup().await;
    let repo = PgKeyPackageRepository::new(pool);
    let unknown = KeyPackageId::from(Uuid::new_v4());
    assert_eq!(
        repo.mark_consumed(&unknown).await.expect("query"),
        ConsumeResult::NotFound
    );
}

/// `add_member` is idempotent — inserting the same (group, device) pair twice
/// must not error and must not create duplicate rows (ON CONFLICT DO NOTHING).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn group_add_member_is_idempotent() {
    let (_c, pool) = setup().await;

    let device = insert_device(&pool, insert_user(&pool).await).await;
    let group_id = insert_group(&pool).await;

    let member = GroupMember {
        group_id: group_id.clone(),
        device_id: device.clone(),
        joined_at_epoch: Epoch(0),
    };
    let repo = PgGroupRepository::new(pool);
    repo.add_member(&member).await.expect("first add");
    repo.add_member(&member)
        .await
        .expect("second add — must be idempotent");

    let members = repo.list_members(&group_id).await.expect("list");
    assert_eq!(
        members.len(),
        1,
        "idempotent add must not create duplicate rows"
    );
}

// ── server_config_repo integration tests ────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn server_config_get_returns_none_before_insert() {
    let (_container, pool) = setup().await;
    let repo = PgServerConfigRepository::new(pool);
    let val = repo.get_bytes("nonexistent_key").await.expect("get_bytes");
    assert!(val.is_none(), "unset key must return None");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn server_config_upsert_and_get_round_trip() {
    let (_container, pool) = setup().await;
    let repo = PgServerConfigRepository::new(pool);
    let secret = [0xabu8; 32];
    repo.upsert_bytes("handle_oracle_secret", &secret)
        .await
        .expect("upsert");
    let got = repo
        .get_bytes("handle_oracle_secret")
        .await
        .expect("get_bytes")
        .expect("must be Some after upsert");
    assert_eq!(got, secret, "round-trip must return the stored bytes");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn server_config_do_nothing_on_conflict_keeps_first_value() {
    // Verifies the first-boot race convergence: INSERT ... ON CONFLICT DO NOTHING
    // must NOT overwrite an already-persisted oracle secret.  All concurrent
    // instances converge on the same value by re-reading after their insert attempt.
    let (_container, pool) = setup().await;
    let repo = PgServerConfigRepository::new(pool);

    let first = [0x11u8; 32];
    let second = [0x22u8; 32];

    repo.upsert_bytes("handle_oracle_secret", &first)
        .await
        .expect("first insert");
    repo.upsert_bytes("handle_oracle_secret", &second)
        .await
        .expect("second insert (must be a no-op)");

    let got = repo
        .get_bytes("handle_oracle_secret")
        .await
        .expect("get_bytes")
        .expect("must be Some");
    assert_eq!(
        got, first,
        "DO NOTHING must preserve the first writer's value"
    );
}
