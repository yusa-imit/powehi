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
//!   - `create_if_absent` never overwrites an existing group row.
//!   - `server_config` round-trip and first-boot race convergence (DO NOTHING).
//!   - `PgLeaderLock` advisory-lock mutual exclusion, distinct-key independence,
//!     and Drop-without-release still frees the lock (moved from powehi-r2 cycle 373).
//!   - `PgDeviceRepository`: find/delete round-trip, `find_by_user` ownership
//!     scoping, and that the upsert `save` path can never reassign a device's
//!     `user_id` (cycle 445).
//!   - `KeyPackageRepository::delete_by_device`: revoking a device deletes
//!     every KeyPackage it uploaded (consumed or not), scoped so a sibling
//!     device's KeyPackages survive (cycle 447).
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers).
//! Run them in CI via: `cargo nextest run -p powehi-postgres --run-ignored all
//!                       -E 'binary(pg_security_it)'`

use chrono::Utc;
use powehi_domain::{
    device::{Device, DeviceId},
    envelope::{Envelope, EnvelopeId, MessageType},
    error::DomainError,
    group::{Epoch, Group, GroupId, GroupMember},
    key_package::{ConsumeResult, KeyPackage, KeyPackageId},
    region::RegionId,
    user::{User, UserId},
};
use powehi_port_outbound::{
    commit_ledger::CommitLedger, device_repo::DeviceRepository, envelope_repo::EnvelopeRepository,
    group_repo::GroupRepository, key_package_repo::KeyPackageRepository,
    server_config_repo::ServerConfigRepository, user_repo::UserRepository,
};
use powehi_postgres::{
    PgCommitLedger, PgDeviceRepository, PgEnvelopeRepository, PgGroupRepository,
    PgKeyPackageRepository, PgLeaderLock, PgServerConfigRepository, PgUserRepository,
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
    let pool = powehi_postgres::connect(&url, 10).await.expect("connect");
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
        .find_pending(&non_member, None, None)
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
        .find_pending(&member, None, None)
        .await
        .expect("find_pending");
    assert_eq!(pending.len(), 1, "member must receive the group broadcast");
    assert_eq!(pending[0].id, broadcast.id);
}

/// A broadcast envelope this device has already acked, but that is still
/// present (waiting on OTHER members to ack before GC — see ack_broadcast),
/// must NOT be re-returned by `find_pending`. Without this exclusion,
/// pagination (`ENVELOPE_POLL_LIMIT`) turns a single perpetually-offline
/// member into a catch-up storm: every poll re-pages through the SAME
/// already-seen backlog before reaching any new content (security-auditor
/// cycle 353, found reviewing the cycle 351/352 pagination diff).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_excludes_broadcast_already_acked_by_this_device() {
    let (_c, pool) = setup().await;

    let sender = insert_device(&pool, insert_user(&pool).await).await;
    let member = insert_device(&pool, insert_user(&pool).await).await;
    let other_member = insert_device(&pool, insert_user(&pool).await).await;
    let group_id = insert_group(&pool).await;
    join_group(&pool, group_id.clone(), sender.clone()).await;
    join_group(&pool, group_id.clone(), member.clone()).await;
    join_group(&pool, group_id.clone(), other_member.clone()).await;

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

    // `member` acks, but `other_member` hasn't yet — the envelope survives
    // (ack_broadcast only deletes once every id in the required set has acked).
    repo.ack_broadcast(&broadcast.id, &member, std::slice::from_ref(&other_member))
        .await
        .expect("ack_broadcast");
    assert!(
        repo.find_by_id(&broadcast.id)
            .await
            .expect("find_by_id")
            .is_some(),
        "envelope must survive a partial ack"
    );

    let pending = repo
        .find_pending(&member, None, None)
        .await
        .expect("find_pending");
    assert!(
        pending.is_empty(),
        "a broadcast this device already acked must not be re-returned, \
         even though it is still pending other members' acks"
    );

    // The OTHER member, who has not yet acked, must still see it.
    let other_pending = repo
        .find_pending(&other_member, None, None)
        .await
        .expect("find_pending");
    assert_eq!(
        other_pending.len(),
        1,
        "a member who has not yet acked must still receive the broadcast"
    );
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
        .find_pending(&device, None, None)
        .await
        .expect("find_pending");
    assert!(
        pending.is_empty(),
        "expired envelope must not be returned by find_pending"
    );
}

/// A single `find_pending` call must never return more than the page limit,
/// even when a device has a much larger backlog — guards against an unbounded
/// `poll_envelopes` response OOMing the polling device (security-auditor
/// cycle 350, prd.md §11.4). The remainder must still be reachable on a
/// follow-up poll using the last page's own `(created_at, id)` as the cursor,
/// mirroring how the frontend pollers (`useMessages.ts`/`useWelcomePoller.ts`)
/// advance their cursor.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_paginates_large_backlog() {
    let (_c, pool) = setup().await;
    let device = insert_device(&pool, insert_user(&pool).await).await;
    let repo = PgEnvelopeRepository::new(pool);

    // Mirrors `ENVELOPE_POLL_LIMIT` in envelope_repo.rs — private to the
    // adapter crate, so duplicated here as a literal for the test.
    const LIMIT: usize = 64;
    let base = Utc::now() - chrono::Duration::seconds(LIMIT as i64 + 10);
    let mut ids = Vec::with_capacity(LIMIT + 5);
    for i in 0..(LIMIT + 5) {
        let env = Envelope {
            id: EnvelopeId::new(),
            group_id: GroupId::from(Uuid::new_v4()),
            sender: device.clone(),
            recipient: Some(device.clone()),
            message_type: MessageType::Application,
            ciphertext: vec![0x01; 8],
            epoch: None,
            created_at: base + chrono::Duration::milliseconds(i as i64),
            expires_at: None,
        };
        ids.push(env.id.clone());
        repo.save(&env).await.expect("save");
    }

    let first_page = repo
        .find_pending(&device, None, None)
        .await
        .expect("find_pending page 1");
    assert_eq!(
        first_page.len(),
        LIMIT,
        "a single poll must never return more than the page limit"
    );
    for (row, expected_id) in first_page.iter().zip(ids.iter()) {
        assert_eq!(&row.id, expected_id, "pages must be oldest-first, in order");
    }

    let last = first_page.last().unwrap();
    let second_page = repo
        .find_pending(&device, Some(last.created_at), Some(last.id.clone()))
        .await
        .expect("find_pending page 2");
    assert_eq!(
        second_page.len(),
        5,
        "the remaining backlog must be returned on the next poll"
    );
    assert_eq!(second_page[0].id, ids[LIMIT]);
}

/// ADVERSARIAL: many envelopes sharing the *exact same* `created_at` must
/// never be split across a page boundary such that some are silently
/// unreachable — a timestamp-only cursor (`created_at > since`) can drop a
/// same-timestamp straggler forever once results are paginated, since a
/// client resuming from that exact timestamp would exclude every row still
/// carrying it. This is precisely the class of bug security-auditor caught
/// in the first draft of the cycle 351 pagination fix (a sustained-send
/// device could deliberately try to trigger it). The `(created_at, id)`
/// keyset cursor must page through all of them, in `id` order, exactly once.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn find_pending_keyset_cursor_splits_same_timestamp_group_safely() {
    let (_c, pool) = setup().await;
    let device = insert_device(&pool, insert_user(&pool).await).await;
    let repo = PgEnvelopeRepository::new(pool);

    const LIMIT: usize = 64;
    // More envelopes than one page, ALL sharing one `created_at` — the
    // worst case for a timestamp-only cursor.
    let same_instant = Utc::now();
    let mut ids = Vec::with_capacity(LIMIT + 7);
    for _ in 0..(LIMIT + 7) {
        let env = Envelope {
            id: EnvelopeId::new(),
            group_id: GroupId::from(Uuid::new_v4()),
            sender: device.clone(),
            recipient: Some(device.clone()),
            message_type: MessageType::Application,
            ciphertext: vec![0x02; 8],
            epoch: None,
            created_at: same_instant,
            expires_at: None,
        };
        ids.push(env.id.clone());
        repo.save(&env).await.expect("save");
    }
    ids.sort_by_key(|id| id.as_uuid());

    let mut collected = Vec::new();
    let mut cursor: Option<(chrono::DateTime<Utc>, EnvelopeId)> = None;
    for _ in 0..10 {
        let page = repo
            .find_pending(
                &device,
                cursor.as_ref().map(|(ts, _)| *ts),
                cursor.as_ref().map(|(_, id)| id.clone()),
            )
            .await
            .expect("find_pending page");
        if page.is_empty() {
            break;
        }
        let last = page.last().unwrap();
        cursor = Some((last.created_at, last.id.clone()));
        collected.extend(page.into_iter().map(|e| e.id));
    }

    collected.sort_by_key(|id| id.as_uuid());
    assert_eq!(
        collected, ids,
        "every envelope sharing one timestamp must be delivered exactly once \
         across pages, none silently dropped"
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

// ── user_repo recovery_pubkey (§8.5) integration tests ──────────────────────

/// §8.5: recovery_pubkey must round-trip through save/find against real Postgres,
/// and a `None` value must stay `None` (not be coerced to an empty Vec by the
/// BYTEA <-> Option<Vec<u8>> mapping).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn user_recovery_pubkey_round_trips_and_none_stays_none() {
    let (_c, pool) = setup().await;
    let repo = PgUserRepository::new(pool.clone());

    // Enrolled user: recovery_pubkey = Some(32 raw bytes).
    let h1 = Uuid::new_v4();
    let h2 = Uuid::new_v4();
    let handle = [h1.as_bytes().as_slice(), h2.as_bytes().as_slice()].concat();
    let vk = vec![0xa5u8; 32];
    let mut enrolled = User::new(UserId::new(), handle);
    enrolled.recovery_pubkey = Some(vk.clone());
    repo.save(&enrolled).await.expect("save enrolled");

    let loaded = repo
        .find_by_id(&enrolled.id)
        .await
        .expect("find enrolled")
        .expect("enrolled user exists");
    assert_eq!(
        loaded.recovery_pubkey,
        Some(vk),
        "recovery_pubkey must round-trip byte-exact"
    );

    // Also reachable via find_by_handle_hash.
    let by_handle = repo
        .find_by_handle_hash(&enrolled.handle_hash)
        .await
        .expect("find by handle")
        .expect("exists");
    assert_eq!(by_handle.recovery_pubkey, loaded.recovery_pubkey);

    // Non-enrolled user: recovery_pubkey stays None (NOT Some(empty vec)).
    let h3 = Uuid::new_v4();
    let h4 = Uuid::new_v4();
    let handle2 = [h3.as_bytes().as_slice(), h4.as_bytes().as_slice()].concat();
    let plain = User::new(UserId::new(), handle2);
    assert!(plain.recovery_pubkey.is_none());
    repo.save(&plain).await.expect("save plain");

    let loaded_plain = repo
        .find_by_id(&plain.id)
        .await
        .expect("find plain")
        .expect("plain user exists");
    assert!(
        loaded_plain.recovery_pubkey.is_none(),
        "absent recovery_pubkey must stay None, not an empty Vec"
    );
}

/// A profile-style re-save (upsert) that carries an already-set recovery_pubkey
/// must NOT NULL it out — the struct's current value is upserted verbatim, matching
/// how handle_hash / opaque_password_file are handled.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn user_recovery_pubkey_survives_upsert() {
    let (_c, pool) = setup().await;
    let repo = PgUserRepository::new(pool.clone());

    let h1 = Uuid::new_v4();
    let h2 = Uuid::new_v4();
    let handle = [h1.as_bytes().as_slice(), h2.as_bytes().as_slice()].concat();
    let vk = vec![0x3cu8; 32];
    let mut user = User::new(UserId::new(), handle);
    user.recovery_pubkey = Some(vk.clone());
    repo.save(&user).await.expect("initial save");

    // Re-save the same struct (still carrying the key) — simulates a later update.
    user.opaque_password_file = vec![0x11u8; 8];
    repo.save(&user).await.expect("upsert");

    let loaded = repo
        .find_by_id(&user.id)
        .await
        .expect("find")
        .expect("exists");
    assert_eq!(
        loaded.recovery_pubkey,
        Some(vk),
        "upsert must not NULL out a previously-set recovery_pubkey"
    );
    assert_eq!(loaded.opaque_password_file, vec![0x11u8; 8]);
}

/// Happy-path proof that the 0011 (create) -> 0012 (guard) -> 0013 (drop)
/// migration sequence runs cleanly end to end on a fresh DB: the new
/// three-column index is valid and serving, and the superseded two-column
/// index is gone. `setup()` already runs the full migration set, so this
/// mainly proves the 0012 guard added in cycle 358 doesn't false-positive on
/// the ordinary, uninterrupted build path.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn full_migration_run_leaves_new_envelope_index_valid_and_old_index_dropped() {
    let (_c, pool) = setup().await;

    let new_idx_valid: bool = sqlx::query_scalar(
        "SELECT indisvalid FROM pg_index WHERE indexrelid = 'envelopes_recipient_created_id_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("new index must exist after migrations");
    assert!(
        new_idx_valid,
        "envelopes_recipient_created_id_idx must be valid after a clean migration run"
    );

    let old_idx_gone: Option<i64> = sqlx::query_scalar(
        "SELECT 1 FROM pg_class WHERE relname = 'envelopes_recipient_created_idx'",
    )
    .fetch_optional(&pool)
    .await
    .expect("query old index catalog entry");
    assert!(
        old_idx_gone.is_none(),
        "superseded two-column index must be dropped by 0013"
    );
}

/// 0012 (`envelope_poll_idx_validity_guard`) automates the manual runbook
/// step documented in 0011's OPERATIONAL NOTE (cycle 353) — it guards 0013's
/// `DROP INDEX CONCURRENTLY` of the fallback index behind a check that the
/// new three-column index actually finished building. Postgres gives no
/// supported way to directly flip `pg_index.indisvalid` on a healthy index
/// outside of interrupting a real `CONCURRENTLY` build, so this test
/// reproduces an invalid index the standard reliable way — a `CREATE UNIQUE
/// INDEX CONCURRENTLY` whose build fails on a genuine duplicate-key
/// violation, which Postgres leaves catalogued-but-invalid rather than
/// rolling back (CONCURRENTLY can't run inside a transaction to roll back).
/// It then runs the *actual shipped migration SQL* via `include_str!` (so
/// this test can't silently drift from what production really runs)
/// retargeted at the synthetic index.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn envelope_poll_idx_validity_guard_aborts_on_invalid_index() {
    let (_c, pool) = setup().await;

    sqlx::query("CREATE TABLE guard_probe (a int)")
        .execute(&pool)
        .await
        .expect("create probe table");
    sqlx::query("INSERT INTO guard_probe VALUES (1), (1)")
        .execute(&pool)
        .await
        .expect("insert duplicate rows");
    sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY guard_probe_idx ON guard_probe(a)")
        .execute(&pool)
        .await
        .expect_err("build must fail on duplicate values, leaving an invalid index");

    // Confirm the setup actually reproduces the scenario this guard exists
    // for: the index is catalogued but invalid, matching an interrupted
    // 0011 build.
    let invalid: bool = sqlx::query_scalar(
        "SELECT NOT indisvalid FROM pg_index WHERE indexrelid = 'guard_probe_idx'::regclass",
    )
    .fetch_one(&pool)
    .await
    .expect("probe index catalogued despite failed build");
    assert!(
        invalid,
        "guard_probe_idx must be INVALID for this test to be meaningful"
    );

    let guard_sql = include_str!("../migrations/0012_envelope_poll_idx_validity_guard.sql")
        .replace("envelopes_recipient_created_id_idx", "guard_probe_idx");

    let guard_err = sqlx::raw_sql(&guard_sql)
        .execute(&pool)
        .await
        .expect_err("guard must abort when the target index is invalid");
    assert!(
        guard_err.to_string().contains("INVALID"),
        "guard error must explain the failure, got: {guard_err}"
    );

    // Rebuild cleanly (dedupe + drop + recreate) and re-run the identical
    // guard SQL — it must now pass silently, proving this isn't a permanent
    // trap once the index is actually rebuilt.
    sqlx::query("DROP INDEX CONCURRENTLY guard_probe_idx")
        .execute(&pool)
        .await
        .expect("drop invalid index");
    sqlx::query(
        "DELETE FROM guard_probe a USING guard_probe b \
         WHERE a.ctid < b.ctid AND a.a = b.a",
    )
    .execute(&pool)
    .await
    .expect("dedupe rows");
    sqlx::query("CREATE UNIQUE INDEX CONCURRENTLY guard_probe_idx ON guard_probe(a)")
        .execute(&pool)
        .await
        .expect("rebuild a valid index");

    sqlx::raw_sql(&guard_sql)
        .execute(&pool)
        .await
        .expect("guard must pass once the index is valid");
}

/// Broken-access-control regression (security-auditor HIGH), proven against
/// real Postgres rather than an in-memory fake: `create_if_absent` must use
/// ON CONFLICT (id) DO NOTHING, so a second call with a colliding client-supplied
/// group_id reports "already existed" and leaves every column of the existing
/// row untouched. The old `save()` upsert (ON CONFLICT DO UPDATE) reset
/// `epoch` to 0 and rewrote `home_region`, which let any authenticated device
/// hijack an arbitrary group by id.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn create_if_absent_does_not_overwrite_an_existing_group() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());

    let group_id = GroupId::from(Uuid::new_v4());
    let created_at = Utc::now();
    let original = Group {
        id: group_id.clone(),
        home_region: RegionId::new("eu-central-1"),
        epoch: Epoch(9),
        created_at,
    };

    // First call: row does not exist yet -> created.
    assert!(
        repo.create_if_absent(&original)
            .await
            .expect("first create_if_absent"),
        "first call must report the group as newly created"
    );
    let stored = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist after the first call");
    assert_eq!(stored.home_region.as_str(), "eu-central-1");
    assert_eq!(stored.epoch, Epoch(9));

    // Second call with a *different* home_region and a reset epoch — exactly
    // the attacker-controlled payload of `POST /v1/groups {"group_id": <victim>}`.
    let attacker_view = Group {
        id: group_id.clone(),
        home_region: RegionId::new("us-east-1"),
        epoch: Epoch(0),
        created_at: Utc::now(),
    };
    assert!(
        !repo
            .create_if_absent(&attacker_view)
            .await
            .expect("second create_if_absent"),
        "second call must report the group as already existing"
    );

    let after = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must still exist");
    assert_eq!(
        after.home_region.as_str(),
        "eu-central-1",
        "home_region must not be overwritten by a colliding create"
    );
    assert_eq!(
        after.epoch,
        Epoch(9),
        "epoch must not be reset by a colliding create"
    );
    assert_eq!(
        after.created_at.timestamp_micros(),
        created_at.timestamp_micros(),
        "created_at must not be rewritten by a colliding create"
    );

    // Exactly one row: DO NOTHING must not have inserted a duplicate.
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM groups WHERE id = $1")
        .bind(group_id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("count group rows");
    assert_eq!(count, 1, "exactly one group row must exist");
}

/// `advance_epoch` is the CAS primitive that `forward_commit`/`send_commit`
/// rely on to accept exactly one MLS Commit per epoch (crypto-reviewer
/// finding on the cross-region ForwardCommit RPC — `save`'s blind upsert
/// cannot provide this). A matching `expected` must advance-and-persist by
/// exactly 1; a stale `expected` must be rejected without touching the row.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn advance_epoch_succeeds_when_expected_matches_and_persists() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)

    let advanced = repo
        .advance_epoch(&group_id, Epoch(0))
        .await
        .expect("advance_epoch");
    assert_eq!(advanced, Some(Epoch(1)));

    let stored = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(stored.epoch, Epoch(1));
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn advance_epoch_rejects_stale_expected_and_leaves_epoch_untouched() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)

    let result = repo
        .advance_epoch(&group_id, Epoch(41))
        .await
        .expect("advance_epoch");
    assert_eq!(
        result, None,
        "a mismatched expected epoch must be rejected, not fabricate a new epoch"
    );

    let stored = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(
        stored.epoch,
        Epoch(0),
        "a rejected CAS must never mutate the stored epoch"
    );
}

// ── CommitLedger: epoch CAS + Commit-envelope insert as ONE transaction ─────
// (prd.md §4A.5). These can only be verified against real Postgres: the whole
// point is that a failed envelope INSERT rolls the epoch UPDATE back, which no
// in-memory fake can meaningfully model.

/// Builds the Commit envelope a caller would hand to the ledger. `epoch` is
/// set to a deliberately wrong value — the port contract says the ledger
/// ignores it and stamps the epoch its own CAS won.
fn commit_envelope_for(group_id: &GroupId, sender: &DeviceId) -> Envelope {
    let mut envelope = Envelope::new(
        group_id.clone(),
        sender.clone(),
        None,
        MessageType::Commit,
        vec![0x01, 0x02, 0x03],
    );
    envelope.epoch = Some(Epoch(9999));
    envelope
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn commit_epoch_and_save_advances_epoch_and_persists_envelope_together() {
    let (_c, pool) = setup().await;
    let ledger = PgCommitLedger::new(pool.clone());
    let group_repo = PgGroupRepository::new(pool.clone());
    let envelope_repo = PgEnvelopeRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)
    let sender = DeviceId::new();
    let envelope = commit_envelope_for(&group_id, &sender);

    let accepted = ledger
        .commit_epoch_and_save(&group_id, Epoch(0), &envelope)
        .await
        .expect("commit_epoch_and_save");
    assert_eq!(accepted, Some(Epoch(1)));

    let stored_group = group_repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(stored_group.epoch, Epoch(1));

    let stored_envelope = envelope_repo
        .find_by_id(&envelope.id)
        .await
        .expect("find_by_id")
        .expect("the Commit envelope must be persisted by the same transaction");
    assert_eq!(
        stored_envelope.epoch,
        Some(Epoch(1)),
        "the ledger must stamp the epoch its CAS won, ignoring the caller's value"
    );
    assert_eq!(stored_envelope.message_type, MessageType::Commit);
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn commit_epoch_and_save_cas_loss_persists_no_envelope() {
    let (_c, pool) = setup().await;
    let ledger = PgCommitLedger::new(pool.clone());
    let group_repo = PgGroupRepository::new(pool.clone());
    let envelope_repo = PgEnvelopeRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)
    let sender = DeviceId::new();
    let envelope = commit_envelope_for(&group_id, &sender);

    let result = ledger
        .commit_epoch_and_save(&group_id, Epoch(41), &envelope)
        .await
        .expect("commit_epoch_and_save");
    assert_eq!(
        result, None,
        "a stale expected epoch must be rejected, same contract as advance_epoch"
    );

    let stored_group = group_repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(
        stored_group.epoch,
        Epoch(0),
        "a rejected CAS must never mutate the stored epoch"
    );
    assert!(
        envelope_repo
            .find_by_id(&envelope.id)
            .await
            .expect("find_by_id")
            .is_none(),
        "a rejected CAS must not persist the Commit envelope"
    );
}

/// THE WEDGE FIX (prd.md §4A.5). Before this, the epoch CAS and the envelope
/// insert were two separate writes: a failure in between durably consumed the
/// epoch with no Commit envelope to deliver, permanently wedging the group.
///
/// `envelopes` has no FK constraints by design (a Welcome may precede group
/// creation — see migration 0001), so the insert is forced to fail with a
/// temporary CHECK constraint instead. Same technique-by-analogy as
/// `create_with_creator_rolls_back_group_row_when_member_insert_fails`, which
/// leans on a real FK.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn commit_epoch_and_save_rolls_back_the_epoch_when_the_envelope_insert_fails() {
    let (_c, pool) = setup().await;
    let ledger = PgCommitLedger::new(pool.clone());
    let group_repo = PgGroupRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)
    let sender = DeviceId::new();

    // Make any Commit-envelope INSERT fail, simulating the DB blip / pod kill
    // that used to leave the epoch consumed and the envelope missing.
    sqlx::query(
        "ALTER TABLE envelopes
         ADD CONSTRAINT test_forced_commit_insert_failure
         CHECK (message_type <> 'commit')",
    )
    .execute(&pool)
    .await
    .expect("install forced-failure constraint");

    let envelope = commit_envelope_for(&group_id, &sender);
    ledger
        .commit_epoch_and_save(&group_id, Epoch(0), &envelope)
        .await
        .expect_err("the envelope insert must fail its CHECK constraint");

    let stored_group = group_repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(
        stored_group.epoch,
        Epoch(0),
        "the epoch advance must roll back with the failed envelope insert — \
         a consumed epoch with no Commit envelope is the wedge this closes"
    );

    let envelope_rows: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM envelopes WHERE group_id = $1")
            .bind(group_id.as_uuid())
            .fetch_one(&pool)
            .await
            .expect("count envelope rows");
    assert_eq!(envelope_rows, 0, "no envelope row may survive the rollback");

    // And the group must still be committable at its original epoch — i.e. the
    // failure cost nothing, which is the whole point of the fix.
    sqlx::query("ALTER TABLE envelopes DROP CONSTRAINT test_forced_commit_insert_failure")
        .execute(&pool)
        .await
        .expect("drop forced-failure constraint");
    let retry = ledger
        .commit_epoch_and_save(
            &group_id,
            Epoch(0),
            &commit_envelope_for(&group_id, &sender),
        )
        .await
        .expect("retry after rollback");
    assert_eq!(
        retry,
        Some(Epoch(1)),
        "the group must remain committable at its original epoch after a rollback"
    );
}

/// Guards against the id-collision bug class crypto-reviewer flagged in cycle
/// 439: if `commit_envelope.id` ever collided with an existing row (both
/// current callers always mint a fresh UUIDv4, so this only matters for a
/// hypothetical future caller reusing an id as an idempotency key), the
/// `ON CONFLICT (id) DO NOTHING` insert must not let the transaction commit
/// having advanced the epoch while silently discarding the intended
/// envelope. It must instead fail the whole unit of work and roll the epoch
/// back — see `PgCommitLedger::commit_epoch_and_save` (cycle 441).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn commit_epoch_and_save_rejects_and_rolls_back_on_envelope_id_collision() {
    let (_c, pool) = setup().await;
    let ledger = PgCommitLedger::new(pool.clone());
    let group_repo = PgGroupRepository::new(pool.clone());
    let group_id = insert_group(&pool).await; // starts at Epoch(0)
    let sender = DeviceId::new();
    let envelope = commit_envelope_for(&group_id, &sender);

    // Pre-seed a row with the same id the ledger will try to insert, so the
    // ledger's own INSERT hits the ON CONFLICT (id) DO NOTHING branch.
    sqlx::query(
        "INSERT INTO envelopes
           (id, group_id, sender_device_id, recipient_device_id, message_type,
            ciphertext, epoch, created_at, expires_at)
         VALUES ($1, $2, $3, NULL, 'commit', $4, 0, now(), NULL)",
    )
    .bind(envelope.id.as_uuid())
    .bind(group_id.as_uuid())
    .bind(sender.as_uuid())
    .bind(&envelope.ciphertext)
    .execute(&pool)
    .await
    .expect("pre-seed colliding envelope row");

    let err = ledger
        .commit_epoch_and_save(&group_id, Epoch(0), &envelope)
        .await
        .expect_err("an id collision must be a hard error, not a silent no-op success");
    assert!(
        matches!(err, DomainError::AlreadyExists(_)),
        "expected AlreadyExists, got {err:?}"
    );

    let stored_group = group_repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(
        stored_group.epoch,
        Epoch(0),
        "the epoch must roll back with the rejected insert — never consumed \
         for an envelope write that didn't actually happen"
    );

    let envelope_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM envelopes WHERE id = $1")
        .bind(envelope.id.as_uuid())
        .fetch_one(&pool)
        .await
        .expect("count envelope rows");
    assert_eq!(
        envelope_rows, 1,
        "exactly the pre-seeded row must remain — no second row, no mutation"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn advance_epoch_unknown_group_returns_none() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());
    let result = repo
        .advance_epoch(&GroupId::from(Uuid::new_v4()), Epoch(0))
        .await
        .expect("advance_epoch");
    assert_eq!(result, None);
}

/// The concurrency guarantee this primitive exists for: two callers racing
/// `advance_epoch` from the same starting epoch against real Postgres must
/// never both succeed — exactly one wins, the epoch advances by exactly 1
/// (never 2), and the loser observes the loss via `None` rather than a
/// second, forked "success". This is the exact race the crypto-reviewer
/// flagged against the pre-CAS `find_by_id` + `save` sequence.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn advance_epoch_concurrent_race_only_one_winner() {
    let (_c, pool) = setup().await;
    let group_id = insert_group(&pool).await; // starts at Epoch(0)

    let pool_a = pool.clone();
    let pool_b = pool.clone();
    let gid_a = group_id.clone();
    let gid_b = group_id.clone();
    let (a, b) = tokio::join!(
        tokio::spawn(async move {
            PgGroupRepository::new(pool_a)
                .advance_epoch(&gid_a, Epoch(0))
                .await
        }),
        tokio::spawn(async move {
            PgGroupRepository::new(pool_b)
                .advance_epoch(&gid_b, Epoch(0))
                .await
        }),
    );
    let a = a.expect("task a").expect("advance_epoch a");
    let b = b.expect("task b").expect("advance_epoch b");

    let winners = [a, b].into_iter().filter(|r| *r == Some(Epoch(1))).count();
    let losers = [a, b].into_iter().filter(|r| r.is_none()).count();
    assert_eq!(winners, 1, "exactly one racer must win the CAS");
    assert_eq!(losers, 1, "exactly one racer must lose the CAS");

    let repo = PgGroupRepository::new(pool.clone());
    let stored = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must exist");
    assert_eq!(
        stored.epoch,
        Epoch(1),
        "the epoch must advance by exactly 1, never 2, under a concurrent race"
    );
}

/// `create_with_creator` must create the group row and the creator's
/// membership row atomically: a fresh id gets both in one commit, and a
/// colliding id leaves both untouched (no orphan group with zero members, and
/// no membership grant on a group it didn't just create).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn create_with_creator_inserts_group_and_member_together() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());

    let group_id = GroupId::from(Uuid::new_v4());
    let creator_device = insert_device(&pool, insert_user(&pool).await).await;
    let created_at = Utc::now();
    let group = Group {
        id: group_id.clone(),
        home_region: RegionId::new("eu-central-1"),
        epoch: Epoch(0),
        created_at,
    };
    let creator = GroupMember {
        group_id: group_id.clone(),
        device_id: creator_device.clone(),
        joined_at_epoch: Epoch(0),
    };

    assert!(
        repo.create_with_creator(&group, &creator)
            .await
            .expect("first create_with_creator"),
        "first call must report the group as newly created"
    );
    assert!(
        repo.find_by_id(&group_id)
            .await
            .expect("find_by_id")
            .is_some(),
        "group row must exist after the first call"
    );
    let members = repo.list_members(&group_id).await.expect("list_members");
    assert_eq!(members.len(), 1, "creator must be the sole member");
    assert_eq!(members[0].device_id, creator_device);

    // Colliding id, different (attacker-controlled) creator: neither the
    // group row nor membership may change.
    let attacker_device = DeviceId::from(Uuid::new_v4());
    let attacker_group = Group {
        id: group_id.clone(),
        home_region: RegionId::new("us-east-1"),
        epoch: Epoch(9),
        created_at: Utc::now(),
    };
    let attacker_member = GroupMember {
        group_id: group_id.clone(),
        device_id: attacker_device.clone(),
        joined_at_epoch: Epoch(0),
    };
    assert!(
        !repo
            .create_with_creator(&attacker_group, &attacker_member)
            .await
            .expect("second create_with_creator"),
        "second call must report the group as already existing"
    );

    let after = repo
        .find_by_id(&group_id)
        .await
        .expect("find_by_id")
        .expect("group row must still exist");
    assert_eq!(after.home_region.as_str(), "eu-central-1");
    assert_eq!(after.epoch, Epoch(0));

    let members_after = repo.list_members(&group_id).await.expect("list_members");
    assert_eq!(
        members_after.len(),
        1,
        "member list must be unchanged by a colliding create"
    );
    assert_eq!(members_after[0].device_id, creator_device);
    assert!(
        !members_after.iter().any(|m| m.device_id == attacker_device),
        "attacker's device must not have been added as a member"
    );
}

/// The regression this cycle fixes: if the membership insert inside
/// `create_with_creator` fails, the whole transaction must roll back rather
/// than leaving a committed, permanently-unusable zero-member group row.
/// Forced here via `creator.device_id` referencing no row in `devices` — the
/// `group_members.device_id` FK rejects it, which must abort the transaction
/// before the group insert (issued on the same, still-open transaction) is
/// ever committed.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn create_with_creator_rolls_back_group_row_when_member_insert_fails() {
    let (_c, pool) = setup().await;
    let repo = PgGroupRepository::new(pool.clone());

    let group_id = GroupId::from(Uuid::new_v4());
    let group = Group {
        id: group_id.clone(),
        home_region: RegionId::new("eu-central-1"),
        epoch: Epoch(0),
        created_at: Utc::now(),
    };
    // Never inserted into `devices` — group_members.device_id's FK must reject it.
    let unregistered_device = DeviceId::from(Uuid::new_v4());
    let creator = GroupMember {
        group_id: group_id.clone(),
        device_id: unregistered_device,
        joined_at_epoch: Epoch(0),
    };

    repo.create_with_creator(&group, &creator)
        .await
        .expect_err("membership insert must fail its device_id FK");

    assert!(
        repo.find_by_id(&group_id)
            .await
            .expect("find_by_id")
            .is_none(),
        "the group row must not survive a rolled-back transaction"
    );
}

// ── GC advisory lock (cycle 368; moved here from powehi-r2 cycle 373 — pure
// Postgres primitive, no R2/MinIO dependency) ───────────────────────────────
// `PgLeaderLock::try_lock` guards the background GC/trim jobs against
// multiple server replicas racing the same job. Session-scoped Postgres
// advisory locks can't be exercised by any mock (the whole point is real
// per-connection session state), so this is testcontainers-only coverage.

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_returns_none_when_already_held() {
    let (_c, pool) = setup().await;
    let lock = PgLeaderLock::new(pool);
    let key = 0x7000_0000_0000_0001i64;

    let guard1 = lock
        .try_lock(key)
        .await
        .expect("try_lock first")
        .expect("lock must be free on first attempt");

    let second = lock.try_lock(key).await.expect("try_lock second");
    assert!(
        second.is_none(),
        "a second session must not acquire a lock already held by the first"
    );

    guard1.release().await;

    let third = lock
        .try_lock(key)
        .await
        .expect("try_lock third")
        .expect("lock must be free again after release()");
    third.release().await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_distinct_keys_do_not_block_each_other() {
    let (_c, pool) = setup().await;
    let lock = PgLeaderLock::new(pool);

    let guard_a = lock
        .try_lock(0x7000_0000_0000_0002)
        .await
        .expect("try_lock a")
        .expect("lock a must be free");
    let guard_b = lock
        .try_lock(0x7000_0000_0000_0003)
        .await
        .expect("try_lock b")
        .expect("a different key must not be blocked by lock a");

    guard_a.release().await;
    guard_b.release().await;
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn try_gc_lock_dropped_without_release_still_frees_the_lock() {
    let (_c, pool) = setup().await;
    let lock = PgLeaderLock::new(pool);
    let key = 0x7000_0000_0000_0004i64;

    let guard = lock
        .try_lock(key)
        .await
        .expect("try_lock first")
        .expect("lock must be free on first attempt");
    drop(guard); // simulates an early return / panic in the guarded job — no explicit release()

    // GcLockGuard's Drop impl detaches and closes the raw connection instead
    // of returning it to the pool — that's what actually releases a
    // session-scoped advisory lock server-side — but TCP teardown is async,
    // so poll briefly instead of asserting the very next instant.
    let mut reacquired = None;
    for _ in 0..20 {
        if let Some(g) = lock.try_lock(key).await.expect("try_lock poll") {
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

// ── Device repository (cycle 445) ───────────────────────────────────────────
// `insert_device` above only ever exercises `PgDeviceRepository::save` as a
// fixture helper for other repos' tests — `find_by_id`, `find_by_user`, and
// `delete` had zero real-Postgres coverage, and the `ON CONFLICT (id) DO
// UPDATE` upsert clause on `save` (which deliberately does NOT update
// `user_id`) had never been exercised against actual SQL semantics either.

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_find_by_id_returns_none_for_unknown_id() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool);
    let found = repo.find_by_id(&DeviceId::new()).await.expect("find_by_id");
    assert!(found.is_none());
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_save_and_find_by_id_round_trips() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool.clone());
    let user_id = insert_user(&pool).await;
    let device = Device::new(DeviceId::new(), user_id.clone(), vec![7u8; 32]);
    repo.save(&device).await.expect("save");

    let found = repo
        .find_by_id(&device.id)
        .await
        .expect("find_by_id")
        .expect("device must be found after save");
    assert_eq!(found.id, device.id);
    assert_eq!(found.user_id, user_id);
    assert_eq!(found.mls_credential, device.mls_credential);
    assert!(found.last_seen_at.is_none());
}

/// SECURITY: `find_by_user` must only return devices owned by that user, and
/// never leak another user's device into the result set.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_find_by_user_is_scoped_to_owner() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool.clone());
    let owner = insert_user(&pool).await;
    let other = insert_user(&pool).await;

    let d1 = Device::new(DeviceId::new(), owner.clone(), vec![1u8; 32]);
    let d2 = Device::new(DeviceId::new(), owner.clone(), vec![2u8; 32]);
    let d_other = Device::new(DeviceId::new(), other, vec![3u8; 32]);
    repo.save(&d1).await.expect("save d1");
    repo.save(&d2).await.expect("save d2");
    repo.save(&d_other).await.expect("save d_other");

    let found = repo.find_by_user(&owner).await.expect("find_by_user");
    let found_ids: std::collections::HashSet<_> = found.iter().map(|d| d.id.clone()).collect();
    assert_eq!(
        found.len(),
        2,
        "must return exactly the owner's own devices"
    );
    assert!(found_ids.contains(&d1.id));
    assert!(found_ids.contains(&d2.id));
    assert!(
        !found_ids.contains(&d_other.id),
        "another user's device must never appear in find_by_user"
    );
}

/// SECURITY: deleting a device must delete every KeyPackage it uploaded
/// (consumed or not). A revoked device must never be able to hand out a
/// stale KeyPackage via fetch_one/ConsumeKeyPackage after revocation.
/// A sibling device's KeyPackages must be untouched by another device's
/// cleanup (scoping, not a blanket wipe).
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn key_package_delete_by_device_removes_only_that_devices_packages() {
    let (_c, pool) = setup().await;
    let user_id = insert_user(&pool).await;
    let target_device = insert_device(&pool, user_id.clone()).await;
    let sibling_device = insert_device(&pool, user_id).await;
    let repo = PgKeyPackageRepository::new(pool);

    let unconsumed = KeyPackage {
        id: KeyPackageId::new(),
        device_id: target_device.clone(),
        data: vec![0x11; 16],
        uploaded_at: Utc::now(),
        consumed: false,
    };
    let consumed = KeyPackage {
        id: KeyPackageId::new(),
        device_id: target_device.clone(),
        data: vec![0x22; 16],
        uploaded_at: Utc::now(),
        consumed: true,
    };
    let sibling_kp = KeyPackage {
        id: KeyPackageId::new(),
        device_id: sibling_device.clone(),
        data: vec![0x33; 16],
        uploaded_at: Utc::now(),
        consumed: false,
    };
    repo.save(&unconsumed).await.expect("save unconsumed");
    repo.save(&consumed).await.expect("save consumed");
    repo.save(&sibling_kp).await.expect("save sibling");

    let deleted = repo
        .delete_by_device(&target_device)
        .await
        .expect("delete_by_device");
    assert_eq!(
        deleted, 2,
        "must delete both the consumed and unconsumed row"
    );

    assert_eq!(
        repo.count_available(&target_device)
            .await
            .expect("count target after delete"),
        0
    );
    assert!(
        repo.fetch_one(&target_device)
            .await
            .expect("fetch_one target after delete")
            .is_none(),
        "no KeyPackage of any consumed-state may survive for the revoked device"
    );
    assert_eq!(
        repo.count_available(&sibling_device)
            .await
            .expect("count sibling after delete"),
        1,
        "a sibling device's KeyPackages must be untouched"
    );

    let again = repo
        .delete_by_device(&target_device)
        .await
        .expect("delete_by_device is idempotent");
    assert_eq!(
        again, 0,
        "a device with zero KeyPackages returns Ok(0), not an error"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_delete_removes_the_row() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool.clone());
    let user_id = insert_user(&pool).await;
    let device = Device::new(DeviceId::new(), user_id, vec![9u8; 32]);
    repo.save(&device).await.expect("save");

    repo.delete(&device.id).await.expect("delete");

    assert!(
        repo.find_by_id(&device.id)
            .await
            .expect("find_by_id after delete")
            .is_none(),
        "device must be gone after delete"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_delete_of_unknown_id_is_a_harmless_no_op() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool);
    // Must not error just because the row never existed (e.g. a retried
    // client-initiated device revocation after the first attempt already
    // succeeded server-side but the response was lost).
    repo.delete(&DeviceId::new()).await.expect("delete");
}

/// SECURITY: re-`save`-ing an existing device id must update its credential
/// and last-seen timestamp (the intended re-key/heartbeat path) but must
/// NEVER reassign `user_id` — the `ON CONFLICT (id) DO UPDATE` clause in
/// `PgDeviceRepository::save` deliberately omits `user_id` from its `SET`
/// list so a device row can't be silently transferred to a different
/// account's ownership by any caller that can reach `save` with a colliding
/// id and a different `user_id`.
#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn device_save_upsert_updates_credential_but_never_reassigns_owner() {
    let (_c, pool) = setup().await;
    let repo = PgDeviceRepository::new(pool.clone());
    let original_owner = insert_user(&pool).await;
    let attacker_owner = insert_user(&pool).await;

    let device = Device::new(DeviceId::new(), original_owner.clone(), vec![1u8; 32]);
    repo.save(&device).await.expect("initial save");

    let now = Utc::now();
    let mut resaved = device.clone();
    resaved.user_id = attacker_owner.clone();
    resaved.mls_credential = vec![2u8; 32];
    resaved.last_seen_at = Some(now);
    // NOTE: a foreign-owner id collision is NOT rejected — `save` returns
    // `Ok(())` and silently keeps the row under `original_owner` (first
    // writer wins on `user_id`; only `mls_credential`/`last_seen_at`
    // actually move). Callers must not treat a colliding-id `save` as proof
    // that the id now belongs to their caller's account. Today's callers
    // never hit this: registration always mints a fresh id
    // (`auth_service.rs`'s registration path), and the recovery-mint path
    // rejects a known id already owned by someone else before ever calling
    // `save`. This test pins the adapter's actual behavior, not a claim that
    // no caller could ever misuse it.
    repo.save(&resaved).await.expect("upsert save");

    let found = repo
        .find_by_id(&device.id)
        .await
        .expect("find_by_id")
        .expect("device must still exist");
    assert_eq!(
        found.user_id, original_owner,
        "user_id must never change on an upsert save — ownership transfer via save() would be a privilege-escalation bug"
    );
    assert_eq!(
        found.mls_credential,
        vec![2u8; 32],
        "mls_credential must update on upsert"
    );
    assert!(
        found.last_seen_at.is_some(),
        "last_seen_at must update on upsert"
    );
    assert_eq!(
        found.created_at.timestamp_micros(),
        device.created_at.timestamp_micros(),
        "created_at must also survive an upsert unchanged (excluded from the SET list, same as user_id)"
    );

    let attacker_devices = repo
        .find_by_user(&attacker_owner)
        .await
        .expect("find_by_user attacker_owner");
    assert!(
        attacker_devices.is_empty(),
        "the colliding save must not make this device visible under the attacker-supplied user_id"
    );
}
