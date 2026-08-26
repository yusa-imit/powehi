//! Push-subscription repository tests.
//!
//! Two layers:
//!   1. Contract tests against an in-memory fake — fast, no DB. These pin the
//!      behavior every `PushSubscriptionRepository` impl (including the Pg one)
//!      must satisfy: upsert stores, fetch returns None when missing, delete
//!      removes, upsert replaces on conflict.
//!   2. A real-Postgres integration test (`#[ignore]`d by default; run with
//!      `cargo test -- --ignored` against a live DB) that also verifies the
//!      0004 migration applies and its rollback SQL drops the table cleanly.

use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError, push_subscription::PushSubscription};
use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;
use std::collections::HashMap;
use std::sync::Mutex;

// ── In-memory fake honoring the same contract as PgPushSubscriptionRepository ──

#[derive(Default)]
struct FakePushRepo {
    store: Mutex<HashMap<uuid::Uuid, PushSubscription>>,
}

#[async_trait]
impl PushSubscriptionRepository for FakePushRepo {
    async fn upsert(&self, sub: &PushSubscription) -> Result<(), DomainError> {
        self.store
            .lock()
            .unwrap()
            .insert(sub.device_id.as_uuid(), sub.clone());
        Ok(())
    }
    async fn fetch_by_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<PushSubscription>, DomainError> {
        Ok(self
            .store
            .lock()
            .unwrap()
            .get(&device_id.as_uuid())
            .cloned())
    }
    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<(), DomainError> {
        self.store.lock().unwrap().remove(&device_id.as_uuid());
        Ok(())
    }
}

fn sub_for(device: &DeviceId, endpoint: &str) -> PushSubscription {
    PushSubscription::new(
        device.clone(),
        endpoint.into(),
        vec![4u8; 65],
        vec![0u8; 16],
    )
}

#[tokio::test]
async fn upsert_stores_correctly() {
    let repo = FakePushRepo::default();
    let device = DeviceId::new();
    repo.upsert(&sub_for(&device, "https://push.example/a"))
        .await
        .unwrap();
    let got = repo
        .fetch_by_device(&device)
        .await
        .unwrap()
        .expect("stored");
    assert_eq!(got.endpoint, "https://push.example/a");
    assert_eq!(got.p256dh.len(), 65);
    assert_eq!(got.auth_secret.len(), 16);
}

#[tokio::test]
async fn fetch_returns_none_when_missing() {
    let repo = FakePushRepo::default();
    let missing = DeviceId::new();
    assert!(repo.fetch_by_device(&missing).await.unwrap().is_none());
}

#[tokio::test]
async fn delete_removes_entry() {
    let repo = FakePushRepo::default();
    let device = DeviceId::new();
    repo.upsert(&sub_for(&device, "https://push.example/b"))
        .await
        .unwrap();
    repo.delete_by_device(&device).await.unwrap();
    assert!(repo.fetch_by_device(&device).await.unwrap().is_none());
}

#[tokio::test]
async fn upsert_replaces_on_conflict() {
    let repo = FakePushRepo::default();
    let device = DeviceId::new();
    repo.upsert(&sub_for(&device, "https://push.example/old"))
        .await
        .unwrap();
    repo.upsert(&sub_for(&device, "https://push.example/new"))
        .await
        .unwrap();
    let got = repo.fetch_by_device(&device).await.unwrap().unwrap();
    assert_eq!(got.endpoint, "https://push.example/new");
}

// ── Real-Postgres integration + migration/rollback verification ────────────────
//
// Requires a reachable DB at TEST_DATABASE_URL. Ignored by default so the unit
// suite stays hermetic; CI's integration stage runs `--ignored`.

#[tokio::test]
#[ignore = "requires live Postgres (set TEST_DATABASE_URL)"]
async fn pg_upsert_fetch_delete_and_rollback() {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must be set for ignored integration test");
    let pool = powehi_postgres::connect(&url, 5).await.expect("connect");
    powehi_postgres::run_migrations(&pool)
        .await
        .expect("forward migrations apply (incl. 0004)");

    // The migration must have created the table.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables \
         WHERE table_name = 'push_subscriptions')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(exists, "0004 migration must create push_subscriptions");

    // Behavioral round-trip needs a real device row (FK constraint).
    let user_id = uuid::Uuid::new_v4();
    let device_uuid = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, handle_hash, created_at, updated_at) \
         VALUES ($1, $2, now(), now())",
    )
    .bind(user_id)
    .bind(vec![1u8; 32])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO devices (id, user_id, mls_credential, created_at) \
         VALUES ($1, $2, $3, now())",
    )
    .bind(device_uuid)
    .bind(user_id)
    .bind(vec![2u8; 16])
    .execute(&pool)
    .await
    .unwrap();

    let device = DeviceId::from(device_uuid);
    let repo = powehi_postgres::PgPushSubscriptionRepository::new(pool.clone());
    repo.upsert(&sub_for(&device, "https://push.example/it"))
        .await
        .unwrap();
    assert_eq!(
        repo.fetch_by_device(&device)
            .await
            .unwrap()
            .unwrap()
            .endpoint,
        "https://push.example/it"
    );
    repo.delete_by_device(&device).await.unwrap();
    assert!(repo.fetch_by_device(&device).await.unwrap().is_none());

    // Rollback verification: apply the checked-in down script and confirm the
    // table is gone, then re-apply forward so the DB is left consistent.
    let down = include_str!("../migrations_rollback/0004_push_subscriptions_down.sql");
    sqlx::query(down)
        .execute(&pool)
        .await
        .expect("rollback runs");
    let exists_after: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT FROM information_schema.tables \
         WHERE table_name = 'push_subscriptions')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(!exists_after, "rollback must drop push_subscriptions");
}
