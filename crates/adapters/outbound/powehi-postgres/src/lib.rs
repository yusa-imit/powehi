//! Postgres outbound adapters — sqlx runtime queries (no compile-time DB required).
//!
//! Security invariant: none of the adapters log or inspect ciphertext, handle
//! hashes, mls_credential bytes, or key-package data (rule: no-plaintext-logging).

pub mod device_repo;
pub mod envelope_repo;
pub mod group_repo;
pub mod key_package_repo;
pub mod leader_lock;
pub mod push_subscription_repo;
pub mod server_config_repo;
pub mod user_repo;

pub use device_repo::PgDeviceRepository;
pub use envelope_repo::PgEnvelopeRepository;
pub use group_repo::PgGroupRepository;
pub use key_package_repo::PgKeyPackageRepository;
pub use leader_lock::{
    GcLockGuard, PgLeaderLock, GC_LOCK_MEDIA_BLOBS, GC_LOCK_MEDIA_LEDGER, GC_LOCK_MEDIA_ORPHANS,
};
pub use push_subscription_repo::PgPushSubscriptionRepository;
pub use server_config_repo::PgServerConfigRepository;
pub use user_repo::PgUserRepository;

use powehi_domain::error::DomainError;
use sqlx::postgres::{PgPool, PgPoolOptions};

/// Connects with an explicit pool size instead of sqlx's undocumented default
/// (currently 10). The pool is shared cluster-wide by request handlers and the
/// background GC/ledger-trim jobs (which each hold a dedicated session-scoped
/// connection for `pg_try_advisory_lock` — see `leader_lock::PgLeaderLock`), so an
/// invisible default is load-bearing capacity, not a cosmetic knob. `max_connections`
/// must leave headroom for those dedicated connections; `powehi_config` enforces a
/// floor before this is ever called.
///
/// Deliberately leaves `min_connections` at its default of 0: `GcLockGuard`'s `Drop`
/// (`leader_lock::PgLeaderLock`) relies on `min_connections == 0` to safely `detach()` a
/// connection during runtime teardown instead of going through `PoolConnection`'s own
/// `Drop`, which spawns a task and panics if Tokio is already shutting down. Do not add
/// `.min_connections(_)` here without re-checking that safety net.
pub async fn connect(url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!().run(pool).await
}

pub(crate) fn map_err(e: sqlx::Error) -> DomainError {
    tracing::error!(error_kind = "sqlx", "database error");
    DomainError::Internal(e.to_string())
}
