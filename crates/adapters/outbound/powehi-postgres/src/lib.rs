//! Postgres outbound adapters — sqlx runtime queries (no compile-time DB required).
//!
//! Security invariant: none of the adapters log or inspect ciphertext, handle
//! hashes, mls_credential bytes, or key-package data (rule: no-plaintext-logging).

pub mod device_repo;
pub mod envelope_repo;
pub mod group_repo;
pub mod key_package_repo;
pub mod push_subscription_repo;
pub mod server_config_repo;
pub mod user_repo;

pub use device_repo::PgDeviceRepository;
pub use envelope_repo::PgEnvelopeRepository;
pub use group_repo::PgGroupRepository;
pub use key_package_repo::PgKeyPackageRepository;
pub use push_subscription_repo::PgPushSubscriptionRepository;
pub use server_config_repo::PgServerConfigRepository;
pub use user_repo::PgUserRepository;

use powehi_domain::error::DomainError;
use sqlx::postgres::PgPool;

pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPool::connect(url).await
}

pub async fn run_migrations(pool: &PgPool) -> Result<(), sqlx::migrate::MigrateError> {
    sqlx::migrate!().run(pool).await
}

pub(crate) fn map_err(e: sqlx::Error) -> DomainError {
    tracing::error!(error_kind = "sqlx", "database error");
    DomainError::Internal(e.to_string())
}
