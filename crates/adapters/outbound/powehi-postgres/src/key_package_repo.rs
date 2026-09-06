use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::{ConsumeResult, KeyPackage, KeyPackageId},
};
use powehi_port_outbound::key_package_repo::KeyPackageRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::map_err;

#[derive(sqlx::FromRow)]
struct KeyPackageRow {
    id: Uuid,
    device_id: Uuid,
    data: Vec<u8>,
    uploaded_at: DateTime<Utc>,
    consumed: bool,
}

impl From<KeyPackageRow> for KeyPackage {
    fn from(r: KeyPackageRow) -> Self {
        KeyPackage {
            id: KeyPackageId::from(r.id),
            device_id: DeviceId::from(r.device_id),
            data: r.data,
            uploaded_at: r.uploaded_at,
            consumed: r.consumed,
        }
    }
}

pub struct PgKeyPackageRepository {
    pool: PgPool,
}

impl PgKeyPackageRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl KeyPackageRepository for PgKeyPackageRepository {
    async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO key_packages (id, device_id, data, uploaded_at, consumed)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(kp.id.as_uuid())
        .bind(kp.device_id.as_uuid())
        .bind(&kp.data)
        .bind(kp.uploaded_at)
        .bind(kp.consumed)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError> {
        // Atomic: mark consumed and return in one statement (SKIP LOCKED prevents races)
        let row = sqlx::query_as::<_, KeyPackageRow>(
            "UPDATE key_packages
             SET consumed = TRUE
             WHERE id = (
                 SELECT id FROM key_packages
                 WHERE device_id = $1 AND consumed = FALSE
                 ORDER BY uploaded_at ASC
                 LIMIT 1
                 FOR UPDATE SKIP LOCKED
             )
             RETURNING id, device_id, data, uploaded_at, consumed",
        )
        .bind(device_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(KeyPackage::from))
    }

    async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM key_packages WHERE device_id = $1 AND consumed = FALSE",
        )
        .bind(device_id.as_uuid())
        .fetch_one(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.0 as u64)
    }

    async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM key_packages WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<u64, DomainError> {
        let rows = sqlx::query("DELETE FROM key_packages WHERE device_id = $1")
            .bind(device_id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?
            .rows_affected();
        Ok(rows)
    }

    async fn mark_consumed(&self, id: &KeyPackageId) -> Result<ConsumeResult, DomainError> {
        // Attempt to flip consumed = FALSE → TRUE atomically.
        let rows = sqlx::query(
            "UPDATE key_packages SET consumed = TRUE WHERE id = $1 AND consumed = FALSE",
        )
        .bind(id.as_uuid())
        .execute(&self.pool)
        .await
        .map_err(map_err)?
        .rows_affected();

        if rows == 1 {
            return Ok(ConsumeResult::Consumed);
        }

        // No rows updated — distinguish AlreadyConsumed from NotFound.
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM key_packages WHERE id = $1)")
                .bind(id.as_uuid())
                .fetch_one(&self.pool)
                .await
                .map_err(map_err)?;

        Ok(if exists {
            ConsumeResult::AlreadyConsumed
        } else {
            ConsumeResult::NotFound
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: KeyPackageRepository>() {}

    #[test]
    fn pg_key_package_repo_impl_trait() {
        assert_impl::<PgKeyPackageRepository>();
    }
}
