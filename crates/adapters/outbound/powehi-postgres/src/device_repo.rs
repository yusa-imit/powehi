use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    user::UserId,
};
use powehi_port_outbound::device_repo::DeviceRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::map_err;

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: Uuid,
    user_id: Uuid,
    mls_credential: Vec<u8>,
    created_at: DateTime<Utc>,
    last_seen_at: Option<DateTime<Utc>>,
}

impl From<DeviceRow> for Device {
    fn from(r: DeviceRow) -> Self {
        Device {
            id: DeviceId::from(r.id),
            user_id: UserId::from(r.user_id),
            mls_credential: r.mls_credential,
            created_at: r.created_at,
            last_seen_at: r.last_seen_at,
        }
    }
}

pub struct PgDeviceRepository {
    pool: PgPool,
}

impl PgDeviceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl DeviceRepository for PgDeviceRepository {
    async fn save(&self, device: &Device) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO devices (id, user_id, mls_credential, created_at, last_seen_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (id) DO UPDATE
               SET mls_credential = EXCLUDED.mls_credential,
                   last_seen_at   = EXCLUDED.last_seen_at",
        )
        .bind(device.id.as_uuid())
        .bind(device.user_id.as_uuid())
        .bind(&device.mls_credential)
        .bind(device.created_at)
        .bind(device.last_seen_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: &DeviceId) -> Result<Option<Device>, DomainError> {
        let row = sqlx::query_as::<_, DeviceRow>(
            "SELECT id, user_id, mls_credential, created_at, last_seen_at
             FROM devices WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(Device::from))
    }

    async fn find_by_user(&self, user_id: &UserId) -> Result<Vec<Device>, DomainError> {
        let rows = sqlx::query_as::<_, DeviceRow>(
            "SELECT id, user_id, mls_credential, created_at, last_seen_at
             FROM devices WHERE user_id = $1 ORDER BY created_at ASC",
        )
        .bind(user_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(Device::from).collect())
    }

    async fn delete(&self, id: &DeviceId) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM devices WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: DeviceRepository>() {}

    #[test]
    fn pg_device_repo_impl_trait() {
        assert_impl::<PgDeviceRepository>();
    }
}
