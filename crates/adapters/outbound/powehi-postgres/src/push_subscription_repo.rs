//! Postgres adapter for Web Push subscriptions.
//!
//! Security invariant: this adapter NEVER logs the endpoint URL, p256dh, or
//! auth_secret — all three are device-identifiable (rule: no-plaintext-logging).
//! Only the device UUID and operation name appear in logs.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{device::DeviceId, error::DomainError, push_subscription::PushSubscription};
use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::map_err;

#[derive(sqlx::FromRow)]
struct PushSubscriptionRow {
    device_id: Uuid,
    endpoint: String,
    p256dh: Vec<u8>,
    auth_secret: Vec<u8>,
    #[allow(dead_code)]
    created_at: DateTime<Utc>,
    #[allow(dead_code)]
    updated_at: DateTime<Utc>,
}

impl From<PushSubscriptionRow> for PushSubscription {
    fn from(r: PushSubscriptionRow) -> Self {
        PushSubscription {
            device_id: DeviceId::from(r.device_id),
            endpoint: r.endpoint,
            p256dh: r.p256dh,
            auth_secret: r.auth_secret,
        }
    }
}

pub struct PgPushSubscriptionRepository {
    pool: PgPool,
}

impl PgPushSubscriptionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PushSubscriptionRepository for PgPushSubscriptionRepository {
    async fn upsert(&self, sub: &PushSubscription) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO push_subscriptions (device_id, endpoint, p256dh, auth_secret, updated_at)
             VALUES ($1, $2, $3, $4, now())
             ON CONFLICT (device_id) DO UPDATE
             SET endpoint = EXCLUDED.endpoint,
                 p256dh = EXCLUDED.p256dh,
                 auth_secret = EXCLUDED.auth_secret,
                 updated_at = now()",
        )
        .bind(sub.device_id.as_uuid())
        .bind(&sub.endpoint)
        .bind(&sub.p256dh)
        .bind(&sub.auth_secret)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn fetch_by_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<PushSubscription>, DomainError> {
        let row = sqlx::query_as::<_, PushSubscriptionRow>(
            "SELECT device_id, endpoint, p256dh, auth_secret, created_at, updated_at
             FROM push_subscriptions
             WHERE device_id = $1",
        )
        .bind(device_id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(PushSubscription::from))
    }

    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM push_subscriptions WHERE device_id = $1")
            .bind(device_id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: PushSubscriptionRepository>() {}

    #[test]
    fn pg_push_subscription_repo_impl_trait() {
        assert_impl::<PgPushSubscriptionRepository>();
    }
}
