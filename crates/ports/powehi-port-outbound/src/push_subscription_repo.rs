use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError, push_subscription::PushSubscription};

/// Persistence port for Web Push subscriptions. One subscription per device;
/// `upsert` replaces an existing row (the browser re-subscribes on key rotation
/// or endpoint change). Implementations MUST NOT log endpoint/key material.
#[async_trait]
pub trait PushSubscriptionRepository: Send + Sync {
    async fn upsert(&self, sub: &PushSubscription) -> Result<(), DomainError>;
    async fn fetch_by_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Option<PushSubscription>, DomainError>;
    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<(), DomainError>;
}
