use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::{KeyPackage, KeyPackageId},
};

#[async_trait]
pub trait KeyPackageRepository: Send + Sync {
    async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError>;
    /// Atomically fetch one unconsumed KeyPackage and mark it consumed.
    async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError>;
    async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError>;
    async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError>;
}
