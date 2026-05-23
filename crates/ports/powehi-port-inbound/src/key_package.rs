use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::KeyPackageId,
};

#[async_trait]
pub trait KeyPackageUseCase: Send + Sync {
    async fn upload(
        &self,
        device_id: &DeviceId,
        packages: Vec<Bytes>,
    ) -> Result<Vec<KeyPackageId>, DomainError>;

    async fn fetch_one(
        &self,
        target_device_id: &DeviceId,
    ) -> Result<Bytes, DomainError>;

    async fn count(
        &self,
        device_id: &DeviceId,
    ) -> Result<u64, DomainError>;
}
