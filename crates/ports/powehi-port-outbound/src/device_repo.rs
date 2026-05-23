use async_trait::async_trait;
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    user::UserId,
};

#[async_trait]
pub trait DeviceRepository: Send + Sync {
    async fn save(&self, device: &Device) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: &DeviceId) -> Result<Option<Device>, DomainError>;
    async fn find_by_user(&self, user_id: &UserId) -> Result<Vec<Device>, DomainError>;
    async fn delete(&self, id: &DeviceId) -> Result<(), DomainError>;
}
