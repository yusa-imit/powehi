use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, GroupId},
};

#[async_trait]
pub trait GroupUseCase: Send + Sync {
    async fn create_group(&self, creator: &DeviceId, group_id: GroupId) -> Result<(), DomainError>;

    async fn add_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError>;

    async fn remove_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError>;
}
