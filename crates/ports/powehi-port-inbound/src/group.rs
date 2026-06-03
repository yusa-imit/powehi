use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, GroupId},
};

#[async_trait]
pub trait GroupUseCase: Send + Sync {
    async fn create_group(&self, creator: &DeviceId, group_id: GroupId) -> Result<(), DomainError>;

    /// Add `device_id` to `group_id` at `epoch`. `caller` must already be a member
    /// of the group; fails with `Unauthorized` otherwise (fail-closed).
    async fn add_member(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError>;

    /// Remove `device_id` from `group_id`. `caller` must already be a member
    /// of the group; fails with `Unauthorized` otherwise (fail-closed).
    async fn remove_member(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError>;
}
