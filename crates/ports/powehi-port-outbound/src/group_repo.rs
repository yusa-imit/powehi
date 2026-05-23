use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Group, GroupId, GroupMember},
};

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn save(&self, group: &Group) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError>;
    async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError>;
    async fn remove_member(&self, group_id: &GroupId, device_id: &DeviceId) -> Result<(), DomainError>;
    async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError>;
}
