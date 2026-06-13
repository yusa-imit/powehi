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
    async fn remove_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError>;
    async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError>;
    /// Returns all group IDs that `device_id` is a member of.
    async fn list_groups_for_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<GroupId>, DomainError>;
    /// Atomically upsert a group stub and insert all members in a single transaction.
    /// Uses ON CONFLICT DO NOTHING for both the group row and each member row, so
    /// re-syncing an already-known group is idempotent and safe under concurrent calls.
    async fn upsert_members(
        &self,
        group: &Group,
        members: &[GroupMember],
    ) -> Result<(), DomainError>;
}
