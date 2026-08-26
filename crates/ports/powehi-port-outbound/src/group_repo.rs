use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Group, GroupId, GroupMember},
};

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn save(&self, group: &Group) -> Result<(), DomainError>;
    /// Insert a group row only if `group.id` is not already present.
    ///
    /// Returns `true` when a new row was created, `false` when the id already
    /// existed — in which case no column of the existing row is modified.
    ///
    /// This is the client-facing creation primitive. Unlike
    /// [`GroupRepository::save`] (a destructive upsert, still needed to persist
    /// an epoch advance on commit), it can never reset an existing group's
    /// `epoch`, `home_region` or `created_at`, so a caller that supplies another
    /// group's id cannot downgrade or hijack it.
    async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError>;
    /// Atomically create a group and add `creator` as its sole initial member
    /// in a single transaction.
    ///
    /// Returns `true` when a new group row was created, `false` when
    /// `group.id` already existed — in which case neither the group row nor
    /// `creator`'s membership row is touched. Unlike calling
    /// [`GroupRepository::create_if_absent`] followed by
    /// [`GroupRepository::add_member`] as two separate calls, a failure
    /// between the two (DB error, pod kill) can never leave a group row with
    /// zero members, which would otherwise be permanently unusable — every
    /// future `create_group` retry would hit the already-exists-and-not-a-
    /// member branch forever since nothing may add the first member once the
    /// group is known to exist.
    ///
    /// Implementors must bind the membership row's `group_id` to `group.id`
    /// (not to `creator.group_id`, which callers are expected but not
    /// enforced to keep equal) — this makes a caller-side mismatch between
    /// the two arguments inert instead of granting membership in whichever
    /// group `creator.group_id` happens to name.
    async fn create_with_creator(
        &self,
        group: &Group,
        creator: &GroupMember,
    ) -> Result<bool, DomainError>;
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
