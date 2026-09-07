use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, GroupId, GroupMember},
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

    /// Returns the devices in `group_id` for which the group's remaining
    /// members still owe an MLS Remove proposal/Commit. `caller` must already
    /// be a member of `group_id`; fails with `Unauthorized` otherwise
    /// (fail-closed, same guard as `add_member`/`remove_member`). The
    /// returned list is routing metadata only — device UUIDs, no key material.
    async fn list_pending_removals(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
    ) -> Result<Vec<DeviceId>, DomainError>;

    /// Returns the devices the server currently records as members of
    /// `group_id`. `caller` must already be a member of `group_id`; fails
    /// with `Unauthorized` otherwise (fail-closed, same guard as
    /// `add_member`/`remove_member`/`list_pending_removals`). An unknown
    /// `group_id` is indistinguishable from a group the caller is not in —
    /// both return `Unauthorized`, so this is not a group-existence oracle
    /// at the response level (status/body/error code). Rejection latency
    /// still scales with the real group's membership size (the guard reads
    /// the full list before checking it), a weak timing side channel this
    /// shares with the sibling guards it's modeled on.
    ///
    /// The returned list is routing metadata only — the server's own
    /// `(group_id, device_id)` mapping (prd.md §3.3), never key material,
    /// never MLS LeafNode data (the server cannot see it — prd.md §5.4).
    /// This exists so clients can reconcile a server-reported
    /// `pending_removals` signal against the group's device list rather
    /// than trusting the server outright (prd.md §5.4 trust boundary).
    async fn list_members(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
    ) -> Result<Vec<GroupMember>, DomainError>;
}
