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

    /// Returns the server's currently-recorded epoch counter for `group_id`.
    /// `caller` must already be a member of `group_id`; fails with
    /// `Unauthorized` otherwise (fail-closed, same guard and non-existence-
    /// oracle property as `list_members`/`list_pending_removals`).
    ///
    /// This is the SERVER's view of the epoch — the value
    /// `GroupRepository::advance_epoch`'s compare-and-swap last advanced it
    /// to on an accepted Commit — not a client's own local MLS epoch. The
    /// two can diverge: the server only advances this counter
    /// through the `send_commit`/`advance_epoch` path, so a client whose
    /// membership changes never went through that path (e.g. today's
    /// `add_member` REST call, which does not call `send_commit`) will see
    /// this value lag its local MLS state. Exists so a client can bound
    /// what `expected_epoch` to pass a future `sendCommit` call against,
    /// not as a substitute for the client's own epoch tracking.
    ///
    /// CALLERS MUST TREAT THIS AS AN OPAQUE CAS PRECONDITION TOKEN ONLY —
    /// never as an input to a client's own MLS state decisions (resync
    /// triggers, ratchet tree judgments, overwriting the local epoch). A
    /// malicious server (T3, prd.md §3.1) can return any value here, so
    /// feeding it into local state decisions would reopen the same class of
    /// hazard prd.md §5.4 item 5 documents for `pending_removals`: trusting
    /// a server-reported signal as ground truth.
    ///
    /// REGION-AUTHORITY GUARD (security-auditor, cycle 499): `groups.epoch`
    /// only ever advances via `advance_epoch`'s CAS in the group's
    /// `home_region` (prd.md §4A.5); a group row synced into a non-home
    /// region via `SyncGroupMembership` is created with epoch pinned to 0
    /// and is never updated afterward. Implementors MUST fail closed with
    /// `DomainError::RegionMismatch` rather than answer with that
    /// stale-or-zero value when the group's `home_region` is not the
    /// implementation's own region — an unauthoritative epoch is
    /// indistinguishable from a genuinely fresh group otherwise, and a
    /// future caller feeding it into a `sendCommit` retry loop would spin
    /// forever against a CAS it can never satisfy (prd.md §3.5.1).
    async fn get_epoch(&self, caller: &DeviceId, group_id: &GroupId) -> Result<Epoch, DomainError>;
}
