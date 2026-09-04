use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
    abuse::AbuseSignal,
    device::DeviceId,
    envelope::Envelope,
    error::DomainError,
    group::{Epoch, GroupId},
    region::RegionId,
    user::UserId,
};

#[async_trait]
pub trait RegionRouter: Send + Sync {
    async fn resolve_home_region(&self, user_id: &UserId) -> Result<RegionId, DomainError>;
    async fn resolve_group_region(&self, group_id: &GroupId) -> Result<RegionId, DomainError>;
    async fn forward_envelope(
        &self,
        target_region: &RegionId,
        envelope: &Envelope,
    ) -> Result<(), DomainError>;
    /// Forward an MLS commit to a peer region.
    ///
    /// `sender_device_id` MUST be the device ID of the locally authenticated
    /// caller. The destination region cross-checks group membership and the
    /// mTLS peer certificate; passing an untrusted value will produce a
    /// `PermissionDenied` response from the peer.
    ///
    /// `expected_epoch` MUST be the epoch the caller built this Commit
    /// against (i.e. the group's last-known epoch locally). The destination
    /// region uses it as a compare-and-swap precondition and rejects the
    /// call with `DomainError::EpochMismatch` if its own stored epoch has
    /// already moved past it — this is the sole mechanism that prevents two
    /// concurrent commits for the same group from both being accepted
    /// against the same epoch. Passing a stale value is always safe (it can
    /// only cause a legitimate rejection); it is never adopted as the new
    /// epoch, which is always the destination's own `stored_epoch + 1`.
    async fn forward_commit(
        &self,
        target_region: &RegionId,
        group_id: &GroupId,
        sender_device_id: &DeviceId,
        commit: Bytes,
        expected_epoch: Epoch,
    ) -> Result<Epoch, DomainError>;
    /// Fan an abuse signal out to every peer region (prd.md §6.4).
    ///
    /// **Best-effort / fire-and-forget.** prd.md §6.4 specifies cross-region
    /// abuse synchronisation as asynchronous with 최종 일관성 (eventual
    /// consistency), so implementations MUST return `Ok(())` even when some or
    /// all peers are unreachable: the caller's *local* block decision has
    /// already been committed and must never be failed or rolled back because a
    /// remote region is down. Individual peer failures are logged (opaque
    /// region ID + error kind only) and dropped.
    ///
    /// Receivers MUST NOT re-broadcast a signal they received — the fan-out is
    /// one hop from the origin region, otherwise the mesh loops forever.
    async fn broadcast_abuse_signal(&self, signal: &AbuseSignal) -> Result<(), DomainError>;

    fn is_local(&self, region: &RegionId) -> bool;
}
