use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
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
    async fn forward_commit(
        &self,
        target_region: &RegionId,
        group_id: &GroupId,
        sender_device_id: &DeviceId,
        commit: Bytes,
    ) -> Result<Epoch, DomainError>;
    fn is_local(&self, region: &RegionId) -> bool;
}
