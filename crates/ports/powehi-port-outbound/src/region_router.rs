use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
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
    async fn forward_commit(
        &self,
        target_region: &RegionId,
        group_id: &GroupId,
        commit: Bytes,
    ) -> Result<Epoch, DomainError>;
    fn is_local(&self, region: &RegionId) -> bool;
}
