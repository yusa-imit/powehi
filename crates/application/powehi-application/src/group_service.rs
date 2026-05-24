use std::sync::Arc;

use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, Group, GroupId, GroupMember},
    region::RegionId,
};
use powehi_port_inbound::group::GroupUseCase;
use powehi_port_outbound::group_repo::GroupRepository;
use tracing::instrument;

pub struct GroupService {
    group_repo: Arc<dyn GroupRepository>,
    local_region: RegionId,
}

impl GroupService {
    pub fn new(group_repo: Arc<dyn GroupRepository>, local_region: RegionId) -> Self {
        Self {
            group_repo,
            local_region,
        }
    }
}

#[async_trait]
impl GroupUseCase for GroupService {
    #[instrument(skip(self), fields(creator = %creator, group_id = %group_id))]
    async fn create_group(&self, creator: &DeviceId, group_id: GroupId) -> Result<(), DomainError> {
        let group = Group::new(group_id.clone(), self.local_region.clone());
        self.group_repo.save(&group).await?;
        let member = GroupMember {
            group_id,
            device_id: creator.clone(),
            joined_at_epoch: Epoch(0),
        };
        self.group_repo.add_member(&member).await
    }

    #[instrument(skip(self), fields(group_id = %group_id, device_id = %device_id))]
    async fn add_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError> {
        let member = GroupMember {
            group_id: group_id.clone(),
            device_id: device_id.clone(),
            joined_at_epoch: epoch,
        };
        self.group_repo.add_member(&member).await
    }

    #[instrument(skip(self), fields(group_id = %group_id, device_id = %device_id))]
    async fn remove_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
        _epoch: Epoch,
    ) -> Result<(), DomainError> {
        self.group_repo.remove_member(group_id, device_id).await
    }
}
