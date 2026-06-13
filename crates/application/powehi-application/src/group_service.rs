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

    #[instrument(skip(self), fields(caller = %caller, group_id = %group_id, device_id = %device_id))]
    async fn add_member(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
        device_id: &DeviceId,
        epoch: Epoch,
    ) -> Result<(), DomainError> {
        // Fail-closed: caller must already be a member. TOCTOU: the list_members
        // read and the add_member write are not in the same transaction. A
        // just-revoked caller could slip through in the window. This is acceptable
        // because (a) the MLS Welcome+Commit protocol is the actual E2E auth
        // boundary — a non-member cannot produce a valid MLS state for the group,
        // and (b) the server is zero-trust per prd.md threat model; this check is
        // defense-in-depth. Tracked: security-auditor YELLOW cycle 81.
        if !self
            .group_repo
            .list_members(group_id)
            .await?
            .iter()
            .any(|m| &m.device_id == caller)
        {
            tracing::warn!(caller = %caller, group_id = %group_id, "add_member: caller is not a member");
            return Err(DomainError::Unauthorized);
        }
        let member = GroupMember {
            group_id: group_id.clone(),
            device_id: device_id.clone(),
            joined_at_epoch: epoch,
        };
        self.group_repo.add_member(&member).await
    }

    #[instrument(skip(self), fields(caller = %caller, group_id = %group_id, device_id = %device_id))]
    async fn remove_member(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
        device_id: &DeviceId,
        _epoch: Epoch,
    ) -> Result<(), DomainError> {
        // Same fail-closed guard and TOCTOU caveat as add_member above.
        if !self
            .group_repo
            .list_members(group_id)
            .await?
            .iter()
            .any(|m| &m.device_id == caller)
        {
            tracing::warn!(caller = %caller, group_id = %group_id, "remove_member: caller is not a member");
            return Err(DomainError::Unauthorized);
        }
        self.group_repo.remove_member(group_id, device_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::group::{Group, GroupMember};
    use powehi_port_outbound::group_repo::GroupRepository;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeGroupRepo {
        groups: Mutex<HashMap<GroupId, Group>>,
        members: Mutex<Vec<GroupMember>>,
    }
    impl FakeGroupRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(vec![]),
            })
        }
    }
    #[async_trait::async_trait]
    impl GroupRepository for FakeGroupRepo {
        async fn save(&self, group: &Group) -> Result<(), DomainError> {
            self.groups
                .lock()
                .unwrap()
                .insert(group.id.clone(), group.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError> {
            Ok(self.groups.lock().unwrap().get(id).cloned())
        }
        async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError> {
            self.members.lock().unwrap().push(member.clone());
            Ok(())
        }
        async fn remove_member(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            self.members
                .lock()
                .unwrap()
                .retain(|m| !(&m.group_id == group_id && &m.device_id == device_id));
            Ok(())
        }
        async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|m| &m.group_id == group_id)
                .cloned()
                .collect())
        }
        async fn list_groups_for_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Vec<GroupId>, DomainError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter(|m| &m.device_id == device_id)
                .map(|m| m.group_id.clone())
                .collect())
        }
        async fn upsert_members(
            &self,
            group: &Group,
            members: &[GroupMember],
        ) -> Result<(), DomainError> {
            if self.find_by_id(&group.id).await?.is_none() {
                self.save(group).await?;
            }
            for m in members {
                self.add_member(m).await?;
            }
            Ok(())
        }
    }

    fn make_svc(repo: Arc<FakeGroupRepo>) -> GroupService {
        GroupService::new(repo, RegionId::new("eu-central"))
    }

    #[tokio::test]
    async fn create_group_saves_group_and_adds_creator() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let creator = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&creator, group_id.clone()).await.unwrap();

        let group = repo.find_by_id(&group_id).await.unwrap().unwrap();
        assert_eq!(group.id, group_id);
        let members = repo.list_members(&group_id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].device_id, creator);
        assert_eq!(members[0].joined_at_epoch, Epoch(0));
    }

    #[tokio::test]
    async fn add_member_appends_to_group() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let creator = DeviceId::new();
        let newcomer = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&creator, group_id.clone()).await.unwrap();
        svc.add_member(&creator, &group_id, &newcomer, Epoch(3))
            .await
            .unwrap();

        let members = repo.list_members(&group_id).await.unwrap();
        assert_eq!(members.len(), 2);
        let joined = members.iter().find(|m| m.device_id == newcomer).unwrap();
        assert_eq!(joined.joined_at_epoch, Epoch(3));
    }

    #[tokio::test]
    async fn add_member_by_non_member_returns_unauthorized() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let creator = DeviceId::new();
        let outsider = DeviceId::new();
        let newcomer = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&creator, group_id.clone()).await.unwrap();
        let err = svc
            .add_member(&outsider, &group_id, &newcomer, Epoch(1))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn remove_member_by_non_member_returns_unauthorized() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let creator = DeviceId::new();
        let outsider = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&creator, group_id.clone()).await.unwrap();
        let err = svc
            .remove_member(&outsider, &group_id, &creator, Epoch(1))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn remove_member_excludes_device_from_list() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&device_a, group_id.clone()).await.unwrap();
        svc.add_member(&device_a, &group_id, &device_b, Epoch(1))
            .await
            .unwrap();
        svc.remove_member(&device_a, &group_id, &device_b, Epoch(2))
            .await
            .unwrap();

        let members = repo.list_members(&group_id).await.unwrap();
        assert!(
            !members.iter().any(|m| m.device_id == device_b),
            "device_b must be gone"
        );
        assert_eq!(members.len(), 1);
    }

    #[tokio::test]
    async fn group_region_is_set_from_service_local_region() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let group_id = GroupId::new();
        svc.create_group(&DeviceId::new(), group_id.clone())
            .await
            .unwrap();
        let group = repo.find_by_id(&group_id).await.unwrap().unwrap();
        assert_eq!(group.home_region.as_str(), "eu-central");
    }
}
