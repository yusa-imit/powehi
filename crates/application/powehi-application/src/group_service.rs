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
        let member = GroupMember {
            group_id: group_id.clone(),
            device_id: creator.clone(),
            joined_at_epoch: Epoch(0),
        };
        // create_with_creator, never save(): save() is a destructive upsert
        // that would reset an existing group's epoch/home_region, so a
        // client-supplied group_id colliding with a live group would hijack
        // it. The group row and the creator's membership row are created in
        // one transaction so a mid-write failure can never leave a group with
        // zero members (which would otherwise be permanently stuck: nothing
        // may add a first member once the id is known to exist).
        if !self.group_repo.create_with_creator(&group, &member).await? {
            // The id already exists. Do NOT fall through to adding a member:
            // that is how a non-member (including a device previously evicted
            // via remove_member) could rejoin an arbitrary group just by
            // knowing its id. Only a device that is already a member may
            // reach this path, and for it the call is an idempotent retry.
            let already_member = self
                .group_repo
                .list_members(&group_id)
                .await?
                .iter()
                .any(|m| &m.device_id == creator);
            if already_member {
                return Ok(());
            }
            tracing::warn!(caller = %creator, group_id = %group_id, "create_group: group id already exists and caller is not a member");
            return Err(DomainError::AlreadyExists(group_id.to_string()));
        }
        Ok(())
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
        self.group_repo.remove_member(group_id, device_id).await?;
        // This is a REQUEST to clear the pending-removal reminder, not a
        // guarantee that it is cleared. The repository only honours it once
        // the group's epoch has advanced strictly past the epoch recorded
        // when the reminder was written — i.e. once *some* Commit landed
        // since then (see `GroupRepository::delete_pending_removal` for why
        // this is a heuristic, not proof that the Remove for THIS device
        // specifically landed — the server cannot see Commit contents at
        // all). Removing `device_id` from `group_members` is server routing
        // metadata only; it is NOT evidence that any Commit ever landed, so
        // a member who calls this endpoint with no epoch advance since the
        // reminder was written leaves the reminder in place by design.
        // Best-effort and idempotent: a device removed for reasons unrelated
        // to revocation simply has no row, and a failure here must not fail
        // the removal — a stale reminder is merely redundant noise for
        // clients, never a loss of a guarantee (the reminder never was a
        // guarantee, and grants no capability either way).
        if self
            .group_repo
            .delete_pending_removal(group_id, device_id)
            .await
            .is_err()
        {
            tracing::warn!(
                group_id = %group_id,
                error_kind = "db_error",
                "remove_member: failed to clear pending removal; stale reminder may persist"
            );
        }
        Ok(())
    }

    #[instrument(skip(self), fields(caller = %caller, group_id = %group_id))]
    async fn list_pending_removals(
        &self,
        caller: &DeviceId,
        group_id: &GroupId,
    ) -> Result<Vec<DeviceId>, DomainError> {
        // Same fail-closed guard and TOCTOU caveat as add_member above.
        if !self
            .group_repo
            .list_members(group_id)
            .await?
            .iter()
            .any(|m| &m.device_id == caller)
        {
            tracing::warn!(caller = %caller, group_id = %group_id, "list_pending_removals: caller is not a member");
            return Err(DomainError::Unauthorized);
        }
        self.group_repo.list_pending_removals(group_id).await
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
        pending: Mutex<Vec<(GroupId, DeviceId, Epoch)>>,
    }
    impl FakeGroupRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(vec![]),
                pending: Mutex::new(vec![]),
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
        async fn advance_epoch(
            &self,
            group_id: &GroupId,
            expected: Epoch,
        ) -> Result<Option<Epoch>, DomainError> {
            // Mirrors the real adapter's CAS: only advance-and-persist when
            // the caller's `expected` matches the stored epoch exactly.
            let mut groups = self.groups.lock().unwrap();
            match groups.get_mut(group_id) {
                Some(group) if group.epoch == expected => {
                    let new_epoch = Epoch(expected.0 + 1);
                    group.epoch = new_epoch;
                    Ok(Some(new_epoch))
                }
                _ => Ok(None),
            }
        }
        async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError> {
            // Mirrors ON CONFLICT (id) DO NOTHING: an existing row is left intact.
            let mut groups = self.groups.lock().unwrap();
            if groups.contains_key(&group.id) {
                return Ok(false);
            }
            groups.insert(group.id.clone(), group.clone());
            Ok(true)
        }
        async fn create_with_creator(
            &self,
            group: &Group,
            creator: &GroupMember,
        ) -> Result<bool, DomainError> {
            // Mirrors the real adapter's single-transaction semantics: both
            // the group lock and the members lock are updated before either
            // is released back to another caller, so no interleaved reader
            // can observe a group with zero members.
            let mut groups = self.groups.lock().unwrap();
            if groups.contains_key(&group.id) {
                return Ok(false);
            }
            groups.insert(group.id.clone(), group.clone());
            self.members.lock().unwrap().push(GroupMember {
                group_id: group.id.clone(),
                device_id: creator.device_id.clone(),
                joined_at_epoch: creator.joined_at_epoch,
            });
            Ok(true)
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
        async fn create_pending_removal(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            // Mirrors the real SQL's epoch gate: capture the group's current
            // epoch atomically with the insert (an absent group records
            // nothing, same as `INSERT ... SELECT ... FROM groups` selecting
            // zero rows), and ON CONFLICT (group_id, device_id) DO NOTHING
            // preserves whatever epoch the original insert recorded. Look up
            // the group and release its lock before taking the `pending`
            // lock, to avoid a lock-ordering deadlock with other methods.
            let epoch = match self.groups.lock().unwrap().get(group_id) {
                Some(group) => group.epoch,
                None => return Ok(()),
            };
            let mut pending = self.pending.lock().unwrap();
            if !pending
                .iter()
                .any(|(g, d, _)| g == group_id && d == device_id)
            {
                pending.push((group_id.clone(), device_id.clone(), epoch));
            }
            Ok(())
        }
        async fn delete_pending_removal(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            // Mirrors the real SQL's epoch gate: only clear entries whose
            // recorded `created_at_epoch` is strictly less than the group's
            // current epoch — i.e. only once a real epoch advance (standing
            // in for a landed MLS Remove Commit) has happened since the
            // reminder was written. An absent group leaves pending untouched.
            let current_epoch = match self.groups.lock().unwrap().get(group_id) {
                Some(group) => group.epoch,
                None => return Ok(()),
            };
            self.pending
                .lock()
                .unwrap()
                .retain(|(g, d, e)| !(g == group_id && d == device_id && *e < current_epoch));
            Ok(())
        }
        async fn list_pending_removals(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            Ok(self
                .pending
                .lock()
                .unwrap()
                .iter()
                .filter(|(g, _, _)| g == group_id)
                .map(|(_, d, _)| d.clone())
                .collect())
        }
        // No-op stub: this fake's `pending` storage carries no timestamps,
        // and no group_service test asserts on retention sweeping.
        async fn sweep_stale_pending_removals(
            &self,
            _older_than: chrono::DateTime<chrono::Utc>,
            _limit: u32,
        ) -> Result<u64, DomainError> {
            Ok(0)
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

    /// Broken-access-control regression (security-auditor HIGH): a device that
    /// is not a member must not be able to attach itself to an existing group by
    /// POSTing that group's id to create_group. Previously `save()`'s destructive
    /// upsert reset the group and `add_member` ran unconditionally, which let an
    /// evicted device rejoin and then evict everyone else.
    #[tokio::test]
    async fn create_group_with_existing_id_by_non_member_returns_already_exists() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let owner = DeviceId::new();
        let attacker = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&owner, group_id.clone()).await.unwrap();

        let err = svc
            .create_group(&attacker, group_id.clone())
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::AlreadyExists(ref id) if id == &group_id.to_string()),
            "expected AlreadyExists, got {err:?}"
        );

        let members = repo.list_members(&group_id).await.unwrap();
        assert_eq!(members.len(), 1, "member list must be unchanged");
        assert_eq!(members[0].device_id, owner);
        assert!(
            !members.iter().any(|m| m.device_id == attacker),
            "attacker must not have been added to the group"
        );
    }

    /// Same attack, but by a device that was previously removed from the group:
    /// removal must be permanent through this path.
    #[tokio::test]
    async fn create_group_cannot_be_used_to_rejoin_after_removal() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let owner = DeviceId::new();
        let evicted = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&owner, group_id.clone()).await.unwrap();
        svc.add_member(&owner, &group_id, &evicted, Epoch(1))
            .await
            .unwrap();
        svc.remove_member(&owner, &group_id, &evicted, Epoch(2))
            .await
            .unwrap();

        let err = svc
            .create_group(&evicted, group_id.clone())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::AlreadyExists(_)));

        let members = repo.list_members(&group_id).await.unwrap();
        assert!(
            !members.iter().any(|m| m.device_id == evicted),
            "an evicted device must not regain membership via create_group"
        );
    }

    /// A genuine client retry (same creator, same group_id) is an idempotent
    /// no-op: no duplicate member row, and the stored group is not reset.
    #[tokio::test]
    async fn create_group_retry_by_existing_member_is_idempotent() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let creator = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&creator, group_id.clone()).await.unwrap();

        // Advance the group the way send_commit would, then retry the create.
        let mut advanced = repo.find_by_id(&group_id).await.unwrap().unwrap();
        advanced.epoch = Epoch(7);
        advanced.home_region = RegionId::new("ap-northeast");
        repo.save(&advanced).await.unwrap();

        svc.create_group(&creator, group_id.clone())
            .await
            .expect("retry by an existing member must succeed as a no-op");

        let members = repo.list_members(&group_id).await.unwrap();
        assert_eq!(members.len(), 1, "retry must not duplicate the member row");
        assert_eq!(members[0].device_id, creator);

        let group = repo.find_by_id(&group_id).await.unwrap().unwrap();
        assert_eq!(group.epoch, Epoch(7), "epoch must not be reset by a retry");
        assert_eq!(
            group.home_region.as_str(),
            "ap-northeast",
            "home_region must not be reset by a retry"
        );
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

    #[tokio::test]
    async fn remove_member_clears_a_pending_removal() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&device_a, group_id.clone()).await.unwrap();
        svc.add_member(&device_a, &group_id, &device_b, Epoch(1))
            .await
            .unwrap();
        repo.create_pending_removal(&group_id, &device_b)
            .await
            .unwrap();

        // Stand in for a Commit landing (the gate can't tell which kind —
        // see the "heuristic, not proof" test below): without an epoch
        // advance at all, `delete_pending_removal` is gated shut (see the
        // no-epoch-advance test below).
        let advanced = repo.advance_epoch(&group_id, Epoch(0)).await.unwrap();
        assert_eq!(advanced, Some(Epoch(1)));

        svc.remove_member(&device_a, &group_id, &device_b, Epoch(2))
            .await
            .unwrap();

        let pending = repo.list_pending_removals(&group_id).await.unwrap();
        assert!(
            !pending.contains(&device_b),
            "pending removal must be cleared once the member is actually removed"
        );
    }

    /// A current member must not be able to erase the durable
    /// pending-removal reminder just by calling `remove_member` with no
    /// epoch advance at all — that only touches `group_members` (server
    /// routing metadata) and is no evidence whatsoever that any Commit
    /// landed. Without any epoch advance since the reminder was written, the
    /// reminder must survive the call. (This is the floor the gate
    /// guarantees; see the next test for its ceiling — it does NOT prove the
    /// specific Remove landed, only that *some* Commit did.)
    #[tokio::test]
    async fn remove_member_without_an_epoch_advance_leaves_the_pending_removal_in_place() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&device_a, group_id.clone()).await.unwrap();
        svc.add_member(&device_a, &group_id, &device_b, Epoch(1))
            .await
            .unwrap();
        repo.create_pending_removal(&group_id, &device_b)
            .await
            .unwrap();

        // No epoch advance here — this is the attack: calling remove_member
        // alone, with no Commit ever landing.
        svc.remove_member(&device_a, &group_id, &device_b, Epoch(2))
            .await
            .unwrap();

        let members = repo.list_members(&group_id).await.unwrap();
        assert!(
            !members.iter().any(|m| m.device_id == device_b),
            "device_b must still be gone from server routing metadata"
        );

        let pending = repo.list_pending_removals(&group_id).await.unwrap();
        assert!(
            pending.contains(&device_b),
            "the pending removal must survive a remove_member call with no \
             epoch advance at all — otherwise any current member could \
             erase the durable reminder for free, with zero Commits sent"
        );
    }

    /// KNOWN LIMITATION, not a regression: the epoch gate cannot distinguish
    /// "the Remove for THIS device landed" from "any unrelated Commit landed
    /// since this row was written", because the server never sees Commit
    /// contents (RFC 9420 §6, §12.4 — proposals are inside the encrypted
    /// Commit). A member can send an ordinary self-Update Commit (routine,
    /// RFC 9420 §12.1.2/§12.4.3 recommends it for PCS) and then call
    /// `remove_member` to erase the reminder for an entirely different
    /// device's revocation, without that device's Remove ever landing. This
    /// test locks in that the gate is a noise-reduction heuristic ("costs
    /// one Commit") and not a cryptographic guarantee — see
    /// `GroupRepository::delete_pending_removal`'s doc for the full
    /// reasoning and why real enforcement can only live client-side.
    #[tokio::test]
    async fn remove_member_erases_the_pending_removal_after_any_unrelated_epoch_advance() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&device_a, group_id.clone()).await.unwrap();
        svc.add_member(&device_a, &group_id, &device_b, Epoch(1))
            .await
            .unwrap();
        repo.create_pending_removal(&group_id, &device_b)
            .await
            .unwrap();

        // Any Commit at all — standing in for e.g. device_a's routine
        // self-Update, unrelated to device_b's revocation.
        repo.advance_epoch(&group_id, Epoch(0)).await.unwrap();

        svc.remove_member(&device_a, &group_id, &device_b, Epoch(2))
            .await
            .unwrap();

        let pending = repo.list_pending_removals(&group_id).await.unwrap();
        assert!(
            !pending.contains(&device_b),
            "the gate opens on ANY epoch advance, not specifically device_b's \
             Remove — this is the documented limitation, not a bug"
        );
    }

    #[tokio::test]
    async fn remove_member_succeeds_when_there_is_no_pending_removal() {
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
            .expect("clearing an absent pending removal must be a no-op, not an error");
    }

    #[tokio::test]
    async fn list_pending_removals_rejects_a_non_member_caller() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let owner = DeviceId::new();
        let outsider = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&owner, group_id.clone()).await.unwrap();

        let err = svc
            .list_pending_removals(&outsider, &group_id)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn list_pending_removals_returns_the_pending_devices_for_a_member() {
        let repo = FakeGroupRepo::new();
        let svc = make_svc(repo.clone());
        let owner = DeviceId::new();
        let revoked_a = DeviceId::new();
        let revoked_b = DeviceId::new();
        let group_id = GroupId::new();

        svc.create_group(&owner, group_id.clone()).await.unwrap();
        repo.create_pending_removal(&group_id, &revoked_a)
            .await
            .unwrap();
        repo.create_pending_removal(&group_id, &revoked_b)
            .await
            .unwrap();

        let mut pending = svc.list_pending_removals(&owner, &group_id).await.unwrap();
        pending.sort_by_key(|d| d.as_uuid());
        let mut expected = [revoked_a, revoked_b];
        expected.sort_by_key(|d| d.as_uuid());
        assert_eq!(pending, expected);
    }
}
