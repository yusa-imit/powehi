use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId, MessageType},
    error::DomainError,
    event::DomainEvent,
    group::{Epoch, GroupId},
};
use powehi_port_inbound::messaging::MessagingUseCase;
use powehi_port_outbound::{
    envelope_repo::EnvelopeRepository, event_bus::DomainEventBus, group_repo::GroupRepository,
    push_subscription_repo::PushSubscriptionRepository, web_push::WebPushPort,
};
use tracing::instrument;

/// Minimum disappearing-message TTL: 30 seconds. Shorter TTLs risk races with
/// in-flight delivery/poll cycles.
const MIN_TTL_SECONDS: u32 = 30;
/// Maximum disappearing-message TTL: 7 days.
const MAX_TTL_SECONDS: u32 = 604_800;
/// Maximum number of push notifications sent per message fan-out. Caps DoS
/// amplification: a single message cannot trigger more than this many pushes
/// regardless of group size. Members beyond the cap receive no push ping but
/// still receive the envelope on their next poll.
const MAX_FAN_OUT_RECIPIENTS: usize = 512;

pub struct MessagingService {
    envelope_repo: Arc<dyn EnvelopeRepository>,
    group_repo: Arc<dyn GroupRepository>,
    event_bus: Arc<dyn DomainEventBus>,
    push_sub_repo: Option<Arc<dyn PushSubscriptionRepository>>,
    web_push: Option<Arc<dyn WebPushPort>>,
}

impl MessagingService {
    pub fn new(
        envelope_repo: Arc<dyn EnvelopeRepository>,
        group_repo: Arc<dyn GroupRepository>,
        event_bus: Arc<dyn DomainEventBus>,
    ) -> Self {
        Self {
            envelope_repo,
            group_repo,
            event_bus,
            push_sub_repo: None,
            web_push: None,
        }
    }

    /// Wire in Web Push support (optional — dev environments may omit VAPID keys).
    pub fn with_push(
        mut self,
        push_sub_repo: Arc<dyn PushSubscriptionRepository>,
        web_push: Arc<dyn WebPushPort>,
    ) -> Self {
        self.push_sub_repo = Some(push_sub_repo);
        self.web_push = Some(web_push);
        self
    }

    /// Fail-closed group membership guard: sender must appear in the group's
    /// member list. Empty member list → Unauthorized (no membership data means
    /// the group was never registered or the group_id is unknown/spoofed).
    async fn check_sender_is_member(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
    ) -> Result<(), DomainError> {
        let members = self.group_repo.list_members(group_id).await?;
        if members.is_empty() {
            tracing::warn!(group_id = %group_id, "messaging: empty member list — fail-closed");
            return Err(DomainError::Unauthorized);
        }
        if !members.iter().any(|m| &m.device_id == sender) {
            return Err(DomainError::Unauthorized);
        }
        Ok(())
    }

    /// Fire-and-forget wake-up notification: look up the recipient's push
    /// subscription and send an empty ping. Errors are logged but never
    /// propagated — push delivery is best-effort and must not fail the message flow.
    async fn maybe_push(&self, recipient: &DeviceId) {
        let (Some(repo), Some(push)) = (self.push_sub_repo.as_ref(), self.web_push.as_ref()) else {
            return;
        };
        match repo.fetch_by_device(recipient).await {
            Ok(Some(sub)) => {
                if push.notify(&sub).await.is_err() {
                    tracing::warn!(error_kind = "push", "web push notify failed");
                }
            }
            Ok(None) => {}
            Err(_) => tracing::warn!(error_kind = "push_repo", "push sub lookup failed"),
        }
    }

    /// Fan-out wake-up: push an empty ping to every group member except the
    /// sender. Sequentially iterates members; individual failures are logged
    /// but never propagated — push delivery is best-effort.
    async fn fan_out_push(&self, sender: &DeviceId, group_id: &GroupId) {
        if self.push_sub_repo.is_none() || self.web_push.is_none() {
            return;
        }
        let members = match self.group_repo.list_members(group_id).await {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!(
                    error_kind = "push_group_lookup",
                    "fan-out push: member lookup failed"
                );
                return;
            }
        };
        let recipients: Vec<_> = members.iter().filter(|m| &m.device_id != sender).collect();
        if recipients.len() > MAX_FAN_OUT_RECIPIENTS {
            tracing::warn!(
                cap = MAX_FAN_OUT_RECIPIENTS,
                "fan-out push: group size cap reached; excess members will not receive push ping"
            );
        }
        for member in recipients.iter().take(MAX_FAN_OUT_RECIPIENTS) {
            self.maybe_push(&member.device_id).await;
        }
    }
}

#[async_trait]
impl MessagingUseCase for MessagingService {
    #[instrument(skip(self, ciphertext), fields(sender = %sender, group_id = %group_id))]
    async fn send_message(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        ciphertext: Bytes,
        ttl_seconds: Option<u32>,
    ) -> Result<EnvelopeId, DomainError> {
        self.check_sender_is_member(sender, group_id).await?;
        // Disappearing messages: TTL is an optional metadata field. When present
        // it must fall within [30s, 7d]. expires_at is computed server-side so
        // clients can never set an arbitrary timestamp. The TTL value itself is
        // never logged alongside device IDs or content (ZK invariant).
        let expires_at = match ttl_seconds {
            Some(ttl) => {
                if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&ttl) {
                    return Err(DomainError::InvalidInput("ttl_seconds out of range".into()));
                }
                Some(Utc::now() + chrono::Duration::seconds(ttl as i64))
            }
            None => None,
        };
        let mut envelope = Envelope::new(
            group_id.clone(),
            sender.clone(),
            None,
            MessageType::Application,
            ciphertext.to_vec(),
        );
        envelope.expires_at = expires_at;
        let id = envelope.id.clone();
        self.envelope_repo.save(&envelope).await?;
        let _ = self
            .event_bus
            .publish(DomainEvent::EnvelopeReceived {
                envelope_id: id.clone(),
                group_id: group_id.clone(),
                at: chrono::Utc::now(),
            })
            .await;
        // Fan-out wake-up push to all group members except the sender (they
        // already know they sent a message). Best-effort: push failure must
        // never stall the message write path.
        self.fan_out_push(sender, group_id).await;
        Ok(id)
    }

    #[instrument(skip(self, welcome), fields(sender = %sender, target = %target))]
    async fn send_welcome(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        welcome: Bytes,
        target: &DeviceId,
    ) -> Result<(), DomainError> {
        self.check_sender_is_member(sender, group_id).await?;
        let envelope = Envelope::new(
            group_id.clone(),
            sender.clone(),
            Some(target.clone()),
            MessageType::Welcome,
            welcome.to_vec(),
        );
        let id = envelope.id.clone();
        self.envelope_repo.save(&envelope).await?;
        let _ = self
            .event_bus
            .publish(DomainEvent::EnvelopeReceived {
                envelope_id: id,
                group_id: group_id.clone(),
                at: chrono::Utc::now(),
            })
            .await;
        // Wake up the Welcome target device via push.
        self.maybe_push(target).await;
        Ok(())
    }

    #[instrument(skip(self, commit), fields(sender = %sender, group_id = %group_id))]
    async fn send_commit(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        commit: Bytes,
    ) -> Result<Epoch, DomainError> {
        let mut group = self
            .group_repo
            .find_by_id(group_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("group".into()))?;
        self.check_sender_is_member(sender, &group.id).await?;
        let new_epoch = Epoch(group.epoch.0 + 1);
        group.epoch = new_epoch;
        self.group_repo.save(&group).await?;
        let mut envelope = Envelope::new(
            group_id.clone(),
            sender.clone(),
            None,
            MessageType::Commit,
            commit.to_vec(),
        );
        envelope.epoch = Some(new_epoch);
        self.envelope_repo.save(&envelope).await?;
        let _ = self
            .event_bus
            .publish(DomainEvent::EpochAdvanced {
                group_id: group_id.clone(),
                new_epoch,
                at: chrono::Utc::now(),
            })
            .await;
        // Wake up all other group members so they can fetch the Commit envelope
        // and ratchet to the new epoch. Best-effort.
        self.fan_out_push(sender, group_id).await;
        Ok(new_epoch)
    }

    #[instrument(skip(self), fields(device_id = %device_id))]
    async fn poll_envelopes(
        &self,
        device_id: &DeviceId,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Envelope>, DomainError> {
        self.envelope_repo.find_pending(device_id, since).await
    }

    #[instrument(skip(self), fields(device_id = %device_id, envelope_id = %envelope_id))]
    async fn ack_envelope(
        &self,
        device_id: &DeviceId,
        envelope_id: &EnvelopeId,
    ) -> Result<(), DomainError> {
        match self.envelope_repo.find_by_id(envelope_id).await? {
            // Envelope already gone — ack is idempotent.
            None => Ok(()),
            // Broadcast (no recipient) — any authenticated device may ack.
            Some(e) if e.recipient.is_none() => self.envelope_repo.delete(envelope_id).await,
            // Unicast — only the intended recipient may ack.
            Some(e) if e.recipient.as_ref() == Some(device_id) => {
                self.envelope_repo.delete(envelope_id).await
            }
            Some(_) => Err(DomainError::Unauthorized),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use powehi_domain::{
        envelope::{Envelope, EnvelopeId},
        event::DomainEvent,
        group::{Group, GroupId},
        push_subscription::PushSubscription,
        region::RegionId,
    };
    use powehi_port_outbound::{
        envelope_repo::EnvelopeRepository,
        event_bus::{DomainEventBus, EventStream},
        group_repo::GroupRepository,
        push_subscription_repo::PushSubscriptionRepository,
        web_push::WebPushPort,
    };
    use std::collections::{HashMap, HashSet};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct FakeEnvelopeRepo {
        store: Mutex<HashMap<EnvelopeId, Envelope>>,
        // group_id → set of member device_ids.  Mirrors the group_members table
        // join in PgEnvelopeRepository: broadcasts are only returned to members.
        memberships: Mutex<HashMap<GroupId, HashSet<DeviceId>>>,
    }
    impl FakeEnvelopeRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
                memberships: Mutex::new(HashMap::new()),
            })
        }

        /// Pre-populate group membership so `find_pending` returns group broadcasts
        /// to the listed members, matching PgEnvelopeRepository's JOIN behaviour.
        fn with_memberships(pairs: Vec<(GroupId, DeviceId)>) -> Arc<Self> {
            let repo = Self::new();
            let mut m = repo.memberships.lock().unwrap();
            for (gid, did) in pairs {
                m.entry(gid).or_default().insert(did);
            }
            drop(m);
            repo
        }
    }
    #[async_trait::async_trait]
    impl EnvelopeRepository for FakeEnvelopeRepo {
        async fn save(&self, env: &Envelope) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(env.id.clone(), env.clone());
            Ok(())
        }
        async fn find_pending(
            &self,
            device_id: &DeviceId,
            _since: Option<chrono::DateTime<Utc>>,
        ) -> Result<Vec<Envelope>, DomainError> {
            let now = Utc::now();
            let store = self.store.lock().unwrap();
            let memberships = self.memberships.lock().unwrap();
            Ok(store
                .values()
                .filter(|e| {
                    match &e.recipient {
                        // Unicast: only the addressed device receives it.
                        Some(r) => r == device_id,
                        // Broadcast: only group members receive it.
                        None => memberships
                            .get(&e.group_id)
                            .is_some_and(|members| members.contains(device_id)),
                    }
                })
                // Disappearing messages: never return envelopes that have expired.
                .filter(|e| e.expires_at.map(|exp| exp > now).unwrap_or(true))
                .cloned()
                .collect())
        }
        async fn find_by_id(&self, id: &EnvelopeId) -> Result<Option<Envelope>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn delete(&self, id: &EnvelopeId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            Ok(())
        }
        async fn delete_expired(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
    }

    struct FakeGroupRepo {
        groups: Mutex<HashMap<GroupId, Group>>,
        members: Mutex<Vec<powehi_domain::group::GroupMember>>,
    }
    impl FakeGroupRepo {
        fn empty() -> Arc<Self> {
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(vec![]),
            })
        }
        /// Group entity + sender as a member (for send_commit tests).
        fn with_group_and_member(group: Group, device_id: DeviceId) -> Arc<Self> {
            let group_id = group.id.clone();
            let mut m = HashMap::new();
            m.insert(group.id.clone(), group);
            Arc::new(Self {
                groups: Mutex::new(m),
                members: Mutex::new(vec![powehi_domain::group::GroupMember {
                    group_id,
                    device_id,
                    joined_at_epoch: Epoch(0),
                }]),
            })
        }
        /// No group entity — just membership record (for send_message / send_welcome tests).
        fn with_member_in(group_id: GroupId, device_id: DeviceId) -> Arc<Self> {
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(vec![powehi_domain::group::GroupMember {
                    group_id,
                    device_id,
                    joined_at_epoch: Epoch(0),
                }]),
            })
        }

        /// Multiple membership records — use when a group needs several members.
        fn with_member_list(pairs: Vec<(GroupId, DeviceId)>) -> Arc<Self> {
            let members = pairs
                .into_iter()
                .map(|(group_id, device_id)| powehi_domain::group::GroupMember {
                    group_id,
                    device_id,
                    joined_at_epoch: Epoch(0),
                })
                .collect();
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(members),
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
        async fn add_member(
            &self,
            member: &powehi_domain::group::GroupMember,
        ) -> Result<(), DomainError> {
            self.members.lock().unwrap().push(member.clone());
            Ok(())
        }
        async fn remove_member(
            &self,
            _group_id: &GroupId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn list_members(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<powehi_domain::group::GroupMember>, DomainError> {
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
            members: &[powehi_domain::group::GroupMember],
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

    struct FakeEventBus;
    #[async_trait::async_trait]
    impl DomainEventBus for FakeEventBus {
        async fn publish(&self, _event: DomainEvent) -> Result<(), DomainError> {
            Ok(())
        }
        async fn subscribe(&self, _topic: &str) -> Result<EventStream, DomainError> {
            Ok(Box::pin(futures::stream::empty()))
        }
    }

    fn make_service(
        env_repo: Arc<dyn EnvelopeRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> MessagingService {
        MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
    }

    /// Helper: service where `sender` is already a member of `group_id`.
    fn make_service_with_member(
        env_repo: Arc<dyn EnvelopeRepository>,
        group_id: GroupId,
        sender: DeviceId,
    ) -> MessagingService {
        let group_repo = FakeGroupRepo::with_member_in(group_id, sender);
        MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
    }

    // ── Push support fakes ────────────────────────────────────────────────────

    struct FakePushSubRepo {
        subs: HashMap<DeviceId, PushSubscription>,
    }
    impl FakePushSubRepo {
        fn with_sub(sub: PushSubscription) -> Arc<Self> {
            let device = sub.device_id.clone();
            Arc::new(Self {
                subs: [(device, sub)].into_iter().collect(),
            })
        }
        fn with_subs(subs: Vec<PushSubscription>) -> Arc<Self> {
            Arc::new(Self {
                subs: subs.into_iter().map(|s| (s.device_id.clone(), s)).collect(),
            })
        }
        fn empty() -> Arc<Self> {
            Arc::new(Self {
                subs: HashMap::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl PushSubscriptionRepository for FakePushSubRepo {
        async fn upsert(&self, _sub: &PushSubscription) -> Result<(), DomainError> {
            Ok(())
        }
        async fn fetch_by_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Option<PushSubscription>, DomainError> {
            Ok(self.subs.get(device_id).cloned())
        }
        async fn delete_by_device(&self, _device_id: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    struct FakeWebPush {
        call_count: AtomicUsize,
        should_fail: bool,
    }
    impl FakeWebPush {
        fn ok() -> Arc<Self> {
            Arc::new(Self {
                call_count: AtomicUsize::new(0),
                should_fail: false,
            })
        }
        fn failing() -> Arc<Self> {
            Arc::new(Self {
                call_count: AtomicUsize::new(0),
                should_fail: true,
            })
        }
    }
    #[async_trait::async_trait]
    impl WebPushPort for FakeWebPush {
        async fn notify(&self, _sub: &PushSubscription) -> Result<(), DomainError> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            if self.should_fail {
                Err(DomainError::Internal("push failed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn make_sub(device: &DeviceId) -> PushSubscription {
        PushSubscription::new(
            device.clone(),
            "https://push.example/abc".into(),
            vec![4u8; 65],
            vec![0u8; 16],
        )
    }

    #[tokio::test]
    async fn send_message_stores_application_envelope() {
        let env_repo = FakeEnvelopeRepo::new();
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc = make_service_with_member(env_repo.clone(), group_id.clone(), sender.clone());
        let id = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        let store = env_repo.store.lock().unwrap();
        let env = store.get(&id).expect("envelope saved");
        assert_eq!(env.message_type, MessageType::Application);
        assert_eq!(env.ciphertext, b"ct");
        assert_eq!(env.sender, sender);
    }

    #[tokio::test]
    async fn send_message_with_ttl_sets_expires_at() {
        let env_repo = FakeEnvelopeRepo::new();
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc = make_service_with_member(env_repo.clone(), group_id.clone(), sender.clone());
        let before = Utc::now();
        let id = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"), Some(60))
            .await
            .unwrap();
        let store = env_repo.store.lock().unwrap();
        let env = store.get(&id).expect("envelope saved");
        let exp = env
            .expires_at
            .expect("expires_at must be set when ttl provided");
        // expires_at is computed server-side: now + 60s.
        assert!(exp > before + chrono::Duration::seconds(59));
        assert!(exp < before + chrono::Duration::seconds(61));
    }

    #[tokio::test]
    async fn send_message_ttl_too_short_returns_invalid_input() {
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc =
            make_service_with_member(FakeEnvelopeRepo::new(), group_id.clone(), sender.clone());
        let err = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"), Some(29))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn send_message_ttl_too_long_returns_invalid_input() {
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc =
            make_service_with_member(FakeEnvelopeRepo::new(), group_id.clone(), sender.clone());
        let err = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"), Some(604_801))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn send_commit_advances_epoch_and_stores_envelope() {
        let sender = DeviceId::new();
        let group = Group::new(GroupId::new(), RegionId::new("eu-central"));
        let group_id = group.id.clone();
        let env_repo = FakeEnvelopeRepo::new();
        let group_repo = FakeGroupRepo::with_group_and_member(group, sender.clone());
        let svc = make_service(env_repo.clone(), group_repo.clone());

        let new_epoch = svc
            .send_commit(&sender, &group_id, Bytes::from_static(b"commit"))
            .await
            .unwrap();

        assert_eq!(new_epoch, Epoch(1));
        let updated = group_repo.find_by_id(&group_id).await.unwrap().unwrap();
        assert_eq!(updated.epoch, Epoch(1));
        let store = env_repo.store.lock().unwrap();
        let commit_env = store
            .values()
            .find(|e| e.message_type == MessageType::Commit)
            .unwrap();
        assert_eq!(commit_env.epoch, Some(Epoch(1)));
    }

    #[tokio::test]
    async fn send_commit_unknown_group_returns_not_found() {
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let err = svc
            .send_commit(&DeviceId::new(), &GroupId::new(), Bytes::from_static(b"x"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn poll_envelopes_returns_recipient_envelopes() {
        let group_id = GroupId::new();
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        // Both devices are members: device_a must be a member for the broadcast
        // to be delivered, and device_b must be a member to send.
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), device_a.clone()),
            (group_id.clone(), device_b.clone()),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), device_a.clone()),
            (group_id.clone(), device_b.clone()),
        ]);
        let svc = make_service(env_repo.clone(), group_repo);

        // Broadcast Application message to the group (recipient = None).
        svc.send_message(&device_b, &group_id, Bytes::from_static(b"for-group"), None)
            .await
            .unwrap();
        // Unicast Welcome addressed to device_a.
        svc.send_welcome(
            &device_b,
            &group_id,
            Bytes::from_static(b"welcome"),
            &device_a,
        )
        .await
        .unwrap();

        let pending = svc.poll_envelopes(&device_a, None).await.unwrap();
        // broadcast (group member) + Welcome unicast — both returned.
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn poll_envelopes_does_not_return_broadcast_for_non_member() {
        // Security invariant: a device NOT in a group must never receive that
        // group's broadcast envelopes, even if they happen to call poll.
        let group_id = GroupId::new();
        let sender = DeviceId::new();
        let non_member = DeviceId::new();
        // Sender is a member; non_member is not.
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![(group_id.clone(), sender.clone())]);
        let group_repo = FakeGroupRepo::with_member_in(group_id.clone(), sender.clone());
        let svc = make_service(env_repo, group_repo);

        svc.send_message(&sender, &group_id, Bytes::from_static(b"secret"), None)
            .await
            .unwrap();

        let pending = svc.poll_envelopes(&non_member, None).await.unwrap();
        assert!(
            pending.is_empty(),
            "non-member must receive zero group broadcasts"
        );
    }

    #[tokio::test]
    async fn poll_envelopes_returns_group_broadcasts_to_member() {
        // A device that IS in the group must receive broadcast Application messages.
        let group_id = GroupId::new();
        let sender = DeviceId::new();
        let member = DeviceId::new();
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member.clone()),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member.clone()),
        ]);
        let svc = make_service(env_repo, group_repo);

        svc.send_message(&sender, &group_id, Bytes::from_static(b"hello"), None)
            .await
            .unwrap();

        let pending = svc.poll_envelopes(&member, None).await.unwrap();
        assert_eq!(pending.len(), 1, "member must receive the group broadcast");
        assert!(pending[0].recipient.is_none(), "envelope is a broadcast");
    }

    #[tokio::test]
    async fn ack_envelope_removes_it() {
        let env_repo = FakeEnvelopeRepo::new();
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc = make_service_with_member(env_repo.clone(), group_id.clone(), sender.clone());
        // send_message creates a broadcast envelope (recipient = None);
        // any authenticated device may ack a broadcast.
        let id = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"x"), None)
            .await
            .unwrap();
        svc.ack_envelope(&DeviceId::new(), &id).await.unwrap();
        assert!(env_repo.store.lock().unwrap().get(&id).is_none());
    }

    #[tokio::test]
    async fn ack_unicast_envelope_by_wrong_device_returns_unauthorized() {
        let sender = DeviceId::new();
        let target = DeviceId::new();
        let wrong = DeviceId::new();
        let group_id = GroupId::new();
        let env_repo = FakeEnvelopeRepo::new();
        let svc = make_service_with_member(env_repo.clone(), group_id.clone(), sender.clone());
        svc.send_welcome(&sender, &group_id, Bytes::from_static(b"welcome"), &target)
            .await
            .unwrap();
        let pending = svc.poll_envelopes(&target, None).await.unwrap();
        assert_eq!(pending.len(), 1);
        let id = pending[0].id.clone();
        let err = svc.ack_envelope(&wrong, &id).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        // envelope must not have been deleted
        assert!(env_repo.store.lock().unwrap().get(&id).is_some());
    }

    #[tokio::test]
    async fn ack_unicast_envelope_by_owner_succeeds() {
        let sender = DeviceId::new();
        let target = DeviceId::new();
        let group_id = GroupId::new();
        let env_repo = FakeEnvelopeRepo::new();
        let svc = make_service_with_member(env_repo.clone(), group_id.clone(), sender.clone());
        svc.send_welcome(&sender, &group_id, Bytes::from_static(b"welcome"), &target)
            .await
            .unwrap();
        let pending = svc.poll_envelopes(&target, None).await.unwrap();
        let id = pending[0].id.clone();
        svc.ack_envelope(&target, &id).await.unwrap();
        assert!(env_repo.store.lock().unwrap().get(&id).is_none());
    }

    #[tokio::test]
    async fn ack_nonexistent_envelope_is_idempotent() {
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let phantom = EnvelopeId::new();
        // deleting something that doesn't exist must not error
        svc.ack_envelope(&DeviceId::new(), &phantom).await.unwrap();
    }

    // ── maybe_push tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn maybe_push_is_noop_when_push_not_configured() {
        // Service built without with_push() — send_message must still succeed.
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let svc =
            make_service_with_member(FakeEnvelopeRepo::new(), group_id.clone(), sender.clone());
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn maybe_push_is_noop_when_no_subscription_found() {
        // Push is configured but no subscription stored for the sender.
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let svc =
            make_service_with_member(FakeEnvelopeRepo::new(), group_id.clone(), sender.clone())
                .with_push(FakePushSubRepo::empty(), push_ref);
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            0,
            "notify must not be called when no subscription exists"
        );
    }

    #[tokio::test]
    async fn maybe_push_notifies_when_subscription_exists() {
        // Fan-out pushes to non-sender members. Add a receiver so the push fires.
        let sender = DeviceId::new();
        let receiver = DeviceId::new();
        let group_id = GroupId::new();
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(vec![make_sub(&sender), make_sub(&receiver)]);
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), receiver.clone()),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), receiver.clone()),
        ]);
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
            .with_push(subs, push_ref);
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        // Only receiver (not sender) is pushed.
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            1,
            "notify must be called once for the receiver"
        );
    }

    #[tokio::test]
    async fn maybe_push_failure_does_not_propagate_to_caller() {
        // Push notify() returns Err — send_message must still return Ok (fire-and-forget).
        let sender = DeviceId::new();
        let receiver = DeviceId::new();
        let group_id = GroupId::new();
        let push = FakeWebPush::failing();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(vec![make_sub(&sender), make_sub(&receiver)]);
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), receiver.clone()),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), receiver.clone()),
        ]);
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
            .with_push(subs, push_ref);
        let result = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await;
        assert!(
            result.is_ok(),
            "push failure must not propagate to message caller"
        );
        // receiver's push was attempted but failed; call count is still 1.
        assert_eq!(push.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn send_welcome_fires_push_to_target_not_sender() {
        // send_welcome must push to the Welcome *target*, not the sender.
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let target = DeviceId::new();
        let sub = make_sub(&target);
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let svc =
            make_service_with_member(FakeEnvelopeRepo::new(), group_id.clone(), sender.clone())
                .with_push(FakePushSubRepo::with_sub(sub), push_ref);
        svc.send_welcome(&sender, &group_id, Bytes::from_static(b"welcome"), &target)
            .await
            .unwrap();
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            1,
            "notify must fire once for the welcome target"
        );
    }

    // ── Group membership authorization tests ─────────────────────────────────

    #[tokio::test]
    async fn send_message_by_non_member_returns_unauthorized() {
        let non_member = DeviceId::new();
        let group_id = GroupId::new();
        // Group exists but non_member is not in it.
        let other_device = DeviceId::new();
        let group_repo = FakeGroupRepo::with_member_in(group_id.clone(), other_device);
        let svc = make_service(FakeEnvelopeRepo::new(), group_repo);
        let err = svc
            .send_message(&non_member, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn send_message_to_unknown_group_returns_unauthorized() {
        // Fail-closed: empty member list → Unauthorized.
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let err = svc
            .send_message(
                &DeviceId::new(),
                &GroupId::new(),
                Bytes::from_static(b"ct"),
                None,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn send_welcome_by_non_member_returns_unauthorized() {
        let non_member = DeviceId::new();
        let target = DeviceId::new();
        let group_id = GroupId::new();
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let err = svc
            .send_welcome(
                &non_member,
                &group_id,
                Bytes::from_static(b"welcome"),
                &target,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn send_commit_by_non_member_returns_unauthorized() {
        let non_member = DeviceId::new();
        let other_device = DeviceId::new();
        let group = Group::new(GroupId::new(), RegionId::new("eu-central"));
        let group_id = group.id.clone();
        // Group exists, but non_member is not in it.
        let group_repo = FakeGroupRepo::with_group_and_member(group, other_device);
        let svc = make_service(FakeEnvelopeRepo::new(), group_repo);
        let err = svc
            .send_commit(&non_member, &group_id, Bytes::from_static(b"commit"))
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    // ── fan_out_push tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn fan_out_notifies_all_members_except_sender() {
        // Security invariant: sender must NOT receive a push for their own message.
        // All other group members MUST receive one push each.
        let sender = DeviceId::new();
        let member_a = DeviceId::new();
        let member_b = DeviceId::new();
        let group_id = GroupId::new();

        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(vec![
            make_sub(&sender),
            make_sub(&member_a),
            make_sub(&member_b),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member_a.clone()),
            (group_id.clone(), member_b.clone()),
        ]);
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member_a.clone()),
            (group_id.clone(), member_b.clone()),
        ]);
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
            .with_push(subs, push_ref);
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        // 2 pushes: member_a + member_b. Sender excluded.
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            2,
            "fan-out must notify exactly 2 members (not the sender)"
        );
    }

    #[tokio::test]
    async fn fan_out_sender_not_notified_even_if_subscribed() {
        // Edge case: only the sender is in the group. Fan-out should fire 0 pushes.
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(vec![make_sub(&sender)]);
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![(group_id.clone(), sender.clone())]);
        let group_repo = FakeGroupRepo::with_member_in(group_id.clone(), sender.clone());
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
            .with_push(subs, push_ref);
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            0,
            "sender-only group must fire zero fan-out pushes"
        );
    }

    #[tokio::test]
    async fn fan_out_on_send_commit_notifies_members_except_committer() {
        let committer = DeviceId::new();
        let peer = DeviceId::new();
        let group = Group::new(GroupId::new(), RegionId::new("eu-de-1"));
        let group_id = group.id.clone();
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(vec![make_sub(&committer), make_sub(&peer)]);
        let group_repo = FakeGroupRepo::with_group_and_member(group, committer.clone());
        // Add peer as a second member via add_member so list_members sees both.
        group_repo
            .add_member(&powehi_domain::group::GroupMember {
                group_id: group_id.clone(),
                device_id: peer.clone(),
                joined_at_epoch: Epoch(0),
            })
            .await
            .unwrap();
        let svc =
            MessagingService::new(FakeEnvelopeRepo::new(), group_repo, Arc::new(FakeEventBus))
                .with_push(subs, push_ref);
        svc.send_commit(&committer, &group_id, Bytes::from_static(b"commit"))
            .await
            .unwrap();
        // Only peer (not committer) should be notified.
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            1,
            "send_commit fan-out must notify peer but not committer"
        );
    }

    #[tokio::test]
    async fn fan_out_noop_when_push_not_configured() {
        // Service with no push config: send_message must still succeed with 0 pushes.
        let sender = DeviceId::new();
        let member = DeviceId::new();
        let group_id = GroupId::new();
        let env_repo = FakeEnvelopeRepo::with_memberships(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member.clone()),
        ]);
        let group_repo = FakeGroupRepo::with_member_list(vec![
            (group_id.clone(), sender.clone()),
            (group_id.clone(), member.clone()),
        ]);
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus));
        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        // No assertion on push count — just verifying no panic/error.
    }

    #[tokio::test]
    async fn fan_out_caps_at_max_recipients() {
        // Security invariant: a group with more than MAX_FAN_OUT_RECIPIENTS members
        // must not trigger more than MAX_FAN_OUT_RECIPIENTS pushes — DoS amplification cap.
        let sender = DeviceId::new();
        let group_id = GroupId::new();

        // Create MAX_FAN_OUT_RECIPIENTS + 2 peers (beyond the cap).
        let peers: Vec<DeviceId> = (0..MAX_FAN_OUT_RECIPIENTS + 2)
            .map(|_| DeviceId::new())
            .collect();

        let mut all_subs: Vec<PushSubscription> = peers.iter().map(make_sub).collect();
        all_subs.push(make_sub(&sender));

        let mut all_pairs: Vec<(GroupId, DeviceId)> = peers
            .iter()
            .map(|p| (group_id.clone(), p.clone()))
            .collect();
        all_pairs.push((group_id.clone(), sender.clone()));

        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let subs = FakePushSubRepo::with_subs(all_subs);
        let group_repo = FakeGroupRepo::with_member_list(all_pairs.clone());
        let env_repo = FakeEnvelopeRepo::with_memberships(all_pairs);
        let svc = MessagingService::new(env_repo, group_repo, Arc::new(FakeEventBus))
            .with_push(subs, push_ref);

        svc.send_message(&sender, &group_id, Bytes::from_static(b"ct"), None)
            .await
            .unwrap();

        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            MAX_FAN_OUT_RECIPIENTS,
            "fan-out must be capped at MAX_FAN_OUT_RECIPIENTS to prevent DoS amplification"
        );
    }
}
