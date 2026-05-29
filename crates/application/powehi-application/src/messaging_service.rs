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
        // Best-effort wake-up push to the sender itself (group message — no per-device recipient).
        // In Phase 4+, fan-out to all group members; for now push to sender's devices.
        self.maybe_push(sender).await;
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
        self.envelope_repo.delete(envelope_id).await
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
    use std::collections::HashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    struct FakeEnvelopeRepo {
        store: Mutex<HashMap<EnvelopeId, Envelope>>,
    }
    impl FakeEnvelopeRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
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
            Ok(store
                .values()
                .filter(|e| e.recipient.as_ref() == Some(device_id) || e.recipient.is_none())
                // Disappearing messages: never return envelopes that have expired.
                .filter(|e| e.expires_at.map(|exp| exp > now).unwrap_or(true))
                .cloned()
                .collect())
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
        store: Mutex<HashMap<GroupId, Group>>,
    }
    impl FakeGroupRepo {
        fn with_group(group: Group) -> Arc<Self> {
            let mut m = HashMap::new();
            m.insert(group.id.clone(), group);
            Arc::new(Self {
                store: Mutex::new(m),
            })
        }
        fn empty() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl GroupRepository for FakeGroupRepo {
        async fn save(&self, group: &Group) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(group.id.clone(), group.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn add_member(
            &self,
            _member: &powehi_domain::group::GroupMember,
        ) -> Result<(), DomainError> {
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
            _group_id: &GroupId,
        ) -> Result<Vec<powehi_domain::group::GroupMember>, DomainError> {
            Ok(vec![])
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

    // ── Push support fakes ────────────────────────────────────────────────────

    struct FakePushSubRepo {
        sub: Option<PushSubscription>,
    }
    impl FakePushSubRepo {
        fn with_sub(sub: PushSubscription) -> Arc<Self> {
            Arc::new(Self { sub: Some(sub) })
        }
        fn empty() -> Arc<Self> {
            Arc::new(Self { sub: None })
        }
    }
    #[async_trait::async_trait]
    impl PushSubscriptionRepository for FakePushSubRepo {
        async fn upsert(&self, _sub: &PushSubscription) -> Result<(), DomainError> {
            Ok(())
        }
        async fn fetch_by_device(
            &self,
            _device_id: &DeviceId,
        ) -> Result<Option<PushSubscription>, DomainError> {
            Ok(self.sub.clone())
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
        let svc = make_service(env_repo.clone(), FakeGroupRepo::empty());
        let sender = DeviceId::new();
        let group_id = GroupId::new();
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
        let svc = make_service(env_repo.clone(), FakeGroupRepo::empty());
        let before = Utc::now();
        let id = svc
            .send_message(
                &DeviceId::new(),
                &GroupId::new(),
                Bytes::from_static(b"ct"),
                Some(60),
            )
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
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let err = svc
            .send_message(
                &DeviceId::new(),
                &GroupId::new(),
                Bytes::from_static(b"ct"),
                Some(29),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn send_message_ttl_too_long_returns_invalid_input() {
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        let err = svc
            .send_message(
                &DeviceId::new(),
                &GroupId::new(),
                Bytes::from_static(b"ct"),
                Some(604_801),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::InvalidInput(_)));
    }

    #[tokio::test]
    async fn send_commit_advances_epoch_and_stores_envelope() {
        let group = Group::new(GroupId::new(), RegionId::new("eu-central"));
        let group_id = group.id.clone();
        let env_repo = FakeEnvelopeRepo::new();
        let group_repo = FakeGroupRepo::with_group(group);
        let svc = make_service(env_repo.clone(), group_repo.clone());
        let sender = DeviceId::new();

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
        let env_repo = FakeEnvelopeRepo::new();
        let device_a = DeviceId::new();
        let device_b = DeviceId::new();
        let svc = make_service(env_repo.clone(), FakeGroupRepo::empty());

        // message to device_a
        svc.send_message(
            &device_b,
            &GroupId::new(),
            Bytes::from_static(b"for-a"),
            None,
        )
        .await
        .unwrap();
        // welcome addressed to device_a
        svc.send_welcome(
            &device_b,
            &GroupId::new(),
            Bytes::from_static(b"welcome"),
            &device_a,
        )
        .await
        .unwrap();

        let pending = svc.poll_envelopes(&device_a, None).await.unwrap();
        // broadcast (no recipient) + welcome to device_a both returned
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn ack_envelope_removes_it() {
        let env_repo = FakeEnvelopeRepo::new();
        let svc = make_service(env_repo.clone(), FakeGroupRepo::empty());
        let id = svc
            .send_message(
                &DeviceId::new(),
                &GroupId::new(),
                Bytes::from_static(b"x"),
                None,
            )
            .await
            .unwrap();
        svc.ack_envelope(&DeviceId::new(), &id).await.unwrap();
        assert!(env_repo.store.lock().unwrap().get(&id).is_none());
    }

    // ── maybe_push tests ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn maybe_push_is_noop_when_push_not_configured() {
        // Service built without with_push() — send_message must still succeed.
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty());
        svc.send_message(
            &DeviceId::new(),
            &GroupId::new(),
            Bytes::from_static(b"ct"),
            None,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn maybe_push_is_noop_when_no_subscription_found() {
        // Push is configured but no subscription stored for the sender.
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty())
            .with_push(FakePushSubRepo::empty(), push_ref);
        svc.send_message(
            &DeviceId::new(),
            &GroupId::new(),
            Bytes::from_static(b"ct"),
            None,
        )
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
        let sender = DeviceId::new();
        let sub = make_sub(&sender);
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty())
            .with_push(FakePushSubRepo::with_sub(sub), push_ref);
        svc.send_message(&sender, &GroupId::new(), Bytes::from_static(b"ct"), None)
            .await
            .unwrap();
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            1,
            "notify must be called once when subscription exists"
        );
    }

    #[tokio::test]
    async fn maybe_push_failure_does_not_propagate_to_caller() {
        // Push notify() returns Err — send_message must still return Ok (fire-and-forget).
        let sender = DeviceId::new();
        let sub = make_sub(&sender);
        let push = FakeWebPush::failing();
        let push_ref = Arc::clone(&push);
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty())
            .with_push(FakePushSubRepo::with_sub(sub), push_ref);
        let result = svc
            .send_message(&sender, &GroupId::new(), Bytes::from_static(b"ct"), None)
            .await;
        assert!(
            result.is_ok(),
            "push failure must not propagate to message caller"
        );
        assert_eq!(push.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn send_welcome_fires_push_to_target_not_sender() {
        // send_welcome must push to the Welcome *target*, not the sender.
        let sender = DeviceId::new();
        let target = DeviceId::new();
        let sub = make_sub(&target);
        let push = FakeWebPush::ok();
        let push_ref = Arc::clone(&push);
        let svc = make_service(FakeEnvelopeRepo::new(), FakeGroupRepo::empty())
            .with_push(FakePushSubRepo::with_sub(sub), push_ref);
        svc.send_welcome(
            &sender,
            &GroupId::new(),
            Bytes::from_static(b"welcome"),
            &target,
        )
        .await
        .unwrap();
        assert_eq!(
            push.call_count.load(Ordering::SeqCst),
            1,
            "notify must fire once for the welcome target"
        );
    }
}
