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
};
use tracing::instrument;

pub struct MessagingService {
    envelope_repo: Arc<dyn EnvelopeRepository>,
    group_repo: Arc<dyn GroupRepository>,
    event_bus: Arc<dyn DomainEventBus>,
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
    ) -> Result<EnvelopeId, DomainError> {
        let envelope = Envelope::new(
            group_id.clone(),
            sender.clone(),
            None,
            MessageType::Application,
            ciphertext.to_vec(),
        );
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
        region::RegionId,
    };
    use powehi_port_outbound::{
        envelope_repo::EnvelopeRepository,
        event_bus::{DomainEventBus, EventStream},
        group_repo::GroupRepository,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

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
            let store = self.store.lock().unwrap();
            Ok(store
                .values()
                .filter(|e| e.recipient.as_ref() == Some(device_id) || e.recipient.is_none())
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

    #[tokio::test]
    async fn send_message_stores_application_envelope() {
        let env_repo = FakeEnvelopeRepo::new();
        let svc = make_service(env_repo.clone(), FakeGroupRepo::empty());
        let sender = DeviceId::new();
        let group_id = GroupId::new();
        let id = svc
            .send_message(&sender, &group_id, Bytes::from_static(b"ct"))
            .await
            .unwrap();
        let store = env_repo.store.lock().unwrap();
        let env = store.get(&id).expect("envelope saved");
        assert_eq!(env.message_type, MessageType::Application);
        assert_eq!(env.ciphertext, b"ct");
        assert_eq!(env.sender, sender);
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
        svc.send_message(&device_b, &GroupId::new(), Bytes::from_static(b"for-a"))
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
            .send_message(&DeviceId::new(), &GroupId::new(), Bytes::from_static(b"x"))
            .await
            .unwrap();
        svc.ack_envelope(&DeviceId::new(), &id).await.unwrap();
        assert!(env_repo.store.lock().unwrap().get(&id).is_none());
    }
}
