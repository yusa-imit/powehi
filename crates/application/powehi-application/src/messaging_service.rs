use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId, MessageType},
    error::DomainError,
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
    #[allow(dead_code)]
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
        self.envelope_repo.save(&envelope).await
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
