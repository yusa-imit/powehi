use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId},
    error::DomainError,
    group::{Epoch, GroupId},
};

#[async_trait]
pub trait MessagingUseCase: Send + Sync {
    async fn send_message(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        ciphertext: Bytes,
        ttl_seconds: Option<u32>,
    ) -> Result<EnvelopeId, DomainError>;

    async fn send_welcome(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        welcome: Bytes,
        target: &DeviceId,
    ) -> Result<(), DomainError>;

    /// `expected_epoch` MUST be the epoch the sender's client built this
    /// Commit against (its own last-known epoch for the group). The server
    /// uses it as a compare-and-swap precondition and rejects with
    /// `DomainError::EpochMismatch` if the stored epoch has already moved —
    /// this is what makes it safe for two clients to race a Commit for the
    /// same group: exactly one is ever accepted, the other must re-fetch the
    /// new epoch and rebuild its Commit before retrying. Mirrors the
    /// cross-region `RegionRouter::forward_commit` contract.
    async fn send_commit(
        &self,
        sender: &DeviceId,
        group_id: &GroupId,
        commit: Bytes,
        expected_epoch: Epoch,
    ) -> Result<Epoch, DomainError>;

    /// `since`/`since_id` form an exact keyset cursor — see
    /// `EnvelopeRepository::find_pending`'s doc comment for why both must be
    /// supplied together (from the same last-processed envelope) rather than
    /// a coarsened timestamp alone.
    async fn poll_envelopes(
        &self,
        device_id: &DeviceId,
        since: Option<DateTime<Utc>>,
        since_id: Option<EnvelopeId>,
    ) -> Result<Vec<Envelope>, DomainError>;

    async fn ack_envelope(
        &self,
        device_id: &DeviceId,
        envelope_id: &EnvelopeId,
    ) -> Result<(), DomainError>;
}
