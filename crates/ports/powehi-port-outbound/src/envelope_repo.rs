use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId},
    error::DomainError,
};

#[async_trait]
pub trait EnvelopeRepository: Send + Sync {
    async fn save(&self, envelope: &Envelope) -> Result<(), DomainError>;
    /// Return pending envelopes for `device_id`, oldest first, paginated
    /// (bounded row count and bounded cumulative `ciphertext` bytes — see the
    /// adapter for exact limits; security-auditor cycle 350/351, prd.md §11.4).
    ///
    /// `since`/`since_id` together form an exact keyset cursor: pass the
    /// `created_at`/`id` of the last envelope this caller fully processed to
    /// resume immediately after it. Both must be supplied together (from the
    /// same envelope) — passing `since` alone (or a coarsened/rounded value
    /// derived from it) can silently and permanently skip envelopes that
    /// share that exact `created_at` once results are paginated, since a
    /// later poll could otherwise land mid-way through a same-timestamp
    /// group. `None`/`None` fetches from the beginning.
    async fn find_pending(
        &self,
        device_id: &DeviceId,
        since: Option<DateTime<Utc>>,
        since_id: Option<EnvelopeId>,
    ) -> Result<Vec<Envelope>, DomainError>;
    async fn find_by_id(&self, id: &EnvelopeId) -> Result<Option<Envelope>, DomainError>;
    async fn delete(&self, id: &EnvelopeId) -> Result<(), DomainError>;
    async fn delete_expired(&self) -> Result<u64, DomainError>;
    /// Record `device_id`'s ack of a broadcast envelope, then delete the envelope
    /// iff every id in `group_member_ids` has now acked it. Callers must already
    /// have verified `device_id` is a current member (fail-closed access control) —
    /// this method only tracks acks and applies the all-members-acked GC rule.
    async fn ack_broadcast(
        &self,
        envelope_id: &EnvelopeId,
        device_id: &DeviceId,
        group_member_ids: &[DeviceId],
    ) -> Result<(), DomainError>;
}
