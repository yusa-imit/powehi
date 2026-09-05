use async_trait::async_trait;
use powehi_domain::{
    envelope::Envelope,
    error::DomainError,
    group::{Epoch, GroupId},
};

/// Single-unit-of-work port for accepting an MLS Commit.
///
/// This is deliberately NOT a generic unit-of-work / outbox abstraction. It
/// exists for exactly one cross-aggregate invariant — "an epoch is consumed
/// if and only if the Commit envelope that consumed it is durably stored" —
/// and should not grow additional methods for unrelated multi-table writes.
#[async_trait]
pub trait CommitLedger: Send + Sync {
    /// Atomically advance `group_id`'s epoch by exactly 1 iff its currently
    /// stored epoch equals `expected`, AND persist `commit_envelope` as the
    /// Commit envelope for the new epoch, as a single unit of work.
    ///
    /// Closes the "epoch CAS succeeds, envelope save fails" wedge (prd.md
    /// §4A.5): either both the epoch advance and envelope persist succeed,
    /// or neither does. `commit_envelope.epoch` is ignored on input — the
    /// implementation always stamps the freshly-CAS'd epoch before insert.
    ///
    /// Returns `Ok(None)` on CAS loss (same rejection contract as
    /// `GroupRepository::advance_epoch`) — `commit_envelope` is NOT persisted
    /// in that case.
    ///
    /// Returns `Err(DomainError::AlreadyExists)` if `commit_envelope.id`
    /// collides with an already-stored envelope. Every implementation MUST
    /// treat this as a hard failure of the whole unit of work — roll back
    /// the epoch advance too, never silently treat the pre-existing row as
    /// "already done" and let the epoch consumption commit anyway. Both
    /// current callers mint a fresh UUIDv4 per attempt, so this should never
    /// trigger in practice; the contract exists so a future caller can't
    /// reintroduce the "epoch consumed, envelope missing" wedge via an id
    /// collision instead of a separate failed statement.
    async fn commit_epoch_and_save(
        &self,
        group_id: &GroupId,
        expected: Epoch,
        commit_envelope: &Envelope,
    ) -> Result<Option<Epoch>, DomainError>;
}
