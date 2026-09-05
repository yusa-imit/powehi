use async_trait::async_trait;
use powehi_domain::{
    envelope::Envelope,
    error::DomainError,
    group::{Epoch, GroupId},
};
use powehi_port_outbound::commit_ledger::CommitLedger;
use sqlx::postgres::PgPool;

use crate::{envelope_repo::msg_type_to_str, map_err};

/// Postgres implementation of [`CommitLedger`]: the epoch CAS and the Commit
/// envelope insert run inside one transaction on one connection, so a failure
/// of the insert rolls the epoch advance back instead of durably consuming an
/// epoch whose Commit envelope was never stored (prd.md §4A.5).
pub struct PgCommitLedger {
    pool: PgPool,
}

impl PgCommitLedger {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl CommitLedger for PgCommitLedger {
    async fn commit_epoch_and_save(
        &self,
        group_id: &GroupId,
        expected: Epoch,
        commit_envelope: &Envelope,
    ) -> Result<Option<Epoch>, DomainError> {
        // Same range guard, and the same `InvalidInput` (not `Internal`)
        // mapping, as `PgGroupRepository::advance_epoch`: `expected` arrives
        // directly from a client (REST) or a peer region (gRPC), so an
        // out-of-range value is bad *input*, not a server fault. Silently
        // truncating via `as i64` would let a stale/corrupt u64 match an
        // unrelated stored value in the WHERE clause below.
        let expected_i64 = i64::try_from(expected.0)
            .map_err(|_| DomainError::InvalidInput("epoch exceeds representable range".into()))?;

        let mut tx = self.pool.begin().await.map_err(map_err)?;

        // Identical CAS to `PgGroupRepository::advance_epoch` — only the
        // caller whose `expected` matches the row currently stored moves it,
        // and Postgres's bigint `+` raises on overflow rather than wrapping.
        let row: Option<(i64,)> = sqlx::query_as(
            "UPDATE groups SET epoch = epoch + 1 WHERE id = $1 AND epoch = $2 RETURNING epoch",
        )
        .bind(group_id.as_uuid())
        .bind(expected_i64)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_err)?;

        let Some((new_epoch_i64,)) = row else {
            // CAS lost (concurrent commit, stale caller view, or unknown
            // group). Roll back explicitly rather than relying on drop, and
            // report the same rejection contract as `advance_epoch` — the
            // envelope is NOT persisted.
            tx.rollback().await.map_err(map_err)?;
            return Ok(None);
        };

        // Identical INSERT to `PgEnvelopeRepository::save`, except the `epoch`
        // column is bound to the epoch this transaction just won rather than
        // to `commit_envelope.epoch` — the port contract states the caller's
        // epoch field is ignored, so a caller can never stamp an envelope with
        // an epoch it did not actually consume.
        let insert_result = sqlx::query(
            "INSERT INTO envelopes
               (id, group_id, sender_device_id, recipient_device_id, message_type,
                ciphertext, epoch, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(commit_envelope.id.as_uuid())
        .bind(commit_envelope.group_id.as_uuid())
        .bind(commit_envelope.sender.as_uuid())
        .bind(commit_envelope.recipient.as_ref().map(|d| d.as_uuid()))
        .bind(msg_type_to_str(commit_envelope.message_type))
        .bind(&commit_envelope.ciphertext)
        .bind(new_epoch_i64)
        .bind(commit_envelope.created_at)
        .bind(commit_envelope.expires_at)
        .execute(&mut *tx)
        .await;

        // Explicit rollback on failure, matching the CAS-loss branch above,
        // rather than relying on `Transaction`'s best-effort `Drop` impl —
        // same auditability standard on both of this method's failure paths
        // (crypto-reviewer + security-auditor, cycle 439).
        let rows_affected = match insert_result {
            Err(e) => {
                tx.rollback().await.map_err(map_err)?;
                return Err(map_err(e));
            }
            Ok(res) => res.rows_affected(),
        };

        // Both current callers always mint a fresh UUIDv4 `commit_envelope.id`,
        // so `ON CONFLICT (id) DO NOTHING` should never actually trigger. If it
        // ever did (e.g. a future caller reusing an id as an idempotency key),
        // silently committing here would durably consume the epoch this
        // transaction just won while leaving the *intended* envelope
        // unstored — the same non-atomicity bug class this ledger exists to
        // close, just via a no-op insert instead of a separate statement
        // (crypto-reviewer, cycle 439/441). Fail loudly instead: an id
        // collision at this point means the caller's assumption was wrong,
        // not that the write can be treated as already-done.
        if rows_affected == 0 {
            tx.rollback().await.map_err(map_err)?;
            return Err(DomainError::AlreadyExists(commit_envelope.id.to_string()));
        }

        tx.commit().await.map_err(map_err)?;
        Ok(Some(Epoch(new_epoch_i64 as u64)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: CommitLedger>() {}

    #[test]
    fn pg_commit_ledger_impl_trait() {
        assert_impl::<PgCommitLedger>();
    }
}
