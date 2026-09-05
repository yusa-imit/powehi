use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId, MessageType},
    error::DomainError,
    group::{Epoch, GroupId},
};
use powehi_port_outbound::envelope_repo::EnvelopeRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid; // used by sqlx::FromRow row structs

use crate::map_err;

/// Default retention ceiling (prd.md §11.4) for envelopes with no explicit
/// disappearing-message TTL — mirrors media_service.rs's GC_RETENTION_DAYS.
const DEFAULT_RETENTION_DAYS: i64 = 30;

/// Maximum rows returned by a single `find_pending` call. Without this, a
/// device that accumulates a large backlog (e.g. offline for a long time, or a
/// sustained-send abuse pattern) would force `poll_envelopes` to serialize an
/// unbounded result set into one JSON response, risking OOM on the polling
/// device. Flagged by security-auditor cycle 350 (prd.md §11.4). Safe to page
/// only because the cursor is an exact `(created_at, id)` keyset (see
/// `find_pending`'s WHERE clause) — an earlier draft of this fix paged with a
/// bare row-count `LIMIT` while the frontend cursor only had whole-second
/// precision, which could permanently drop same-second envelopes (including
/// MLS Commits — a permanent group-epoch desync) at a page boundary; caught
/// by security-auditor before merge, cycle 351.
///
/// Kept deliberately small (not e.g. 200): `find_pending`'s `fetch_all`
/// materializes every row's full `ciphertext` into the API pod's heap
/// *before* `ENVELOPE_POLL_MAX_BYTES` below gets a chance to trim it —
/// security-auditor cycle 352 pointed out that a byte trim applied only
/// after `fetch_all` returns doesn't bound *server*-side peak memory, only
/// the client-facing response. Now that `messaging_service.rs`'s
/// `MAX_WELCOME_BYTES`/`MAX_COMMIT_BYTES`/`MAX_CIPHERTEXT_BYTES` cap every
/// message type sent over the REST ingress path at send time (also cycle
/// 352 — Welcome/Commit were previously uncapped, the direct enabler of
/// this finding), the worst case per poll is bounded by
/// `ENVELOPE_POLL_LIMIT * MAX_WELCOME_BYTES` (the largest of the three,
/// theoretically) = 64 * 256KB = 16MB raw pre-trim. In practice this is
/// looser than the *actual* worst case, which is lower still: `send_welcome`
/// sits behind `powehi-rest-api`'s global 512KiB body limit, so
/// `MAX_WELCOME_BYTES` is currently unreachable over HTTP and the real cap
/// there is ~143KB raw (see `MAX_WELCOME_BYTES`'s own doc comment,
/// `messaging_service.rs`) — but this constant intentionally reasons from
/// `MAX_WELCOME_BYTES` rather than that tighter, layer-dependent number, so
/// the bound stated here stays correct even if the body limit changes.
/// Envelopes forwarded cross-region via gRPC (`powehi-grpc`'s
/// `forward_envelope`/`forward_commit`) are a separate ingress path with
/// their own matching per-type caps (`MAX_APPLICATION_CIPHERTEXT_BYTES`/
/// `MAX_COMMIT_BYTES`/`MAX_WELCOME_BYTES` duplicated in `server.rs`,
/// threat-model-checker cycle 353) — both paths write into the same
/// `envelopes` table this query reads from, so both had to be bounded for
/// this doc comment's worst case to actually hold. This bound is a
/// meaningful reduction from the prior unbounded-Welcome worst case, though
/// still not as tight as pushing the byte budget into the SQL query itself
/// (deferred,
/// same cycle 352 finding, larger scope than fits one cycle: the WHERE
/// clause's unicast-OR-broadcast branches need separate `UNION ALL` legs to
/// support a `SUM(...) OVER (...)` filter, see the sort-order finding on
/// this query's WHERE clause below).
const ENVELOPE_POLL_LIMIT: i64 = 64;

/// Maximum cumulative *raw* `ciphertext` bytes accumulated across a single
/// `find_pending` page, independent of `ENVELOPE_POLL_LIMIT`. Row count alone
/// doesn't bound response size when individual envelopes are large — a
/// Welcome carries a full MLS ratchet tree (`use_ratchet_tree_extension`,
/// mls_group.rs) that scales with group size, and group size is otherwise
/// unbounded in this codebase (`MAX_WELCOME_BYTES` in messaging_service.rs is
/// generous specifically to avoid rejecting a legitimate large-group invite,
/// cycle 352). Bounding the page total instead closes the client-facing OOM
/// vector for every message type without that risk. At least one row is
/// always returned (see the trim loop below) so a single oversized envelope
/// still makes forward progress rather than stalling the poll loop. Note
/// this bounds the *response*, not the server's peak `fetch_all` allocation
/// — see `ENVELOPE_POLL_LIMIT`'s doc comment above for that half.
///
/// Set to a 4 MiB *raw* budget, not the ~16 MiB actual wire-response ceiling
/// this is meant to bound: `Envelope.ciphertext: Vec<u8>` has no
/// `serde_bytes`, so `axum::Json` serializes it as a JSON numeric array
/// (`[1,2,3,...]`), which — like `MAX_CIPHERTEXT_BYTES` in
/// messaging_service.rs documents for the same reason — inflates raw bytes
/// by ~3.57x. 4 MiB raw × 3.57 ≈ 14.3 MiB wire, comfortably under 16 MiB.
/// Flagged by security-auditor cycle 351 (both the missing budget and this
/// unit mismatch in the first draft).
const ENVELOPE_POLL_MAX_BYTES: usize = 4 * 1024 * 1024;

#[derive(sqlx::FromRow)]
struct EnvelopeRow {
    id: Uuid,
    group_id: Uuid,
    sender_device_id: Uuid,
    recipient_device_id: Option<Uuid>,
    message_type: String,
    ciphertext: Vec<u8>,
    epoch: Option<i64>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

/// `pub(crate)` so `commit_ledger.rs` binds the `message_type` column with the
/// exact same mapping this repo's `save` uses — the two write the same table
/// and must never disagree on the string form.
pub(crate) fn msg_type_to_str(t: MessageType) -> &'static str {
    match t {
        MessageType::Application => "application",
        MessageType::Welcome => "welcome",
        MessageType::Commit => "commit",
        MessageType::Proposal => "proposal",
    }
}

fn str_to_msg_type(s: &str) -> MessageType {
    match s {
        "welcome" => MessageType::Welcome,
        "commit" => MessageType::Commit,
        "proposal" => MessageType::Proposal,
        _ => MessageType::Application,
    }
}

impl From<EnvelopeRow> for Envelope {
    fn from(r: EnvelopeRow) -> Self {
        Envelope {
            id: EnvelopeId::from(r.id),
            group_id: GroupId::from(r.group_id),
            sender: DeviceId::from(r.sender_device_id),
            recipient: r.recipient_device_id.map(DeviceId::from),
            message_type: str_to_msg_type(&r.message_type),
            ciphertext: r.ciphertext,
            epoch: r.epoch.map(|e| Epoch(e as u64)),
            created_at: r.created_at,
            expires_at: r.expires_at,
        }
    }
}

pub struct PgEnvelopeRepository {
    pool: PgPool,
}

impl PgEnvelopeRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EnvelopeRepository for PgEnvelopeRepository {
    async fn save(&self, envelope: &Envelope) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO envelopes
               (id, group_id, sender_device_id, recipient_device_id, message_type,
                ciphertext, epoch, created_at, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(envelope.id.as_uuid())
        .bind(envelope.group_id.as_uuid())
        .bind(envelope.sender.as_uuid())
        .bind(envelope.recipient.as_ref().map(|d| d.as_uuid()))
        .bind(msg_type_to_str(envelope.message_type))
        .bind(&envelope.ciphertext)
        .bind(envelope.epoch.map(|e| e.0 as i64))
        .bind(envelope.created_at)
        .bind(envelope.expires_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_pending(
        &self,
        device_id: &DeviceId,
        since: Option<DateTime<Utc>>,
        since_id: Option<EnvelopeId>,
    ) -> Result<Vec<Envelope>, DomainError> {
        // Return envelopes for this device in two cases:
        //   1. Unicast: recipient_device_id matches the device directly.
        //   2. Broadcast (group message, recipient_device_id IS NULL): the device
        //      is a member of the envelope's group.  The subquery references $1
        //      again — PostgreSQL allows a placeholder to appear multiple times.
        // Fail-closed: `IN (<empty subquery>)` evaluates to FALSE in Postgres, so a
        // device with no group memberships receives zero broadcasts — unicasts arrive
        // normally.  This invariant must be preserved if the subquery is ever
        // refactored to a JOIN (LEFT JOIN / IS NOT DISTINCT FROM have different NULL
        // semantics).
        //
        // Cursor: `(created_at, id) > ($2, $3)`, evaluated as "created_at > $2, OR
        // created_at = $2 AND id > $3" below. This is an exact keyset — unlike a
        // bare `created_at > $2` timestamp cursor, it never ambiguously splits a
        // group of envelopes that share the same `created_at` across two pages,
        // which a rounded/coarsened client-side cursor could otherwise cause to be
        // silently and permanently skipped once results are paginated (see
        // `EnvelopeRepository::find_pending`'s doc comment). `$3` defaults to the
        // nil UUID (always < any real v4 id) when `since_id` is omitted, so
        // `since`-only callers still see every envelope at that exact timestamp.
        //
        // KNOWN GAP (security-auditor cycle 352, deferred — not blocking, ticketed):
        // the `OR` between the unicast and broadcast branches likely makes Postgres
        // plan this as a `BitmapOr`, which returns rows unordered — forcing a full
        // `Sort` of every matching row (`ciphertext` included) before `LIMIT` can
        // apply, even though `envelopes_recipient_created_id_idx` (migration 0011)
        // covers the `ORDER BY`. So `LIMIT` bounds the *response*/app-heap size
        // (see `ENVELOPE_POLL_LIMIT`'s doc comment) but not Postgres's own sort
        // work for a device with a very large backlog. A `UNION ALL` of two
        // separately-ordered, separately-`LIMIT`ed subqueries (one per branch,
        // merged in Rust or via `ORDER BY ... LIMIT` on the union) would let
        // Postgres use an index-ordered scan on each leg instead — larger change,
        // needs its own `EXPLAIN (ANALYZE, BUFFERS)` verification against a seeded
        // backlog, not attempted in the same cycle as the pagination fix itself.
        // Broadcast envelopes this device has already acked but that are still
        // present (waiting on OTHER members to ack — see ack_broadcast) must be
        // excluded here, not just re-tolerated. Pre-pagination this was wasteful
        // but harmless (one poll still returned everything, including new
        // content, in the same response). Post-pagination it is pathological: a
        // single perpetually-offline/removed member can pin a group's entire
        // broadcast history for the full DEFAULT_RETENTION_DAYS floor, and
        // without this filter every reload (fresh sinceRef) would have to page
        // through that ENTIRE already-seen backlog at ENVELOPE_POLL_LIMIT rows
        // per poll before reaching any new traffic — security-auditor cycle 353.
        // NOTE: this closes the storm for envelopes THIS device has explicitly
        // acked, but a device's OWN sent broadcasts are a separate, un-closed
        // instance of the same class — useMessages.ts never acks its own
        // envelopes (they fail MLS decrypt client-side, by design), so they
        // accumulate unacked for the full retention floor exactly like an
        // unresponsive peer's would, and this filter cannot exclude them (no ack
        // row exists to check). A strict improvement, not a full closure of
        // "every reload re-pages the whole already-seen backlog" — security-
        // auditor cycle 353 verification round, deferred as a next-cycle
        // candidate (would need a sender-side skip-and-ack in useMessages.ts).
        // Unicast envelopes need no such check: PgEnvelopeRepository::delete
        // removes them immediately on ack (messaging_service.rs's ack_envelope),
        // so an already-acked unicast envelope can never still be `IN envelopes`.
        let mut rows: Vec<EnvelopeRow> = sqlx::query_as::<_, EnvelopeRow>(
            "SELECT id, group_id, sender_device_id, recipient_device_id,
                    message_type, ciphertext, epoch, created_at, expires_at
             FROM envelopes
             WHERE (
                 recipient_device_id = $1
                 OR (
                     recipient_device_id IS NULL
                     AND group_id IN (
                         SELECT group_id FROM group_members WHERE device_id = $1
                     )
                 )
             )
               AND (expires_at IS NULL OR expires_at > NOW())
               AND (
                   recipient_device_id IS NOT NULL
                   OR NOT EXISTS (
                       SELECT 1 FROM envelope_acks
                       WHERE envelope_acks.envelope_id = envelopes.id
                         AND envelope_acks.device_id = $1
                   )
               )
               AND (
                   $2::timestamptz IS NULL
                   OR created_at > $2
                   OR (created_at = $2 AND id > COALESCE($3::uuid, '00000000-0000-0000-0000-000000000000'::uuid))
               )
             ORDER BY created_at ASC, id ASC
             LIMIT $4",
        )
        .bind(device_id.as_uuid())
        .bind(since)
        .bind(since_id.map(|id| id.as_uuid()))
        .bind(ENVELOPE_POLL_LIMIT)
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;

        // Bound cumulative response size independent of the row-count LIMIT
        // above (see ENVELOPE_POLL_MAX_BYTES doc comment). Safe to cut at any
        // row boundary here — the keyset cursor above has no ties to worry
        // about, unlike a timestamp-only cursor would.
        let mut acc_bytes = 0usize;
        let mut cutoff = rows.len();
        for (i, r) in rows.iter().enumerate() {
            acc_bytes += r.ciphertext.len();
            if acc_bytes > ENVELOPE_POLL_MAX_BYTES && i > 0 {
                cutoff = i;
                break;
            }
        }
        rows.truncate(cutoff);

        Ok(rows.into_iter().map(Envelope::from).collect())
    }

    async fn find_by_id(&self, id: &EnvelopeId) -> Result<Option<Envelope>, DomainError> {
        sqlx::query_as::<_, EnvelopeRow>(
            "SELECT id, group_id, sender_device_id, recipient_device_id,
                    message_type, ciphertext, epoch, created_at, expires_at
             FROM envelopes
             WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)
        .map(|opt| opt.map(Envelope::from))
    }

    async fn delete(&self, id: &EnvelopeId) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM envelopes WHERE id = $1")
            .bind(id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64, DomainError> {
        // Two eligibility paths, matching prd.md §11.4's "Stored_Server -> Expired:
        // TTL 도달 (기본 30일)" state:
        //   1. Explicit disappearing-message TTL (expires_at IS NOT NULL) — deleted
        //      once it elapses, regardless of ack state.
        //   2. Default retention floor (DEFAULT_RETENTION_DAYS) for envelopes with
        //      no explicit TTL — a backstop for broadcasts that can never reach the
        //      all-current-members-acked condition in `ack_broadcast` (e.g. a
        //      member who left the group without ever polling), so they don't
        //      retain ciphertext indefinitely.
        let result = sqlx::query(
            "DELETE FROM envelopes
             WHERE (expires_at IS NOT NULL AND expires_at < NOW())
                OR (expires_at IS NULL
                    AND created_at < NOW() - ($1::bigint * INTERVAL '1 day'))",
        )
        .bind(DEFAULT_RETENTION_DAYS)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(result.rows_affected())
    }

    async fn ack_broadcast(
        &self,
        envelope_id: &EnvelopeId,
        device_id: &DeviceId,
        group_member_ids: &[DeviceId],
    ) -> Result<(), DomainError> {
        let member_uuids: Vec<Uuid> = group_member_ids.iter().map(|d| d.as_uuid()).collect();
        let mut tx = self.pool.begin().await.map_err(map_err)?;
        sqlx::query(
            "INSERT INTO envelope_acks (envelope_id, device_id) VALUES ($1, $2)
             ON CONFLICT (envelope_id, device_id) DO NOTHING",
        )
        .bind(envelope_id.as_uuid())
        .bind(device_id.as_uuid())
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        // Delete the envelope only once every id in group_member_ids has an ack
        // row for it — the `NOT EXISTS (member without a matching ack)` check
        // below is a set-containment test done entirely in SQL for atomicity.
        sqlx::query(
            "DELETE FROM envelopes
             WHERE id = $1
               AND NOT EXISTS (
                   SELECT 1 FROM unnest($2::uuid[]) AS m(device_id)
                   WHERE NOT EXISTS (
                       SELECT 1 FROM envelope_acks
                       WHERE envelope_id = $1 AND device_id = m.device_id
                   )
               )",
        )
        .bind(envelope_id.as_uuid())
        .bind(&member_uuids)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;
        tx.commit().await.map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: EnvelopeRepository>() {}

    #[test]
    fn pg_envelope_repo_impl_trait() {
        assert_impl::<PgEnvelopeRepository>();
    }
}
