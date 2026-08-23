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

fn msg_type_to_str(t: MessageType) -> &'static str {
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
        let rows = if let Some(since) = since {
            sqlx::query_as::<_, EnvelopeRow>(
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
                   AND created_at > $2
                   AND (expires_at IS NULL OR expires_at > NOW())
                 ORDER BY created_at ASC",
            )
            .bind(device_id.as_uuid())
            .bind(since)
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?
        } else {
            sqlx::query_as::<_, EnvelopeRow>(
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
                 ORDER BY created_at ASC",
            )
            .bind(device_id.as_uuid())
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?
        };
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
