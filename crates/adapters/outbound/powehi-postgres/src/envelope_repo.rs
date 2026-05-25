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
        let rows = if let Some(since) = since {
            sqlx::query_as::<_, EnvelopeRow>(
                "SELECT id, group_id, sender_device_id, recipient_device_id,
                        message_type, ciphertext, epoch, created_at, expires_at
                 FROM envelopes
                 WHERE recipient_device_id = $1 AND created_at > $2
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
                 WHERE recipient_device_id = $1
                 ORDER BY created_at ASC",
            )
            .bind(device_id.as_uuid())
            .fetch_all(&self.pool)
            .await
            .map_err(map_err)?
        };
        Ok(rows.into_iter().map(Envelope::from).collect())
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
        let result = sqlx::query(
            "DELETE FROM envelopes WHERE expires_at IS NOT NULL AND expires_at < NOW()",
        )
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(result.rows_affected())
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
