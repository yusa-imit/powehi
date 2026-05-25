use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;
use crate::group::{Epoch, GroupId};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvelopeId(Uuid);

impl EnvelopeId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for EnvelopeId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for EnvelopeId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for EnvelopeId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// MLS application message (fully encrypted, server cannot read).
    Application,
    /// MLS Welcome message for new members.
    Welcome,
    /// MLS Commit updating the group epoch.
    Commit,
    /// MLS Proposal (not yet committed).
    Proposal,
}

/// Opaque delivery unit. The `ciphertext` field is E2EE — server never decrypts it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: EnvelopeId,
    pub group_id: GroupId,
    pub sender: DeviceId,
    pub recipient: Option<DeviceId>,
    pub message_type: MessageType,
    /// Opaque MLS ciphertext / message bytes. Server MUST NOT attempt to decrypt.
    pub ciphertext: Vec<u8>,
    pub epoch: Option<Epoch>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl Envelope {
    pub fn new(
        group_id: GroupId,
        sender: DeviceId,
        recipient: Option<DeviceId>,
        message_type: MessageType,
        ciphertext: Vec<u8>,
    ) -> Self {
        Self {
            id: EnvelopeId::new(),
            group_id,
            sender,
            recipient,
            message_type,
            ciphertext,
            epoch: None,
            created_at: Utc::now(),
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceId;
    use crate::group::GroupId;

    #[test]
    fn envelope_id_is_unique() {
        assert_ne!(EnvelopeId::new(), EnvelopeId::new());
    }

    #[test]
    fn envelope_id_from_str_roundtrips() {
        let id = EnvelopeId::new();
        let parsed: EnvelopeId = id.to_string().parse().unwrap();
        assert_eq!(parsed, id);
    }

    #[test]
    fn envelope_id_from_str_rejects_garbage() {
        assert!("not-a-uuid".parse::<EnvelopeId>().is_err());
    }

    #[test]
    fn new_envelope_has_no_epoch_or_expiry() {
        let env = Envelope::new(
            GroupId::new(),
            DeviceId::new(),
            None,
            MessageType::Application,
            vec![0xde, 0xad, 0xbe, 0xef],
        );
        assert!(env.epoch.is_none());
        assert!(env.expires_at.is_none());
        assert!(env.recipient.is_none());
    }

    #[test]
    fn ciphertext_is_stored_verbatim() {
        let ct = vec![1u8, 2, 3, 4, 5];
        let env = Envelope::new(
            GroupId::new(),
            DeviceId::new(),
            None,
            MessageType::Application,
            ct.clone(),
        );
        assert_eq!(env.ciphertext, ct);
    }

    #[test]
    fn welcome_message_can_have_recipient() {
        let recipient = DeviceId::new();
        let env = Envelope::new(
            GroupId::new(),
            DeviceId::new(),
            Some(recipient.clone()),
            MessageType::Welcome,
            vec![0u8; 8],
        );
        assert_eq!(env.recipient, Some(recipient));
        assert_eq!(env.message_type, MessageType::Welcome);
    }
}
