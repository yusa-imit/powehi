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
