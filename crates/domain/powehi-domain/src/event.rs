use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::device::DeviceId;
use crate::envelope::EnvelopeId;
use crate::group::{Epoch, GroupId};
use crate::user::UserId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DomainEvent {
    UserRegistered {
        user_id: UserId,
        at: DateTime<Utc>,
    },
    DeviceRegistered {
        device_id: DeviceId,
        user_id: UserId,
        at: DateTime<Utc>,
    },
    DeviceRevoked {
        device_id: DeviceId,
        at: DateTime<Utc>,
    },
    EnvelopeReceived {
        envelope_id: EnvelopeId,
        group_id: GroupId,
        at: DateTime<Utc>,
    },
    EpochAdvanced {
        group_id: GroupId,
        new_epoch: Epoch,
        at: DateTime<Utc>,
    },
    MemberAdded {
        group_id: GroupId,
        device_id: DeviceId,
        epoch: Epoch,
        at: DateTime<Utc>,
    },
    MemberRemoved {
        group_id: GroupId,
        device_id: DeviceId,
        epoch: Epoch,
        at: DateTime<Utc>,
    },
}

impl DomainEvent {
    pub fn occurred_at(&self) -> DateTime<Utc> {
        match self {
            DomainEvent::UserRegistered { at, .. }
            | DomainEvent::DeviceRegistered { at, .. }
            | DomainEvent::DeviceRevoked { at, .. }
            | DomainEvent::EnvelopeReceived { at, .. }
            | DomainEvent::EpochAdvanced { at, .. }
            | DomainEvent::MemberAdded { at, .. }
            | DomainEvent::MemberRemoved { at, .. } => *at,
        }
    }
}
