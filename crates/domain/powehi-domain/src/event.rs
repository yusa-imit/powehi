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
    /// The device `device_id` was revoked while it was still a member of the
    /// MLS group `group_id`. The server can NEVER construct the MLS Remove
    /// itself — it holds no group state and no key material (prd.md §5.4,
    /// §8.5) — so this event is the durable signal telling the group's
    /// REMAINING members that they must issue a Remove proposal + Commit for
    /// the revoked device's leaf. One event is published per affected group.
    ///
    /// Distinct from `MemberRemoved`, which reports that server-side routing
    /// metadata has ALREADY been updated after a client landed the Commit.
    /// `RemovalRequired` is the demand; `MemberRemoved` is the receipt.
    ///
    /// Deliberately a separate variant from `DeviceRevoked` (an
    /// account-scoped fact with no group dimension): making `group_id`
    /// mandatory on `DeviceRevoked` would make it unpublishable for a device
    /// that belonged to zero groups.
    RemovalRequired {
        group_id: GroupId,
        device_id: DeviceId,
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
            | DomainEvent::MemberRemoved { at, .. }
            | DomainEvent::RemovalRequired { at, .. } => *at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        device::DeviceId,
        envelope::EnvelopeId,
        group::{Epoch, GroupId},
        user::UserId,
    };
    use chrono::TimeZone;

    fn fixed_ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn sample_events() -> Vec<DomainEvent> {
        let at = fixed_ts();
        vec![
            DomainEvent::UserRegistered {
                user_id: UserId::new(),
                at,
            },
            DomainEvent::DeviceRegistered {
                device_id: DeviceId::new(),
                user_id: UserId::new(),
                at,
            },
            DomainEvent::DeviceRevoked {
                device_id: DeviceId::new(),
                at,
            },
            DomainEvent::EnvelopeReceived {
                envelope_id: EnvelopeId::new(),
                group_id: GroupId::new(),
                at,
            },
            DomainEvent::EpochAdvanced {
                group_id: GroupId::new(),
                new_epoch: Epoch(3),
                at,
            },
            DomainEvent::MemberAdded {
                group_id: GroupId::new(),
                device_id: DeviceId::new(),
                epoch: Epoch(1),
                at,
            },
            DomainEvent::MemberRemoved {
                group_id: GroupId::new(),
                device_id: DeviceId::new(),
                epoch: Epoch(2),
                at,
            },
            DomainEvent::RemovalRequired {
                group_id: GroupId::new(),
                device_id: DeviceId::new(),
                at,
            },
        ]
    }

    #[test]
    fn occurred_at_returns_at_field_for_all_variants() {
        let expected = fixed_ts();
        for event in sample_events() {
            assert_eq!(
                event.occurred_at(),
                expected,
                "occurred_at must equal the 'at' field for {:?}",
                std::mem::discriminant(&event)
            );
        }
    }

    #[test]
    fn serde_json_round_trips_all_variants() {
        for event in sample_events() {
            let json = serde_json::to_string(&event).expect("serialization must succeed");
            let restored: DomainEvent =
                serde_json::from_str(&json).expect("deserialization must succeed");
            // Verify occurred_at survives the round-trip — timestamps are the
            // only invariant we can compare without PartialEq on the enum.
            assert_eq!(
                restored.occurred_at(),
                event.occurred_at(),
                "occurred_at must survive serde round-trip for {:?}",
                std::mem::discriminant(&event)
            );
        }
    }

    #[test]
    fn epoch_advanced_preserves_epoch_through_serde() {
        let at = fixed_ts();
        let gid = GroupId::new();
        let event = DomainEvent::EpochAdvanced {
            group_id: gid,
            new_epoch: Epoch(42),
            at,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: DomainEvent = serde_json::from_str(&json).unwrap();
        if let DomainEvent::EpochAdvanced { new_epoch, .. } = restored {
            assert_eq!(new_epoch, Epoch(42));
        } else {
            panic!("wrong variant after round-trip");
        }
    }

    #[test]
    fn member_removed_preserves_epoch_through_serde() {
        let at = fixed_ts();
        let event = DomainEvent::MemberRemoved {
            group_id: GroupId::new(),
            device_id: DeviceId::new(),
            epoch: Epoch(7),
            at,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: DomainEvent = serde_json::from_str(&json).unwrap();
        if let DomainEvent::MemberRemoved { epoch, .. } = restored {
            assert_eq!(epoch, Epoch(7));
        } else {
            panic!("wrong variant after round-trip");
        }
    }

    #[test]
    fn removal_required_preserves_group_and_device_through_serde() {
        let at = fixed_ts();
        let gid = GroupId::new();
        let did = DeviceId::new();
        let event = DomainEvent::RemovalRequired {
            group_id: gid.clone(),
            device_id: did.clone(),
            at,
        };
        let json = serde_json::to_string(&event).unwrap();
        let restored: DomainEvent = serde_json::from_str(&json).unwrap();
        if let DomainEvent::RemovalRequired {
            group_id,
            device_id,
            ..
        } = restored
        {
            assert_eq!(group_id, gid);
            assert_eq!(device_id, did);
        } else {
            panic!("wrong variant after round-trip");
        }
    }
}
