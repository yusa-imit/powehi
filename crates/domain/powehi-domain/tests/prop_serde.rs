//! Property-based serialization round-trip tests for domain ID types.
//! Invariant: for any UUID bytes, the newtype IDs must round-trip through
//! JSON serialization and Display/FromStr without loss or mutation.

use powehi_domain::{
    device::DeviceId,
    envelope::{EnvelopeId, MessageType},
    group::{Epoch, GroupId},
    user::UserId,
};
use proptest::prelude::*;
use uuid::Uuid;

/// Derive an arbitrary Uuid from 16 raw bytes.
fn uuid_from_bytes(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

proptest! {
    #[test]
    fn group_id_json_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = GroupId::from(uuid_from_bytes(bytes));
        let json = serde_json::to_string(&id).unwrap();
        let restored: GroupId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(id, restored);
    }

    #[test]
    fn device_id_json_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = DeviceId::from(uuid_from_bytes(bytes));
        let json = serde_json::to_string(&id).unwrap();
        let restored: DeviceId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(id, restored);
    }

    #[test]
    fn device_id_display_fromstr_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = DeviceId::from(uuid_from_bytes(bytes));
        let s = id.to_string();
        let parsed: DeviceId = s.parse().unwrap();
        prop_assert_eq!(id, parsed);
    }

    #[test]
    fn user_id_json_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = UserId::from(uuid_from_bytes(bytes));
        let json = serde_json::to_string(&id).unwrap();
        let restored: UserId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(id, restored);
    }

    #[test]
    fn envelope_id_json_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = EnvelopeId::from(uuid_from_bytes(bytes));
        let json = serde_json::to_string(&id).unwrap();
        let restored: EnvelopeId = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(id, restored);
    }

    #[test]
    fn envelope_id_display_fromstr_roundtrip(bytes in any::<[u8; 16]>()) {
        let id = EnvelopeId::from(uuid_from_bytes(bytes));
        let s = id.to_string();
        let parsed: EnvelopeId = s.parse().unwrap();
        prop_assert_eq!(id, parsed);
    }

    #[test]
    fn epoch_json_roundtrip(v in any::<u64>()) {
        let epoch = Epoch(v);
        let json = serde_json::to_string(&epoch).unwrap();
        let restored: Epoch = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(epoch, restored);
    }

    #[test]
    fn epoch_ordering_is_consistent(a in any::<u64>(), b in any::<u64>()) {
        let ea = Epoch(a);
        let eb = Epoch(b);
        if a < b {
            prop_assert!(ea < eb);
        } else if a > b {
            prop_assert!(ea > eb);
        } else {
            prop_assert_eq!(ea, eb);
        }
    }

    #[test]
    fn message_type_json_roundtrip(variant in 0u8..4) {
        let mt = match variant {
            0 => MessageType::Application,
            1 => MessageType::Welcome,
            2 => MessageType::Commit,
            _ => MessageType::Proposal,
        };
        let json = serde_json::to_string(&mt).unwrap();
        let restored: MessageType = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(mt, restored);
    }

    #[test]
    fn group_id_uuid_identity(bytes in any::<[u8; 16]>()) {
        let uuid = uuid_from_bytes(bytes);
        let id = GroupId::from(uuid);
        prop_assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn device_id_uuid_identity(bytes in any::<[u8; 16]>()) {
        let uuid = uuid_from_bytes(bytes);
        let id = DeviceId::from(uuid);
        prop_assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn user_id_uuid_identity(bytes in any::<[u8; 16]>()) {
        let uuid = uuid_from_bytes(bytes);
        let id = UserId::from(uuid);
        prop_assert_eq!(id.as_uuid(), uuid);
    }
}
