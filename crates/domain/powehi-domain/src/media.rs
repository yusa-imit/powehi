use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;
use crate::group::GroupId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaId(Uuid);

impl MediaId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for MediaId {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

impl Default for MediaId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MediaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Metadata for an E2EE media blob stored in R2. The key and IV are client-side only.
/// Uploader is tracked at device granularity. If the blob was shared to an MLS group,
/// `group_id` records it so group members can obtain a download URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MediaBlob {
    pub id: MediaId,
    pub uploader_device: DeviceId,
    /// R2 object key (opaque reference; no content info).
    pub storage_key: String,
    pub content_type: String,
    pub size_bytes: u64,
    pub uploaded_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// MLS group this blob was shared to. When set, any group member may download.
    pub group_id: Option<GroupId>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_id_from_uuid_round_trips() {
        let uuid = Uuid::new_v4();
        let id = MediaId::from(uuid);
        assert_eq!(id.as_uuid(), uuid);
    }

    #[test]
    fn media_id_new_creates_valid_uuid() {
        let id = MediaId::new();
        // as_uuid() must return a valid v4 UUID — non-nil
        assert_ne!(id.as_uuid(), Uuid::nil());
    }

    #[test]
    fn media_id_two_news_are_distinct() {
        let a = MediaId::new();
        let b = MediaId::new();
        assert_ne!(a.as_uuid(), b.as_uuid());
    }

    #[test]
    fn media_id_display_matches_inner_uuid() {
        let uuid = Uuid::new_v4();
        let id = MediaId::from(uuid);
        assert_eq!(id.to_string(), uuid.to_string());
    }

    #[test]
    fn media_id_default_is_non_nil() {
        let id = MediaId::default();
        assert_ne!(id.as_uuid(), Uuid::nil());
    }

    #[test]
    fn media_id_equality_on_same_uuid() {
        let uuid = Uuid::new_v4();
        let a = MediaId::from(uuid);
        let b = MediaId::from(uuid);
        assert_eq!(a, b);
    }

    #[test]
    fn media_id_serializes_as_uuid_string() {
        let uuid = Uuid::new_v4();
        let id = MediaId::from(uuid);
        let json = serde_json::to_string(&id).unwrap();
        // Serde UUID serializes as "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
        assert_eq!(json, format!("\"{}\"", uuid));
    }

    #[test]
    fn media_id_deserializes_from_uuid_string() {
        let uuid = Uuid::new_v4();
        let json = format!("\"{}\"", uuid);
        let id: MediaId = serde_json::from_str(&json).unwrap();
        assert_eq!(id.as_uuid(), uuid);
    }
}
