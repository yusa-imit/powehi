use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;

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
/// Uploader is tracked at device granularity (Phase 3: bearer token = DeviceId).
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
}
