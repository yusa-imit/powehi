use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyPackageId(Uuid);

impl KeyPackageId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for KeyPackageId {
    fn default() -> Self {
        Self::new()
    }
}

/// MLS KeyPackage — opaque bytes stored by the server; consumed exactly once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    pub id: KeyPackageId,
    pub device_id: DeviceId,
    /// Raw TLS-serialized MLS KeyPackage bytes. Server cannot decrypt this.
    pub data: Vec<u8>,
    pub uploaded_at: DateTime<Utc>,
    pub consumed: bool,
}

impl KeyPackage {
    pub fn new(device_id: DeviceId, data: Vec<u8>) -> Self {
        Self { id: KeyPackageId::new(), device_id, data, uploaded_at: Utc::now(), consumed: false }
    }
}
