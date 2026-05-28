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

impl KeyPackageId {
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl From<Uuid> for KeyPackageId {
    fn from(id: Uuid) -> Self {
        Self(id)
    }
}

/// Result of a cross-region KeyPackage consumption attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Successfully marked as consumed (was unconsumed).
    Consumed,
    /// Already consumed by a prior request (idempotency guard).
    AlreadyConsumed,
    /// No KeyPackage found with the given ID.
    NotFound,
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
        Self {
            id: KeyPackageId::new(),
            device_id,
            data,
            uploaded_at: Utc::now(),
            consumed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceId;

    #[test]
    fn consume_result_variants_are_distinct() {
        assert_ne!(ConsumeResult::Consumed, ConsumeResult::AlreadyConsumed);
        assert_ne!(ConsumeResult::Consumed, ConsumeResult::NotFound);
        assert_ne!(ConsumeResult::AlreadyConsumed, ConsumeResult::NotFound);
    }

    #[test]
    fn key_package_starts_unconsumed() {
        let kp = KeyPackage::new(DeviceId::new(), vec![0u8; 32]);
        assert!(!kp.consumed);
    }

    #[test]
    fn key_package_id_is_unique() {
        assert_ne!(KeyPackageId::new(), KeyPackageId::new());
    }

    #[test]
    fn key_package_data_is_stored_verbatim() {
        let data = (0u8..=255).collect::<Vec<_>>();
        let kp = KeyPackage::new(DeviceId::new(), data.clone());
        assert_eq!(kp.data, data);
    }
}
