use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::user::UserId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub user_id: UserId,
    /// MLS credential bytes (opaque to the server).
    pub mls_credential: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

impl Device {
    pub fn new(id: DeviceId, user_id: UserId, mls_credential: Vec<u8>) -> Self {
        Self { id, user_id, mls_credential, created_at: Utc::now(), last_seen_at: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_is_unique() {
        assert_ne!(DeviceId::new(), DeviceId::new());
    }
}
