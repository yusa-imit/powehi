use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::device::DeviceId;
use crate::region::RegionId;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GroupId(Uuid);

impl GroupId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for GroupId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for GroupId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Epoch(pub u64);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: GroupId,
    pub home_region: RegionId,
    pub epoch: Epoch,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    pub group_id: GroupId,
    pub device_id: DeviceId,
    pub joined_at_epoch: Epoch,
}

impl Group {
    pub fn new(id: GroupId, home_region: RegionId) -> Self {
        Self {
            id,
            home_region,
            epoch: Epoch(0),
            created_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::region::RegionId;

    #[test]
    fn group_id_is_unique() {
        assert_ne!(GroupId::new(), GroupId::new());
    }

    #[test]
    fn group_starts_at_epoch_zero() {
        let g = Group::new(GroupId::new(), RegionId::new("eu-central"));
        assert_eq!(g.epoch, Epoch(0));
    }

    #[test]
    fn epoch_ordering() {
        assert!(Epoch(1) > Epoch(0));
        assert!(Epoch(100) > Epoch(99));
    }

    #[test]
    fn group_id_display_is_uuid() {
        let id = GroupId::new();
        let s = id.to_string();
        assert!(uuid::Uuid::parse_str(&s).is_ok());
    }
}
