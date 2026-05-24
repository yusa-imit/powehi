use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegionId(String);

impl RegionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RegionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Service tier determines SLA and replication policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// Primary region — full stack, MLS delivery, KeyPackage service.
    Tier1,
    /// Secondary region — MLS delivery only, relays to Tier1 for KeyPackages.
    Tier2,
    /// Edge PoP — WebSocket termination + local caching only.
    Tier3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn region_id_roundtrips_display() {
        let id = RegionId::new("ap-seoul-1");
        assert_eq!(id.as_str(), "ap-seoul-1");
        assert_eq!(id.to_string(), "ap-seoul-1");
    }

    #[test]
    fn region_ids_compare_by_inner_string() {
        assert_eq!(RegionId::new("eu-central"), RegionId::new("eu-central"));
        assert_ne!(RegionId::new("eu-central"), RegionId::new("us-east"));
    }

    #[test]
    fn tier_variants_are_distinct() {
        assert_ne!(Tier::Tier1, Tier::Tier2);
        assert_ne!(Tier::Tier2, Tier::Tier3);
        assert_ne!(Tier::Tier1, Tier::Tier3);
    }
}
