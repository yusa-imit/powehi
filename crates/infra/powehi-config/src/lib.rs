use powehi_domain::region::{RegionId, Tier};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config load failed: {0}")]
    Load(#[from] config::ConfigError),
}

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    pub region_id: String,
    pub tier: Tier,
    pub database_url: String,
    pub redis_url: String,
    pub host: String,
    pub port: u16,
}

impl AppConfig {
    pub fn region(&self) -> RegionId {
        RegionId::new(&self.region_id)
    }
}

pub fn load() -> Result<AppConfig, ConfigError> {
    let cfg = config::Config::builder()
        .add_source(config::Environment::with_prefix("POWEHI").separator("__"))
        .set_default("host", "0.0.0.0")?
        .set_default("port", 8080)?
        .set_default("region_id", "local")?
        .set_default("tier", "Tier1")?
        .build()?;
    Ok(cfg.try_deserialize()?)
}
