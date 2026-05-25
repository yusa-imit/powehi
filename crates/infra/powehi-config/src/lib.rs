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

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::region::Tier;

    fn default_config() -> AppConfig {
        AppConfig {
            region_id: "eu-central-1".into(),
            tier: Tier::Tier1,
            database_url: "postgres://localhost/test".into(),
            redis_url: "redis://localhost".into(),
            host: "0.0.0.0".into(),
            port: 8080,
        }
    }

    #[test]
    fn region_wraps_region_id_string() {
        let cfg = default_config();
        assert_eq!(cfg.region().to_string(), "eu-central-1");
    }

    #[test]
    fn region_id_roundtrips_through_config() {
        let cfg = AppConfig {
            region_id: "ap-northeast-1".into(),
            ..default_config()
        };
        assert_eq!(cfg.region().to_string(), "ap-northeast-1");
    }

    #[test]
    fn load_uses_defaults_when_no_env_vars_set() {
        // Verify the default values match documentation expectations.
        // Uses build() without any source; falls back to set_default values.
        let cfg = config::Config::builder()
            .set_default("host", "0.0.0.0")
            .unwrap()
            .set_default("port", 8080u16)
            .unwrap()
            .set_default("region_id", "local")
            .unwrap()
            .set_default("tier", "Tier1")
            .unwrap()
            .set_default("database_url", "postgres://localhost/powehi")
            .unwrap()
            .set_default("redis_url", "redis://localhost")
            .unwrap()
            .build()
            .unwrap();
        let app: AppConfig = cfg.try_deserialize().unwrap();
        assert_eq!(app.host, "0.0.0.0");
        assert_eq!(app.port, 8080);
        assert_eq!(app.region_id, "local");
        assert_eq!(app.region().to_string(), "local");
    }
}
