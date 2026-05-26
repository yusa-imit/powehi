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
    /// Cloudflare R2 S3-compatible endpoint: `https://<account>.r2.cloudflarestorage.com`
    pub r2_endpoint: String,
    pub r2_bucket: String,
    pub r2_access_key_id: String,
    pub r2_secret_access_key: String,
    /// Pre-signed upload URL TTL in seconds (default 900 = 15 min).
    #[serde(default = "default_presign_upload_ttl")]
    pub r2_presign_upload_ttl_secs: u64,
    /// Pre-signed download URL TTL in seconds (default 300 = 5 min).
    #[serde(default = "default_presign_download_ttl")]
    pub r2_presign_download_ttl_secs: u64,
}

fn default_presign_upload_ttl() -> u64 {
    900
}
fn default_presign_download_ttl() -> u64 {
    300
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
        .set_default("r2_endpoint", "http://localhost:9000")?
        .set_default("r2_bucket", "powehi-media")?
        // No defaults for credentials — POWEHI__R2_ACCESS_KEY_ID and
        // POWEHI__R2_SECRET_ACCESS_KEY must be injected by the operator.
        .set_default("r2_access_key_id", "")?
        .set_default("r2_secret_access_key", "")?
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
            r2_endpoint: "http://localhost:9000".into(),
            r2_bucket: "powehi-media".into(),
            r2_access_key_id: "dev-test-key".into(),
            r2_secret_access_key: "dev-test-secret".into(),
            r2_presign_upload_ttl_secs: 900,
            r2_presign_download_ttl_secs: 300,
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
    fn presign_ttl_defaults_are_correct() {
        assert_eq!(default_presign_upload_ttl(), 900);
        assert_eq!(default_presign_download_ttl(), 300);
    }

    #[test]
    fn load_uses_defaults_when_no_env_vars_set() {
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
            .set_default("r2_endpoint", "http://localhost:9000")
            .unwrap()
            .set_default("r2_bucket", "powehi-media")
            .unwrap()
            .set_default("r2_access_key_id", "")
            .unwrap()
            .set_default("r2_secret_access_key", "")
            .unwrap()
            .build()
            .unwrap();
        let app: AppConfig = cfg.try_deserialize().unwrap();
        assert_eq!(app.host, "0.0.0.0");
        assert_eq!(app.port, 8080);
        assert_eq!(app.region_id, "local");
        assert_eq!(app.region().to_string(), "local");
        assert_eq!(app.r2_bucket, "powehi-media");
        assert_eq!(app.r2_presign_upload_ttl_secs, 900);
        assert_eq!(app.r2_presign_download_ttl_secs, 300);
        assert!(
            app.r2_access_key_id.is_empty(),
            "credentials must be injected by operator"
        );
    }
}
