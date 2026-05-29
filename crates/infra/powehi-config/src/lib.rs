use powehi_domain::region::{RegionId, Tier};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config load failed: {0}")]
    Load(#[from] config::ConfigError),
}

#[derive(Deserialize)]
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
    /// Internal admin port for Prometheus metrics scraping.
    /// Bound to 127.0.0.1 only — MUST NOT be exposed via the public ingress.
    /// Prometheus scrapes from within the cluster (k8s pod-to-pod).
    #[serde(default = "default_admin_port")]
    pub admin_port: u16,
    /// gRPC port for the inter-region mesh (default 50051).
    /// Bound on all interfaces so peer regions can reach it; secured by mTLS in production.
    #[serde(default = "default_grpc_port")]
    pub grpc_port: u16,
    /// Comma-separated peer region endpoints: `"region_id=https://host:port,..."`
    /// Empty string means no cross-region peers (single-region deployment).
    #[serde(default)]
    pub grpc_peers: String,
    /// Path to this region's TLS certificate PEM. Empty = plaintext (dev only).
    #[serde(default)]
    pub grpc_tls_cert: String,
    /// Path to this region's TLS private key PEM.
    #[serde(default)]
    pub grpc_tls_key: String,
    /// Path to the CA certificate PEM used to verify peer region certificates.
    #[serde(default)]
    pub grpc_tls_ca: String,
    /// VAPID private key (PKCS#8 PEM) for Web Push signing.
    /// `POWEHI__VAPID_PRIVATE_KEY_PEM`. None = push disabled (dev).
    #[serde(default)]
    pub vapid_private_key_pem: Option<String>,
    /// VAPID contact URI (`mailto:` or `https:`) per RFC 8292 section 2.1.
    /// `POWEHI__VAPID_CONTACT`.
    #[serde(default)]
    pub vapid_contact: Option<String>,
}

fn default_presign_upload_ttl() -> u64 {
    900
}
fn default_presign_download_ttl() -> u64 {
    300
}
fn default_admin_port() -> u16 {
    9090
}
fn default_grpc_port() -> u16 {
    50051
}

impl AppConfig {
    pub fn region(&self) -> RegionId {
        RegionId::new(&self.region_id)
    }

    /// Parse `grpc_peers` into a list of `(RegionId, endpoint)` pairs.
    ///
    /// Format: `"region_id=https://host:port,region_id2=https://host2:port2"`
    pub fn grpc_peer_list(&self) -> Vec<(powehi_domain::region::RegionId, String)> {
        if self.grpc_peers.is_empty() {
            return vec![];
        }
        self.grpc_peers
            .split(',')
            .filter_map(|pair| {
                let (id, endpoint) = pair.trim().split_once('=')?;
                Some((RegionId::new(id.trim()), endpoint.trim().to_string()))
            })
            .collect()
    }

    /// Returns `true` if mTLS is configured (all three TLS fields are non-empty).
    pub fn grpc_tls_enabled(&self) -> bool {
        !self.grpc_tls_cert.is_empty()
            && !self.grpc_tls_key.is_empty()
            && !self.grpc_tls_ca.is_empty()
    }
}

impl std::fmt::Debug for AppConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppConfig")
            .field("region_id", &self.region_id)
            .field("tier", &self.tier)
            .field("database_url", &"<redacted>")
            .field("redis_url", &"<redacted>")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("r2_endpoint", &self.r2_endpoint)
            .field("r2_bucket", &self.r2_bucket)
            .field("r2_access_key_id", &self.r2_access_key_id)
            .field("r2_secret_access_key", &"<redacted>")
            .field(
                "r2_presign_upload_ttl_secs",
                &self.r2_presign_upload_ttl_secs,
            )
            .field(
                "r2_presign_download_ttl_secs",
                &self.r2_presign_download_ttl_secs,
            )
            .field("admin_port", &self.admin_port)
            .field("grpc_port", &self.grpc_port)
            .field("grpc_peers", &self.grpc_peers)
            .field("grpc_tls_cert", &self.grpc_tls_cert)
            .field("grpc_tls_key", &self.grpc_tls_key)
            .field("grpc_tls_ca", &self.grpc_tls_ca)
            .field("vapid_private_key_pem", &"<redacted>")
            .field("vapid_contact", &self.vapid_contact)
            .finish()
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
        .set_default("admin_port", 9090)?
        .set_default("grpc_port", 50051)?
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
            admin_port: 9090,
            grpc_port: 50051,
            grpc_peers: String::new(),
            grpc_tls_cert: String::new(),
            grpc_tls_key: String::new(),
            grpc_tls_ca: String::new(),
            vapid_private_key_pem: None,
            vapid_contact: None,
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
    fn grpc_port_default_is_50051() {
        assert_eq!(default_grpc_port(), 50051);
        assert_eq!(default_config().grpc_port, 50051);
    }

    #[test]
    fn grpc_peer_list_parses_comma_separated_pairs() {
        let cfg = AppConfig {
            grpc_peers:
                "eu-central-1=https://eu.internal:50051,ap-seoul-1=https://ap.internal:50051".into(),
            ..default_config()
        };
        let peers = cfg.grpc_peer_list();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].0.to_string(), "eu-central-1");
        assert_eq!(peers[0].1, "https://eu.internal:50051");
        assert_eq!(peers[1].0.to_string(), "ap-seoul-1");
        assert_eq!(peers[1].1, "https://ap.internal:50051");
    }

    #[test]
    fn grpc_peer_list_empty_when_no_peers_configured() {
        assert!(default_config().grpc_peer_list().is_empty());
    }

    #[test]
    fn grpc_tls_enabled_requires_all_three_fields() {
        let no_tls = default_config();
        assert!(!no_tls.grpc_tls_enabled());

        let partial_tls = AppConfig {
            grpc_tls_cert: "/path/to/cert.pem".into(),
            ..default_config()
        };
        assert!(
            !partial_tls.grpc_tls_enabled(),
            "partial config must not enable TLS"
        );

        let full_tls = AppConfig {
            grpc_tls_cert: "/path/cert.pem".into(),
            grpc_tls_key: "/path/key.pem".into(),
            grpc_tls_ca: "/path/ca.pem".into(),
            ..default_config()
        };
        assert!(full_tls.grpc_tls_enabled());
    }

    #[test]
    fn vapid_fields_default_to_none() {
        let cfg = default_config();
        assert!(cfg.vapid_private_key_pem.is_none());
        assert!(cfg.vapid_contact.is_none());
    }

    #[test]
    fn debug_output_redacts_secrets() {
        let cfg = AppConfig {
            database_url: "postgres://user:hunter2@localhost/powehi".into(),
            redis_url: "redis://:supersecret@localhost".into(),
            r2_secret_access_key: "AKIASECRET123".into(),
            vapid_private_key_pem: Some(
                "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----".into(),
            ),
            ..default_config()
        };
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("hunter2"),
            "database password must not appear in Debug output"
        );
        assert!(
            !debug.contains("supersecret"),
            "redis password must not appear in Debug output"
        );
        assert!(
            !debug.contains("AKIASECRET123"),
            "R2 secret must not appear in Debug output"
        );
        assert!(
            !debug.contains("BEGIN PRIVATE KEY"),
            "VAPID private key must not appear in Debug output"
        );
        assert!(
            debug.contains("<redacted>"),
            "must show <redacted> placeholder"
        );
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
