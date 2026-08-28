use powehi_domain::region::{RegionId, Tier};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config load failed: {0}")]
    Load(#[from] config::ConfigError),
    #[error(
        "database_max_connections={0} is below the minimum safe value ({MIN_DATABASE_MAX_CONNECTIONS}): \
         the media GC and ledger-trim background jobs each pin one dedicated connection for an \
         advisory lock while the job's own query needs a second connection from the same pool, so \
         fewer than {MIN_DATABASE_MAX_CONNECTIONS} connections can self-deadlock the job (and starve \
         every request handler for the acquire-timeout duration if both jobs overlap)"
    )]
    DatabaseMaxConnectionsTooLow(u32),
    #[error(
        "r2_request_timeout_secs={0} is below the minimum safe value ({MIN_R2_REQUEST_TIMEOUT_SECS}): \
         the AWS SDK's own default connect timeout is ~3.1s, so anything at or below that fails \
         every R2 call before a fresh connection can even complete, silently breaking media \
         presigning and the hourly media-blob GC background job"
    )]
    R2RequestTimeoutTooLow(u64),
    #[error(
        "media_gc_sweep_timeout_secs={0} is below the minimum safe value \
         ({MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS}): a single `list_gc_candidates` page can legitimately \
         take several seconds against a large table, so anything below the floor would abort a \
         healthy sweep before it can make progress"
    )]
    MediaGcSweepTimeoutTooLow(u64),
    #[error(
        "media_gc_sweep_timeout_secs={0} is less than {MEDIA_GC_SWEEP_TIMEOUT_MIN_MULTIPLE_OF_R2}x \
         r2_request_timeout_secs={1}: a single slow-but-healthy R2 call could then consume the \
         entire sweep budget, timing out the GC job on every tick with zero net progress on any \
         batch with non-trivial R2 latency"
    )]
    MediaGcSweepTimeoutTooCloseToR2Timeout(u64, u64),
    #[error(
        "r2_endpoint is still the dev-only default ({DEV_R2_ENDPOINT_DEFAULT:?}) but \
         region_id={0:?} is not \"local\": POWEHI__R2_ENDPOINT was never set for this \
         deployment, which would silently point every pre-signed media URL at the \
         operator's own loopback instead of a real R2 endpoint rather than failing loudly"
    )]
    R2DevDefaultEndpointInNonLocalRegion(String),
    #[error(
        "r2_access_key_id/r2_secret_access_key are empty but region_id={0:?} is not \"local\": \
         POWEHI__R2_ACCESS_KEY_ID/POWEHI__R2_SECRET_ACCESS_KEY were never injected for this \
         deployment, which would start successfully and only fail the first time a real media \
         upload or download is attempted rather than failing loudly at startup"
    )]
    R2CredentialsMissingInNonLocalRegion(String),
}

/// Below this, a GC/ledger-trim job's dedicated advisory-lock connection plus its own query
/// connection can exhaust the pool and self-deadlock (see
/// `powehi_postgres::leader_lock::PgLeaderLock::try_lock`); two concurrent jobs need one pair
/// each, so 3 is the floor, not sqlx's per-connection minimum of 1.
const MIN_DATABASE_MAX_CONNECTIONS: u32 = 3;

/// The AWS SDK's own default connect timeout is ~3.1s (see
/// `aws-smithy-runtime`'s `DEFAULT_CONNECT_TIMEOUT`); a configured operation
/// timeout at or below that fails every R2 call before a fresh connection can
/// even complete, which clears naive "just reject zero" validation while still
/// being a silent total outage. 5 gives headroom above that floor.
const MIN_R2_REQUEST_TIMEOUT_SECS: u64 = 5;

/// A single `list_gc_candidates` page plus its per-blob R2 deletes can take a
/// few seconds even when healthy; anything below this would risk aborting a
/// normal-speed sweep on its first page.
const MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS: u64 = 30;

/// The sweep timeout must leave room for at least this many full-length R2 calls so a single
/// slow-but-healthy operation can't consume the entire sweep budget and starve the job of net
/// forward progress every tick. Shipped defaults (1800 / 30) clear this by 60x; this only bites
/// an operator who tightens `media_gc_sweep_timeout_secs` down near its own floor while leaving
/// `r2_request_timeout_secs` at a normal value.
const MEDIA_GC_SWEEP_TIMEOUT_MIN_MULTIPLE_OF_R2: u64 = 2;

/// The dev-only `r2_endpoint` default installed by `load()`'s `set_default`. Any deployed
/// (non-`local`) region whose config still resolves to this literal at `validate()` time means
/// `POWEHI__R2_ENDPOINT` was never actually set by the Helm chart/operator for that
/// environment — every 3 real overlays (prod-eu, prod-ap, staging) went unnoticed running this
/// way until it was wired in (see `infra/helm/powehi/values.yaml`'s `config.r2Endpoint`).
/// Without this guard the failure mode is silent: presigned media URLs point at the server's
/// own loopback instead of a crash an operator would actually see.
const DEV_R2_ENDPOINT_DEFAULT: &str = "http://localhost:9000";

#[derive(Deserialize)]
pub struct AppConfig {
    pub region_id: String,
    pub tier: Tier,
    pub database_url: String,
    /// Explicit Postgres pool size (`POWEHI__DATABASE_MAX_CONNECTIONS`). sqlx's
    /// undocumented default is 10 — too small once background GC/ledger-trim jobs
    /// each pin a dedicated session-scoped connection for advisory locks alongside
    /// normal request-handler traffic. Default 20; tune per-deployment DB capacity.
    #[serde(default = "default_database_max_connections")]
    pub database_max_connections: u32,
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
    /// Bounds each server-to-R2 S3 operation in `R2MediaAdapter`'s S3 client (each
    /// individual retry attempt is bounded at a third of this, so a stalled attempt
    /// still leaves room for a retry). Without it the SDK has no request timeout, so
    /// a hung R2 request hangs the hourly media-blob GC background task indefinitely
    /// — and since that job is guarded by a Postgres advisory lock, a hang on one
    /// replica blocks the job cluster-wide. The daily ledger-trim job is Postgres-only
    /// and unaffected (it never calls R2). NOT the same thing as the pre-signed URL
    /// TTLs above (those are client-facing upload/download windows; this is
    /// server-to-R2 call latency). Default 30 (seconds).
    #[serde(default = "default_r2_request_timeout_secs")]
    pub r2_request_timeout_secs: u64,
    /// Bounds the *whole* hourly media-blob GC sweep (`MediaService::run_gc`), not just a
    /// single R2 call (`r2_request_timeout_secs` above already bounds that). Without this,
    /// N slow-but-not-hung per-blob deletes can each individually succeed under the R2 call
    /// timeout while their sum still holds the cross-replica Postgres advisory lock
    /// (`GC_LOCK_MEDIA_BLOBS`) past the next hourly tick, delaying every other replica's
    /// attempt indefinitely. Default 1800 (30 min) — comfortably under the hourly interval so
    /// the lock is always released before the job would run again anyway.
    #[serde(default = "default_media_gc_sweep_timeout_secs")]
    pub media_gc_sweep_timeout_secs: u64,
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
    /// Arbitrary secret token used to derive the HMAC-SHA256 key for the
    /// login_init handle-existence anti-oracle (deterministic synthetic user_id).
    /// Set to any high-entropy string (e.g. a UUID) and keep it stable across
    /// restarts. If empty, a random key is generated at startup (per-restart only).
    /// `POWEHI__HANDLE_ORACLE_SECRET_TOKEN`.
    #[serde(default)]
    pub handle_oracle_secret_token: String,
}

fn default_database_max_connections() -> u32 {
    20
}
fn default_presign_upload_ttl() -> u64 {
    900
}
fn default_presign_download_ttl() -> u64 {
    300
}
fn default_r2_request_timeout_secs() -> u64 {
    30
}
fn default_media_gc_sweep_timeout_secs() -> u64 {
    1800
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
            .field("database_max_connections", &self.database_max_connections)
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
            .field("r2_request_timeout_secs", &self.r2_request_timeout_secs)
            .field(
                "media_gc_sweep_timeout_secs",
                &self.media_gc_sweep_timeout_secs,
            )
            .field("admin_port", &self.admin_port)
            .field("grpc_port", &self.grpc_port)
            .field("grpc_peers", &self.grpc_peers)
            .field("grpc_tls_cert", &self.grpc_tls_cert)
            .field("grpc_tls_key", &self.grpc_tls_key)
            .field("grpc_tls_ca", &self.grpc_tls_ca)
            .field("vapid_private_key_pem", &"<redacted>")
            .field("vapid_contact", &self.vapid_contact)
            .field("handle_oracle_secret_token", &"<redacted>")
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
        .set_default("r2_endpoint", DEV_R2_ENDPOINT_DEFAULT)?
        .set_default("r2_bucket", "powehi-media")?
        .set_default("admin_port", 9090)?
        .set_default("grpc_port", 50051)?
        .set_default("database_max_connections", 20)?
        .set_default("r2_request_timeout_secs", 30)?
        .set_default("media_gc_sweep_timeout_secs", 1800)?
        // No defaults for credentials — POWEHI__R2_ACCESS_KEY_ID and
        // POWEHI__R2_SECRET_ACCESS_KEY must be injected by the operator.
        .set_default("r2_access_key_id", "")?
        .set_default("r2_secret_access_key", "")?
        .build()?;
    let app: AppConfig = cfg.try_deserialize()?;
    validate(&app)?;
    Ok(app)
}

fn validate(app: &AppConfig) -> Result<(), ConfigError> {
    if app.database_max_connections < MIN_DATABASE_MAX_CONNECTIONS {
        return Err(ConfigError::DatabaseMaxConnectionsTooLow(
            app.database_max_connections,
        ));
    }
    if app.r2_request_timeout_secs < MIN_R2_REQUEST_TIMEOUT_SECS {
        return Err(ConfigError::R2RequestTimeoutTooLow(
            app.r2_request_timeout_secs,
        ));
    }
    if app.media_gc_sweep_timeout_secs < MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS {
        return Err(ConfigError::MediaGcSweepTimeoutTooLow(
            app.media_gc_sweep_timeout_secs,
        ));
    }
    if app.media_gc_sweep_timeout_secs
        < app
            .r2_request_timeout_secs
            .saturating_mul(MEDIA_GC_SWEEP_TIMEOUT_MIN_MULTIPLE_OF_R2)
    {
        return Err(ConfigError::MediaGcSweepTimeoutTooCloseToR2Timeout(
            app.media_gc_sweep_timeout_secs,
            app.r2_request_timeout_secs,
        ));
    }
    if app.region_id != "local" && app.r2_endpoint == DEV_R2_ENDPOINT_DEFAULT {
        return Err(ConfigError::R2DevDefaultEndpointInNonLocalRegion(
            app.region_id.clone(),
        ));
    }
    if app.region_id != "local"
        && (app.r2_access_key_id.is_empty() || app.r2_secret_access_key.is_empty())
    {
        return Err(ConfigError::R2CredentialsMissingInNonLocalRegion(
            app.region_id.clone(),
        ));
    }
    Ok(())
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
            database_max_connections: 20,
            redis_url: "redis://localhost".into(),
            host: "0.0.0.0".into(),
            port: 8080,
            r2_endpoint: "https://acct.r2.cloudflarestorage.com".into(),
            r2_bucket: "powehi-media".into(),
            r2_access_key_id: "dev-test-key".into(),
            r2_secret_access_key: "dev-test-secret".into(),
            r2_presign_upload_ttl_secs: 900,
            r2_presign_download_ttl_secs: 300,
            r2_request_timeout_secs: 30,
            media_gc_sweep_timeout_secs: 1800,
            admin_port: 9090,
            grpc_port: 50051,
            grpc_peers: String::new(),
            grpc_tls_cert: String::new(),
            grpc_tls_key: String::new(),
            grpc_tls_ca: String::new(),
            vapid_private_key_pem: None,
            vapid_contact: None,
            handle_oracle_secret_token: String::new(),
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
    fn database_max_connections_default_is_20() {
        assert_eq!(default_database_max_connections(), 20);
        assert_eq!(default_config().database_max_connections, 20);
    }

    #[test]
    fn database_max_connections_below_floor_is_rejected() {
        for too_low in [0u32, 1, 2] {
            let cfg = AppConfig {
                database_max_connections: too_low,
                ..default_config()
            };
            let err = validate(&cfg).expect_err(&format!(
                "database_max_connections={too_low} must be rejected"
            ));
            assert!(matches!(err, ConfigError::DatabaseMaxConnectionsTooLow(v) if v == too_low));
        }
    }

    #[test]
    fn database_max_connections_at_or_above_floor_is_accepted() {
        for ok in [
            MIN_DATABASE_MAX_CONNECTIONS,
            MIN_DATABASE_MAX_CONNECTIONS + 1,
            20,
        ] {
            let cfg = AppConfig {
                database_max_connections: ok,
                ..default_config()
            };
            assert!(
                validate(&cfg).is_ok(),
                "database_max_connections={ok} must be accepted"
            );
        }
    }

    #[test]
    fn r2_request_timeout_default_is_30() {
        assert_eq!(default_r2_request_timeout_secs(), 30);
        assert_eq!(default_config().r2_request_timeout_secs, 30);
    }

    #[test]
    fn r2_request_timeout_below_floor_is_rejected() {
        for bad in [0, MIN_R2_REQUEST_TIMEOUT_SECS - 1] {
            let cfg = AppConfig {
                r2_request_timeout_secs: bad,
                ..default_config()
            };
            let err = validate(&cfg)
                .expect_err(&format!("r2_request_timeout_secs={bad} must be rejected"));
            assert!(matches!(err, ConfigError::R2RequestTimeoutTooLow(v) if v == bad));
        }
    }

    #[test]
    fn r2_request_timeout_at_or_above_floor_is_accepted() {
        for ok in [
            MIN_R2_REQUEST_TIMEOUT_SECS,
            MIN_R2_REQUEST_TIMEOUT_SECS + 1,
            30,
            120,
        ] {
            let cfg = AppConfig {
                r2_request_timeout_secs: ok,
                ..default_config()
            };
            assert!(
                validate(&cfg).is_ok(),
                "r2_request_timeout_secs={ok} must be accepted"
            );
        }
    }

    #[test]
    fn media_gc_sweep_timeout_default_is_1800() {
        assert_eq!(default_media_gc_sweep_timeout_secs(), 1800);
        assert_eq!(default_config().media_gc_sweep_timeout_secs, 1800);
    }

    #[test]
    fn media_gc_sweep_timeout_below_floor_is_rejected() {
        for bad in [0, MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS - 1] {
            let cfg = AppConfig {
                media_gc_sweep_timeout_secs: bad,
                ..default_config()
            };
            let err = validate(&cfg).expect_err(&format!(
                "media_gc_sweep_timeout_secs={bad} must be rejected"
            ));
            assert!(matches!(err, ConfigError::MediaGcSweepTimeoutTooLow(v) if v == bad));
        }
    }

    #[test]
    fn media_gc_sweep_timeout_at_or_above_floor_is_accepted() {
        for ok in [
            MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS,
            MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS + 1,
            1800,
            3600,
        ] {
            let cfg = AppConfig {
                media_gc_sweep_timeout_secs: ok,
                // Pinned at its own floor so every `ok` value above (which is itself
                // >= MIN_MEDIA_GC_SWEEP_TIMEOUT_SECS = 30) clears the separate
                // 2x-r2_request_timeout_secs cross-field check too (30 >= 2*5).
                r2_request_timeout_secs: MIN_R2_REQUEST_TIMEOUT_SECS,
                ..default_config()
            };
            assert!(
                validate(&cfg).is_ok(),
                "media_gc_sweep_timeout_secs={ok} must be accepted"
            );
        }
    }

    #[test]
    fn media_gc_sweep_timeout_too_close_to_r2_timeout_is_rejected() {
        let cfg = AppConfig {
            r2_request_timeout_secs: 30,
            media_gc_sweep_timeout_secs: 59,
            ..default_config()
        };
        let err = validate(&cfg).expect_err("sweep timeout under 2x r2 timeout must be rejected");
        assert!(matches!(
            err,
            ConfigError::MediaGcSweepTimeoutTooCloseToR2Timeout(59, 30)
        ));
    }

    #[test]
    fn media_gc_sweep_timeout_at_exactly_2x_r2_timeout_is_accepted() {
        let cfg = AppConfig {
            r2_request_timeout_secs: 30,
            media_gc_sweep_timeout_secs: 60,
            ..default_config()
        };
        assert!(
            validate(&cfg).is_ok(),
            "sweep timeout at exactly 2x r2 timeout must be accepted"
        );
    }

    #[test]
    fn dev_default_r2_endpoint_in_non_local_region_is_rejected() {
        for region in ["eu-central-1", "ap-seoul-1", "us-east-1"] {
            let cfg = AppConfig {
                region_id: region.into(),
                r2_endpoint: DEV_R2_ENDPOINT_DEFAULT.into(),
                ..default_config()
            };
            let err = validate(&cfg).expect_err(&format!(
                "dev r2_endpoint default in region {region} must be rejected"
            ));
            assert!(matches!(
                err,
                ConfigError::R2DevDefaultEndpointInNonLocalRegion(ref r) if r == region
            ));
        }
    }

    #[test]
    fn dev_default_r2_endpoint_in_local_region_is_accepted() {
        let cfg = AppConfig {
            region_id: "local".into(),
            r2_endpoint: DEV_R2_ENDPOINT_DEFAULT.into(),
            ..default_config()
        };
        assert!(
            validate(&cfg).is_ok(),
            "dev r2_endpoint default must be accepted for region_id=local"
        );
    }

    #[test]
    fn real_r2_endpoint_in_non_local_region_is_accepted() {
        let cfg = AppConfig {
            region_id: "eu-central-1".into(),
            r2_endpoint: "https://acct.r2.cloudflarestorage.com".into(),
            ..default_config()
        };
        assert!(
            validate(&cfg).is_ok(),
            "a real r2_endpoint must be accepted regardless of region_id"
        );
    }

    #[test]
    fn missing_r2_credentials_in_non_local_region_is_rejected() {
        for region in ["eu-central-1", "ap-seoul-1", "us-east-1"] {
            for (access_key, secret_key) in
                [("", "dev-test-secret"), ("dev-test-key", ""), ("", "")]
            {
                let cfg = AppConfig {
                    region_id: region.into(),
                    r2_access_key_id: access_key.into(),
                    r2_secret_access_key: secret_key.into(),
                    ..default_config()
                };
                let err = validate(&cfg).expect_err(&format!(
                    "missing r2 credentials (access_key={access_key:?}, secret_key={secret_key:?}) \
                     in region {region} must be rejected"
                ));
                assert!(matches!(
                    err,
                    ConfigError::R2CredentialsMissingInNonLocalRegion(ref r) if r == region
                ));
            }
        }
    }

    #[test]
    fn missing_r2_credentials_in_local_region_is_accepted() {
        let cfg = AppConfig {
            region_id: "local".into(),
            r2_access_key_id: String::new(),
            r2_secret_access_key: String::new(),
            ..default_config()
        };
        assert!(
            validate(&cfg).is_ok(),
            "missing r2 credentials must be accepted for region_id=local"
        );
    }

    #[test]
    fn real_r2_credentials_in_non_local_region_is_accepted() {
        let cfg = AppConfig {
            region_id: "eu-central-1".into(),
            r2_access_key_id: "AKIAREALKEY".into(),
            r2_secret_access_key: "real-secret-value".into(),
            ..default_config()
        };
        assert!(
            validate(&cfg).is_ok(),
            "real r2 credentials must be accepted regardless of region_id"
        );
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
            handle_oracle_secret_token: "super-secret-oracle-token-12345".into(),
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
            !debug.contains("super-secret-oracle-token-12345"),
            "handle oracle secret must not appear in Debug output"
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
        assert_eq!(app.r2_request_timeout_secs, 30);
        assert_eq!(app.media_gc_sweep_timeout_secs, 1800);
        assert!(
            app.r2_access_key_id.is_empty(),
            "credentials must be injected by operator"
        );
    }
}
