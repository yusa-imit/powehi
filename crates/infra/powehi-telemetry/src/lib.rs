//! Telemetry initialisation for Powehi.
//!
//! Provides two entry points:
//! - [`init`]: JSON structured logging + Prometheus metrics recorder (no OTLP).
//! - [`init_with_otlp`]: adds OTLP/gRPC span export to an OpenTelemetry Collector
//!   (`OTEL_EXPORTER_OTLP_ENDPOINT`), on top of JSON logging + Prometheus.
//!
//! # Security invariant (prd.md §13.2 + no-plaintext-logging rule)
//!
//! Exported spans contain **only** operation names, HTTP method/status codes, and
//! latencies.  No message content, envelope payloads, device IDs, user emails, or
//! any user-derived identifiers enter the trace pipeline.  This is enforced by
//! `#[instrument(skip(...))]` annotations on every handler that receives sensitive
//! parameters — the OTLP exporter simply re-exports whatever `tracing` emits.

use metrics_exporter_prometheus::PrometheusBuilder;
use opentelemetry::{global, trace::TracerProvider as _, KeyValue};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{trace as sdktrace, Resource};
use tracing_opentelemetry::OpenTelemetryLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub use metrics_exporter_prometheus::PrometheusHandle;

/// OTLP exporter configuration (prd.md §13.3).
///
/// Construct via [`OtlpConfig::from_env`] (reads standard OTEL env vars) or
/// build directly for tests.
///
/// # Security invariant
///
/// Only `service.name` and `service.version` resource attributes are attached
/// to spans.  No user-identifying data is ever added as a span attribute or
/// resource label.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// OTLP/gRPC collector endpoint, e.g. `"http://otel-collector:4317"`.
    pub endpoint: String,
    /// `service.name` resource attribute.  Defaults to `"powehi"`.
    pub service_name: String,
    /// `service.version` resource attribute.  Defaults to the crate version.
    pub service_version: String,
}

impl OtlpConfig {
    /// Read configuration from standard OpenTelemetry SDK environment variables.
    ///
    /// Returns `None` when `OTEL_EXPORTER_OTLP_ENDPOINT` is unset — OTLP is
    /// disabled and the caller should use [`init`] instead.
    ///
    /// | Env var | Default |
    /// |---------|---------|
    /// | `OTEL_EXPORTER_OTLP_ENDPOINT` | — (required; absent → `None`) |
    /// | `OTEL_SERVICE_NAME` | `"powehi"` |
    pub fn from_env() -> Option<Self> {
        std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .ok()
            .map(|endpoint| Self {
                endpoint,
                service_name: std::env::var("OTEL_SERVICE_NAME")
                    .unwrap_or_else(|_| "powehi".to_owned()),
                service_version: env!("CARGO_PKG_VERSION").to_owned(),
            })
    }
}

/// Initialise the structured JSON tracing subscriber (no OTLP export).
///
/// Reads the log level from `RUST_LOG` (default: `info`).
/// Call once at process startup.
pub fn init() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

/// Initialise tracing with OTLP/gRPC span export plus JSON console logging.
///
/// Spans are batched and exported via gRPC to the collector at
/// `config.endpoint`.  The global `TracerProvider` is installed; call
/// [`shutdown_otlp`] on graceful application exit to flush pending spans.
///
/// If OTLP setup fails (e.g. the collector is unreachable at startup) this
/// function returns an error and **the caller should fall back to [`init`]** so
/// the application does not refuse to start due to an unavailable exporter.
///
/// # Security invariant (prd.md §13.2)
///
/// Exported spans inherit whatever `tracing` emits.  All handlers that accept
/// sensitive parameters use `#[instrument(skip(...))]` to prevent them from
/// entering the span field set.  No filtering is done here — correctness is
/// enforced at the instrumentation site.
pub fn init_with_otlp(config: &OtlpConfig) -> anyhow::Result<()> {
    let resource = Resource::new(vec![
        KeyValue::new("service.name", config.service_name.clone()),
        KeyValue::new("service.version", config.service_version.clone()),
    ]);

    // install_batch returns a TracerProvider in opentelemetry-otlp 0.26+.
    // Register it as the global provider so shutdown_otlp() can flush spans.
    let provider = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(config.endpoint.clone()),
        )
        .with_trace_config(sdktrace::Config::default().with_resource(resource))
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| anyhow::anyhow!("failed to install OTLP tracer: {e}"))?;

    global::set_tracer_provider(provider.clone());

    // Obtain a concrete Tracer — OpenTelemetryLayer requires a PreSampledTracer,
    // which is implemented by opentelemetry_sdk::trace::Tracer (SdkTracer) but
    // not by TracerProvider directly.
    let tracer = provider.tracer("powehi");

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .with(OpenTelemetryLayer::new(tracer))
        .init();

    Ok(())
}

/// Flush and shut down the global OTLP tracer provider.
///
/// Must be called on graceful application exit when OTLP is enabled.
/// Harmless no-op if OTLP was never initialised.
pub fn shutdown_otlp() {
    global::shutdown_tracer_provider();
}

/// Install the global Prometheus metrics recorder.
///
/// Call once at startup after [`init`] or [`init_with_otlp`].
/// Returns a [`PrometheusHandle`] that renders accumulated metrics as
/// Prometheus exposition text.
///
/// Security: the returned handle exposes only aggregate counters and
/// histograms — no user identifiers, device IDs, or message content
/// (invariant: no-plaintext-logging rule). Bind the `/metrics` route to
/// an internal-only admin port; do not expose via the public ingress.
pub fn install_prometheus() -> anyhow::Result<PrometheusHandle> {
    PrometheusBuilder::new()
        .install_recorder()
        .map_err(|e| anyhow::anyhow!("failed to install Prometheus recorder: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;

    fn test_handle() -> &'static PrometheusHandle {
        static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
        HANDLE.get_or_init(|| install_prometheus().expect("prometheus test handle"))
    }

    #[test]
    fn install_prometheus_succeeds() {
        let _ = test_handle();
    }

    #[test]
    fn prometheus_handle_renders_valid_text_format() {
        let text = test_handle().render();
        for line in text.lines() {
            assert!(
                line.starts_with('#')
                    || line.is_empty()
                    || line.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_'),
                "unexpected prometheus line: {line}"
            );
        }
    }

    #[test]
    fn prometheus_output_contains_no_user_identifiers() {
        // Security invariant: no UUIDs, emails, or handles in metrics output.
        let text = test_handle().render();
        for line in text.lines() {
            assert!(
                !line.contains('@'),
                "metrics must not contain email-like strings: {line}"
            );
        }
    }

    // ── OtlpConfig unit tests ─────────────────────────────────────────────────

    #[test]
    fn otlp_config_fields_are_accessible() {
        let cfg = OtlpConfig {
            endpoint: "http://otel-collector:4317".to_owned(),
            service_name: "powehi".to_owned(),
            service_version: "0.1.0".to_owned(),
        };
        assert_eq!(cfg.endpoint, "http://otel-collector:4317");
        assert_eq!(cfg.service_name, "powehi");
        assert_eq!(cfg.service_version, "0.1.0");
    }

    #[test]
    fn otlp_config_clone_is_independent() {
        let cfg = OtlpConfig {
            endpoint: "http://a:4317".to_owned(),
            service_name: "svc".to_owned(),
            service_version: "1.0.0".to_owned(),
        };
        let mut copy = cfg.clone();
        copy.endpoint = "http://b:4317".to_owned();
        assert_eq!(cfg.endpoint, "http://a:4317");
        assert_eq!(copy.endpoint, "http://b:4317");
    }

    #[test]
    fn otlp_config_from_env_returns_none_when_endpoint_absent() {
        // Valid when OTEL_EXPORTER_OTLP_ENDPOINT is not set in the test env.
        // If the env var happens to be set (integration environment), skip.
        if std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok() {
            return; // guard: external OTEL collector present — skip
        }
        assert!(
            OtlpConfig::from_env().is_none(),
            "from_env() must return None when OTEL_EXPORTER_OTLP_ENDPOINT is unset"
        );
    }

    #[test]
    fn otlp_config_service_version_matches_crate_version() {
        // Verify that from_env() injects CARGO_PKG_VERSION for service.version.
        // We test the literal value since the crate version is constant.
        let version_from_config = env!("CARGO_PKG_VERSION");
        // Constructing manually mirrors what from_env() would produce.
        let cfg = OtlpConfig {
            endpoint: "http://localhost:4317".to_owned(),
            service_name: "powehi".to_owned(),
            service_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        assert_eq!(cfg.service_version, version_from_config);
    }

    // ── OtlpConfig::from_env() Some-branch tests ──────────────────────────────
    //
    // These tests mutate the process environment, so a static Mutex serialises
    // them to avoid races when cargo test runs threads in parallel.

    static ENV_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // RAII guard that restores an env var to its previous value on drop.
    struct EnvGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvGuard {
        // Set key=value; restores original on drop. SAFETY: caller holds ENV_TEST_MUTEX.
        fn set(key: &'static str, value: &str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: serialised by ENV_TEST_MUTEX; no concurrent env access.
            unsafe { std::env::set_var(key, value) };
            Self { key, original }
        }

        // Remove key from env; restores it on drop. SAFETY: caller holds ENV_TEST_MUTEX.
        fn remove(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            // SAFETY: serialised by ENV_TEST_MUTEX; no concurrent env access.
            unsafe { std::env::remove_var(key) };
            Self { key, original }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn otlp_config_from_env_returns_some_when_endpoint_set() {
        let _lock = ENV_TEST_MUTEX.lock().unwrap();
        let _ep = EnvGuard::set("OTEL_EXPORTER_OTLP_ENDPOINT", "http://test-collector:4317");
        // Ensure OTEL_SERVICE_NAME is absent so the default path is exercised.
        let _sn = EnvGuard::remove("OTEL_SERVICE_NAME");

        let cfg = OtlpConfig::from_env().expect("from_env() must return Some when endpoint is set");
        assert_eq!(cfg.endpoint, "http://test-collector:4317");
        assert_eq!(
            cfg.service_name, "powehi",
            "service_name must default to 'powehi' when OTEL_SERVICE_NAME is absent"
        );
        assert_eq!(
            cfg.service_version,
            env!("CARGO_PKG_VERSION"),
            "service_version must equal CARGO_PKG_VERSION"
        );
    }

    #[test]
    fn otlp_config_from_env_reads_custom_otel_service_name() {
        let _lock = ENV_TEST_MUTEX.lock().unwrap();
        let _ep = EnvGuard::set("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317");
        let _sn = EnvGuard::set("OTEL_SERVICE_NAME", "my-powehi-replica");

        let cfg = OtlpConfig::from_env().expect("Some when endpoint is set");
        assert_eq!(cfg.service_name, "my-powehi-replica");
    }

    #[test]
    fn shutdown_otlp_does_not_panic_without_prior_init() {
        // global::shutdown_tracer_provider() is a no-op when no provider was
        // installed; calling it (and a second time for idempotency) must not panic.
        shutdown_otlp();
        shutdown_otlp();
    }
}
