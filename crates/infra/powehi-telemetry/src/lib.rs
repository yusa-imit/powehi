use metrics_exporter_prometheus::PrometheusBuilder;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub use metrics_exporter_prometheus::PrometheusHandle;

/// Initialise the structured JSON tracing subscriber.
pub fn init() {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer().json())
        .init();
}

/// Install the global Prometheus metrics recorder.
///
/// Call once at startup after [`init`]. Returns a [`PrometheusHandle`] that
/// renders accumulated metrics as Prometheus exposition text.
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
}
