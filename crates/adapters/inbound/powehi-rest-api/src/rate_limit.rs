use governor::middleware::NoOpMiddleware;
use http::header::HeaderValue;
use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};
use tower_governor::{
    GovernorError,
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::KeyExtractor,
    GovernorLayer,
};

/// Rate-limit key extractor with layered trust:
///
/// 1. `CF-Connecting-IP` (Cloudflare-set single-value header, never forwarded by clients
///    downstream; use this when behind Cloudflare CDN).
/// 2. **Rightmost** `X-Forwarded-For` token (the last hop — the one appended by the
///    most-recent trusted proxy — rather than the leftmost client-supplied value).
/// 3. `X-Real-IP` (set by Nginx/Traefik; single value, no appending by clients).
/// 4. `0.0.0.0` global-bucket fallback (keeps rate limiting active when no IP can
///    be determined; all such requests share one bucket).
///
/// **Before production:** configure Cloudflare + Traefik to always set CF-Connecting-IP
/// and strip/overwrite XFF to a single trusted value so the rightmost-XFF heuristic is
/// not necessary. Without proper ingress XFF stripping an attacker can still rotate the
/// rightmost XFF entry if the client is the only upstream (e.g. direct LB access that
/// bypasses CF). Phase-5 hardening should add `cargo deny` to keep
/// `tower_governor`'s `tracing` feature off (that feature logs raw client IPs which
/// violates the no-plaintext-logging rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrustedProxyKeyExtractor;

fn parse_ip(v: &HeaderValue) -> Option<IpAddr> {
    v.to_str().ok()?.trim().parse::<IpAddr>().ok()
}

fn rightmost_xff(v: &HeaderValue) -> Option<IpAddr> {
    // Walk from the right so the innermost trusted-proxy append is preferred.
    v.to_str()
        .ok()?
        .split(',')
        .rev()
        .find_map(|s| s.trim().parse::<IpAddr>().ok())
}

impl KeyExtractor for TrustedProxyKeyExtractor {
    type Key = IpAddr;

    fn extract<T>(&self, req: &http::Request<T>) -> Result<Self::Key, GovernorError> {
        let h = req.headers();
        let ip = h
            .get("cf-connecting-ip")
            .and_then(parse_ip)
            .or_else(|| h.get("x-forwarded-for").and_then(rightmost_xff))
            .or_else(|| h.get("x-real-ip").and_then(parse_ip))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        Ok(ip)
    }
}

pub type IpGovernorLayer = GovernorLayer<TrustedProxyKeyExtractor, NoOpMiddleware>;
type IpGovernorConfig = GovernorConfig<TrustedProxyKeyExtractor, NoOpMiddleware>;

fn make_layer(period_secs: u64, burst: u32) -> IpGovernorLayer {
    let mut b = GovernorConfigBuilder::default();
    b.per_second(period_secs).burst_size(burst);
    let config: IpGovernorConfig = b
        .key_extractor(TrustedProxyKeyExtractor)
        .finish()
        .expect("non-zero period and burst guaranteed by caller");
    GovernorLayer {
        config: Arc::new(config),
    }
}

/// Strict per-IP limit for auth endpoints — brute-force / enumeration protection.
/// Token bucket: burst=5, 1 token refilled every 6 s → ~10 req/min sustained.
/// A normal register (2 req) + login (2 req) = 4 tokens; fits within the burst.
/// TODO(hardening): add a second per-handle_hash bucket for credential stuffing protection.
pub fn auth_governor() -> IpGovernorLayer {
    make_layer(6, 5)
}

/// General per-IP limit for authenticated API endpoints.
/// Token bucket: burst=60, 1 token refilled every 2 s → ~30 req/s sustained.
pub fn api_governor() -> IpGovernorLayer {
    make_layer(2, 60)
}

/// Tight governor for tests: burst=1, refill every hour.
/// The second consecutive request from the same IP is always rate-limited.
#[cfg(test)]
pub(crate) fn tight_governor() -> IpGovernorLayer {
    make_layer(3600, 1)
}
