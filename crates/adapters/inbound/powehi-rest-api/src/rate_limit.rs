use governor::{middleware::NoOpMiddleware, DefaultKeyedRateLimiter, Quota, RateLimiter};
use http::header::HeaderValue;
use std::{
    net::{IpAddr, Ipv4Addr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};
use tower_governor::{
    governor::{GovernorConfig, GovernorConfigBuilder},
    key_extractor::KeyExtractor,
    GovernorError, GovernorLayer,
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
/// Complemented by `HandleRateLimiter` which adds a per-handle-hash bucket.
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

/// Per-handle-hash rate limiter for credential-stuffing protection.
///
/// Key: first 16 bytes of `handle_hash` (SHA-256 of plaintext handle) packed as `u128`.
/// Rate: burst=5, 1 token refilled every 3 minutes.
///
/// Complementary to the per-IP `auth_governor()`. An attacker rotating IP
/// addresses is still bounded to 5 attempts per handle per refill window, which
/// is enough for a normal register (1) + login (1) = 2 tokens.
///
/// NOTE: The underlying `DefaultKeyedStateStore` grows without bound;
/// pair with periodic `retain_recent` shrinkage in long-lived processes.
pub struct HandleRateLimiter {
    inner: Arc<DefaultKeyedRateLimiter<u128>>,
}

impl HandleRateLimiter {
    pub fn new() -> Self {
        let quota = Quota::with_period(Duration::from_secs(180))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(5).expect("non-zero burst"));
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    /// Check and consume one token for the given handle_hash.
    /// Returns `true` if allowed, `false` if the per-handle bucket is exhausted.
    pub fn check(&self, handle_hash: &[u8]) -> bool {
        self.inner.check_key(&Self::key(handle_hash)).is_ok()
    }

    fn key(handle_hash: &[u8]) -> u128 {
        let mut buf = [0u8; 16];
        let len = handle_hash.len().min(16);
        buf[..len].copy_from_slice(&handle_hash[..len]);
        u128::from_le_bytes(buf)
    }

    /// Remove stale per-handle entries to bound memory growth.
    /// Call periodically (e.g. every hour) in a background task.
    pub fn retain_recent(&self) {
        self.inner.retain_recent();
    }

    /// Tight limiter for tests: burst=1, refill every hour.
    /// The second consecutive call from the same hash is always blocked.
    #[cfg(test)]
    pub(crate) fn tight() -> Self {
        let quota = Quota::with_period(Duration::from_secs(3600))
            .expect("non-zero period")
            .allow_burst(NonZeroU32::new(1).expect("non-zero burst"));
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }
}

impl Default for HandleRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use std::net::{IpAddr, Ipv4Addr};

    fn extract(req: Request<()>) -> IpAddr {
        TrustedProxyKeyExtractor.extract(&req).unwrap()
    }

    fn req_with_headers<F: Fn(http::request::Builder) -> http::request::Builder>(
        f: F,
    ) -> Request<()> {
        f(Request::builder().method("GET").uri("/"))
            .body(())
            .unwrap()
    }

    /// CF-Connecting-IP must win over any XFF or X-Real-IP value.
    #[test]
    fn cf_connecting_ip_takes_precedence_over_xff() {
        let req = req_with_headers(|b| {
            b.header("cf-connecting-ip", "1.2.3.4")
                .header("x-forwarded-for", "9.9.9.9, 8.8.8.8")
                .header("x-real-ip", "7.7.7.7")
        });
        assert_eq!(extract(req), "1.2.3.4".parse::<IpAddr>().unwrap());
    }

    /// Rightmost XFF token is used, not leftmost (prevents client IP spoofing).
    #[test]
    fn rightmost_xff_is_used_not_leftmost() {
        let req = req_with_headers(|b| {
            // Leftmost is the attacker-supplied spoof; rightmost is the proxy-observed IP.
            b.header("x-forwarded-for", "10.0.0.1, 10.0.0.2, 192.0.2.1")
        });
        // Must be the rightmost: 192.0.2.1
        assert_eq!(extract(req), "192.0.2.1".parse::<IpAddr>().unwrap());
    }

    /// Single-token XFF (no commas) is parsed correctly.
    #[test]
    fn xff_single_ip_works() {
        let req = req_with_headers(|b| b.header("x-forwarded-for", "203.0.113.5"));
        assert_eq!(extract(req), "203.0.113.5".parse::<IpAddr>().unwrap());
    }

    /// X-Real-IP is used when CF and XFF headers are absent.
    #[test]
    fn x_real_ip_used_when_no_cf_or_xff() {
        let req = req_with_headers(|b| b.header("x-real-ip", "198.51.100.7"));
        assert_eq!(extract(req), "198.51.100.7".parse::<IpAddr>().unwrap());
    }

    /// Global-bucket fallback (0.0.0.0) when no trusted header is present.
    #[test]
    fn global_bucket_fallback_when_no_headers() {
        let req = req_with_headers(|b| b);
        assert_eq!(
            extract(req),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "should fall back to 0.0.0.0"
        );
    }

    /// Malformed CF-Connecting-IP falls through to XFF.
    #[test]
    fn malformed_cf_header_falls_through_to_xff() {
        let req = req_with_headers(|b| {
            b.header("cf-connecting-ip", "not-an-ip")
                .header("x-forwarded-for", "10.1.2.3")
        });
        assert_eq!(extract(req), "10.1.2.3".parse::<IpAddr>().unwrap());
    }

    /// All-malformed XFF tokens fall through to X-Real-IP.
    #[test]
    fn malformed_xff_falls_through_to_x_real_ip() {
        let req = req_with_headers(|b| {
            b.header("x-forwarded-for", "not-an-ip, also-bad")
                .header("x-real-ip", "172.16.0.1")
        });
        assert_eq!(extract(req), "172.16.0.1".parse::<IpAddr>().unwrap());
    }

    /// XFF with trailing whitespace around IPs is parsed correctly.
    #[test]
    fn xff_ignores_whitespace_around_ip() {
        let req = req_with_headers(|b| b.header("x-forwarded-for", " 10.0.0.5 , 10.0.0.6 "));
        assert_eq!(extract(req), "10.0.0.6".parse::<IpAddr>().unwrap());
    }

    // ── HandleRateLimiter tests ──────────────────────────────────────────────

    #[test]
    fn handle_rate_limiter_blocks_after_burst_exhausted() {
        let rl = HandleRateLimiter::tight();
        let hash = vec![0x42u8; 32];
        assert!(rl.check(&hash), "first token consumed OK");
        assert!(
            !rl.check(&hash),
            "second call must be rate-limited (burst=1 exhausted)"
        );
    }

    #[test]
    fn handle_rate_limiter_isolates_distinct_hashes() {
        let rl = HandleRateLimiter::tight();
        let hash_a = vec![0u8; 32];
        let hash_b = vec![1u8; 32];
        assert!(rl.check(&hash_a));
        assert!(!rl.check(&hash_a), "hash_a bucket exhausted");
        assert!(
            rl.check(&hash_b),
            "hash_b must be unaffected by hash_a exhaustion"
        );
    }

    #[test]
    fn handle_rate_limiter_short_or_empty_hash_does_not_panic() {
        let rl = HandleRateLimiter::tight();
        let _ = rl.check(&[]);
        let _ = rl.check(&[0u8; 1]);
        let _ = rl.check(&[0u8; 8]);
        let _ = rl.check(&[0u8; 16]);
    }
}
