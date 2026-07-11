//! Shared SSRF guard: reject private/internal/loopback network destinations.
//!
//! Used at TWO points in the push-notification path so an attacker cannot
//! bypass the guard by racing DNS:
//!   1. Registration time (`powehi-rest-api`): rejects an endpoint whose
//!      literal host is already a private IP or `localhost`.
//!   2. Send time (`powehi-webpush`): rejects an endpoint whose hostname
//!      *resolves* to a private IP, even if the hostname itself looked public
//!      at registration time (DNS rebinding — the registered hostname's DNS
//!      answer can legitimately change between registration and every send).
//!
//! `is_private_ip` is the single source of truth for "is this address
//! internal"; both call sites go through it so the two checks can never
//! silently drift apart.

use std::net::{IpAddr, Ipv4Addr};

/// Returns `true` if `ip` belongs to a private/internal/loopback/link-local
/// range that must never be reachable from an outbound push request.
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:a.b.c.d) embeds a real IPv4 address. Check it
            // first so `::ffff:169.254.169.254` is correctly blocked. We do NOT
            // call the deprecated `to_ipv4()` compat form (::a.b.c.d), which
            // matches ::1 as 0.0.0.1 and would skip `is_loopback()` below.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_v4(v4);
            }
            v6.is_loopback()    // ::1
                || v6.is_unspecified() // ::
                // Link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // ULA fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_loopback()       // 127.0.0.0/8
        || v4.is_private() // 10.x / 172.16-31.x / 192.168.x
        || v4.is_link_local() // 169.254.x.x
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
}

/// Returns `true` if `host` (a bare hostname or IP literal, no port) is a
/// private/internal/loopback destination. IP literals are checked via
/// [`is_private_ip`]; non-IP hostnames are checked only for the well-known
/// `localhost` aliases — a plain domain name cannot be judged private without
/// resolving it (see [`is_private_ip`] used again at send time for that).
pub fn is_private_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    if h == "localhost" || h == "ip6-localhost" {
        return true;
    }
    h.parse::<IpAddr>().is_ok_and(is_private_ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_rfc1918_172_range() {
        assert!(is_private_host("172.16.0.1"));
        assert!(is_private_host("172.31.255.255"));
        assert!(!is_private_host("172.32.0.1"));
    }

    #[test]
    fn blocks_unspecified_and_broadcast() {
        assert!(is_private_host("0.0.0.0"));
        assert!(is_private_host("255.255.255.255"));
    }

    #[test]
    fn blocks_ipv6_unspecified_and_loopback() {
        assert!(is_private_host("::"));
        assert!(is_private_host("::1"));
    }

    #[test]
    fn blocks_ipv4_mapped_ipv6_link_local() {
        // Metadata-service SSRF classic: ::ffff:169.254.169.254
        assert!(is_private_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn allows_public_ips_and_hostnames() {
        assert!(!is_private_host("8.8.8.8"));
        assert!(!is_private_host("1.1.1.1"));
        assert!(!is_private_host("push.example.com"));
    }

    #[test]
    fn blocks_localhost_aliases() {
        assert!(is_private_host("localhost"));
        assert!(is_private_host("LOCALHOST"));
        assert!(is_private_host("ip6-localhost"));
    }
}
