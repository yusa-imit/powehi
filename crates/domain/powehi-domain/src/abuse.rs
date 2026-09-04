//! Cross-region abuse signals (prd.md §6.4 — "리전 간 abuse signal 동기화").
//!
//! A region that locally decides to block a subject (an IP or a user) emits an
//! [`AbuseSignal`] which is propagated to every peer region so the block takes
//! effect mesh-wide. Propagation is best-effort / eventually consistent — see
//! `RegionRouter::broadcast_abuse_signal` in `powehi-port-outbound`.
//!
//! Zero-knowledge / PII invariant: a raw IP address is PII and MUST NOT be
//! stored, logged, or put on the wire. Only [`AbuseSubject::IpHash`] — the
//! SHA-256 of the canonicalised address under a domain-separation prefix —
//! ever leaves this module.
//!
//! Threat-model note (deliberate, documented limitation): SHA-256 over the
//! IPv4 space (2^32) is enumerable by an attacker who already holds the hash,
//! so `IpHash` is a *pseudonymisation* measure — it keeps raw addresses out of
//! logs, Redis and the inter-region wire — not a confidentiality guarantee
//! against an adversary who has compromised the store. Upgrading to
//! HMAC-SHA256 under a mesh-shared secret (same pattern as the handle oracle
//! secret in `powehi-application`'s `auth_service`) is tracked as a follow-up.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{region::RegionId, user::UserId};

/// Length in bytes of an [`AbuseSubject::IpHash`] digest (SHA-256).
pub const ABUSE_IP_HASH_LEN: usize = 32;

/// Domain-separation prefix so an IP digest can never collide with any other
/// SHA-256 usage in the system (handle hashes, media blob hashes, …).
const IP_HASH_DOMAIN: &[u8] = b"powehi/abuse-subject/ip/v1";

/// Address-family tags, mixed into the digest so a 4-byte and a 16-byte input
/// can never produce the same preimage stream.
const IP_TAG_V4: u8 = 4;
const IP_TAG_V6: u8 = 6;

/// What is being blocked.
///
/// Both variants are opaque: a 32-byte digest or an internal UUID. Neither
/// carries a raw IP, a handle, or any other user-supplied identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbuseSubject {
    /// SHA-256 of the canonicalised client IP — never the address itself.
    IpHash([u8; ABUSE_IP_HASH_LEN]),
    /// An internal user UUID.
    User(UserId),
}

impl AbuseSubject {
    /// Hash a client IP into an opaque subject.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are canonicalised to their
    /// IPv4 form first, so the same client reaches the same digest regardless of
    /// which socket family terminated the connection.
    pub fn from_ip(ip: &IpAddr) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(IP_HASH_DOMAIN);
        match canonicalise(ip) {
            IpAddr::V4(v4) => {
                hasher.update([IP_TAG_V4]);
                hasher.update(v4.octets());
            }
            IpAddr::V6(v6) => {
                hasher.update([IP_TAG_V6]);
                hasher.update(v6.octets());
            }
        }
        Self::IpHash(hasher.finalize().into())
    }

    /// Lowercase-hex rendering of the IP digest, or the user UUID string.
    ///
    /// Safe to use as a **storage key**. NOT safe as a log field for the
    /// `IpHash` variant: per the module-level threat-model note, a bare
    /// SHA-256 over the IPv4 space is enumerable, so persisting this string
    /// in a log is equivalent to logging the IP itself (rule:
    /// no-plaintext-logging). Log [`AbuseSubject::kind`] instead.
    pub fn opaque_key(&self) -> String {
        match self {
            Self::IpHash(hash) => hex_lower(hash),
            Self::User(user_id) => user_id.as_uuid().to_string(),
        }
    }

    /// Short, non-identifying label for metrics/log dimensions.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::IpHash(_) => "ip",
            Self::User(_) => "user",
        }
    }
}

/// Collapse IPv4-mapped IPv6 addresses to their IPv4 form.
fn canonicalise(ip: &IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(*v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(*v6),
        },
    }
}

/// Lowercase hex without pulling in a `hex` dependency.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // Writing to a String is infallible; the Result is discarded rather
        // than unwrapped (rule: crates-naming — no unwrap in lib code).
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Why a subject was blocked. Mirrors the three triggers named in prd.md §6.4:
/// IP rate limiting, KeyPackage consumption flooding, and auth brute force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbuseReason {
    /// Local per-IP / per-handle rate limiter tripped.
    RateLimitExceeded,
    /// KeyPackage consumption flood (reconnaissance probing).
    KeyPackageFlood,
    /// Repeated failed authentication attempts.
    AuthBruteForce,
}

impl AbuseReason {
    /// Stable wire/storage token. Kept explicit so a rename of the Rust variant
    /// cannot silently change what already-persisted Redis values mean.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimitExceeded => "rate_limit_exceeded",
            Self::KeyPackageFlood => "key_package_flood",
            Self::AuthBruteForce => "auth_brute_force",
        }
    }
}

impl std::fmt::Display for AbuseReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A block decision made in one region, destined for the whole mesh.
///
/// Every field is opaque metadata: a digest or UUID, an enum, a region ID and
/// an expiry instant. No content, no PII.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseSignal {
    pub subject: AbuseSubject,
    pub reason: AbuseReason,
    /// Region that made the local block decision.
    pub origin_region: RegionId,
    /// Absolute expiry — the block is a TTL'd entry, never permanent.
    pub expires_at: DateTime<Utc>,
}

impl AbuseSignal {
    pub fn new(
        subject: AbuseSubject,
        reason: AbuseReason,
        origin_region: RegionId,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            subject,
            reason,
            origin_region,
            expires_at,
        }
    }

    /// Remaining lifetime relative to `now`, or `None` once expired.
    pub fn ttl_from(&self, now: DateTime<Utc>) -> Option<std::time::Duration> {
        (self.expires_at - now).to_std().ok()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn from_ip_is_deterministic() {
        let ip = v4(203, 0, 113, 7);
        assert_eq!(AbuseSubject::from_ip(&ip), AbuseSubject::from_ip(&ip));
    }

    #[test]
    fn different_ips_produce_different_hashes() {
        assert_ne!(
            AbuseSubject::from_ip(&v4(203, 0, 113, 7)),
            AbuseSubject::from_ip(&v4(203, 0, 113, 8))
        );
    }

    #[test]
    fn hash_is_thirty_two_bytes() {
        match AbuseSubject::from_ip(&v4(198, 51, 100, 1)) {
            AbuseSubject::IpHash(h) => assert_eq!(h.len(), ABUSE_IP_HASH_LEN),
            AbuseSubject::User(_) => panic!("from_ip must yield IpHash"),
        }
    }

    #[test]
    fn hash_does_not_contain_the_raw_address_bytes() {
        // Defence-in-depth: the digest must not be a passthrough of the octets.
        let octets = [203u8, 0, 113, 7];
        match AbuseSubject::from_ip(&v4(203, 0, 113, 7)) {
            AbuseSubject::IpHash(h) => {
                assert!(
                    !h.windows(octets.len()).any(|w| w == octets),
                    "digest must not embed the raw address octets"
                );
            }
            AbuseSubject::User(_) => panic!("from_ip must yield IpHash"),
        }
    }

    #[test]
    fn ipv4_mapped_ipv6_canonicalises_to_ipv4() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xcb00, 0x7107));
        assert_eq!(
            AbuseSubject::from_ip(&mapped),
            AbuseSubject::from_ip(&v4(203, 0, 113, 7)),
            "::ffff:203.0.113.7 and 203.0.113.7 are the same client"
        );
    }

    #[test]
    fn ipv6_differs_from_ipv4() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        assert_ne!(
            AbuseSubject::from_ip(&v6),
            AbuseSubject::from_ip(&v4(0, 0, 0, 1))
        );
    }

    #[test]
    fn user_subjects_compare_by_uuid() {
        let id = UserId::new();
        assert_eq!(
            AbuseSubject::User(id.clone()),
            AbuseSubject::User(id.clone())
        );
        assert_ne!(AbuseSubject::User(id), AbuseSubject::User(UserId::new()));
    }

    #[test]
    fn ip_and_user_subjects_are_never_equal() {
        assert_ne!(
            AbuseSubject::from_ip(&v4(203, 0, 113, 7)),
            AbuseSubject::User(UserId::new())
        );
    }

    #[test]
    fn opaque_key_for_ip_is_64_hex_chars() {
        let key = AbuseSubject::from_ip(&v4(203, 0, 113, 7)).opaque_key();
        assert_eq!(key.len(), ABUSE_IP_HASH_LEN * 2);
        assert!(key
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
        // Must not leak the dotted-quad form.
        assert!(!key.contains("203.0.113.7"));
    }

    #[test]
    fn opaque_key_for_user_is_the_uuid() {
        let id = UserId::new();
        assert_eq!(
            AbuseSubject::User(id.clone()).opaque_key(),
            id.as_uuid().to_string()
        );
    }

    #[test]
    fn subject_kind_labels() {
        assert_eq!(AbuseSubject::from_ip(&v4(1, 1, 1, 1)).kind(), "ip");
        assert_eq!(AbuseSubject::User(UserId::new()).kind(), "user");
    }

    #[test]
    fn reason_tokens_are_stable_and_distinct() {
        let all = [
            AbuseReason::RateLimitExceeded,
            AbuseReason::KeyPackageFlood,
            AbuseReason::AuthBruteForce,
        ];
        assert_eq!(all[0].as_str(), "rate_limit_exceeded");
        assert_eq!(all[1].as_str(), "key_package_flood");
        assert_eq!(all[2].as_str(), "auth_brute_force");
        for (i, a) in all.iter().enumerate() {
            for b in all.iter().skip(i + 1) {
                assert_ne!(a.as_str(), b.as_str());
            }
        }
    }

    #[test]
    fn ttl_from_returns_remaining_duration() {
        let now = Utc::now();
        let signal = AbuseSignal::new(
            AbuseSubject::from_ip(&v4(203, 0, 113, 7)),
            AbuseReason::RateLimitExceeded,
            RegionId::new("eu-central-1"),
            now + chrono::Duration::seconds(60),
        );
        let ttl = signal.ttl_from(now).expect("not yet expired");
        assert_eq!(ttl.as_secs(), 60);
    }

    #[test]
    fn ttl_from_returns_none_when_expired() {
        let now = Utc::now();
        let signal = AbuseSignal::new(
            AbuseSubject::User(UserId::new()),
            AbuseReason::AuthBruteForce,
            RegionId::new("ap-seoul-1"),
            now - chrono::Duration::seconds(1),
        );
        assert!(signal.ttl_from(now).is_none());
    }

    #[test]
    fn serialised_signal_carries_no_raw_address() {
        let signal = AbuseSignal::new(
            AbuseSubject::from_ip(&v4(203, 0, 113, 7)),
            AbuseReason::KeyPackageFlood,
            RegionId::new("eu-central-1"),
            Utc::now(),
        );
        let json = serde_json::to_string(&signal).expect("serialize");
        assert!(
            !json.contains("203.0.113.7"),
            "raw IP must never be serialised"
        );
        assert!(!json.contains("plaintext"));
        assert!(json.contains("eu-central-1"));
    }
}
