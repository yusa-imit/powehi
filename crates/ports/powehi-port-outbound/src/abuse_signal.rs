//! Outbound port for the region-local abuse-signal store (prd.md §6.4).
//!
//! A block decision is a TTL'd entry keyed by an opaque [`AbuseSubject`]. The
//! store is region-local; mesh-wide propagation is the separate concern of
//! [`crate::region_router::RegionRouter::broadcast_abuse_signal`].
//!
//! Zero-knowledge invariant: implementations MUST NOT persist or log a raw IP
//! address, a handle, or any message content. The subject is already a SHA-256
//! digest or an internal UUID by construction.

use std::time::Duration;

use async_trait::async_trait;
use powehi_domain::{
    abuse::{AbuseReason, AbuseSubject},
    error::DomainError,
    region::RegionId,
};

/// Hard ceiling on any block's lifetime, independent of caller.
///
/// The gRPC receiving path (`powehi-grpc`'s `MAX_ABUSE_SIGNAL_TTL_SECS`) already
/// clamps a peer-supplied TTL before calling `block()`. This constant exists so
/// a *local* caller of `block()` (e.g. a future rate-limit trip point wired
/// directly into this port) cannot accidentally install a near-permanent block
/// by passing an unclamped duration — defense in depth, not the only guard
/// (security-auditor finding, cycle 433).
pub const MAX_ABUSE_SIGNAL_TTL: Duration = Duration::from_secs(24 * 60 * 60);

#[async_trait]
pub trait AbuseSignalStore: Send + Sync {
    /// Record a block for `subject`, expiring after `ttl`.
    ///
    /// Idempotent: blocking an already-blocked subject refreshes the entry.
    /// `origin_region` identifies which region made the decision so operators
    /// can attribute a mesh-wide block; it is opaque metadata, never PII.
    /// Implementations MUST clamp `ttl` to at most [`MAX_ABUSE_SIGNAL_TTL`].
    async fn block(
        &self,
        subject: &AbuseSubject,
        reason: AbuseReason,
        ttl: Duration,
        origin_region: RegionId,
    ) -> Result<(), DomainError>;

    /// Whether `subject` currently has an unexpired block entry.
    ///
    /// Call sites are expected to fail *open* on `Err` (a Redis outage must not
    /// take the API down); fail-closed would turn a cache outage into a
    /// full denial of service. Prefer [`AbuseSignalStore::is_blocked_or_allow`],
    /// which encodes that policy instead of leaving it to caller discipline.
    async fn is_blocked(&self, subject: &AbuseSubject) -> Result<bool, DomainError>;

    /// [`AbuseSignalStore::is_blocked`], but a store error is treated as "not
    /// blocked" rather than propagated — the fail-open policy documented on
    /// `is_blocked`, enforced in the type instead of by caller convention
    /// (threat-model-checker finding, cycle 433: with zero production call
    /// sites today, an `Err`-propagating caller added later would go
    /// unnoticed until a Redis outage turned this control into an outage).
    async fn is_blocked_or_allow(&self, subject: &AbuseSubject) -> bool {
        self.is_blocked(subject).await.unwrap_or(false)
    }
}
