use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::DateTime;
use governor::{DefaultKeyedRateLimiter, Quota, RateLimiter};
use powehi_domain::{
    abuse::{AbuseReason as DomainAbuseReason, AbuseSignal, AbuseSubject, ABUSE_IP_HASH_LEN},
    device::DeviceId,
    envelope::{Envelope, EnvelopeId, MessageType},
    error::DomainError,
    event::DomainEvent,
    group::{Epoch, Group, GroupId, GroupMember},
    key_package::{ConsumeResult, KeyPackageId},
    region::RegionId,
    user::UserId,
};
use powehi_port_outbound::{
    abuse_signal::AbuseSignalStore, commit_ledger::CommitLedger, envelope_repo::EnvelopeRepository,
    event_bus::DomainEventBus, group_repo::GroupRepository, key_package_repo::KeyPackageRepository,
};
use tonic::{Request, Response, Status};
use tracing::{instrument, warn};
use uuid::Uuid;

use powehi_proto::region::{
    propagate_abuse_signal_request::Subject as ProtoAbuseSubject,
    region_service_server::RegionService, AbuseReason as ProtoAbuseReason,
    ConsumeKeyPackageRequest, ConsumeKeyPackageResponse, ConsumeStatus, EnvelopeType,
    ForwardCommitRequest, ForwardCommitResponse, ForwardEnvelopeRequest, ForwardEnvelopeResponse,
    ForwardStatus, HealthCheckRequest, HealthCheckResponse, HealthStatus,
    PropagateAbuseSignalRequest, PropagateAbuseSignalResponse, SyncGroupMembershipRequest,
    SyncGroupMembershipResponse,
};

use crate::error::domain_err_to_status;

/// Per-type ciphertext/commit/welcome byte caps for cross-region envelope
/// forwarding (RED-1 closure) — duplicated from (must be kept in sync with)
/// `MAX_CIPHERTEXT_BYTES`/`MAX_COMMIT_BYTES`/`MAX_WELCOME_BYTES` in
/// `powehi-application`'s `messaging_service.rs`. Deliberately duplicated
/// rather than imported: `powehi-grpc` is an inbound adapter and does not
/// depend on `powehi-application` (hexagonal boundary — same precedent as
/// `pg_security_it.rs`'s local `ENVELOPE_POLL_LIMIT` literal).
///
/// A single generic `MAX_CIPHERTEXT_BYTES = 1 MiB` cap for every message type
/// here previously let a hostile/compromised peer region (prd.md §3.5.1, T7)
/// forward Application/Proposal envelopes at up to 1 MiB each — 4x the REST
/// ingress path's 96 KiB Application cap — silently invalidating
/// `ENVELOPE_POLL_LIMIT`'s documented worst-case per-poll memory bound in
/// `envelope_repo.rs` (64 × 256KB assumed every type capped at Welcome's
/// ceiling; a cross-region-forwarded Application/Proposal envelope was not).
/// threat-model-checker cycle 353.
///
/// `pub` (not private) solely so `bin/powehi-server`'s
/// `tests/size_cap_consistency.rs` can assert these stay equal to their
/// `powehi-application`/`messaging_service.rs` counterparts — see that
/// module's `MAX_CIPHERTEXT_BYTES` doc comment. threat-model-checker cycle
/// 355 follow-up: this pair had no compiler/test-enforced sync before this.
pub const MAX_APPLICATION_CIPHERTEXT_BYTES: usize = 96 * 1024; // 96 KiB
pub const MAX_COMMIT_BYTES: usize = 64 * 1024; // 64 KiB
pub const MAX_WELCOME_BYTES: usize = 256 * 1024; // 256 KiB

/// Maximum number of device members accepted per SyncGroupMembership call (RED-1 closure).
/// Prevents amplified DB writes from a malicious or misconfigured peer.
const MAX_SYNC_MEMBERS: usize = 10_000;

/// Maximum region-ID length accepted from a peer, for both `home_region`
/// (SyncGroupMembership) and `origin_region` (PropagateAbuseSignal).
const MAX_REGION_ID_LEN: usize = 64;

/// Hard ceiling on the lifetime of a peer-supplied abuse block (prd.md §6.4).
///
/// `expires_at_unix_ms` is attacker-controllable by a compromised peer region.
/// Without a cap, a single PropagateAbuseSignal could install an effectively
/// permanent mesh-wide block on an IP digest or user — turning the abuse
/// defence into a denial-of-service weapon against legitimate users. Blocks are
/// re-propagated by the origin region for as long as the abuse continues, so
/// clamping to 24h costs nothing operationally.
const MAX_ABUSE_SIGNAL_TTL_SECS: u64 = 24 * 60 * 60;

/// Per-origin-region rate limit for `PropagateAbuseSignal` (security-auditor
/// finding, cycle 433).
///
/// Without this, one authenticated peer region could call the RPC without
/// bound, writing an unlimited number of distinct `abuse:*` keys (each with
/// up to a 24h TTL) into the region-local Redis — the same T7-class threat
/// (prd.md §3.5.1, hostile/compromised peer region) that `MAX_SYNC_MEMBERS`
/// already defends against for `SyncGroupMembership`, just unaddressed here.
/// This bounds *call frequency* per claimed origin region — it does NOT by
/// itself bound the rate limiter's own key space (see
/// `abuse_signal_limiter_handle`'s doc comment for that separate guard).
/// Burst=60, 1 token refilled per second — mirrors the KeyPackage-consumption
/// limit prd.md §6.4 already documents ("동일 IP에서 분당 60회 제한"): legitimate
/// abuse-signal traffic from one peer region is bursty (reacting to an
/// attack), not sustained near this rate.
const ABUSE_SIGNAL_RATE_BURST: NonZeroU32 = match NonZeroU32::new(60) {
    Some(n) => n,
    None => panic!("ABUSE_SIGNAL_RATE_BURST must be non-zero"),
};

/// Maximum allowed clock skew for `sent_at_unix_ms` in ForwardEnvelope (Y-14 closure).
/// Timestamps outside ±5 minutes of server-local time are clamped to now, preventing
/// a compromised peer from manipulating envelope ordering via far-past/future timestamps.
const MAX_SENT_AT_SKEW_SECS: i64 = 300; // 5 minutes

pub struct RegionGrpcServer {
    pub local_region: RegionId,
    pub envelope_repo: Arc<dyn EnvelopeRepository>,
    pub event_bus: Arc<dyn DomainEventBus>,
    pub key_package_repo: Arc<dyn KeyPackageRepository>,
    pub group_repo: Arc<dyn GroupRepository>,
    /// Single-transaction epoch-CAS + Commit-envelope persist (prd.md §4A.5),
    /// used by `forward_commit`. Required, not optional: accepting a forwarded
    /// Commit is only correct if the epoch advance and the envelope insert
    /// commit or roll back together.
    pub commit_ledger: Arc<dyn CommitLedger>,
    /// Region-local store for cross-region abuse blocks (prd.md §6.4).
    ///
    /// This is the RECEIVING end of the mesh fan-out: signals arriving via
    /// `PropagateAbuseSignal` are written here and deliberately NOT
    /// re-broadcast. `RegionGrpcServer` intentionally holds no `RegionRouter`,
    /// which makes "receivers never re-broadcast" a structural guarantee
    /// rather than a convention.
    pub abuse_signal_store: Arc<dyn AbuseSignalStore>,
    /// Bounds `PropagateAbuseSignal` call frequency per claimed `origin_region`.
    /// See `ABUSE_SIGNAL_RATE_BURST`. Keyed by region ID (not by peer
    /// connection), so a peer can't multiply its quota by opening more
    /// connections — but see `abuse_signal_limiter_handle` for the *map's own*
    /// memory-growth guard, which this field alone does not provide.
    abuse_signal_limiter: Arc<DefaultKeyedRateLimiter<String>>,
    /// When `true`, requests that arrive without `TlsConnectInfo` are rejected with
    /// PermissionDenied instead of being passed through with a warning. Set to
    /// `cfg.grpc_tls_enabled()` in the composition root so that any misconfiguration
    /// that causes the gRPC listener to start without TLS (despite TLS being configured)
    /// is caught at the RPC layer rather than silently degrading to plaintext.
    pub tls_required: bool,
}

impl RegionGrpcServer {
    // Every parameter is a required collaborator of the composition root, and
    // each is load-bearing for a security invariant (`commit_ledger` for the
    // epoch/envelope atomicity in `forward_commit`, `tls_required` for the
    // fail-closed mTLS check). A builder with `with_*` setters would make them
    // individually omissible and turn a wiring mistake into a silent runtime
    // degradation instead of a compile error, so keep the positional
    // constructor and take the lint suppression.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_region: RegionId,
        envelope_repo: Arc<dyn EnvelopeRepository>,
        event_bus: Arc<dyn DomainEventBus>,
        key_package_repo: Arc<dyn KeyPackageRepository>,
        group_repo: Arc<dyn GroupRepository>,
        commit_ledger: Arc<dyn CommitLedger>,
        abuse_signal_store: Arc<dyn AbuseSignalStore>,
        tls_required: bool,
    ) -> Self {
        // `per_minute(60)` replenishes one token every 60s/60 = 1s with a burst
        // capacity of 60 — the exact quota this module documents ("Burst=60, 1
        // token refilled per second"), expressed via a `const fn` constructor
        // instead of `Quota::with_period(..).expect(..)` so no runtime
        // unwrap/expect is needed for a value that can never actually fail
        // (rule: crates-naming, no unwrap/expect in lib code).
        let quota = Quota::per_minute(ABUSE_SIGNAL_RATE_BURST);
        Self {
            local_region,
            envelope_repo,
            event_bus,
            key_package_repo,
            group_repo,
            commit_ledger,
            abuse_signal_store,
            abuse_signal_limiter: Arc::new(RateLimiter::keyed(quota)),
            tls_required,
        }
    }

    /// A cloned handle to the per-origin-region abuse-signal rate limiter, so
    /// the composition root can run periodic `retain_recent()` GC on it
    /// (security-auditor finding, cycle 434): the limiter's internal map
    /// grows once per distinct claimed `origin_region` and is never reaped by
    /// the limiter itself, so it can grow without bound — most importantly on
    /// the `tls_required=false` fail-open path, where `origin_region` is
    /// attacker-chosen (see `verify_peer_region`) rather than mTLS-verified
    /// against a finite peer set. Mirrors `HandleRateLimiter::retain_recent`'s
    /// GC task in `powehi-rest-api` / the composition root (`bin/powehi-server`).
    ///
    /// Call this **before** moving `self` into `RegionServiceServer::new`,
    /// which takes `self` by value.
    pub fn abuse_signal_limiter_handle(&self) -> Arc<DefaultKeyedRateLimiter<String>> {
        Arc::clone(&self.abuse_signal_limiter)
    }
}

impl RegionGrpcServer {
    /// Verify that the calling peer's mTLS certificate CN or DNS SAN matches `expected_region`.
    ///
    /// Behaviour matrix:
    /// - `TlsConnectInfo` absent AND `self.tls_required = false` (dev/test mode): warns + passes.
    /// - `TlsConnectInfo` absent AND `self.tls_required = true` (production): PermissionDenied.
    ///   This catches the misconfiguration where the gRPC listener started without `.tls_config()`
    ///   even though TLS was configured — fail-closed rather than silently degrading.
    /// - `TlsConnectInfo` present but peer presented no certificate: PermissionDenied.
    /// - Peer cert fails to parse: PermissionDenied.
    /// - No CN/SAN matches `expected_region`: PermissionDenied.
    ///
    /// Logging policy (no-plaintext-logging.md): only the region string is logged — no device
    /// IDs, no certificate bytes, no DNs.
    #[allow(clippy::result_large_err)] // tonic::Status is large by design; boxing would cascade
    fn verify_peer_region(
        &self,
        extensions: &tonic::Extensions,
        expected_region: &str,
    ) -> Result<(), Status> {
        use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};

        let Some(tls_info) = extensions.get::<TlsConnectInfo<TcpConnectInfo>>() else {
            if self.tls_required {
                // TLS is configured on this server but the listener did not inject
                // TlsConnectInfo. Reject rather than silently bypassing peer-cert checks.
                warn!(
                    expected_region,
                    "no TlsConnectInfo despite tls_required=true — rejecting request"
                );
                return Err(Status::permission_denied("peer certificate required"));
            }
            // Dev/test mode — no TLS termination on this hop. Fail-open with a warning so
            // unit tests and local dev still function. In production the gRPC listener MUST
            // be wrapped in `tonic::transport::Server::builder().tls_config(...)`, which
            // inserts this extension. Set POWEHI__GRPC_TLS_* env vars to enable tls_required.
            warn!(
                expected_region,
                "no TlsConnectInfo — skipping peer cert check (dev/test mode)"
            );
            return Ok(());
        };

        let Some(certs) = tls_info.peer_certs() else {
            warn!(expected_region, "peer presented no certificate under mTLS");
            return Err(Status::permission_denied("peer certificate required"));
        };

        let Some(first_cert) = certs.first() else {
            return Err(Status::permission_denied("peer certificate required"));
        };

        // Y-9: warn if the peer's mTLS cert is expired or expiring soon.
        // Primary expiry enforcement is done by rustls during the TLS handshake; this
        // is a secondary operational signal so operators get advance notice before
        // rustls starts rejecting connections.
        inspect_cert_expiry(first_cert.as_ref(), expected_region);

        match peer_cert_matches_region(first_cert.as_ref(), expected_region) {
            Ok(true) => Ok(()),
            Ok(false) => {
                warn!(
                    expected_region,
                    "peer cert CN/SAN does not match home_region"
                );
                Err(Status::permission_denied("peer region mismatch"))
            }
            Err(e) => {
                warn!(expected_region, error = %e, "failed to parse peer certificate");
                Err(Status::permission_denied("peer certificate invalid"))
            }
        }
    }

    /// Verify that `sender` is a known member of `group_id` in the local membership store.
    ///
    /// Fail-closed: if no membership data exists the envelope is rejected with PermissionDenied.
    /// The correct operational sequence is: peer region calls SyncGroupMembership before
    /// any ForwardEnvelope/ForwardCommit for a given group.
    ///
    /// RED-2/RED-3 closure: SyncGroupMembership additionally verifies that the calling peer's
    /// mTLS Subject CN / DNS SAN equals the claimed `home_region` (see `verify_peer_region`).
    /// `ForwardEnvelope` and `ForwardCommit` rely on the membership table populated by Sync;
    /// because Sync is gated by peer-cert region, only the authoritative home-region peer can
    /// declare membership for a given group_id.
    async fn check_sender_is_member(
        &self,
        group_id: &GroupId,
        sender: &DeviceId,
    ) -> Result<(), Status> {
        let members = self
            .group_repo
            .list_members(group_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        if members.is_empty() {
            warn!(
                group_id = %group_id.as_uuid(),
                "forward rejected: no membership data; SyncGroupMembership must precede ForwardEnvelope"
            );
            return Err(Status::permission_denied(
                "sender is not authorized for this group",
            ));
        }

        if !members.iter().any(|m| &m.device_id == sender) {
            return Err(Status::permission_denied(
                "sender is not authorized for this group",
            ));
        }
        Ok(())
    }
}

fn parse_group_id(s: &str) -> Option<GroupId> {
    Uuid::parse_str(s).ok().map(GroupId::from)
}

fn parse_envelope_id(s: &str) -> Option<EnvelopeId> {
    s.parse::<EnvelopeId>().ok()
}

fn parse_device_id(s: &str) -> Option<powehi_domain::device::DeviceId> {
    s.parse::<powehi_domain::device::DeviceId>().ok()
}

fn proto_type_to_domain(t: i32) -> Option<MessageType> {
    match EnvelopeType::try_from(t).unwrap_or(EnvelopeType::Unspecified) {
        EnvelopeType::Application => Some(MessageType::Application),
        EnvelopeType::Welcome => Some(MessageType::Welcome),
        EnvelopeType::Commit => Some(MessageType::Commit),
        EnvelopeType::Proposal => Some(MessageType::Proposal),
        EnvelopeType::Unspecified => None,
    }
}

/// Log a warning if the peer's certificate is expired or expiring within 30 days.
/// Parsing failures are silently ignored (the TLS handshake already validated the cert).
fn inspect_cert_expiry(der: &[u8], expected_region: &str) {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return;
    };
    let not_after = cert.validity().not_after.timestamp();
    let now = chrono::Utc::now().timestamp();

    if now > not_after {
        // Should be impossible: rustls rejects expired certs during handshake.
        // Log at warn for defense-in-depth visibility.
        warn!(expected_region, "peer mTLS certificate is expired");
    } else {
        let days_until_expiry = (not_after - now) / 86_400;
        if days_until_expiry < 30 {
            warn!(
                expected_region,
                days_until_expiry, "peer mTLS certificate expires soon — rotate before expiry"
            );
        }
    }
}

/// Parse a DER-encoded X.509 certificate and check if any Subject CN or DNS SAN
/// matches `region`. Matching is case-insensitive per RFC 6125 §6.4.1 (DNS names
/// and CNs used as hostnames are case-insensitive).
///
/// This is a parser-only helper. It does NOT perform any cryptographic operations
/// (no signature verification, no chain validation) — chain trust is enforced one
/// layer below by the rustls handshake. Here we just bind the already-trusted peer
/// identity to the `home_region` claim.
fn peer_cert_matches_region(der: &[u8], region: &str) -> Result<bool, String> {
    use x509_parser::oid_registry::OID_X509_COMMON_NAME;
    use x509_parser::prelude::{FromDer, GeneralName, X509Certificate};

    let (_, cert) = X509Certificate::from_der(der).map_err(|e| format!("DER parse error: {e}"))?;

    // Check Subject CN — any RDN whose AttributeType is commonName.
    // Case-insensitive: RFC 6125 §6.4.1 states DNS name comparison is case-insensitive.
    for rdn in cert.subject().iter_rdn() {
        for attr in rdn.iter() {
            if attr.attr_type() == &OID_X509_COMMON_NAME {
                if let Ok(cn) = attr.as_str() {
                    if cn.eq_ignore_ascii_case(region) {
                        return Ok(true);
                    }
                }
            }
        }
    }

    // Check SAN DNS names — also case-insensitive per RFC 6125.
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::DNSName(dns) = name {
                if dns.eq_ignore_ascii_case(region) {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

#[tonic::async_trait]
impl RegionService for RegionGrpcServer {
    #[instrument(
        skip(self, request),
        fields(
            region = %self.local_region,
            // log only opaque IDs — no ciphertext, no plaintext (no-plaintext-logging rule)
        )
    )]
    async fn forward_envelope(
        &self,
        request: Request<ForwardEnvelopeRequest>,
    ) -> Result<Response<ForwardEnvelopeResponse>, Status> {
        let (_metadata, request_exts, req) = request.into_parts();

        // RED-1: cap ciphertext size before the `req.ciphertext.to_vec()` clone
        // below (tonic/prost has already decoded the request into `req` by this
        // point — the real bound on pre-decode allocation is tonic's own
        // `max_decoding_message_size`, set at the server composition root), using
        // a per-type budget (Welcome's ratchet-tree payload legitimately dwarfs
        // an Application message) matching the REST ingress path's caps — a
        // single generic 1 MiB ceiling here previously let a hostile/compromised
        // peer region forward oversized Application/Proposal envelopes, invalidating
        // `ENVELOPE_POLL_LIMIT`'s documented worst-case poll memory bound
        // (threat-model-checker cycle 353). message_type must be parsed first to
        // pick the right budget; this is still before any owned-Vec allocation.
        let message_type = proto_type_to_domain(req.envelope_type)
            .ok_or_else(|| Status::invalid_argument("envelope_type unspecified"))?;
        let max_ciphertext_bytes = match message_type {
            MessageType::Welcome => MAX_WELCOME_BYTES,
            MessageType::Commit => MAX_COMMIT_BYTES,
            MessageType::Application | MessageType::Proposal => MAX_APPLICATION_CIPHERTEXT_BYTES,
        };
        if req.ciphertext.len() > max_ciphertext_bytes {
            return Err(Status::invalid_argument("ciphertext exceeds maximum size"));
        }

        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;
        let envelope_id = parse_envelope_id(&req.envelope_id)
            .ok_or_else(|| Status::invalid_argument("invalid envelope_id UUID"))?;
        let sender = parse_device_id(&req.sender_device_id)
            .ok_or_else(|| Status::invalid_argument("invalid sender_device_id UUID"))?;
        let recipient = if req.recipient_device_id.is_empty() {
            None
        } else {
            Some(
                parse_device_id(&req.recipient_device_id)
                    .ok_or_else(|| Status::invalid_argument("invalid recipient_device_id UUID"))?,
            )
        };
        // Y-14: clamp peer-supplied timestamp to ±MAX_SENT_AT_SKEW_SECS from now.
        // A compromised peer could manipulate `sent_at_unix_ms` to shift envelope
        // ordering (e.g., far-past to appear ancient, far-future to appear newer
        // than currently-delivered messages). Clamping to server-local time neutralises
        // this without hard-rejecting envelopes that arrive with small clock skew.
        let created_at = {
            let now = chrono::Utc::now();
            DateTime::from_timestamp_millis(req.sent_at_unix_ms)
                .filter(|&ts| (ts - now).num_seconds().abs() <= MAX_SENT_AT_SKEW_SECS)
                .unwrap_or(now)
        };

        // RED-2: verify the calling peer's mTLS cert matches the group's home_region.
        // If the group is unknown locally, check_sender_is_member will reject with
        // PermissionDenied (no members); no extra cert check is needed for that path.
        if let Some(group) = self
            .group_repo
            .find_by_id(&group_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?
        {
            self.verify_peer_region(&request_exts, &group.home_region.to_string())?;
        }

        self.check_sender_is_member(&group_id, &sender).await?;

        let envelope = Envelope {
            id: envelope_id.clone(),
            group_id: group_id.clone(),
            sender,
            recipient,
            message_type,
            ciphertext: req.ciphertext.to_vec(),
            epoch: None,
            created_at,
            expires_at: None,
        };

        self.envelope_repo
            .save(&envelope)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        if let Err(e) = self
            .event_bus
            .publish(DomainEvent::EnvelopeReceived {
                envelope_id,
                group_id,
                at: chrono::Utc::now(),
            })
            .await
        {
            tracing::warn!(error = %e, "event_bus publish failed for forwarded envelope");
        }

        Ok(Response::new(ForwardEnvelopeResponse {
            status: ForwardStatus::Accepted as i32,
        }))
    }

    #[instrument(
        skip(self, request),
        fields(region = %self.local_region)
    )]
    async fn forward_commit(
        &self,
        request: Request<ForwardCommitRequest>,
    ) -> Result<Response<ForwardCommitResponse>, Status> {
        let (_metadata, request_exts, req) = request.into_parts();

        // RED-1: cap commit bytes before any downstream use of `req.commit`,
        // matching the REST ingress path's MAX_COMMIT_BYTES (see the module doc
        // comment) — same pre-decode caveat as forward_envelope's RED-1 comment.
        if req.commit.len() > MAX_COMMIT_BYTES {
            return Err(Status::invalid_argument("commit exceeds maximum size"));
        }

        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // The commit bytes are opaque — we do not decrypt them.
        let sender = parse_device_id(&req.sender_device_id)
            .ok_or_else(|| Status::invalid_argument("invalid sender_device_id UUID"))?;

        // RED-2: verify calling peer's mTLS cert matches the group's home_region.
        let group = self
            .group_repo
            .find_by_id(&group_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        if let Some(g) = &group {
            self.verify_peer_region(&request_exts, &g.home_region.to_string())?;
        }

        self.check_sender_is_member(&group_id, &sender).await?;

        // `group` was already fetched above for the RED-2 peer-region check
        // (GroupRepository has always been injected on this struct; the
        // previous "deferred until GroupRepository is injected" note was
        // stale). `check_sender_is_member` above already fails closed on
        // empty membership, so a `None` here — this region has no record of
        // the group at all — cannot occur via a real request; still handled
        // explicitly rather than assumed unreachable.
        let group = group.ok_or_else(|| {
            Status::failed_precondition("group is unknown to this region's GroupRepository")
        })?;

        // Home-region epoch serialisation (prd.md §6, "동시 commit 시 첫 번째만
        // 수락, 나머지는 거부"): `req.expected_epoch` is the peer's claim about
        // which epoch it built this Commit against. We do NOT adopt it as the
        // new epoch value (that always comes from the server's own `+ 1`),
        // but it MUST gate acceptance as a compare-and-swap precondition —
        // otherwise two concurrent commits (or a stale retry racing a fresher
        // commit) can both be accepted against the same starting epoch, which
        // RFC 9420 forbids (exactly one Commit is valid per epoch) and would
        // fork group state. `CommitLedger::commit_epoch_and_save` is the CAS
        // primitive for this; `GroupRepository::save`'s blind upsert must
        // never be used here.
        //
        // A CAS loss and an unmapped/expired FailedPrecondition are both
        // rejections, not empty-epoch successes: the client's gRPC layer
        // treats FailedPrecondition as non-retryable, so a lost race reports
        // failure once instead of the previous behaviour where a retried
        // call after a dropped response would advance the epoch again on
        // every attempt.
        //
        // The CAS and the Commit-envelope insert are ONE Postgres transaction
        // (prd.md §4A.5). Previously (cycle 438) they were two separate writes
        // and a failure between them durably consumed the epoch with no Commit
        // envelope to deliver, permanently wedging the group; a failed insert
        // now rolls the epoch back instead. `envelope.epoch` is left unset —
        // the ledger ignores it and stamps the epoch its own CAS just won.
        let envelope = Envelope::new(
            group_id.clone(),
            sender,
            None,
            MessageType::Commit,
            req.commit.to_vec(),
        );

        let new_epoch = self
            .commit_ledger
            .commit_epoch_and_save(&group_id, Epoch(req.expected_epoch), &envelope)
            .await
            .map_err(|e| domain_err_to_status(&e))?
            .ok_or_else(|| {
                domain_err_to_status(&DomainError::EpochMismatch {
                    expected: req.expected_epoch,
                    got: group.epoch.0,
                })
            })?;

        if let Err(e) = self
            .event_bus
            .publish(DomainEvent::EpochAdvanced {
                group_id: group_id.clone(),
                new_epoch,
                at: chrono::Utc::now(),
            })
            .await
        {
            tracing::warn!(error = %e, "event_bus publish failed for forwarded commit epoch");
        }

        Ok(Response::new(ForwardCommitResponse {
            status: ForwardStatus::Accepted as i32,
            accepted_epoch: new_epoch.0,
        }))
    }

    #[instrument(
        skip(self, request),
        fields(
            region = %self.local_region,
            // device UUIDs are pseudonymous but kept out of spans per no-plaintext-logging.md
        )
    )]
    async fn sync_group_membership(
        &self,
        request: Request<SyncGroupMembershipRequest>,
    ) -> Result<Response<SyncGroupMembershipResponse>, Status> {
        // Split the request once so we can both read extensions (for the peer-cert check)
        // and consume the inner body without cloning.
        let (_metadata, request_exts, req) = request.into_parts();
        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // Validate home_region shape before any cert work: non-empty, ≤64 bytes.
        if req.home_region.is_empty() || req.home_region.len() > MAX_REGION_ID_LEN {
            return Err(Status::invalid_argument(
                "home_region must be 1–64 characters",
            ));
        }

        // RED-2/RED-3 closure: verify the calling peer's mTLS Subject CN / DNS SAN matches
        // the claimed home_region. Only the authoritative home-region peer is allowed to
        // declare membership for a given group_id; without this, any peer inside the mTLS
        // perimeter could synthesise membership and pivot to ForwardEnvelope acceptance.
        self.verify_peer_region(&request_exts, &req.home_region)?;

        // RED-1: cap member count before any DB writes.
        if req.member_device_ids.len() > MAX_SYNC_MEMBERS {
            return Err(Status::invalid_argument(
                "member_device_ids exceeds maximum count",
            ));
        }

        // Validate, collect, and deduplicate device IDs before any DB writes (fail-fast).
        // Dedup prevents a peer from amplifying transaction cost by repeating the same UUID
        // up to MAX_SYNC_MEMBERS times (each would be a no-op INSERT but still costs I/O).
        let mut seen = std::collections::HashSet::with_capacity(req.member_device_ids.len());
        let mut device_ids: Vec<DeviceId> = Vec::with_capacity(req.member_device_ids.len());
        for did in &req.member_device_ids {
            let parsed = parse_device_id(did)
                .ok_or_else(|| Status::invalid_argument("invalid member_device_id UUID"))?;
            if seen.insert(parsed.as_uuid()) {
                device_ids.push(parsed);
            }
        }

        // Build the group stub and member list, then upsert atomically.
        // upsert_members uses ON CONFLICT DO NOTHING for both the group row and
        // each member row, so a remote peer cannot downgrade a locally-tracked epoch
        // and re-syncing an already-known group is idempotent. Y-15 CLOSED.
        let group_stub = Group {
            id: group_id.clone(),
            home_region: RegionId::new(req.home_region.clone()),
            epoch: Epoch(0),
            created_at: chrono::Utc::now(),
        };
        let members: Vec<GroupMember> = device_ids
            .into_iter()
            .map(|device_id| GroupMember {
                group_id: group_id.clone(),
                device_id,
                joined_at_epoch: Epoch(0),
            })
            .collect();
        let member_count = members.len();
        self.group_repo
            .upsert_members(&group_stub, &members)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        tracing::debug!(
            group_id = %group_id.as_uuid(),
            member_count,
            "sync_group_membership accepted"
        );

        Ok(Response::new(SyncGroupMembershipResponse {
            status: ForwardStatus::Accepted as i32,
        }))
    }

    #[instrument(
        skip(self, request),
        fields(region = %self.local_region)
    )]
    async fn consume_key_package(
        &self,
        request: Request<ConsumeKeyPackageRequest>,
    ) -> Result<Response<ConsumeKeyPackageResponse>, Status> {
        let req = request.into_inner();

        // Validate UUIDs — zero-knowledge: we never inspect KP content.
        let kp_id = Uuid::parse_str(&req.key_package_id)
            .map(KeyPackageId::from)
            .map_err(|_| Status::invalid_argument("invalid key_package_id UUID"))?;
        // Validate device_id and consuming_region for format — not used past validation.
        Uuid::parse_str(&req.device_id)
            .map_err(|_| Status::invalid_argument("invalid device_id UUID"))?;
        if req.consuming_region.is_empty() {
            return Err(Status::invalid_argument(
                "consuming_region must not be empty",
            ));
        }

        let result = self
            .key_package_repo
            .mark_consumed(&kp_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        let status = match result {
            ConsumeResult::Consumed => ConsumeStatus::Consumed,
            ConsumeResult::AlreadyConsumed => ConsumeStatus::AlreadyConsumed,
            ConsumeResult::NotFound => ConsumeStatus::NotFound,
        };

        Ok(Response::new(ConsumeKeyPackageResponse {
            status: status as i32,
        }))
    }

    /// Receive a peer region's abuse/block decision and apply it locally
    /// (prd.md §6.4 — "리전 간 abuse signal 동기화").
    ///
    /// This is the RECEIVING end of the mesh fan-out. It stores the block and
    /// deliberately does **not** re-broadcast: propagation is exactly one hop
    /// from the origin region, otherwise every peer would re-emit to every
    /// other peer and the mesh would loop forever.
    ///
    /// Trust model: the claimed `origin_region` is bound to the caller's mTLS
    /// peer certificate (same check `sync_group_membership` applies to
    /// `home_region`), so a peer inside the mTLS perimeter cannot forge a block
    /// attributed to a different region.
    ///
    /// Logging policy (no-plaintext-logging.md): only the origin region, the
    /// reason token, the subject *kind* and the TTL are logged. The IP digest
    /// and the user UUID are never logged, and a raw IP address never reaches
    /// this process at all — only its SHA-256 crosses the wire.
    #[instrument(
        skip(self, request),
        fields(region = %self.local_region)
    )]
    async fn propagate_abuse_signal(
        &self,
        request: Request<PropagateAbuseSignalRequest>,
    ) -> Result<Response<PropagateAbuseSignalResponse>, Status> {
        let (_metadata, request_exts, req) = request.into_parts();

        // Validate origin_region shape before any cert work (cheap fail-fast).
        // The mTLS peer-cert check below is the primary defence against a
        // forged origin_region in production, but this string still reaches
        // `tracing` fields on the dev/test fail-open path (tls_required=false,
        // see `verify_peer_region`) — reject control characters so that path
        // can never carry a log-injection payload (security-auditor finding,
        // cycle 433).
        if req.origin_region.is_empty()
            || req.origin_region.len() > MAX_REGION_ID_LEN
            || req.origin_region.bytes().any(|b| b.is_ascii_control())
        {
            return Err(Status::invalid_argument(
                "origin_region must be 1–64 printable characters",
            ));
        }

        // Bind the claimed origin to the mTLS peer identity: a peer may only
        // propagate signals it decided itself.
        self.verify_peer_region(&request_exts, &req.origin_region)?;

        // Defence in depth: no peer may claim to *be* this region. Under mTLS
        // the cert check above already makes this unreachable, but an explicit
        // check keeps the invariant true even in the dev/test fail-open path.
        if req.origin_region == self.local_region.as_str() {
            warn!("abuse signal rejected: peer claimed the local region as origin");
            return Err(Status::permission_denied(
                "origin_region must not be the local region",
            ));
        }

        // Bound call frequency per origin region (see ABUSE_SIGNAL_RATE_BURST doc
        // comment) — prevents an authenticated peer from flooding this region's
        // Redis with unbounded abuse-signal keys.
        if self
            .abuse_signal_limiter
            .check_key(&req.origin_region)
            .is_err()
        {
            warn!(
                origin_region = %req.origin_region,
                "abuse signal rejected: per-region rate limit exceeded"
            );
            return Err(Status::resource_exhausted(
                "PropagateAbuseSignal rate limit exceeded for this origin region",
            ));
        }

        let reason =
            match ProtoAbuseReason::try_from(req.reason).unwrap_or(ProtoAbuseReason::Unspecified) {
                ProtoAbuseReason::RateLimitExceeded => DomainAbuseReason::RateLimitExceeded,
                ProtoAbuseReason::KeyPackageFlood => DomainAbuseReason::KeyPackageFlood,
                ProtoAbuseReason::AuthBruteForce => DomainAbuseReason::AuthBruteForce,
                ProtoAbuseReason::Unspecified => {
                    return Err(Status::invalid_argument("reason unspecified"))
                }
            };

        // The subject is opaque by construction: either a fixed-length digest
        // or a UUID. A wrong-length digest is rejected rather than padded or
        // truncated, so a peer cannot smuggle arbitrary-length bytes into the
        // key space.
        let subject = match req.subject {
            Some(ProtoAbuseSubject::SubjectIpHash(bytes)) => {
                let hash: [u8; ABUSE_IP_HASH_LEN] = bytes.as_slice().try_into().map_err(|_| {
                    Status::invalid_argument("subject_ip_hash must be exactly 32 bytes")
                })?;
                AbuseSubject::IpHash(hash)
            }
            Some(ProtoAbuseSubject::SubjectUserId(id)) => {
                let uuid = Uuid::parse_str(&id)
                    .map_err(|_| Status::invalid_argument("invalid subject_user_id UUID"))?;
                AbuseSubject::User(UserId::from(uuid))
            }
            None => return Err(Status::invalid_argument("subject must be set")),
        };

        let expires_at = DateTime::from_timestamp_millis(req.expires_at_unix_ms)
            .ok_or_else(|| Status::invalid_argument("invalid expires_at_unix_ms"))?;
        let signal = AbuseSignal::new(
            subject,
            reason,
            RegionId::new(req.origin_region.clone()),
            expires_at,
        );

        let now = chrono::Utc::now();
        let Some(remaining) = signal.ttl_from(now) else {
            // Already expired on arrival (clock skew or a late delivery).
            // Nothing to store. REJECTED rather than an error: propagation is
            // fire-and-forget, and an error status here would be
            // indistinguishable from a genuine failure at the sender.
            tracing::debug!(
                origin_region = %signal.origin_region,
                "abuse signal ignored: already expired on arrival"
            );
            return Ok(Response::new(PropagateAbuseSignalResponse {
                status: ForwardStatus::Rejected as i32,
            }));
        };
        // Clamp the peer-controlled lifetime — see MAX_ABUSE_SIGNAL_TTL_SECS.
        let ttl = remaining.min(Duration::from_secs(MAX_ABUSE_SIGNAL_TTL_SECS));

        self.abuse_signal_store
            .block(
                &signal.subject,
                signal.reason,
                ttl,
                signal.origin_region.clone(),
            )
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        tracing::debug!(
            origin_region = %signal.origin_region,
            reason = signal.reason.as_str(),
            subject_kind = signal.subject.kind(),
            ttl_secs = ttl.as_secs(),
            "abuse signal accepted from peer region"
        );

        // No re-broadcast: see the doc comment above.
        Ok(Response::new(PropagateAbuseSignalResponse {
            status: ForwardStatus::Accepted as i32,
        }))
    }

    async fn health_check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let start = Instant::now();
        let caller_region = request.into_inner().region_id;
        if caller_region.is_empty() {
            warn!("health_check received empty region_id");
        }
        Ok(Response::new(HealthCheckResponse {
            status: HealthStatus::Healthy as i32,
            region_id: self.local_region.to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use chrono::{DateTime, Utc};
    use futures_core::Stream;
    use powehi_domain::{
        device::DeviceId,
        envelope::{Envelope, EnvelopeId},
        error::DomainError,
        event::DomainEvent,
        group::{Epoch, Group, GroupId, GroupMember},
        key_package::{ConsumeResult, KeyPackage, KeyPackageId},
    };
    use powehi_port_outbound::{
        abuse_signal::AbuseSignalStore, commit_ledger::CommitLedger,
        envelope_repo::EnvelopeRepository, event_bus::DomainEventBus, group_repo::GroupRepository,
        key_package_repo::KeyPackageRepository,
    };
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};

    struct NoopEnvelopeRepo;

    #[async_trait]
    impl EnvelopeRepository for NoopEnvelopeRepo {
        async fn save(&self, _envelope: &Envelope) -> Result<(), DomainError> {
            Ok(())
        }
        async fn find_pending(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
            _since_id: Option<EnvelopeId>,
        ) -> Result<Vec<Envelope>, DomainError> {
            Ok(vec![])
        }
        async fn find_by_id(&self, _id: &EnvelopeId) -> Result<Option<Envelope>, DomainError> {
            Ok(None)
        }
        async fn delete(&self, _id: &EnvelopeId) -> Result<(), DomainError> {
            Ok(())
        }
        async fn delete_expired(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
        async fn ack_broadcast(
            &self,
            _envelope_id: &EnvelopeId,
            _device_id: &DeviceId,
            _group_member_ids: &[DeviceId],
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    struct CaptureEnvelopeRepo {
        captured: std::sync::Mutex<Vec<Envelope>>,
    }

    impl CaptureEnvelopeRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                captured: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn last_created_at(&self) -> Option<DateTime<Utc>> {
            self.captured.lock().unwrap().last().map(|e| e.created_at)
        }
    }

    #[async_trait]
    impl EnvelopeRepository for CaptureEnvelopeRepo {
        async fn save(&self, envelope: &Envelope) -> Result<(), DomainError> {
            self.captured.lock().unwrap().push(envelope.clone());
            Ok(())
        }
        async fn find_pending(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
            _since_id: Option<EnvelopeId>,
        ) -> Result<Vec<Envelope>, DomainError> {
            Ok(vec![])
        }
        async fn find_by_id(&self, _id: &EnvelopeId) -> Result<Option<Envelope>, DomainError> {
            Ok(None)
        }
        async fn delete(&self, _id: &EnvelopeId) -> Result<(), DomainError> {
            Ok(())
        }
        async fn delete_expired(&self) -> Result<u64, DomainError> {
            Ok(0)
        }
        async fn ack_broadcast(
            &self,
            _envelope_id: &EnvelopeId,
            _device_id: &DeviceId,
            _group_member_ids: &[DeviceId],
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    struct NoopEventBus;

    #[async_trait]
    impl DomainEventBus for NoopEventBus {
        async fn publish(&self, _event: DomainEvent) -> Result<(), DomainError> {
            Ok(())
        }

        async fn subscribe(
            &self,
            _topic: &str,
        ) -> Result<Pin<Box<dyn Stream<Item = Result<DomainEvent, DomainError>> + Send>>, DomainError>
        {
            Err(DomainError::Internal("noop event bus".to_string()))
        }
    }

    struct FakeKpRepo {
        store: Mutex<HashMap<KeyPackageId, KeyPackage>>,
    }

    impl FakeKpRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }

        fn with_kp(kp: KeyPackage) -> Arc<Self> {
            let repo = Self::new();
            repo.store.lock().unwrap().insert(kp.id.clone(), kp);
            repo
        }
    }

    #[async_trait]
    impl KeyPackageRepository for FakeKpRepo {
        async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(kp.id.clone(), kp.clone());
            Ok(())
        }
        async fn fetch_one(
            &self,
            _device_id: &DeviceId,
        ) -> Result<Option<KeyPackage>, DomainError> {
            Ok(None)
        }
        async fn count_available(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            Ok(0)
        }
        async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            Ok(())
        }
        async fn mark_consumed(&self, id: &KeyPackageId) -> Result<ConsumeResult, DomainError> {
            let mut store = self.store.lock().unwrap();
            match store.get_mut(id) {
                Some(kp) if kp.consumed => Ok(ConsumeResult::AlreadyConsumed),
                Some(kp) => {
                    kp.consumed = true;
                    Ok(ConsumeResult::Consumed)
                }
                None => Ok(ConsumeResult::NotFound),
            }
        }
    }

    struct FakeGroupRepo {
        groups: Mutex<HashMap<GroupId, Group>>,
        members: Mutex<HashMap<GroupId, Vec<GroupMember>>>,
    }

    impl FakeGroupRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                groups: Mutex::new(HashMap::new()),
                members: Mutex::new(HashMap::new()),
            })
        }

        fn with_member(group_id: GroupId, device_id: DeviceId) -> Arc<Self> {
            let repo = Self::new();
            {
                let mut gs = repo.groups.lock().unwrap();
                gs.insert(
                    group_id.clone(),
                    Group {
                        id: group_id.clone(),
                        home_region: RegionId::new("eu-central-1"),
                        epoch: Epoch(0),
                        created_at: Utc::now(),
                    },
                );
            }
            {
                let mut ms = repo.members.lock().unwrap();
                ms.entry(group_id.clone()).or_default().push(GroupMember {
                    group_id,
                    device_id,
                    joined_at_epoch: Epoch(0),
                });
            }
            repo
        }
    }

    #[async_trait]
    impl GroupRepository for FakeGroupRepo {
        async fn save(&self, group: &Group) -> Result<(), DomainError> {
            self.groups
                .lock()
                .unwrap()
                .insert(group.id.clone(), group.clone());
            Ok(())
        }
        async fn advance_epoch(
            &self,
            group_id: &GroupId,
            expected: Epoch,
        ) -> Result<Option<Epoch>, DomainError> {
            let mut groups = self.groups.lock().unwrap();
            let Some(group) = groups.get_mut(group_id) else {
                return Ok(None);
            };
            if group.epoch != expected {
                return Ok(None);
            }
            group.epoch = Epoch(group.epoch.0 + 1);
            Ok(Some(group.epoch))
        }
        async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError> {
            // Mirrors ON CONFLICT (id) DO NOTHING: an existing row is left intact.
            let mut groups = self.groups.lock().unwrap();
            if groups.contains_key(&group.id) {
                return Ok(false);
            }
            groups.insert(group.id.clone(), group.clone());
            Ok(true)
        }
        async fn create_with_creator(
            &self,
            group: &Group,
            creator: &GroupMember,
        ) -> Result<bool, DomainError> {
            let mut groups = self.groups.lock().unwrap();
            if groups.contains_key(&group.id) {
                return Ok(false);
            }
            groups.insert(group.id.clone(), group.clone());
            self.members
                .lock()
                .unwrap()
                .entry(group.id.clone())
                .or_default()
                .push(GroupMember {
                    group_id: group.id.clone(),
                    device_id: creator.device_id.clone(),
                    joined_at_epoch: creator.joined_at_epoch,
                });
            Ok(true)
        }
        async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError> {
            Ok(self.groups.lock().unwrap().get(id).cloned())
        }
        async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError> {
            self.members
                .lock()
                .unwrap()
                .entry(member.group_id.clone())
                .or_default()
                .push(member.clone());
            Ok(())
        }
        async fn remove_member(
            &self,
            group_id: &GroupId,
            device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            if let Some(members) = self.members.lock().unwrap().get_mut(group_id) {
                members.retain(|m| &m.device_id != device_id);
            }
            Ok(())
        }
        async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .get(group_id)
                .cloned()
                .unwrap_or_default())
        }
        async fn list_groups_for_device(
            &self,
            device_id: &DeviceId,
        ) -> Result<Vec<GroupId>, DomainError> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .iter()
                .filter_map(|(gid, members)| {
                    if members.iter().any(|m| &m.device_id == device_id) {
                        Some(gid.clone())
                    } else {
                        None
                    }
                })
                .collect())
        }
        async fn upsert_members(
            &self,
            group: &Group,
            members: &[GroupMember],
        ) -> Result<(), DomainError> {
            // Mirror ON CONFLICT DO NOTHING for the group row: only insert if absent.
            if self.find_by_id(&group.id).await?.is_none() {
                self.save(group).await?;
            }
            for m in members {
                self.add_member(m).await?;
            }
            Ok(())
        }
    }

    /// In-memory [`CommitLedger`] fake that delegates to whichever
    /// `GroupRepository`/`EnvelopeRepository` fakes a test already wired up,
    /// so the ledger observes and mutates the same state the rest of the test
    /// asserts against.
    ///
    /// Deliberately NOT atomic: unit tests only need the accept/reject
    /// semantics of the CAS plus the epoch-stamping contract. Real
    /// all-or-nothing behaviour is a property of `PgCommitLedger`'s
    /// transaction and belongs to the Postgres integration suite.
    struct FakeCommitLedger {
        group_repo: Arc<dyn GroupRepository>,
        envelope_repo: Arc<dyn EnvelopeRepository>,
    }

    impl FakeCommitLedger {
        fn new(
            group_repo: Arc<dyn GroupRepository>,
            envelope_repo: Arc<dyn EnvelopeRepository>,
        ) -> Arc<Self> {
            Arc::new(Self {
                group_repo,
                envelope_repo,
            })
        }
    }

    #[async_trait]
    impl CommitLedger for FakeCommitLedger {
        async fn commit_epoch_and_save(
            &self,
            group_id: &GroupId,
            expected: Epoch,
            commit_envelope: &Envelope,
        ) -> Result<Option<Epoch>, DomainError> {
            let Some(new_epoch) = self.group_repo.advance_epoch(group_id, expected).await? else {
                return Ok(None);
            };
            // Mirror the real adapter's contract: the caller's `epoch` field is
            // ignored and the freshly-won epoch is stamped instead.
            let mut envelope = commit_envelope.clone();
            envelope.epoch = Some(new_epoch);
            self.envelope_repo.save(&envelope).await?;
            Ok(Some(new_epoch))
        }
    }

    /// [`CommitLedger`] that always fails without touching any state — stands
    /// in for the DB blip / pod kill that used to wedge a group (prd.md
    /// §4A.5). Because the real adapter runs the CAS and the envelope insert
    /// in one transaction, a failure means NEITHER happened.
    struct FailingCommitLedger;

    #[async_trait]
    impl CommitLedger for FailingCommitLedger {
        async fn commit_epoch_and_save(
            &self,
            _group_id: &GroupId,
            _expected: Epoch,
            _commit_envelope: &Envelope,
        ) -> Result<Option<Epoch>, DomainError> {
            Err(DomainError::Internal(
                "simulated commit ledger failure".into(),
            ))
        }
    }

    /// One recorded `block()` call: subject, reason, clamped TTL, attributed region.
    type RecordedBlock = (
        AbuseSubject,
        DomainAbuseReason,
        std::time::Duration,
        RegionId,
    );

    /// Records every `block()` call so tests can assert what the handler
    /// actually stored.
    struct FakeAbuseStore {
        blocks: Mutex<Vec<RecordedBlock>>,
    }

    impl FakeAbuseStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                blocks: Mutex::new(Vec::new()),
            })
        }

        fn calls(&self) -> Vec<RecordedBlock> {
            self.blocks.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AbuseSignalStore for FakeAbuseStore {
        async fn block(
            &self,
            subject: &AbuseSubject,
            reason: DomainAbuseReason,
            ttl: std::time::Duration,
            origin_region: RegionId,
        ) -> Result<(), DomainError> {
            self.blocks
                .lock()
                .unwrap()
                .push((subject.clone(), reason, ttl, origin_region));
            Ok(())
        }

        async fn is_blocked(&self, subject: &AbuseSubject) -> Result<bool, DomainError> {
            Ok(self
                .blocks
                .lock()
                .unwrap()
                .iter()
                .any(|(s, ..)| s == subject))
        }
    }

    /// Test-only constructor mirroring `RegionGrpcServer::new`, but deriving
    /// the `CommitLedger` from the same group/envelope fakes the caller
    /// passes, so every test site keeps its original argument list.
    #[allow(clippy::too_many_arguments)]
    fn make_server_full(
        local_region: RegionId,
        envelope_repo: Arc<dyn EnvelopeRepository>,
        event_bus: Arc<dyn DomainEventBus>,
        key_package_repo: Arc<dyn KeyPackageRepository>,
        group_repo: Arc<dyn GroupRepository>,
        abuse_signal_store: Arc<dyn AbuseSignalStore>,
        tls_required: bool,
    ) -> RegionGrpcServer {
        let commit_ledger = FakeCommitLedger::new(group_repo.clone(), envelope_repo.clone());
        RegionGrpcServer::new(
            local_region,
            envelope_repo,
            event_bus,
            key_package_repo,
            group_repo,
            commit_ledger,
            abuse_signal_store,
            tls_required,
        )
    }

    fn make_server() -> RegionGrpcServer {
        make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
            FakeAbuseStore::new(),
            false, // tls_required=false in unit tests (no TLS listener)
        )
    }

    fn make_server_with_kp(kp: KeyPackage) -> RegionGrpcServer {
        make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::with_kp(kp),
            FakeGroupRepo::new(),
            FakeAbuseStore::new(),
            false,
        )
    }

    fn make_server_with_group_member(group_id: GroupId, device_id: DeviceId) -> RegionGrpcServer {
        make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id, device_id),
            FakeAbuseStore::new(),
            false,
        )
    }

    #[tokio::test]
    async fn health_check_returns_healthy_with_local_region_id() {
        let server = make_server();
        let req = Request::new(HealthCheckRequest {
            region_id: "ap-seoul-1".to_string(),
        });
        let resp = server.health_check(req).await.unwrap();
        let body = resp.into_inner();
        assert_eq!(body.status, HealthStatus::Healthy as i32);
        assert_eq!(body.region_id, "eu-central-1");
    }

    #[tokio::test]
    async fn forward_envelope_invalid_group_id_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: "not-a-uuid".to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xde, 0xad, 0xbe, 0xef],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 0,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn forward_envelope_valid_request_returns_accepted() {
        // Sender must be a known member for the envelope to be accepted (fail-closed policy).
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            // ciphertext is opaque bytes — server never reads content
            ciphertext: vec![0xca, 0xfe, 0xba, 0xbe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    #[tokio::test]
    async fn forward_commit_advances_epoch_when_expected_epoch_matches() {
        // Sender must be a known member for the commit to be accepted (fail-closed policy).
        // `with_member` seeds the group at Epoch(0), so a matching expected_epoch of 0
        // yields an authoritative advance to 1 — the new value is server-derived
        // (`stored + 1`), never echoed back from the request.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let resp = server.forward_commit(req).await.unwrap();
        let body = resp.into_inner();
        assert_eq!(body.status, ForwardStatus::Accepted as i32);
        assert_eq!(
            body.accepted_epoch, 1,
            "server must derive the new epoch from stored group state (stored + 1)"
        );

        let updated = server
            .group_repo
            .find_by_id(&group_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            updated.epoch,
            Epoch(1),
            "GroupRepository must persist the advanced epoch"
        );
    }

    #[tokio::test]
    async fn forward_commit_rejects_stale_expected_epoch() {
        // A peer claiming to build against an epoch that no longer matches
        // stored state (already advanced, or simply wrong) must be rejected
        // with FailedPrecondition — never silently accepted at a fabricated
        // epoch. This is the CAS precondition (prd.md §6) that prevents two
        // concurrent commits from both landing against the same epoch.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 42,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::FailedPrecondition);

        let unchanged = server
            .group_repo
            .find_by_id(&group_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            unchanged.epoch,
            Epoch(0),
            "a rejected CAS must never advance the stored epoch"
        );
    }

    #[tokio::test]
    async fn forward_commit_persists_commit_envelope_stamped_with_the_accepted_epoch() {
        // The Commit envelope must actually be persisted (that is the half of
        // the unit of work whose failure used to wedge the group), and it must
        // carry the epoch the CAS actually won — not one the handler picked.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let env_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            env_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });

        let resp = server.forward_commit(req).await.unwrap().into_inner();
        assert_eq!(resp.accepted_epoch, 1);

        let captured = env_repo.captured.lock().unwrap();
        assert_eq!(captured.len(), 1, "exactly one Commit envelope persisted");
        assert_eq!(captured[0].message_type, MessageType::Commit);
        assert_eq!(
            captured[0].epoch,
            Some(Epoch(1)),
            "the persisted envelope must carry the epoch the CAS won"
        );
    }

    #[tokio::test]
    async fn forward_commit_ledger_failure_returns_error_and_does_not_advance_epoch() {
        // The wedge this closes (prd.md §4A.5): the epoch advance and the
        // Commit-envelope insert are one transaction, so a failure must leave
        // the stored epoch untouched and the group still committable — not
        // durably consume an epoch whose Commit envelope never existed.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let group_repo = FakeGroupRepo::with_member(group_id.clone(), sender.clone());
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            group_repo.clone(),
            Arc::new(FailingCommitLedger),
            FakeAbuseStore::new(),
            false,
        );
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });

        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::Internal);

        let unchanged = group_repo.find_by_id(&group_id).await.unwrap().unwrap();
        assert_eq!(
            unchanged.epoch,
            Epoch(0),
            "a failed commit must not consume the epoch — that was the wedge"
        );
    }

    #[tokio::test]
    async fn forward_commit_second_call_must_use_the_new_epoch() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        for expected in [0u64, 1u64] {
            let req = Request::new(ForwardCommitRequest {
                group_id: group_id.as_uuid().to_string(),
                sender_device_id: sender.as_uuid().to_string(),
                commit: vec![0x01, 0x02],
                expected_epoch: expected,
            });
            let resp = server.forward_commit(req).await.unwrap();
            assert_eq!(resp.into_inner().accepted_epoch, expected + 1);
        }
    }

    #[tokio::test]
    async fn forward_commit_retry_with_stale_epoch_after_success_is_rejected_not_double_applied() {
        // Simulates a client retrying a call whose response was lost after the
        // server already committed it: the retry reuses the *same*
        // expected_epoch as the original (successful) attempt. It must be
        // rejected, not re-accepted and re-advance the epoch a second time —
        // this is what makes ForwardCommit safe under the gRPC client's
        // automatic retry-on-transient-error behaviour.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let make_req = || {
            Request::new(ForwardCommitRequest {
                group_id: group_id.as_uuid().to_string(),
                sender_device_id: sender.as_uuid().to_string(),
                commit: vec![0x01, 0x02],
                expected_epoch: 0,
            })
        };
        let first = server.forward_commit(make_req()).await.unwrap();
        assert_eq!(first.into_inner().accepted_epoch, 1);

        let retry_err = server.forward_commit(make_req()).await.unwrap_err();
        assert_eq!(retry_err.code(), tonic::Code::FailedPrecondition);

        let final_state = server
            .group_repo
            .find_by_id(&group_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            final_state.epoch,
            Epoch(1),
            "a rejected retry must not advance the epoch a second time"
        );
    }

    #[tokio::test]
    async fn forward_commit_unknown_group_returns_permission_denied_and_no_group_write() {
        // `check_sender_is_member` fails closed (empty membership) before the
        // epoch-advance branch is reached — confirms the `group == None` path
        // in `forward_commit` is unreachable via a real request, but stays
        // defined and safe (FailedPrecondition, not a fabricated Accepted)
        // rather than panicking.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(GroupId::from(Uuid::new_v4()), sender.clone());
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(server
            .group_repo
            .find_by_id(&group_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn forward_envelope_unspecified_type_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0x01],
            envelope_type: 0, // UNSPECIFIED
            sent_at_unix_ms: 0,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── ConsumeKeyPackage integrity tests ─────────────────────────────────────

    #[tokio::test]
    async fn consume_key_package_unconsumed_returns_consumed() {
        let kp = KeyPackage::new(DeviceId::new(), vec![0xde, 0xad]);
        let kp_id = kp.id.clone();
        let device_id = kp.device_id.clone();
        let server = make_server_with_kp(kp);
        let req = Request::new(ConsumeKeyPackageRequest {
            device_id: device_id.as_uuid().to_string(),
            key_package_id: kp_id.as_uuid().to_string(),
            consuming_region: "ap-seoul-1".to_string(),
        });
        let resp = server.consume_key_package(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ConsumeStatus::Consumed as i32);
    }

    #[tokio::test]
    async fn consume_key_package_already_consumed_returns_already_consumed() {
        let mut kp = KeyPackage::new(DeviceId::new(), vec![0xca, 0xfe]);
        kp.consumed = true;
        let kp_id = kp.id.clone();
        let device_id = kp.device_id.clone();
        let server = make_server_with_kp(kp);
        let req = Request::new(ConsumeKeyPackageRequest {
            device_id: device_id.as_uuid().to_string(),
            key_package_id: kp_id.as_uuid().to_string(),
            consuming_region: "ap-seoul-1".to_string(),
        });
        let resp = server.consume_key_package(req).await.unwrap();
        assert_eq!(
            resp.into_inner().status,
            ConsumeStatus::AlreadyConsumed as i32
        );
    }

    #[tokio::test]
    async fn consume_key_package_unknown_id_returns_not_found() {
        let server = make_server();
        let req = Request::new(ConsumeKeyPackageRequest {
            device_id: Uuid::new_v4().to_string(),
            key_package_id: Uuid::new_v4().to_string(),
            consuming_region: "ap-seoul-1".to_string(),
        });
        let resp = server.consume_key_package(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ConsumeStatus::NotFound as i32);
    }

    #[tokio::test]
    async fn consume_key_package_invalid_uuid_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ConsumeKeyPackageRequest {
            device_id: Uuid::new_v4().to_string(),
            key_package_id: "not-a-uuid".to_string(),
            consuming_region: "ap-seoul-1".to_string(),
        });
        let err = server.consume_key_package(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn consume_key_package_empty_region_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ConsumeKeyPackageRequest {
            device_id: Uuid::new_v4().to_string(),
            key_package_id: Uuid::new_v4().to_string(),
            consuming_region: String::new(),
        });
        let err = server.consume_key_package(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── Data residency invariant tests (prd.md §4A.6) ─────────────────────────
    //
    // Principle: User PII (handle_hash, OPAQUE envelope, device keys) NEVER
    // crosses region boundaries. Only opaque UUIDs + ciphertext are forwarded.
    // These tests provide a compile-time + runtime proof that the wire format
    // for cross-region messages contains no PII fields.

    #[test]
    fn forward_envelope_request_contains_exactly_seven_opaque_fields() {
        // Exhaustive destructuring: if a PII field is added to ForwardEnvelopeRequest,
        // this test will FAIL TO COMPILE, catching the violation before merge.
        let req = ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe, 0xba, 0xbe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        };
        // Destructure ALL fields — Rust requires exhaustiveness;
        // a new field without a binding here causes a compile error.
        let ForwardEnvelopeRequest {
            envelope_id,
            group_id,
            sender_device_id,
            recipient_device_id,
            ciphertext,
            envelope_type,
            sent_at_unix_ms,
        } = req;

        // IDs must be valid UUIDs — they cannot be user-visible handles or emails.
        assert!(
            Uuid::parse_str(&envelope_id).is_ok(),
            "envelope_id must be UUID"
        );
        assert!(Uuid::parse_str(&group_id).is_ok(), "group_id must be UUID");
        assert!(
            Uuid::parse_str(&sender_device_id).is_ok(),
            "sender_device_id must be UUID"
        );
        // recipient may be empty for broadcast (non-unicast) envelopes
        assert!(
            recipient_device_id.is_empty() || Uuid::parse_str(&recipient_device_id).is_ok(),
            "recipient_device_id must be UUID or empty"
        );
        // ciphertext is opaque — present and non-zero length in a real envelope
        assert!(!ciphertext.is_empty(), "ciphertext must be non-empty");
        // envelope_type is a protocol enum, not linked to user identity
        assert!(envelope_type > 0, "envelope_type must be specified");
        // timestamp: milliseconds since epoch — no user identity information
        assert!(sent_at_unix_ms > 0, "sent_at_unix_ms must be non-zero");
    }

    #[test]
    fn forward_commit_request_contains_exactly_four_opaque_fields() {
        // Exhaustive destructuring for ForwardCommitRequest — same invariant.
        let req = ForwardCommitRequest {
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            commit: vec![0x01, 0x02, 0x03],
            expected_epoch: 7,
        };
        let ForwardCommitRequest {
            group_id,
            sender_device_id,
            commit,
            expected_epoch,
        } = req;

        assert!(Uuid::parse_str(&group_id).is_ok(), "group_id must be UUID");
        assert!(
            Uuid::parse_str(&sender_device_id).is_ok(),
            "sender_device_id must be UUID"
        );
        // commit bytes are opaque MLS ciphertext — never decrypted server-side
        assert!(!commit.is_empty(), "commit bytes must be non-empty");
        // expected_epoch is a counter, not a PII field
        assert_eq!(expected_epoch, 7);
    }

    #[test]
    fn sync_group_membership_member_ids_are_opaque_uuids() {
        // SyncGroupMembership: only group UUID + opaque device UUIDs cross the wire.
        // No handle_hash, no OPAQUE enrollment data, no device keys.
        let member_ids: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
        let req = SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: member_ids.clone(),
        };
        assert!(Uuid::parse_str(&req.group_id).is_ok());
        for id in &req.member_device_ids {
            assert!(
                Uuid::parse_str(id).is_ok(),
                "member_device_id must be opaque UUID, got: {id}"
            );
        }
    }

    // ── Sender-membership enforcement tests ───────────────────────────────────

    #[tokio::test]
    async fn forward_envelope_sender_is_known_member_returns_accepted() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    #[tokio::test]
    async fn forward_envelope_sender_not_member_returns_permission_denied() {
        let group_id = GroupId::from(Uuid::new_v4());
        let real_member = DeviceId::new();
        let impostor = DeviceId::new();
        // group has real_member but NOT impostor
        let server = make_server_with_group_member(group_id.clone(), real_member);
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: impostor.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0x01],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn forward_commit_sender_not_member_returns_permission_denied() {
        let group_id = GroupId::from(Uuid::new_v4());
        let real_member = DeviceId::new();
        let impostor = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), real_member);
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: impostor.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn forward_envelope_unknown_group_returns_permission_denied() {
        // Fail-closed: no membership data → reject (SyncGroupMembership must precede ForwardEnvelope)
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0x01],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn sync_group_membership_empty_home_region_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: String::new(),
            member_device_ids: vec![Uuid::new_v4().to_string()],
        });
        let err = server.sync_group_membership(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sync_group_membership_home_region_too_long_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "x".repeat(65), // > 64 chars
            member_device_ids: vec![Uuid::new_v4().to_string()],
        });
        let err = server.sync_group_membership(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sync_group_membership_invalid_member_device_id_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: vec!["not-a-uuid".to_string()],
        });
        let err = server.sync_group_membership(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sync_group_membership_home_region_exactly_64_chars_is_accepted() {
        let server = make_server();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "x".repeat(64), // boundary: exactly 64 chars must be accepted
            member_device_ids: vec![Uuid::new_v4().to_string()],
        });
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    #[tokio::test]
    async fn forward_commit_invalid_group_id_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardCommitRequest {
            group_id: "not-a-uuid".to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn forward_commit_invalid_sender_device_id_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardCommitRequest {
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: "not-a-uuid".to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sync_group_membership_persists_members() {
        let server = make_server();
        let group_id = Uuid::new_v4();
        let member_ids: Vec<String> = (0..2).map(|_| Uuid::new_v4().to_string()).collect();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: group_id.to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: member_ids.clone(),
        });
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);

        // Members are now stored; a forwarded envelope from member[0] must be accepted
        let sender_id = member_ids[0].clone();
        let fwd_req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            sender_device_id: sender_id,
            recipient_device_id: String::new(),
            ciphertext: vec![0xde, 0xad],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let fwd_resp = server.forward_envelope(fwd_req).await.unwrap();
        assert_eq!(fwd_resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    // ── PropagateAbuseSignal tests (prd.md §6.4) ─────────────────────────────

    const PEER_REGION: &str = "ap-seoul-1";

    fn make_server_with_abuse_store(
        store: Arc<FakeAbuseStore>,
        tls_required: bool,
    ) -> RegionGrpcServer {
        make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
            store,
            tls_required,
        )
    }

    fn abuse_req(subject: Option<ProtoAbuseSubject>) -> PropagateAbuseSignalRequest {
        PropagateAbuseSignalRequest {
            subject,
            reason: ProtoAbuseReason::RateLimitExceeded as i32,
            origin_region: PEER_REGION.to_string(),
            expires_at_unix_ms: (chrono::Utc::now() + chrono::Duration::seconds(300))
                .timestamp_millis(),
        }
    }

    fn ip_hash_subject() -> ProtoAbuseSubject {
        ProtoAbuseSubject::SubjectIpHash(vec![0xab; ABUSE_IP_HASH_LEN])
    }

    #[tokio::test]
    async fn propagate_abuse_signal_ip_hash_is_accepted_and_stored() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let resp = server
            .propagate_abuse_signal(Request::new(abuse_req(Some(ip_hash_subject()))))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);

        let calls = store.calls();
        assert_eq!(calls.len(), 1, "exactly one block must be recorded");
        let (subject, reason, ttl, origin) = &calls[0];
        assert_eq!(*subject, AbuseSubject::IpHash([0xab; ABUSE_IP_HASH_LEN]));
        assert_eq!(*reason, DomainAbuseReason::RateLimitExceeded);
        assert_eq!(*origin, RegionId::new(PEER_REGION));
        assert!(ttl.as_secs() > 0 && ttl.as_secs() <= 300);
    }

    #[tokio::test]
    async fn propagate_abuse_signal_user_id_is_accepted_and_stored() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let user_uuid = Uuid::new_v4();
        let mut req = abuse_req(Some(ProtoAbuseSubject::SubjectUserId(
            user_uuid.to_string(),
        )));
        req.reason = ProtoAbuseReason::AuthBruteForce as i32;

        let resp = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);

        let calls = store.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, AbuseSubject::User(UserId::from(user_uuid)));
        assert_eq!(calls[0].1, DomainAbuseReason::AuthBruteForce);
    }

    #[tokio::test]
    async fn propagate_abuse_signal_maps_key_package_flood_reason() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.reason = ProtoAbuseReason::KeyPackageFlood as i32;
        server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap();
        assert_eq!(store.calls()[0].1, DomainAbuseReason::KeyPackageFlood);
    }

    // ── Spoofing / authorization ─────────────────────────────────────────────

    /// A peer must not be able to attribute a block to this region: that would
    /// launder a remote decision as locally-made and defeat attribution.
    #[tokio::test]
    async fn propagate_abuse_signal_origin_equal_to_local_region_is_rejected() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.origin_region = "eu-central-1".to_string(); // == server's local region
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(store.calls().is_empty(), "nothing may be stored on reject");
    }

    /// With tls_required=true a request carrying no TlsConnectInfo cannot have
    /// its claimed origin_region bound to a peer certificate — fail closed.
    /// This is the spoofed-peer path: an unauthenticated caller claiming to be
    /// `ap-seoul-1` gets PermissionDenied and stores nothing.
    #[tokio::test]
    async fn propagate_abuse_signal_spoofed_origin_rejected_when_tls_required() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), true);
        let err = server
            .propagate_abuse_signal(Request::new(abuse_req(Some(ip_hash_subject()))))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "unverified peer must not be able to inject a mesh-wide block"
        );
        assert!(store.calls().is_empty(), "nothing may be stored on reject");
    }

    // ── Malformed input ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn propagate_abuse_signal_missing_subject_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let err = server
            .propagate_abuse_signal(Request::new(abuse_req(None)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn propagate_abuse_signal_wrong_hash_length_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        // Under-, over-, and zero-length digests are all rejected — never
        // padded or truncated into the key space.
        for len in [
            0usize,
            1,
            ABUSE_IP_HASH_LEN - 1,
            ABUSE_IP_HASH_LEN + 1,
            4096,
        ] {
            let req = abuse_req(Some(ProtoAbuseSubject::SubjectIpHash(vec![0x01; len])));
            let err = server
                .propagate_abuse_signal(Request::new(req))
                .await
                .unwrap_err();
            assert_eq!(
                err.code(),
                tonic::Code::InvalidArgument,
                "digest of {len} bytes must be rejected"
            );
        }
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn propagate_abuse_signal_invalid_user_uuid_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let req = abuse_req(Some(ProtoAbuseSubject::SubjectUserId(
            "not-a-uuid".to_string(),
        )));
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn propagate_abuse_signal_unspecified_reason_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.reason = 0; // UNSPECIFIED
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn propagate_abuse_signal_unknown_reason_value_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.reason = 9_999; // not a known enum value
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn propagate_abuse_signal_empty_origin_region_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.origin_region = String::new();
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn propagate_abuse_signal_oversized_origin_region_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.origin_region = "x".repeat(MAX_REGION_ID_LEN + 1);
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(store.calls().is_empty());
    }

    #[tokio::test]
    async fn propagate_abuse_signal_out_of_range_expiry_returns_invalid_argument() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.expires_at_unix_ms = i64::MIN; // not a representable timestamp
        let err = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── TTL bounds ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn propagate_abuse_signal_expired_on_arrival_is_rejected_without_storing() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.expires_at_unix_ms =
            (chrono::Utc::now() - chrono::Duration::seconds(60)).timestamp_millis();
        let resp = server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Rejected as i32);
        assert!(
            store.calls().is_empty(),
            "an already-expired signal must not create a block"
        );
    }

    /// A compromised peer must not be able to install a near-permanent block.
    #[tokio::test]
    async fn propagate_abuse_signal_clamps_absurd_ttl() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        let mut req = abuse_req(Some(ip_hash_subject()));
        req.expires_at_unix_ms =
            (chrono::Utc::now() + chrono::Duration::days(3650)).timestamp_millis();
        server
            .propagate_abuse_signal(Request::new(req))
            .await
            .unwrap();
        let ttl = store.calls()[0].2;
        assert_eq!(
            ttl.as_secs(),
            MAX_ABUSE_SIGNAL_TTL_SECS,
            "peer-supplied TTL must be clamped to the 24h ceiling"
        );
    }

    // ── No re-broadcast (mesh loop prevention) ───────────────────────────────

    /// The receiving side stores the block exactly once and has no outbound
    /// router at all — `RegionGrpcServer` holds no `RegionRouter` field, so
    /// re-broadcast is structurally impossible, not merely omitted. This test
    /// pins the runtime half of that: one inbound RPC produces exactly one
    /// local write and no further work.
    #[tokio::test]
    async fn propagate_abuse_signal_does_not_re_broadcast() {
        let store = FakeAbuseStore::new();
        let server = make_server_with_abuse_store(Arc::clone(&store), false);
        server
            .propagate_abuse_signal(Request::new(abuse_req(Some(ip_hash_subject()))))
            .await
            .unwrap();
        assert_eq!(
            store.calls().len(),
            1,
            "one inbound signal must produce exactly one local block"
        );
    }

    // ── Data residency invariant (prd.md §4A.6) ──────────────────────────────

    /// Exhaustive destructuring: if a PII field is ever added to
    /// PropagateAbuseSignalRequest this test fails to compile.
    #[test]
    fn propagate_abuse_signal_request_carries_only_opaque_fields() {
        let req = PropagateAbuseSignalRequest {
            subject: Some(ip_hash_subject()),
            reason: ProtoAbuseReason::RateLimitExceeded as i32,
            origin_region: PEER_REGION.to_string(),
            expires_at_unix_ms: 1_700_000_000_000,
        };
        let PropagateAbuseSignalRequest {
            subject,
            reason,
            origin_region,
            expires_at_unix_ms,
        } = req;

        match subject.expect("subject set") {
            // A raw IP never crosses the wire — only a fixed-length digest.
            ProtoAbuseSubject::SubjectIpHash(h) => assert_eq!(h.len(), ABUSE_IP_HASH_LEN),
            ProtoAbuseSubject::SubjectUserId(id) => {
                assert!(Uuid::parse_str(&id).is_ok(), "user id must be a UUID")
            }
        }
        assert!(reason > 0, "reason is a protocol enum, not user data");
        assert!(
            origin_region.len() <= MAX_REGION_ID_LEN,
            "region ID is an operator-assigned label"
        );
        assert!(
            expires_at_unix_ms > 0,
            "expiry is a timestamp, not identity"
        );
    }

    /// The 32-byte digest is the only IP-derived value on the wire: a request
    /// built from a real address must not contain the address in any form.
    #[test]
    fn propagate_abuse_signal_request_never_contains_a_raw_ip() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let AbuseSubject::IpHash(hash) = AbuseSubject::from_ip(&ip) else {
            panic!("from_ip must yield IpHash");
        };
        let req = PropagateAbuseSignalRequest {
            subject: Some(ProtoAbuseSubject::SubjectIpHash(hash.to_vec())),
            reason: ProtoAbuseReason::RateLimitExceeded as i32,
            origin_region: PEER_REGION.to_string(),
            expires_at_unix_ms: 1_700_000_000_000,
        };
        let encoded = {
            use prost::Message as _;
            req.encode_to_vec()
        };
        let octets = ip.to_string().into_bytes();
        assert!(
            !encoded
                .windows(octets.len())
                .any(|w| w == octets.as_slice()),
            "the dotted-quad address must never appear in the encoded request"
        );
        assert!(
            !encoded.windows(4).any(|w| w == [203u8, 0, 113, 7]),
            "the raw address octets must never appear in the encoded request"
        );
    }

    // ── peer_cert_matches_region unit tests ──────────────────────────────────
    //
    // Pre-generated with OpenSSL (P-256 ECDSA). These are self-signed test certs:
    //   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout /dev/null \
    //     -out cert.pem -days 3650 -nodes -subj "/CN=<cn>" [optional -addext]
    //
    // Cert 1: CN=eu-de-1, no SAN
    #[rustfmt::skip]
    const EU_DE_1_CN_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x79, 0x30, 0x82, 0x01, 0x1f, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x0b, 0x09, 0x48, 0xcf, 0xfa, 0xfc, 0xd8, 0x3a, 0xa3,
        0x90, 0x00, 0x3e, 0x77, 0x42, 0xbb, 0x12, 0xce, 0xfd, 0xc9, 0x99, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x07,
        0x65, 0x75, 0x2d, 0x64, 0x65, 0x2d, 0x31, 0x30, 0x1e, 0x17, 0x0d, 0x32,
        0x36, 0x30, 0x36, 0x30, 0x32, 0x31, 0x33, 0x35, 0x35, 0x32, 0x34, 0x5a,
        0x17, 0x0d, 0x33, 0x36, 0x30, 0x35, 0x33, 0x30, 0x31, 0x33, 0x35, 0x35,
        0x32, 0x34, 0x5a, 0x30, 0x12, 0x31, 0x10, 0x30, 0x0e, 0x06, 0x03, 0x55,
        0x04, 0x03, 0x0c, 0x07, 0x65, 0x75, 0x2d, 0x64, 0x65, 0x2d, 0x31, 0x30,
        0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
        0x00, 0x04, 0xa1, 0x89, 0x08, 0x62, 0x10, 0xda, 0x3e, 0x99, 0x33, 0xc3,
        0x19, 0x4d, 0x54, 0xb9, 0xfe, 0x73, 0x6e, 0xf5, 0x33, 0xaf, 0x2a, 0x6d,
        0x2b, 0x22, 0x0e, 0x7e, 0x4d, 0x87, 0xd6, 0x8d, 0xd6, 0x19, 0x0d, 0xde,
        0x76, 0x5b, 0xa5, 0xaa, 0x3f, 0xc2, 0xdd, 0x00, 0x39, 0x57, 0x97, 0xd4,
        0x50, 0xa1, 0x20, 0x1e, 0x21, 0xd8, 0xbf, 0xba, 0xa6, 0x68, 0x84, 0xf0,
        0x58, 0xa3, 0x62, 0x1f, 0xf6, 0x34, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d,
        0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xc1, 0x55, 0xd1,
        0x5c, 0x65, 0x97, 0x98, 0x73, 0x98, 0x49, 0x77, 0xc0, 0x3b, 0x5f, 0x1c,
        0xd3, 0x89, 0x33, 0xf1, 0x16, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23,
        0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0xc1, 0x55, 0xd1, 0x5c, 0x65, 0x97,
        0x98, 0x73, 0x98, 0x49, 0x77, 0xc0, 0x3b, 0x5f, 0x1c, 0xd3, 0x89, 0x33,
        0xf1, 0x16, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff,
        0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45,
        0x02, 0x20, 0x38, 0x93, 0x14, 0xff, 0x57, 0x80, 0x04, 0x0f, 0xb0, 0x61,
        0xe0, 0xc1, 0xf7, 0x7d, 0xbc, 0x9e, 0x6c, 0xbe, 0x94, 0xf2, 0xfb, 0xc9,
        0x8f, 0xd1, 0x2f, 0xb9, 0x6a, 0x1f, 0x6d, 0x8a, 0x05, 0x70, 0x02, 0x21,
        0x00, 0x9e, 0xaf, 0xbf, 0xa4, 0xca, 0x75, 0x89, 0x61, 0x89, 0x13, 0x21,
        0x76, 0x7d, 0x8f, 0x1c, 0xba, 0x3c, 0xb3, 0x2a, 0xca, 0x49, 0xc3, 0x7c,
        0xde, 0xce, 0x90, 0xd8, 0x4d, 0xc0, 0xca, 0x32, 0xc6,
    ];

    // Cert 2: CN=ap-sin-1, no SAN
    #[rustfmt::skip]
    const AP_SIN_1_CN_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x7b, 0x30, 0x82, 0x01, 0x21, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x21, 0x5c, 0x9d, 0x4c, 0xb5, 0x42, 0x37, 0x54, 0xc1,
        0xa8, 0x37, 0xa1, 0x11, 0xb3, 0x93, 0x2d, 0x9f, 0x93, 0x17, 0x59, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x08,
        0x61, 0x70, 0x2d, 0x73, 0x69, 0x6e, 0x2d, 0x31, 0x30, 0x1e, 0x17, 0x0d,
        0x32, 0x36, 0x30, 0x36, 0x30, 0x32, 0x31, 0x33, 0x35, 0x35, 0x33, 0x34,
        0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x35, 0x33, 0x30, 0x31, 0x33, 0x35,
        0x35, 0x33, 0x34, 0x5a, 0x30, 0x13, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x08, 0x61, 0x70, 0x2d, 0x73, 0x69, 0x6e, 0x2d,
        0x31, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d,
        0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
        0x03, 0x42, 0x00, 0x04, 0xbd, 0xb4, 0xdf, 0xe9, 0x98, 0xc2, 0x71, 0xf8,
        0x6c, 0xc3, 0x75, 0xa1, 0xd2, 0x32, 0xa9, 0xbe, 0xb7, 0xa0, 0x22, 0xa6,
        0x2b, 0xf7, 0x77, 0x8a, 0xfa, 0x3d, 0x71, 0x5e, 0x0f, 0xe3, 0xf4, 0xcb,
        0x81, 0x8d, 0x99, 0x7e, 0x64, 0xe1, 0xf9, 0x33, 0x95, 0xd6, 0x81, 0x2a,
        0x23, 0x53, 0x6b, 0xa1, 0x46, 0xed, 0x98, 0xad, 0x93, 0x67, 0x2e, 0xd8,
        0xae, 0x5a, 0x24, 0x35, 0xb1, 0x1e, 0x63, 0xb2, 0xa3, 0x53, 0x30, 0x51,
        0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x69,
        0x4d, 0xd9, 0xf8, 0x82, 0xdb, 0x55, 0x4c, 0xac, 0x68, 0xc8, 0x70, 0xb9,
        0x55, 0x5d, 0xda, 0x15, 0x9f, 0x9c, 0x6a, 0x30, 0x1f, 0x06, 0x03, 0x55,
        0x1d, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14, 0x69, 0x4d, 0xd9, 0xf8,
        0x82, 0xdb, 0x55, 0x4c, 0xac, 0x68, 0xc8, 0x70, 0xb9, 0x55, 0x5d, 0xda,
        0x15, 0x9f, 0x9c, 0x6a, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
        0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06,
        0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00,
        0x30, 0x45, 0x02, 0x20, 0x03, 0x4c, 0xce, 0x99, 0x87, 0xb5, 0x7d, 0x4b,
        0x0f, 0x7d, 0x8f, 0x17, 0x2e, 0x43, 0xeb, 0xaf, 0x43, 0xba, 0x32, 0x8a,
        0x2e, 0xc5, 0xda, 0x37, 0x41, 0x90, 0xfc, 0x1c, 0x29, 0x6d, 0x63, 0x49,
        0x02, 0x21, 0x00, 0x93, 0x90, 0x21, 0x15, 0x09, 0x5a, 0xdf, 0x3a, 0x71,
        0x70, 0xc1, 0x48, 0x9f, 0x4e, 0xa1, 0x3d, 0xe9, 0xd4, 0xb2, 0x58, 0x10,
        0xaf, 0x7d, 0x34, 0xb4, 0x23, 0x84, 0xe3, 0xcf, 0xbc, 0x36, 0x4f,
    ];

    // Cert 3: CN=some-other-cn, SAN DNS=eu-de-1
    #[rustfmt::skip]
    const EU_DE_1_SAN_DER: &[u8] = &[
        0x30, 0x82, 0x01, 0x66, 0x30, 0x82, 0x01, 0x0d, 0xa0, 0x03, 0x02, 0x01,
        0x02, 0x02, 0x14, 0x63, 0x67, 0xa6, 0x22, 0x85, 0xa2, 0xa6, 0x87, 0x82,
        0x04, 0x87, 0xf1, 0xae, 0x92, 0x66, 0xe1, 0xbc, 0x8a, 0xfb, 0x62, 0x30,
        0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
        0x18, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0d,
        0x73, 0x6f, 0x6d, 0x65, 0x2d, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2d, 0x63,
        0x6e, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x36, 0x30, 0x36, 0x30, 0x32, 0x31,
        0x33, 0x35, 0x35, 0x33, 0x34, 0x5a, 0x17, 0x0d, 0x33, 0x36, 0x30, 0x35,
        0x33, 0x30, 0x31, 0x33, 0x35, 0x35, 0x33, 0x34, 0x5a, 0x30, 0x18, 0x31,
        0x16, 0x30, 0x14, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0d, 0x73, 0x6f,
        0x6d, 0x65, 0x2d, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x2d, 0x63, 0x6e, 0x30,
        0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
        0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
        0x00, 0x04, 0xbc, 0x99, 0xaa, 0xa2, 0x5e, 0xd5, 0x56, 0xac, 0xcb, 0x51,
        0x65, 0xf8, 0xe4, 0xab, 0x32, 0x8d, 0x59, 0xe2, 0x88, 0xd3, 0x6c, 0xf1,
        0xe1, 0x89, 0x78, 0xbe, 0x75, 0x85, 0xbb, 0xb9, 0x13, 0x86, 0x73, 0x74,
        0xbd, 0x0d, 0x0b, 0xfa, 0x1b, 0xb6, 0x19, 0x69, 0xb8, 0x38, 0x68, 0x16,
        0xb3, 0x84, 0xb1, 0x72, 0x13, 0x57, 0x60, 0x15, 0x18, 0x00, 0x0c, 0x81,
        0x7f, 0x3f, 0x5b, 0xfa, 0x66, 0x4f, 0xa3, 0x35, 0x30, 0x33, 0x30, 0x12,
        0x06, 0x03, 0x55, 0x1d, 0x11, 0x04, 0x0b, 0x30, 0x09, 0x82, 0x07, 0x65,
        0x75, 0x2d, 0x64, 0x65, 0x2d, 0x31, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
        0x0e, 0x04, 0x16, 0x04, 0x14, 0x04, 0x8c, 0x4c, 0xfc, 0xab, 0xd0, 0x19,
        0x2d, 0x3a, 0x65, 0xa4, 0x0d, 0x85, 0x72, 0xc0, 0x01, 0xe1, 0xf2, 0x72,
        0x35, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
        0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x4e, 0xb6, 0xdd, 0xe0,
        0x5a, 0x71, 0xac, 0xba, 0x6b, 0x4f, 0xf3, 0x4b, 0x32, 0x31, 0x5b, 0x60,
        0x2b, 0x8a, 0x6c, 0x2e, 0x6e, 0xa0, 0x24, 0xfc, 0x1d, 0xfc, 0xda, 0x4e,
        0xe9, 0x29, 0x08, 0x31, 0x02, 0x20, 0x39, 0xa8, 0x45, 0x13, 0x37, 0x6d,
        0x22, 0x20, 0xde, 0xe2, 0x84, 0x54, 0x0b, 0x8a, 0x29, 0x97, 0x47, 0x71,
        0x3f, 0x85, 0x89, 0x14, 0xfe, 0x62, 0x62, 0x8a, 0x25, 0xc3, 0x27, 0xa0,
        0xf0, 0x95,
    ];

    #[test]
    fn peer_cert_matches_by_cn() {
        assert!(peer_cert_matches_region(EU_DE_1_CN_DER, "eu-de-1").unwrap());
    }

    #[test]
    fn peer_cert_matches_by_san_dns() {
        // Cert 3 has CN=some-other-cn but SAN DNS=eu-de-1
        assert!(peer_cert_matches_region(EU_DE_1_SAN_DER, "eu-de-1").unwrap());
    }

    #[test]
    fn peer_cert_mismatched_region_returns_false() {
        // Cert 2 has CN=ap-sin-1 — should NOT match eu-de-1
        assert!(!peer_cert_matches_region(AP_SIN_1_CN_DER, "eu-de-1").unwrap());
    }

    #[test]
    fn peer_cert_wrong_cn_no_matching_san_returns_false() {
        // Cert 3 has CN=some-other-cn, SAN=eu-de-1 — should NOT match ap-sin-1
        assert!(!peer_cert_matches_region(EU_DE_1_SAN_DER, "ap-sin-1").unwrap());
    }

    #[test]
    fn peer_cert_cn_matches_own_region_correctly() {
        // Cert 2 (CN=ap-sin-1) must match its own region
        assert!(peer_cert_matches_region(AP_SIN_1_CN_DER, "ap-sin-1").unwrap());
    }

    #[test]
    fn peer_cert_invalid_der_returns_err() {
        let result = peer_cert_matches_region(b"not-a-der-cert", "eu-de-1");
        assert!(result.is_err());
    }

    // ── tls_required startup-assertion tests ─────────────────────────────────
    //
    // Security invariant: when the composition root sets tls_required=true (because
    // POWEHI__GRPC_TLS_* env vars are configured), requests arriving without
    // TlsConnectInfo must be rejected with PermissionDenied. This catches the
    // misconfiguration where the gRPC listener starts without .tls_config(…) even
    // though TLS material was supplied — fail-closed rather than silently degrading
    // to plaintext and logging a warning.

    #[tokio::test]
    async fn sync_group_membership_without_tls_info_rejected_when_tls_required() {
        // Build a server with tls_required=true (production mode).
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
            FakeAbuseStore::new(),
            true, // tls_required — no TlsConnectInfo in extensions → must reject
        );
        // A plain Request::new() has no TlsConnectInfo in its extensions.
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: vec![Uuid::new_v4().to_string()],
        });
        let err = server.sync_group_membership(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "missing TlsConnectInfo must be rejected when tls_required=true"
        );
    }

    #[tokio::test]
    async fn sync_group_membership_without_tls_info_passes_when_tls_not_required() {
        // Build a server with tls_required=false (dev/test mode).
        let server = make_server(); // tls_required=false
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: vec![Uuid::new_v4().to_string()],
        });
        // No TlsConnectInfo in extensions but tls_required=false → warn + pass.
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    // ── RED-1 size-cap tests (DoS / memory-exhaustion closure) ────────────────

    #[tokio::test]
    async fn forward_envelope_oversized_ciphertext_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0u8; MAX_APPLICATION_CIPHERTEXT_BYTES + 1],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // Per-type cap dispatch (threat-model-checker cycle 353 fix): a Welcome must
    // NOT be rejected at the Application cap, since a real ratchet tree
    // legitimately exceeds it — proves forward_envelope picks the budget by
    // message_type rather than applying one generic ceiling to every type.
    #[tokio::test]
    async fn forward_envelope_welcome_between_application_and_welcome_cap_is_accepted() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: Uuid::new_v4().to_string(),
            ciphertext: vec![0u8; MAX_APPLICATION_CIPHERTEXT_BYTES + 1],
            envelope_type: EnvelopeType::Welcome as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    #[tokio::test]
    async fn forward_envelope_oversized_welcome_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            recipient_device_id: Uuid::new_v4().to_string(),
            ciphertext: vec![0u8; MAX_WELCOME_BYTES + 1],
            envelope_type: EnvelopeType::Welcome as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn forward_commit_oversized_commit_returns_invalid_argument() {
        let server = make_server();
        let req = Request::new(ForwardCommitRequest {
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            commit: vec![0u8; MAX_COMMIT_BYTES + 1],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn sync_group_membership_too_many_members_returns_invalid_argument() {
        let server = make_server();
        let member_ids: Vec<String> = (0..=MAX_SYNC_MEMBERS)
            .map(|_| Uuid::new_v4().to_string())
            .collect();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: Uuid::new_v4().to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: member_ids,
        });
        let err = server.sync_group_membership(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    // ── RED-2 peer-region enforcement on forward_* (tls_required=true path) ──

    #[tokio::test]
    async fn forward_envelope_no_tls_info_rejected_when_group_known_and_tls_required() {
        // When tls_required=true AND the group is already known locally, forward_envelope
        // must verify the peer's cert against home_region. A plain Request (no TlsConnectInfo)
        // must be rejected with PermissionDenied.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let group_repo = FakeGroupRepo::with_member(group_id.clone(), sender.clone());
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            group_repo,
            FakeAbuseStore::new(),
            true, // tls_required
        );
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let err = server.forward_envelope(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "missing TlsConnectInfo must be rejected when group is known and tls_required=true"
        );
    }

    #[tokio::test]
    async fn forward_commit_no_tls_info_rejected_when_group_known_and_tls_required() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let group_repo = FakeGroupRepo::with_member(group_id.clone(), sender.clone());
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            group_repo,
            FakeAbuseStore::new(),
            true, // tls_required
        );
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            expected_epoch: 0,
        });
        let err = server.forward_commit(req).await.unwrap_err();
        assert_eq!(
            err.code(),
            tonic::Code::PermissionDenied,
            "missing TlsConnectInfo must be rejected when group is known and tls_required=true"
        );
    }

    // ── Y-7: RFC 6125 case-insensitive CN/SAN matching ────────────────────────

    #[test]
    fn peer_cert_matches_region_case_insensitive_cn() {
        // eu-de-1 cert (CN=eu-de-1) must also match "EU-DE-1" per RFC 6125 §6.4.1.
        assert!(
            peer_cert_matches_region(EU_DE_1_CN_DER, "EU-DE-1").unwrap(),
            "CN comparison must be case-insensitive"
        );
    }

    #[test]
    fn peer_cert_matches_region_case_insensitive_san() {
        // eu-de-1 SAN cert (CN=some-other-cn, SAN DNS=eu-de-1) must match "EU-DE-1".
        assert!(
            peer_cert_matches_region(EU_DE_1_SAN_DER, "EU-DE-1").unwrap(),
            "SAN DNS comparison must be case-insensitive"
        );
    }

    #[test]
    fn peer_cert_does_not_match_different_region_regardless_of_case() {
        // ap-sin-1 cert (CN=ap-sin-1) must NOT match "EU-DE-1" in any case form.
        assert!(!peer_cert_matches_region(AP_SIN_1_CN_DER, "EU-DE-1").unwrap());
    }

    // ── Y-14: sent_at_unix_ms skew clamp tests ────────────────────────────────

    #[tokio::test]
    async fn forward_envelope_far_future_timestamp_clamped_to_now() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let capture_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let now = chrono::Utc::now();
        // 1 year in the future — well outside the ±5 minute skew window.
        let far_future_ms = (now + chrono::Duration::days(365)).timestamp_millis();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: far_future_ms,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
        // created_at must be clamped to near server-local time, not peer-supplied far-future.
        let stored_at = capture_repo.last_created_at().unwrap();
        let skew_secs = (stored_at - now).num_seconds().abs();
        assert!(
            skew_secs <= 5,
            "far-future timestamp must be clamped to near-now (skew={skew_secs}s)"
        );
    }

    #[tokio::test]
    async fn forward_envelope_far_past_timestamp_clamped_to_now() {
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let capture_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let now = chrono::Utc::now();
        // 2023-11-14 — well over 5 minutes in the past.
        let far_past_ms: i64 = 1_700_000_000_000;
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: far_past_ms,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
        // created_at must be clamped to near server-local time, not 2023.
        let stored_at = capture_repo.last_created_at().unwrap();
        let skew_secs = (stored_at - now).num_seconds().abs();
        assert!(
            skew_secs <= 5,
            "far-past timestamp must be clamped to near-now (skew={skew_secs}s)"
        );
    }

    #[tokio::test]
    async fn forward_envelope_recent_timestamp_preserved() {
        // A timestamp within the skew window must be accepted as-is (not clamped).
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let capture_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let now = chrono::Utc::now();
        // 30 seconds in the past — well within the ±5 minute window.
        let recent_ms = (now - chrono::Duration::seconds(30)).timestamp_millis();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: recent_ms,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
        // created_at should reflect the peer-supplied timestamp (within skew window).
        let stored_at = capture_repo.last_created_at().unwrap();
        let diff_ms = (stored_at.timestamp_millis() - recent_ms).unsigned_abs();
        assert!(
            diff_ms < 100,
            "timestamp within skew window must be stored as-is (diff={diff_ms}ms)"
        );
    }

    #[tokio::test]
    async fn forward_envelope_extreme_timestamp_i64_min_clamped_to_now() {
        // i64::MIN cannot be represented as a valid DateTime; from_timestamp_millis returns None.
        // The clamp must fall through to now without panicking.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let capture_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let now = chrono::Utc::now();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: i64::MIN,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
        let stored_at = capture_repo.last_created_at().unwrap();
        let skew_secs = (stored_at - now).num_seconds().abs();
        assert!(
            skew_secs <= 5,
            "i64::MIN timestamp must be clamped to near-now"
        );
    }

    #[tokio::test]
    async fn forward_envelope_extreme_timestamp_i64_max_clamped_to_now() {
        // i64::MAX in millis is beyond chrono's representable range; from_timestamp_millis
        // returns None → fall through to now. Must not panic.
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let capture_repo = CaptureEnvelopeRepo::new();
        let server = make_server_full(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
            FakeAbuseStore::new(),
            false,
        );
        let now = chrono::Utc::now();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            recipient_device_id: String::new(),
            ciphertext: vec![0xca, 0xfe],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: i64::MAX,
        });
        let resp = server.forward_envelope(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
        let stored_at = capture_repo.last_created_at().unwrap();
        let skew_secs = (stored_at - now).num_seconds().abs();
        assert!(
            skew_secs <= 5,
            "i64::MAX timestamp must be clamped to near-now"
        );
    }

    // ── Y-15: sync_group_membership uses upsert_members (atomic batch) ────────

    #[tokio::test]
    async fn sync_group_membership_all_members_persisted_atomically() {
        // Three members in one sync call — all must be stored and any subsequent
        // forward from any member must be accepted (verifies batch upsert path).
        let server = make_server();
        let group_id = Uuid::new_v4();
        let member_ids: Vec<String> = (0..3).map(|_| Uuid::new_v4().to_string()).collect();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: group_id.to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: member_ids.clone(),
        });
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);

        // Every member in the batch must be individually accepted by forward_envelope.
        for sender_id in &member_ids {
            let fwd_req = Request::new(ForwardEnvelopeRequest {
                envelope_id: Uuid::new_v4().to_string(),
                group_id: group_id.to_string(),
                sender_device_id: sender_id.clone(),
                recipient_device_id: String::new(),
                ciphertext: vec![0xab, 0xcd],
                envelope_type: EnvelopeType::Application as i32,
                sent_at_unix_ms: 1_700_000_000_000,
            });
            let fwd_resp = server.forward_envelope(fwd_req).await.unwrap();
            assert_eq!(
                fwd_resp.into_inner().status,
                ForwardStatus::Accepted as i32,
                "member {sender_id} must be accepted after batch upsert"
            );
        }
    }

    #[tokio::test]
    async fn sync_group_membership_zero_members_creates_group_stub() {
        // An empty member list is valid: creates only the group stub.
        let server = make_server();
        let group_id = Uuid::new_v4();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: group_id.to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: vec![],
        });
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);
    }

    #[tokio::test]
    async fn sync_group_membership_duplicate_device_ids_are_deduped() {
        // Peer sends the same UUID 3 times — only one membership row must result.
        // Verifies YELLOW-2 closure: dedup before INSERT prevents amplified no-op writes.
        let server = make_server();
        let group_id = Uuid::new_v4();
        let member_id = Uuid::new_v4().to_string();
        let req = Request::new(SyncGroupMembershipRequest {
            group_id: group_id.to_string(),
            home_region: "eu-de-1".to_string(),
            member_device_ids: vec![member_id.clone(), member_id.clone(), member_id.clone()],
        });
        let resp = server.sync_group_membership(req).await.unwrap();
        assert_eq!(resp.into_inner().status, ForwardStatus::Accepted as i32);

        // The deduplicated member must still be accepted by forward_envelope.
        let fwd_req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: group_id.to_string(),
            sender_device_id: member_id,
            recipient_device_id: String::new(),
            ciphertext: vec![0xef, 0x01],
            envelope_type: EnvelopeType::Application as i32,
            sent_at_unix_ms: 1_700_000_000_000,
        });
        let fwd_resp = server.forward_envelope(fwd_req).await.unwrap();
        assert_eq!(fwd_resp.into_inner().status, ForwardStatus::Accepted as i32);
    }
}
