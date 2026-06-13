use std::sync::Arc;
use std::time::Instant;

use chrono::DateTime;
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId, MessageType},
    event::DomainEvent,
    group::{Epoch, Group, GroupId, GroupMember},
    key_package::{ConsumeResult, KeyPackageId},
    region::RegionId,
};
use powehi_port_outbound::{
    envelope_repo::EnvelopeRepository, event_bus::DomainEventBus, group_repo::GroupRepository,
    key_package_repo::KeyPackageRepository,
};
use tonic::{Request, Response, Status};
use tracing::{instrument, warn};
use uuid::Uuid;

use powehi_proto::region::{
    region_service_server::RegionService, ConsumeKeyPackageRequest, ConsumeKeyPackageResponse,
    ConsumeStatus, EnvelopeType, ForwardCommitRequest, ForwardCommitResponse,
    ForwardEnvelopeRequest, ForwardEnvelopeResponse, ForwardStatus, HealthCheckRequest,
    HealthCheckResponse, HealthStatus, SyncGroupMembershipRequest, SyncGroupMembershipResponse,
};

use crate::error::domain_err_to_status;

/// Maximum ciphertext / commit bytes accepted per gRPC call (RED-1 closure).
/// Prevents memory-exhaustion via oversized payloads from compromised peers.
/// MLS ApplicationMessage ciphertext is bounded by the plaintext budget plus
/// roughly 80 bytes of AEAD + MLS framing overhead — 1 MiB is a generous cap.
const MAX_CIPHERTEXT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum number of device members accepted per SyncGroupMembership call (RED-1 closure).
/// Prevents amplified DB writes from a malicious or misconfigured peer.
const MAX_SYNC_MEMBERS: usize = 10_000;

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
    /// When `true`, requests that arrive without `TlsConnectInfo` are rejected with
    /// PermissionDenied instead of being passed through with a warning. Set to
    /// `cfg.grpc_tls_enabled()` in the composition root so that any misconfiguration
    /// that causes the gRPC listener to start without TLS (despite TLS being configured)
    /// is caught at the RPC layer rather than silently degrading to plaintext.
    pub tls_required: bool,
}

impl RegionGrpcServer {
    pub fn new(
        local_region: RegionId,
        envelope_repo: Arc<dyn EnvelopeRepository>,
        event_bus: Arc<dyn DomainEventBus>,
        key_package_repo: Arc<dyn KeyPackageRepository>,
        group_repo: Arc<dyn GroupRepository>,
        tls_required: bool,
    ) -> Self {
        Self {
            local_region,
            envelope_repo,
            event_bus,
            key_package_repo,
            group_repo,
            tls_required,
        }
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

        // RED-1: cap ciphertext size before any allocation into owned Vec.
        if req.ciphertext.len() > MAX_CIPHERTEXT_BYTES {
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
        let message_type = proto_type_to_domain(req.envelope_type)
            .ok_or_else(|| Status::invalid_argument("envelope_type unspecified"))?;
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

        // RED-1: cap commit bytes before any allocation into owned Vec.
        if req.commit.len() > MAX_CIPHERTEXT_BYTES {
            return Err(Status::invalid_argument("commit exceeds maximum size"));
        }

        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // Home-region epoch serialisation: store the commit envelope.
        // The commit bytes are opaque — we do not decrypt them.
        let sender = parse_device_id(&req.sender_device_id)
            .ok_or_else(|| Status::invalid_argument("invalid sender_device_id UUID"))?;

        // RED-2: verify calling peer's mTLS cert matches the group's home_region.
        if let Some(group) = self
            .group_repo
            .find_by_id(&group_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?
        {
            self.verify_peer_region(&request_exts, &group.home_region.to_string())?;
        }

        self.check_sender_is_member(&group_id, &sender).await?;

        let envelope = Envelope::new(
            group_id.clone(),
            sender,
            None,
            MessageType::Commit,
            req.commit.to_vec(),
        );

        self.envelope_repo
            .save(&envelope)
            .await
            .map_err(|e| domain_err_to_status(&e))?;

        // Security: we do NOT trust req.expected_epoch from the peer for the
        // EpochAdvanced event. Epoch validation against the DB is deferred until
        // GroupRepository is injected (Phase 6 follow-up). The commit envelope is
        // stored for recipients to poll; no epoch event is published to avoid
        // injecting an attacker-controlled epoch value into the event bus.

        Ok(Response::new(ForwardCommitResponse {
            status: ForwardStatus::Accepted as i32,
            // accepted_epoch is left as 0 until GroupRepository validates the epoch.
            accepted_epoch: 0,
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
        if req.home_region.is_empty() || req.home_region.len() > 64 {
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

        // Validate and collect all device IDs before any DB writes (fail-fast)
        let mut device_ids: Vec<DeviceId> = Vec::with_capacity(req.member_device_ids.len());
        for did in &req.member_device_ids {
            device_ids.push(
                parse_device_id(did)
                    .ok_or_else(|| Status::invalid_argument("invalid member_device_id UUID"))?,
            );
        }

        // Ensure the group record exists before inserting members (FK constraint).
        // If the group is unknown locally, create a stub record with epoch 0.
        // We do NOT update epoch on conflict to avoid downgrading a locally-tracked epoch.
        if self
            .group_repo
            .find_by_id(&group_id)
            .await
            .map_err(|e| domain_err_to_status(&e))?
            .is_none()
        {
            let group = Group {
                id: group_id.clone(),
                home_region: RegionId::new(req.home_region.clone()),
                epoch: Epoch(0),
                created_at: chrono::Utc::now(),
            };
            self.group_repo
                .save(&group)
                .await
                .map_err(|e| domain_err_to_status(&e))?;
        }

        let member_count = device_ids.len();
        // Upsert members (add_member uses ON CONFLICT DO NOTHING)
        for device_id in device_ids {
            let member = GroupMember {
                group_id: group_id.clone(),
                device_id,
                joined_at_epoch: Epoch(0),
            };
            self.group_repo
                .add_member(&member)
                .await
                .map_err(|e| domain_err_to_status(&e))?;
        }

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
    }

    fn make_server() -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
            false, // tls_required=false in unit tests (no TLS listener)
        )
    }

    fn make_server_with_kp(kp: KeyPackage) -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::with_kp(kp),
            FakeGroupRepo::new(),
            false,
        )
    }

    fn make_server_with_group_member(group_id: GroupId, device_id: DeviceId) -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id, device_id),
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
    async fn forward_commit_returns_accepted_with_zero_epoch() {
        // Sender must be a known member for the commit to be accepted (fail-closed policy).
        let group_id = GroupId::from(Uuid::new_v4());
        let sender = DeviceId::new();
        let server = make_server_with_group_member(group_id.clone(), sender.clone());
        let req = Request::new(ForwardCommitRequest {
            group_id: group_id.as_uuid().to_string(),
            sender_device_id: sender.as_uuid().to_string(),
            commit: vec![0x01, 0x02],
            // expected_epoch from peer is NOT trusted — server returns 0 until GroupRepository validates
            expected_epoch: 42,
        });
        let resp = server.forward_commit(req).await.unwrap();
        let body = resp.into_inner();
        assert_eq!(body.status, ForwardStatus::Accepted as i32);
        assert_eq!(
            body.accepted_epoch, 0,
            "server must not echo back peer-supplied epoch"
        );
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
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
            ciphertext: vec![0u8; MAX_CIPHERTEXT_BYTES + 1],
            envelope_type: EnvelopeType::Application as i32,
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
            commit: vec![0u8; MAX_CIPHERTEXT_BYTES + 1],
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            group_repo,
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            group_repo,
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
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
        let server = RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            capture_repo.clone(),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id.clone(), sender.clone()),
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
}
