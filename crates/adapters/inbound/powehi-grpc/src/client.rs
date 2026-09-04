use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
    abuse::{AbuseReason, AbuseSignal, AbuseSubject},
    device::DeviceId,
    envelope::Envelope,
    error::DomainError,
    group::{Epoch, GroupId},
    region::RegionId,
    user::UserId,
};
use powehi_port_outbound::region_router::RegionRouter;
use tonic::transport::Channel;
use tracing::{debug, instrument, warn};

use powehi_proto::region::{
    propagate_abuse_signal_request::Subject as ProtoAbuseSubject,
    region_service_client::RegionServiceClient, AbuseReason as ProtoAbuseReason, EnvelopeType,
    ForwardCommitRequest, ForwardEnvelopeRequest, ForwardStatus, PropagateAbuseSignalRequest,
};

use crate::circuit::CircuitBreaker;
use crate::tls::TlsConfig;

const RETRY_MAX: u32 = 3;
const RETRY_BASE_MS: u64 = 100;
/// Retry budget for an abuse-signal broadcast.
///
/// Lower than `RETRY_MAX` on purpose: propagation is best-effort with eventual
/// consistency (prd.md §6.4), the origin region re-emits while the abuse
/// continues, and a full retry ladder per peer would turn a fire-and-forget
/// fan-out into a long-running call.
const ABUSE_BROADCAST_RETRY_MAX: u32 = 1;
const CIRCUIT_THRESHOLD: u32 = 5;
const CIRCUIT_OPEN_SECS: u64 = 30;

struct PeerState {
    client: RegionServiceClient<Channel>,
    circuit: CircuitBreaker,
}

/// gRPC client adapter implementing [`RegionRouter`].
///
/// Forwards envelopes and commits to peer regions via mTLS-secured gRPC.
/// Includes per-peer circuit breakers and exponential-backoff retry.
pub struct RegionGrpcRouter {
    local_region: RegionId,
    peers: HashMap<String, Arc<tokio::sync::Mutex<PeerState>>>,
}

impl RegionGrpcRouter {
    /// Build the router from a list of (region_id, endpoint_uri) pairs.
    ///
    /// Connects to all peers at construction time. Pass `tls = None` for
    /// plaintext (development only — never in production).
    pub async fn new(
        local_region: RegionId,
        peers: Vec<(RegionId, String)>,
        tls: Option<&TlsConfig>,
    ) -> anyhow::Result<Self> {
        let mut map = HashMap::new();
        for (region, endpoint) in peers {
            let channel = build_channel(&endpoint, tls).await?;
            let state = PeerState {
                client: RegionServiceClient::new(channel),
                circuit: CircuitBreaker::new(
                    CIRCUIT_THRESHOLD,
                    Duration::from_secs(CIRCUIT_OPEN_SECS),
                ),
            };
            map.insert(region.to_string(), Arc::new(tokio::sync::Mutex::new(state)));
        }
        Ok(Self {
            local_region,
            peers: map,
        })
    }

    fn get_peer(&self, region: &RegionId) -> Option<Arc<tokio::sync::Mutex<PeerState>>> {
        self.peers.get(region.as_str()).cloned()
    }
}

async fn build_channel(endpoint: &str, tls: Option<&TlsConfig>) -> anyhow::Result<Channel> {
    // Parse and validate the endpoint URI before connecting.
    let uri: http::Uri = endpoint
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid gRPC endpoint URI '{endpoint}': {e}"))?;
    let scheme = uri.scheme_str().unwrap_or("");

    if tls.is_some() {
        // Security: require https when mTLS is configured; reject http or unknown schemes.
        // An http:// peer would silently skip TLS and expose the mesh to MitM.
        anyhow::ensure!(
            scheme == "https",
            "gRPC endpoint must use https:// when mTLS is configured; got '{scheme}' in '{endpoint}'"
        );
    }

    let domain = uri
        .host()
        .ok_or_else(|| anyhow::anyhow!("gRPC endpoint '{endpoint}' has no host"))?;

    let mut builder = tonic::transport::Channel::from_shared(endpoint.to_string())?
        .connect_timeout(std::time::Duration::from_secs(5))
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)));

    if let Some(cfg) = tls {
        builder = builder.tls_config(cfg.client_tls(domain)?)?;
    }

    Ok(builder.connect().await?)
}

fn envelope_type_proto(envelope: &Envelope) -> i32 {
    match envelope.message_type {
        powehi_domain::envelope::MessageType::Application => EnvelopeType::Application as i32,
        powehi_domain::envelope::MessageType::Welcome => EnvelopeType::Welcome as i32,
        powehi_domain::envelope::MessageType::Commit => EnvelopeType::Commit as i32,
        powehi_domain::envelope::MessageType::Proposal => EnvelopeType::Proposal as i32,
    }
}

fn abuse_reason_proto(reason: AbuseReason) -> i32 {
    match reason {
        AbuseReason::RateLimitExceeded => ProtoAbuseReason::RateLimitExceeded as i32,
        AbuseReason::KeyPackageFlood => ProtoAbuseReason::KeyPackageFlood as i32,
        AbuseReason::AuthBruteForce => ProtoAbuseReason::AuthBruteForce as i32,
    }
}

fn abuse_subject_proto(subject: &AbuseSubject) -> ProtoAbuseSubject {
    match subject {
        // The digest is already opaque — a raw IP never reaches this adapter.
        AbuseSubject::IpHash(hash) => ProtoAbuseSubject::SubjectIpHash(hash.to_vec()),
        AbuseSubject::User(user_id) => {
            ProtoAbuseSubject::SubjectUserId(user_id.as_uuid().to_string())
        }
    }
}

/// Coarse, content-free label for a failed peer call.
///
/// Deliberately does NOT include the error's message: `GrpcError`'s Display
/// embeds peer-supplied status text, which must not reach our logs
/// (rule: no-plaintext-logging — error categories, not error messages).
fn broadcast_error_kind(e: &GrpcError) -> (&'static str, Option<tonic::Code>) {
    match e {
        GrpcError::Transport(_) => ("transport", None),
        GrpcError::Status(s) => ("rpc_status", Some(s.code())),
        GrpcError::CircuitOpen(_) => ("circuit_open", None),
        GrpcError::InvalidRequest(_) => ("invalid_request", None),
    }
}

#[async_trait]
impl RegionRouter for RegionGrpcRouter {
    async fn resolve_home_region(&self, _user_id: &UserId) -> Result<RegionId, DomainError> {
        // Region resolution requires DB lookup (UserRepository).
        // This is performed at the application service layer before calling forward_*.
        Err(DomainError::Internal(
            "resolve_home_region must be done via UserRepository before forwarding".to_string(),
        ))
    }

    async fn resolve_group_region(&self, _group_id: &GroupId) -> Result<RegionId, DomainError> {
        Err(DomainError::Internal(
            "resolve_group_region must be done via GroupRepository before forwarding".to_string(),
        ))
    }

    #[instrument(skip(self, envelope), fields(target = %target_region))]
    async fn forward_envelope(
        &self,
        target_region: &RegionId,
        envelope: &Envelope,
    ) -> Result<(), DomainError> {
        let peer = self
            .get_peer(target_region)
            .ok_or_else(|| DomainError::Internal(format!("no peer for region {target_region}")))?;

        let recipient_did = envelope
            .recipient
            .as_ref()
            .map(|d| d.to_string())
            .unwrap_or_default();

        let req_body = ForwardEnvelopeRequest {
            envelope_id: envelope.id.to_string(),
            group_id: envelope.group_id.to_string(),
            sender_device_id: envelope.sender.to_string(),
            recipient_device_id: recipient_did,
            // ciphertext is passed through opaquely — server MUST NOT decrypt
            ciphertext: envelope.ciphertext.clone(),
            envelope_type: envelope_type_proto(envelope),
            sent_at_unix_ms: envelope.created_at.timestamp_millis(),
        };

        with_retry(peer, RETRY_MAX, RETRY_BASE_MS, move |mut client| {
            let req = req_body.clone();
            Box::pin(async move {
                let resp = client
                    .forward_envelope(tonic::Request::new(req))
                    .await?
                    .into_inner();
                if resp.status == ForwardStatus::Accepted as i32 {
                    Ok(())
                } else {
                    Err(tonic::Status::failed_precondition("envelope not accepted"))
                }
            })
        })
        .await
        .map_err(DomainError::from)
    }

    #[instrument(skip(self, commit), fields(target = %target_region, group_id = %group_id))]
    async fn forward_commit(
        &self,
        target_region: &RegionId,
        group_id: &GroupId,
        sender_device_id: &DeviceId,
        commit: Bytes,
        expected_epoch: Epoch,
    ) -> Result<Epoch, DomainError> {
        let peer = self
            .get_peer(target_region)
            .ok_or_else(|| DomainError::Internal(format!("no peer for region {target_region}")))?;

        let group_str = group_id.to_string();
        let sender_str = sender_device_id.to_string();
        let commit_bytes = commit.clone();

        with_retry(peer, RETRY_MAX, RETRY_BASE_MS, move |mut client| {
            let gid = group_str.clone();
            let sid = sender_str.clone();
            let cb = commit_bytes.clone();
            Box::pin(async move {
                let resp = client
                    .forward_commit(tonic::Request::new(ForwardCommitRequest {
                        group_id: gid,
                        sender_device_id: sid,
                        commit: cb.to_vec(),
                        expected_epoch: expected_epoch.0,
                    }))
                    .await?
                    .into_inner();
                if resp.status == ForwardStatus::Accepted as i32 {
                    Ok(Epoch(resp.accepted_epoch))
                } else {
                    Err(tonic::Status::failed_precondition("commit not accepted"))
                }
            })
        })
        .await
        .map_err(DomainError::from)
    }

    /// Fan an abuse signal out to every peer region (prd.md §6.4).
    ///
    /// Best-effort by contract (see the port doc comment): this always returns
    /// `Ok(())`. The caller's local block has already been committed, and a
    /// remote region being down must never undo or fail it — prd.md §6.4
    /// specifies this path as asynchronous with 최종 일관성.
    ///
    /// Peers are contacted concurrently; peers whose circuit breaker is open
    /// are skipped outright rather than paying the retry ladder. Individual
    /// failures are logged with the peer region and a coarse error kind only —
    /// never a raw IP (one never reaches this adapter: `AbuseSubject::IpHash`
    /// is already a SHA-256 digest) and never peer-supplied status text.
    #[instrument(
        skip(self, signal),
        fields(
            origin_region = %signal.origin_region,
            reason = signal.reason.as_str(),
            subject_kind = signal.subject.kind(),
        )
    )]
    async fn broadcast_abuse_signal(&self, signal: &AbuseSignal) -> Result<(), DomainError> {
        let req_body = PropagateAbuseSignalRequest {
            subject: Some(abuse_subject_proto(&signal.subject)),
            reason: abuse_reason_proto(signal.reason),
            origin_region: signal.origin_region.to_string(),
            expires_at_unix_ms: signal.expires_at.timestamp_millis(),
        };

        let mut tasks = tokio::task::JoinSet::new();
        for (region, peer) in &self.peers {
            if peer.lock().await.circuit.is_open() {
                debug!(
                    peer_region = %region,
                    "skipping abuse signal broadcast: peer circuit open"
                );
                continue;
            }
            let peer = Arc::clone(peer);
            let region = region.clone();
            let body = req_body.clone();
            tasks.spawn(async move {
                let result = with_retry(
                    peer,
                    ABUSE_BROADCAST_RETRY_MAX,
                    RETRY_BASE_MS,
                    move |mut client| {
                        let req = body.clone();
                        Box::pin(async move {
                            let resp = client
                                .propagate_abuse_signal(tonic::Request::new(req))
                                .await?
                                .into_inner();
                            if resp.status == ForwardStatus::Accepted as i32 {
                                Ok(())
                            } else {
                                Err(tonic::Status::failed_precondition(
                                    "abuse signal not accepted",
                                ))
                            }
                        })
                    },
                )
                .await;
                (region, result)
            });
        }

        while let Some(joined) = tasks.join_next().await {
            match joined {
                Ok((_, Ok(()))) => {}
                Ok((region, Err(e))) => {
                    let (error_kind, code) = broadcast_error_kind(&e);
                    warn!(
                        peer_region = %region,
                        error_kind,
                        code = ?code,
                        "abuse signal propagation to peer failed (best-effort, ignored)"
                    );
                }
                Err(e) => {
                    // A broadcast task panicked or was cancelled. Never fail the
                    // caller for it; log the category only.
                    warn!(
                        error_kind = "join",
                        panicked = e.is_panic(),
                        "abuse signal broadcast task did not complete"
                    );
                }
            }
        }

        Ok(())
    }

    fn is_local(&self, region: &RegionId) -> bool {
        *region == self.local_region
    }
}

use crate::error::GrpcError;
use std::future::Future;
use std::pin::Pin;

/// Non-retryable gRPC codes are deterministic client errors: retrying cannot
/// succeed without the caller fixing the request. Retrying these burns quota
/// and can mask bugs (Y-2 advisory, cycle 140).
fn is_retryable(code: tonic::Code) -> bool {
    !matches!(
        code,
        tonic::Code::InvalidArgument
            | tonic::Code::NotFound
            | tonic::Code::AlreadyExists
            | tonic::Code::PermissionDenied
            | tonic::Code::Unauthenticated
            | tonic::Code::FailedPrecondition
            | tonic::Code::Unimplemented
            | tonic::Code::OutOfRange
    )
}

async fn with_retry<T, F, Fut>(
    peer: Arc<tokio::sync::Mutex<PeerState>>,
    max_retries: u32,
    base_delay_ms: u64,
    mut make_call: F,
) -> Result<T, GrpcError>
where
    F: FnMut(RegionServiceClient<Channel>) -> Pin<Box<Fut>>,
    Fut: Future<Output = Result<T, tonic::Status>>,
{
    {
        let state = peer.lock().await;
        if state.circuit.is_open() {
            return Err(GrpcError::CircuitOpen("peer".to_string()));
        }
    }

    let mut delay_ms = base_delay_ms;
    let mut last_err: Option<tonic::Status> = None;

    for _ in 0..=max_retries {
        let client = peer.lock().await.client.clone();
        match make_call(client).await {
            Ok(v) => {
                peer.lock().await.circuit.record_success();
                return Ok(v);
            }
            Err(e) => {
                if !is_retryable(e.code()) {
                    // Non-retryable: do not count as circuit failure — the
                    // peer is healthy but the request is malformed or rejected.
                    return Err(GrpcError::Status(e));
                }
                warn!(code = ?e.code(), "gRPC call failed, will retry");
                last_err = Some(e);
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    delay_ms *= 2;
                }
            }
        }
    }

    peer.lock().await.circuit.record_failure();
    Err(GrpcError::Status(last_err.expect(
        "loop runs max_retries+1 >= 1 times; only exits here via the retryable-error \
         branch, which always sets last_err before the next iteration or loop exit",
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_local_returns_true_for_own_region() {
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers: HashMap::new(),
        };
        assert!(router.is_local(&RegionId::new("eu-central-1")));
        assert!(!router.is_local(&RegionId::new("ap-seoul-1")));
    }

    #[tokio::test]
    async fn forward_envelope_returns_error_for_unknown_region() {
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers: HashMap::new(),
        };
        let envelope = Envelope::new(
            GroupId::new(),
            powehi_domain::device::DeviceId::new(),
            None,
            powehi_domain::envelope::MessageType::Application,
            vec![0xde, 0xad],
        );
        let result = router
            .forward_envelope(&RegionId::new("unknown"), &envelope)
            .await;
        assert!(matches!(result, Err(DomainError::Internal(_))));
    }

    #[tokio::test]
    async fn resolve_home_region_returns_internal_error() {
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers: HashMap::new(),
        };
        let result = router
            .resolve_home_region(&powehi_domain::user::UserId::new())
            .await;
        assert!(matches!(result, Err(DomainError::Internal(_))));
    }

    // ── Circuit breaker integration tests ─────────────────────────────────

    /// When the circuit is open, with_retry must fast-reject without invoking
    /// the RPC call at all.  This is the auto-failover fast-path: a downed
    /// peer trips the circuit after CIRCUIT_THRESHOLD failures; subsequent
    /// callers receive CircuitOpen immediately, enabling RTO <5 min (prd.md §4A.7).
    #[tokio::test]
    async fn with_retry_fast_rejects_when_circuit_open() {
        // Lazy channel: no real connection until first RPC — the circuit check
        // fires before any network call, so this test runs offline.
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let circuit = CircuitBreaker::new(1, Duration::from_secs(60));
        circuit.record_failure(); // threshold=1 → circuit opens immediately
        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));

        let result: Result<(), GrpcError> = with_retry(peer, 3, 0, |_client| {
            Box::pin(async { Ok::<(), tonic::Status>(()) })
        })
        .await;

        assert!(
            matches!(result, Err(GrpcError::CircuitOpen(_))),
            "expected CircuitOpen, got {result:?}"
        );
    }

    /// After all retries are exhausted, with_retry must record one failure on
    /// the circuit breaker.  This ensures repeated peer failures accumulate
    /// toward the open threshold — preventing the retry loop from masking a
    /// degraded peer indefinitely.
    #[tokio::test]
    async fn with_retry_trips_circuit_after_all_retries_fail() {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        // threshold=1: a single record_failure() call opens the circuit.
        let circuit = CircuitBreaker::new(1, Duration::from_secs(60));
        assert!(!circuit.is_open(), "circuit must start closed");

        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));
        let peer_ref = Arc::clone(&peer);

        // Force every attempt to fail with Unavailable.
        let result: Result<(), GrpcError> = with_retry(
            peer,
            2, // max_retries=2 → 3 total attempts (0..=2)
            0,
            |_client| {
                Box::pin(async {
                    Err::<(), tonic::Status>(tonic::Status::unavailable("forced failure"))
                })
            },
        )
        .await;

        assert!(
            result.is_err(),
            "expected error after all retries exhausted"
        );
        // After the retry loop, with_retry calls circuit.record_failure() once.
        // With threshold=1 that single call opens the circuit.
        assert!(
            peer_ref.lock().await.circuit.is_open(),
            "circuit must be open after all retries failed"
        );
    }

    // ── Y-1: forward_commit includes sender_device_id ─────────────────────

    /// forward_commit returns Internal for unknown regions regardless of
    /// sender_device_id — confirms the new parameter is accepted.
    #[tokio::test]
    async fn forward_commit_returns_error_for_unknown_region() {
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers: HashMap::new(),
        };
        let group_id = GroupId::new();
        let sender = DeviceId::new();
        let result = router
            .forward_commit(
                &RegionId::new("unknown"),
                &group_id,
                &sender,
                bytes::Bytes::from(vec![0xca, 0xfe]),
                Epoch(0),
            )
            .await;
        assert!(matches!(result, Err(DomainError::Internal(_))));
    }

    // ── Y-2: non-retryable codes must not be retried ──────────────────────

    /// INVALID_ARGUMENT must be returned immediately without retrying. A request
    /// that the server rejects as malformed will never succeed on retry; retrying
    /// would burn the retry budget and inflate latency (Y-2, cycle 140).
    #[tokio::test]
    async fn with_retry_does_not_retry_invalid_argument() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let circuit = CircuitBreaker::new(5, Duration::from_secs(60));
        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));
        let peer_ref = Arc::clone(&peer);
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&call_count);

        let result: Result<(), GrpcError> = with_retry(peer, 3, 0, move |_client| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err::<(), _>(tonic::Status::invalid_argument("bad request")) })
        })
        .await;

        assert!(result.is_err(), "expected error on InvalidArgument");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "InvalidArgument must not be retried"
        );
        assert!(
            !peer_ref.lock().await.circuit.is_open(),
            "circuit must stay closed — peer is healthy, request is malformed"
        );
    }

    /// PERMISSION_DENIED must be returned immediately without retrying.
    /// Authorization status is stable; retrying cannot change the outcome.
    #[tokio::test]
    async fn with_retry_does_not_retry_permission_denied() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let circuit = CircuitBreaker::new(5, Duration::from_secs(60));
        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&call_count);

        let result: Result<(), GrpcError> = with_retry(peer, 3, 0, move |_client| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err::<(), _>(tonic::Status::permission_denied("forbidden")) })
        })
        .await;

        assert!(result.is_err(), "expected error on PermissionDenied");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "PermissionDenied must not be retried"
        );
    }

    /// UNAUTHENTICATED must be returned immediately without retrying.
    #[tokio::test]
    async fn with_retry_does_not_retry_unauthenticated() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let circuit = CircuitBreaker::new(5, Duration::from_secs(60));
        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&call_count);

        let result: Result<(), GrpcError> = with_retry(peer, 3, 0, move |_client| {
            counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err::<(), _>(tonic::Status::unauthenticated("no token")) })
        })
        .await;

        assert!(result.is_err(), "expected error on Unauthenticated");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            1,
            "Unauthenticated must not be retried"
        );
    }

    /// UNAVAILABLE is retryable — circuit breaker should trip after all retries.
    /// Regression guard: ensure is_retryable still allows retry for transient errors.
    #[tokio::test]
    async fn with_retry_retries_unavailable() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let circuit = CircuitBreaker::new(10, Duration::from_secs(60));
        let peer = Arc::new(tokio::sync::Mutex::new(PeerState {
            client: RegionServiceClient::new(channel),
            circuit,
        }));
        let call_count = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&call_count);

        let result: Result<(), GrpcError> = with_retry(
            peer,
            2, // max_retries=2 → 3 total attempts
            0,
            move |_client| {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Err::<(), _>(tonic::Status::unavailable("transient")) })
            },
        )
        .await;

        assert!(result.is_err(), "expected error after retries exhausted");
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "Unavailable must be retried up to max_retries+1 times"
        );
    }

    // ── broadcast_abuse_signal (prd.md §6.4) ──────────────────────────────

    fn test_signal() -> AbuseSignal {
        use std::net::{IpAddr, Ipv4Addr};
        AbuseSignal::new(
            // TEST-NET-3 (RFC 5737) documentation address.
            AbuseSubject::from_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))),
            AbuseReason::RateLimitExceeded,
            RegionId::new("eu-central-1"),
            chrono::Utc::now() + chrono::Duration::seconds(300),
        )
    }

    fn router_with_peer(region: &str, circuit: CircuitBreaker) -> RegionGrpcRouter {
        // Lazy channel: no connection is made until an RPC is attempted, so
        // these tests run offline.
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let mut peers = HashMap::new();
        peers.insert(
            region.to_string(),
            Arc::new(tokio::sync::Mutex::new(PeerState {
                client: RegionServiceClient::new(channel),
                circuit,
            })),
        );
        RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers,
        }
    }

    /// With no peers configured the broadcast is a no-op that still succeeds.
    #[tokio::test]
    async fn broadcast_abuse_signal_with_no_peers_returns_ok() {
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers: HashMap::new(),
        };
        assert!(router.broadcast_abuse_signal(&test_signal()).await.is_ok());
    }

    /// Core contract: an unreachable peer must NOT fail the caller. The local
    /// block has already been committed; propagation is eventually consistent.
    #[tokio::test]
    async fn broadcast_abuse_signal_ignores_unreachable_peers() {
        let router = router_with_peer(
            "ap-seoul-1",
            CircuitBreaker::new(CIRCUIT_THRESHOLD, Duration::from_secs(CIRCUIT_OPEN_SECS)),
        );
        // 127.0.0.1:1 refuses the connection — every attempt fails.
        assert!(
            router.broadcast_abuse_signal(&test_signal()).await.is_ok(),
            "a dead peer must never fail the caller's local block"
        );
    }

    /// A peer whose circuit is open is skipped without any RPC attempt, and the
    /// broadcast still reports success.
    #[tokio::test]
    async fn broadcast_abuse_signal_skips_open_circuit_peers() {
        let circuit = CircuitBreaker::new(1, Duration::from_secs(60));
        circuit.record_failure(); // threshold=1 → opens immediately
        let router = router_with_peer("ap-seoul-1", circuit);

        let start = std::time::Instant::now();
        assert!(router.broadcast_abuse_signal(&test_signal()).await.is_ok());
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "an open-circuit peer must be skipped, not dialled"
        );
    }

    /// Multiple failing peers still yield Ok — fire-and-forget by design.
    #[tokio::test]
    async fn broadcast_abuse_signal_tolerates_all_peers_failing() {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        let mut peers = HashMap::new();
        for region in ["ap-seoul-1", "us-east-1", "eu-west-1"] {
            peers.insert(
                region.to_string(),
                Arc::new(tokio::sync::Mutex::new(PeerState {
                    client: RegionServiceClient::new(channel.clone()),
                    circuit: CircuitBreaker::new(
                        CIRCUIT_THRESHOLD,
                        Duration::from_secs(CIRCUIT_OPEN_SECS),
                    ),
                })),
            );
        }
        let router = RegionGrpcRouter {
            local_region: RegionId::new("eu-central-1"),
            peers,
        };
        assert!(router.broadcast_abuse_signal(&test_signal()).await.is_ok());
    }

    /// A user-subject signal broadcasts through the same path.
    #[tokio::test]
    async fn broadcast_abuse_signal_supports_user_subjects() {
        let router = router_with_peer(
            "ap-seoul-1",
            CircuitBreaker::new(CIRCUIT_THRESHOLD, Duration::from_secs(CIRCUIT_OPEN_SECS)),
        );
        let signal = AbuseSignal::new(
            AbuseSubject::User(UserId::new()),
            AbuseReason::AuthBruteForce,
            RegionId::new("eu-central-1"),
            chrono::Utc::now() + chrono::Duration::seconds(60),
        );
        assert!(router.broadcast_abuse_signal(&signal).await.is_ok());
    }

    // ── proto mapping ─────────────────────────────────────────────────────

    #[test]
    fn abuse_reason_proto_maps_every_variant_distinctly() {
        let mapped = [
            abuse_reason_proto(AbuseReason::RateLimitExceeded),
            abuse_reason_proto(AbuseReason::KeyPackageFlood),
            abuse_reason_proto(AbuseReason::AuthBruteForce),
        ];
        assert_eq!(mapped[0], ProtoAbuseReason::RateLimitExceeded as i32);
        assert_eq!(mapped[1], ProtoAbuseReason::KeyPackageFlood as i32);
        assert_eq!(mapped[2], ProtoAbuseReason::AuthBruteForce as i32);
        for m in mapped {
            assert_ne!(
                m,
                ProtoAbuseReason::Unspecified as i32,
                "no domain reason may map to UNSPECIFIED"
            );
        }
    }

    #[test]
    fn abuse_subject_proto_sends_only_the_digest_for_an_ip() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        match abuse_subject_proto(&AbuseSubject::from_ip(&ip)) {
            ProtoAbuseSubject::SubjectIpHash(hash) => {
                assert_eq!(hash.len(), 32, "digest must be exactly 32 bytes");
                // The raw octets must not survive into the wire value.
                assert!(!hash.windows(4).any(|w| w == [203u8, 0, 113, 7]));
            }
            ProtoAbuseSubject::SubjectUserId(_) => panic!("IP subject must map to a digest"),
        }
    }

    #[test]
    fn abuse_subject_proto_sends_the_uuid_for_a_user() {
        let user_id = UserId::new();
        match abuse_subject_proto(&AbuseSubject::User(user_id.clone())) {
            ProtoAbuseSubject::SubjectUserId(id) => {
                assert_eq!(id, user_id.as_uuid().to_string())
            }
            ProtoAbuseSubject::SubjectIpHash(_) => panic!("user subject must map to a UUID"),
        }
    }

    // ── error-kind labels must stay content-free ──────────────────────────

    /// `broadcast_error_kind` feeds a tracing field. It must emit a fixed label,
    /// never peer-supplied status text (rule: no-plaintext-logging).
    #[test]
    fn broadcast_error_kind_never_echoes_peer_message_text() {
        let secret = "SELECT credentials FROM users; --";
        let (kind, code) =
            broadcast_error_kind(&GrpcError::Status(tonic::Status::internal(secret)));
        assert_eq!(kind, "rpc_status");
        assert_eq!(code, Some(tonic::Code::Internal));
        assert!(!kind.contains("SELECT"));

        let (kind, code) = broadcast_error_kind(&GrpcError::CircuitOpen("ap-seoul-1".to_string()));
        assert_eq!(kind, "circuit_open");
        assert_eq!(code, None);

        let (kind, _) = broadcast_error_kind(&GrpcError::InvalidRequest(secret.to_string()));
        assert_eq!(kind, "invalid_request");
        assert!(!kind.contains("SELECT"));
    }

    // ── is_retryable unit tests ────────────────────────────────────────────

    #[test]
    fn is_retryable_returns_false_for_non_retryable_codes() {
        let non_retryable = [
            tonic::Code::InvalidArgument,
            tonic::Code::NotFound,
            tonic::Code::AlreadyExists,
            tonic::Code::PermissionDenied,
            tonic::Code::Unauthenticated,
            tonic::Code::FailedPrecondition,
            tonic::Code::Unimplemented,
            tonic::Code::OutOfRange,
        ];
        for code in non_retryable {
            assert!(!is_retryable(code), "{code:?} should not be retryable");
        }
    }

    #[test]
    fn is_retryable_returns_true_for_transient_codes() {
        let retryable = [
            tonic::Code::Unavailable,
            tonic::Code::Internal,
            tonic::Code::DeadlineExceeded,
            tonic::Code::ResourceExhausted,
        ];
        for code in retryable {
            assert!(is_retryable(code), "{code:?} should be retryable");
        }
    }
}
