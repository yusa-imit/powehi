use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use powehi_domain::{
    envelope::Envelope,
    error::DomainError,
    group::{Epoch, GroupId},
    region::RegionId,
    user::UserId,
};
use powehi_port_outbound::region_router::RegionRouter;
use tonic::transport::Channel;
use tracing::{instrument, warn};

use powehi_proto::region::{
    region_service_client::RegionServiceClient, EnvelopeType, ForwardCommitRequest,
    ForwardEnvelopeRequest, ForwardStatus,
};

use crate::circuit::CircuitBreaker;
use crate::tls::TlsConfig;

const RETRY_MAX: u32 = 3;
const RETRY_BASE_MS: u64 = 100;
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
        commit: Bytes,
    ) -> Result<Epoch, DomainError> {
        let peer = self
            .get_peer(target_region)
            .ok_or_else(|| DomainError::Internal(format!("no peer for region {target_region}")))?;

        let group_str = group_id.to_string();
        let commit_bytes = commit.clone();

        with_retry(peer, RETRY_MAX, RETRY_BASE_MS, move |mut client| {
            let gid = group_str.clone();
            let cb = commit_bytes.clone();
            Box::pin(async move {
                let resp = client
                    .forward_commit(tonic::Request::new(ForwardCommitRequest {
                        group_id: gid,
                        sender_device_id: String::new(),
                        commit: cb.to_vec(),
                        expected_epoch: 0,
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

    fn is_local(&self, region: &RegionId) -> bool {
        *region == self.local_region
    }
}

use crate::error::GrpcError;
use std::future::Future;
use std::pin::Pin;

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
    Err(GrpcError::Status(last_err.unwrap()))
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
}
