use std::sync::Arc;
use std::time::Instant;

use chrono::DateTime;
use powehi_domain::{
    envelope::{Envelope, EnvelopeId, MessageType},
    event::DomainEvent,
    group::GroupId,
    region::RegionId,
};
use powehi_port_outbound::{envelope_repo::EnvelopeRepository, event_bus::DomainEventBus};
use tonic::{Request, Response, Status};
use tracing::{instrument, warn};
use uuid::Uuid;

use powehi_proto::region::{
    region_service_server::RegionService, ConsumeKeyPackageRequest, ConsumeKeyPackageResponse,
    EnvelopeType, ForwardCommitRequest, ForwardCommitResponse, ForwardEnvelopeRequest,
    ForwardEnvelopeResponse, ForwardStatus, HealthCheckRequest, HealthCheckResponse, HealthStatus,
    SyncGroupMembershipRequest, SyncGroupMembershipResponse,
};

use crate::error::domain_err_to_status;

pub struct RegionGrpcServer {
    pub local_region: RegionId,
    pub envelope_repo: Arc<dyn EnvelopeRepository>,
    pub event_bus: Arc<dyn DomainEventBus>,
}

impl RegionGrpcServer {
    pub fn new(
        local_region: RegionId,
        envelope_repo: Arc<dyn EnvelopeRepository>,
        event_bus: Arc<dyn DomainEventBus>,
    ) -> Self {
        Self {
            local_region,
            envelope_repo,
            event_bus,
        }
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
        let req = request.into_inner();
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
        let created_at =
            DateTime::from_timestamp_millis(req.sent_at_unix_ms).unwrap_or_else(chrono::Utc::now);

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
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // Home-region epoch serialisation: store the commit envelope.
        // The commit bytes are opaque — we do not decrypt them.
        let sender = parse_device_id(&req.sender_device_id)
            .ok_or_else(|| Status::invalid_argument("invalid sender_device_id UUID"))?;
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

    async fn sync_group_membership(
        &self,
        request: Request<SyncGroupMembershipRequest>,
    ) -> Result<Response<SyncGroupMembershipResponse>, Status> {
        // Membership sync is stored via the group_repo; deferred to follow-up.
        // Validate UUIDs only to enforce the zero-knowledge invariant.
        let req = request.into_inner();
        parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;
        for did in &req.member_device_ids {
            parse_device_id(did)
                .ok_or_else(|| Status::invalid_argument("invalid member_device_id UUID"))?;
        }
        Ok(Response::new(SyncGroupMembershipResponse {
            status: ForwardStatus::Accepted as i32,
        }))
    }

    async fn consume_key_package(
        &self,
        _request: Request<ConsumeKeyPackageRequest>,
    ) -> Result<Response<ConsumeKeyPackageResponse>, Status> {
        // Cross-region KeyPackage consumption deferred until KeyPackageRepository
        // is injected (Phase 6 follow-up). Returning Unimplemented is safer than
        // a stub that silently returns Consumed — a caller must not act on a
        // false confirmation.
        Err(Status::unimplemented(
            "ConsumeKeyPackage not yet implemented",
        ))
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
    };
    use powehi_port_outbound::{envelope_repo::EnvelopeRepository, event_bus::DomainEventBus};
    use std::pin::Pin;
    use std::sync::Arc;

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

    fn make_server() -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
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
        let server = make_server();
        let req = Request::new(ForwardEnvelopeRequest {
            envelope_id: Uuid::new_v4().to_string(),
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
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
        let server = make_server();
        let req = Request::new(ForwardCommitRequest {
            group_id: Uuid::new_v4().to_string(),
            sender_device_id: Uuid::new_v4().to_string(),
            commit: vec![0x01, 0x02],
            // expected_epoch from peer is NOT trusted — server returns 0 until GroupRepository validates
            expected_epoch: 42,
        });
        let resp = server.forward_commit(req).await.unwrap();
        let body = resp.into_inner();
        assert_eq!(body.status, ForwardStatus::Accepted as i32);
        assert_eq!(body.accepted_epoch, 0, "server must not echo back peer-supplied epoch");
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
}
