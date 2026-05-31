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

pub struct RegionGrpcServer {
    pub local_region: RegionId,
    pub envelope_repo: Arc<dyn EnvelopeRepository>,
    pub event_bus: Arc<dyn DomainEventBus>,
    pub key_package_repo: Arc<dyn KeyPackageRepository>,
    pub group_repo: Arc<dyn GroupRepository>,
}

impl RegionGrpcServer {
    pub fn new(
        local_region: RegionId,
        envelope_repo: Arc<dyn EnvelopeRepository>,
        event_bus: Arc<dyn DomainEventBus>,
        key_package_repo: Arc<dyn KeyPackageRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            local_region,
            envelope_repo,
            event_bus,
            key_package_repo,
            group_repo,
        }
    }
}

impl RegionGrpcServer {
    /// Verify that `sender` is a known member of `group_id` in the local membership store.
    ///
    /// Fail-closed: if no membership data exists the envelope is rejected with PermissionDenied.
    /// The correct operational sequence is: peer region calls SyncGroupMembership before
    /// any ForwardEnvelope/ForwardCommit for a given group.
    ///
    /// Architectural deferral (RED-2/RED-3): tonic does not yet expose the mTLS peer certificate
    /// in a way this handler can read without changes to the TLS handshake plumbing. Once
    /// `tonic::transport::server::TlsConnectInfo` is wired through, we must additionally verify
    /// that the mTLS Subject/SAN of the calling peer matches `group.home_region` so that only
    /// the authoritative home-region peer can issue SyncGroupMembership for a given group_id.
    /// Until then, any peer in the mTLS perimeter can sync membership for any group_id.
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
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // Home-region epoch serialisation: store the commit envelope.
        // The commit bytes are opaque — we do not decrypt them.
        let sender = parse_device_id(&req.sender_device_id)
            .ok_or_else(|| Status::invalid_argument("invalid sender_device_id UUID"))?;

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
        let req = request.into_inner();
        let group_id = parse_group_id(&req.group_id)
            .ok_or_else(|| Status::invalid_argument("invalid group_id UUID"))?;

        // Validate home_region: non-empty, reasonable length, ASCII printable.
        // Architectural note (RED-2/RED-3): We also need to verify the calling peer's mTLS
        // cert matches this home_region claim — deferred until tonic TlsConnectInfo plumbing.
        if req.home_region.is_empty() || req.home_region.len() > 64 {
            return Err(Status::invalid_argument(
                "home_region must be 1–64 characters",
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
    }

    fn make_server() -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::new(),
        )
    }

    fn make_server_with_kp(kp: KeyPackage) -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::with_kp(kp),
            FakeGroupRepo::new(),
        )
    }

    fn make_server_with_group_member(group_id: GroupId, device_id: DeviceId) -> RegionGrpcServer {
        RegionGrpcServer::new(
            RegionId::new("eu-central-1"),
            Arc::new(NoopEnvelopeRepo),
            Arc::new(NoopEventBus),
            FakeKpRepo::new(),
            FakeGroupRepo::with_member(group_id, device_id),
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
}
