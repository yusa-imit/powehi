//! Contact invite link routes (prd.md §8.3).
//!
//! One-time invite codes allow authenticated devices to share a contact URL
//! out-of-band (QR code, link, etc.). The recipient redeems the code once
//! to discover the inviting device's ID, then fetches their KeyPackage to
//! create an MLS group.
//!
//! Routes:
//!   POST  /v1/invites         — create a 24-hour one-time invite code
//!   POST  /v1/invites/redeem  — redeem an invite code (one-time, authenticated)
//!
//! Design note (threat model §8.3): the invite code is sent in the request body,
//! not the URL path, so it never appears in access logs, WAF rule traces, or CDN
//! request logs. This preserves the fragment-scheme intent from §8.3.

use axum::{extract::State, http::StatusCode, Json};
use powehi_domain::error::DomainError;
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

#[derive(Serialize)]
pub struct CreateInviteResponse {
    pub code: String,
}

#[derive(Deserialize)]
pub struct RedeemInviteRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct RedeemInviteResponse {
    pub device_id: String,
}

/// `POST /v1/invites` — create a one-time 24-hour invite code.
pub async fn create(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
) -> Result<(StatusCode, Json<CreateInviteResponse>), ApiError> {
    let invite = state.invite.create_invite(&device_id).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateInviteResponse { code: invite.code }),
    ))
}

/// `POST /v1/invites/redeem` — redeem an invite code (one-time, authenticated).
///
/// The code is sent in the request body (not the URL path) to avoid it
/// appearing in access logs or WAF traces (threat model §8.3).
///
/// Returns the inviting device's opaque UUID so the caller can fetch their
/// KeyPackage via `GET /v1/key-packages/:device_id` and initiate an MLS Welcome.
pub async fn redeem(
    State(state): State<AppState>,
    AuthenticatedDevice(_caller): AuthenticatedDevice,
    Json(body): Json<RedeemInviteRequest>,
) -> Result<Json<RedeemInviteResponse>, ApiError> {
    let code = body.code;
    // Validate code format: 32 lowercase hex chars (UUID simple form). Any other
    // input cannot match a stored code, so return 404 immediately without a cache
    // lookup — prevents cache key injection via oversized inputs.
    // Restricted to lowercase [0-9a-f] to match Uuid::new_v4().simple() output exactly.
    if code.len() != 32
        || !code
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        return Err(ApiError::from(DomainError::NotFound(
            "invalid code format".into(),
        )));
    }
    let redeemed = state.invite.redeem_invite(&code).await?;
    Ok(Json(RedeemInviteResponse {
        device_id: redeemed.device_id.as_uuid().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use powehi_domain::{
        device::DeviceId,
        envelope::{Envelope, EnvelopeId},
        error::DomainError,
        group::{Epoch, GroupId},
        key_package::KeyPackageId,
        media::MediaId,
        push_subscription::PushSubscription,
        user::UserId,
    };
    use powehi_port_inbound::{
        auth::{
            AuthUseCase, DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest,
            LoginInitResponse, RegistrationFinishRequest, RegistrationFinishResponse,
            RegistrationInitRequest, RegistrationInitResponse, SessionToken,
        },
        invite::{CreatedInvite, InviteUseCase, RedeemedInvite},
        key_package::KeyPackageUseCase,
        media::MediaUseCase,
        messaging::MessagingUseCase,
    };
    use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "invite-test-token";

    fn test_device_id() -> DeviceId {
        DeviceId::from(uuid::Uuid::from_bytes([2u8; 16]))
    }

    fn invited_device_id() -> DeviceId {
        DeviceId::from(uuid::Uuid::from_bytes([3u8; 16]))
    }

    fn bearer_header() -> String {
        format!("Bearer {TEST_TOKEN}")
    }

    // ── Null implementations for use cases not under test ────────────────────

    struct NullUseCase;

    #[async_trait]
    impl AuthUseCase for NullUseCase {
        async fn register_init(
            &self,
            _: RegistrationInitRequest,
        ) -> Result<RegistrationInitResponse, DomainError> {
            unimplemented!()
        }
        async fn register_finish(
            &self,
            _: RegistrationFinishRequest,
        ) -> Result<RegistrationFinishResponse, DomainError> {
            unimplemented!()
        }
        async fn login_init(&self, _: LoginInitRequest) -> Result<LoginInitResponse, DomainError> {
            unimplemented!()
        }
        async fn login_finish(&self, _: LoginFinishRequest) -> Result<SessionToken, DomainError> {
            unimplemented!()
        }
        async fn register_device(
            &self,
            _: &UserId,
            _: DeviceRegistrationRequest,
        ) -> Result<DeviceId, DomainError> {
            unimplemented!()
        }
        async fn revoke_device(&self, _: &UserId, _: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn list_devices(
            &self,
            _: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl MessagingUseCase for NullUseCase {
        async fn send_message(
            &self,
            _: &DeviceId,
            _: &GroupId,
            _: Bytes,
            _: Option<u32>,
        ) -> Result<EnvelopeId, DomainError> {
            unimplemented!()
        }
        async fn send_welcome(
            &self,
            _: &DeviceId,
            _: &GroupId,
            _: Bytes,
            _: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn send_commit(
            &self,
            _: &DeviceId,
            _: &GroupId,
            _: Bytes,
        ) -> Result<Epoch, DomainError> {
            unimplemented!()
        }
        async fn poll_envelopes(
            &self,
            _: &DeviceId,
            _: Option<DateTime<Utc>>,
        ) -> Result<Vec<Envelope>, DomainError> {
            unimplemented!()
        }
        async fn ack_envelope(&self, _: &DeviceId, _: &EnvelopeId) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl KeyPackageUseCase for NullUseCase {
        async fn upload(
            &self,
            _: &DeviceId,
            _: Vec<Bytes>,
        ) -> Result<Vec<KeyPackageId>, DomainError> {
            unimplemented!()
        }
        async fn fetch_one(&self, _: &DeviceId) -> Result<Bytes, DomainError> {
            unimplemented!()
        }
        async fn count(&self, _: &DeviceId) -> Result<u64, DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl MediaUseCase for NullUseCase {
        async fn request_upload(
            &self,
            _: &DeviceId,
            _: &str,
            _: u64,
            _: Option<&GroupId>,
        ) -> Result<(MediaId, String), DomainError> {
            unimplemented!()
        }
        async fn confirm_upload(&self, _: &MediaId, _: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn get_download_url(&self, _: &MediaId, _: &DeviceId) -> Result<String, DomainError> {
            unimplemented!()
        }
        async fn delete(&self, _: &MediaId, _: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl powehi_port_inbound::group::GroupUseCase for NullUseCase {
        async fn create_group(&self, _: &DeviceId, _: GroupId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn add_member(
            &self,
            _: &DeviceId,
            _: &GroupId,
            _: &DeviceId,
            _: Epoch,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn remove_member(
            &self,
            _: &DeviceId,
            _: &GroupId,
            _: &DeviceId,
            _: Epoch,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl PushSubscriptionRepository for NullUseCase {
        async fn upsert(&self, _: &PushSubscription) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn fetch_by_device(
            &self,
            _: &DeviceId,
        ) -> Result<Option<PushSubscription>, DomainError> {
            unimplemented!()
        }
        async fn delete_by_device(&self, _: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    #[async_trait]
    impl powehi_port_outbound::device_repo::DeviceRepository for NullUseCase {
        async fn save(&self, _: &powehi_domain::device::Device) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn find_by_id(
            &self,
            _: &DeviceId,
        ) -> Result<Option<powehi_domain::device::Device>, DomainError> {
            unimplemented!()
        }
        async fn find_by_user(
            &self,
            _: &UserId,
        ) -> Result<Vec<powehi_domain::device::Device>, DomainError> {
            unimplemented!()
        }
        async fn delete(&self, _: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    // ── Invite-specific mocks ────────────────────────────────────────────────

    struct MockInviteSuccess;

    #[async_trait]
    impl InviteUseCase for MockInviteSuccess {
        async fn create_invite(&self, _: &DeviceId) -> Result<CreatedInvite, DomainError> {
            Ok(CreatedInvite {
                code: "aabbccdd00112233aabbccdd00112233".to_string(),
            })
        }

        async fn redeem_invite(&self, _: &str) -> Result<RedeemedInvite, DomainError> {
            Ok(RedeemedInvite {
                device_id: invited_device_id(),
            })
        }
    }

    struct MockInviteNotFound;

    #[async_trait]
    impl InviteUseCase for MockInviteNotFound {
        async fn create_invite(&self, _: &DeviceId) -> Result<CreatedInvite, DomainError> {
            Err(DomainError::Internal("not configured".into()))
        }

        async fn redeem_invite(&self, _: &str) -> Result<RedeemedInvite, DomainError> {
            Err(DomainError::NotFound("invite code not found".into()))
        }
    }

    // ── Session cache ────────────────────────────────────────────────────────

    fn session_cache() -> Arc<dyn powehi_port_outbound::cache::CachePort> {
        use powehi_port_outbound::cache::CachePort;
        use std::collections::HashMap;
        use std::time::Duration;

        struct FakeCache {
            store: Mutex<HashMap<String, Vec<u8>>>,
        }
        #[async_trait]
        impl CachePort for FakeCache {
            async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
                Ok(self.store.lock().unwrap().get(key).cloned())
            }
            async fn set(
                &self,
                key: &str,
                value: Vec<u8>,
                _: Option<Duration>,
            ) -> Result<(), DomainError> {
                self.store.lock().unwrap().insert(key.to_owned(), value);
                Ok(())
            }
            async fn delete(&self, key: &str) -> Result<(), DomainError> {
                self.store.lock().unwrap().remove(key);
                Ok(())
            }
            async fn exists(&self, key: &str) -> Result<bool, DomainError> {
                Ok(self.store.lock().unwrap().contains_key(key))
            }
        }
        let cache = Arc::new(FakeCache {
            store: Mutex::new(HashMap::new()),
        });
        let key = format!("session:{TEST_TOKEN}");
        cache
            .store
            .lock()
            .unwrap()
            .insert(key, test_device_id().as_uuid().as_bytes().to_vec());
        cache
    }

    // ── Router factory ───────────────────────────────────────────────────────

    fn make_router(invite: Arc<dyn InviteUseCase>) -> Router {
        let null: Arc<NullUseCase> = Arc::new(NullUseCase);
        let state = crate::AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: null.clone(),
            group: null.clone(),
            messaging: null.clone(),
            key_package: null.clone(),
            media: null.clone(),
            push_sub_repo: null.clone(),
            invite,
            device_repo: null.clone(),
            cache: session_cache(),
            handle_rate_limiter: Arc::new(crate::rate_limit::HandleRateLimiter::new()),
        };

        Router::new()
            .route("/v1/invites", post(crate::routes::invite::create))
            .route("/v1/invites/redeem", post(crate::routes::invite::redeem))
            .with_state(state)
    }

    fn redeem_body(code: &str) -> Body {
        Body::from(serde_json::json!({ "code": code }).to_string())
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_invite_without_token_returns_401() {
        let router = make_router(Arc::new(MockInviteSuccess));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invites")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_invite_returns_201_with_code() {
        let router = make_router(Arc::new(MockInviteSuccess));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invites")
                    .header("Authorization", bearer_header())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["code"].is_string());
        assert_eq!(json["code"].as_str().unwrap().len(), 32);
    }

    #[tokio::test]
    async fn redeem_invite_without_token_returns_401() {
        let router = make_router(Arc::new(MockInviteSuccess));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invites/redeem")
                    .header("content-type", "application/json")
                    .body(redeem_body("aabbccdd00112233aabbccdd00112233"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn redeem_invite_returns_200_with_device_id() {
        let router = make_router(Arc::new(MockInviteSuccess));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invites/redeem")
                    .header("Authorization", bearer_header())
                    .header("content-type", "application/json")
                    .body(redeem_body("aabbccdd00112233aabbccdd00112233"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let device_id_str = json["device_id"]
            .as_str()
            .expect("device_id must be a string");
        uuid::Uuid::parse_str(device_id_str).expect("device_id must be a valid UUID");
    }

    #[tokio::test]
    async fn redeem_invite_with_invalid_code_format_returns_404() {
        let router = make_router(Arc::new(MockInviteSuccess));
        for bad_code in &[
            "short",
            "!!invalid-chars!!",
            // UUID with hyphens (36 chars) must be rejected — only 32-char lowercase hex accepted
            "aabbccdd-0011-2233-aabb-ccdd00112233",
            // Uppercase hex rejected (Uuid::simple() always emits lowercase)
            "AABBCCDD00112233AABBCCDD00112233",
        ] {
            let resp = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/invites/redeem")
                        .header("Authorization", bearer_header())
                        .header("content-type", "application/json")
                        .body(redeem_body(bad_code))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "bad code '{bad_code}' must return 404"
            );
        }
    }

    #[tokio::test]
    async fn redeem_expired_or_wrong_code_returns_404() {
        let router = make_router(Arc::new(MockInviteNotFound));
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/invites/redeem")
                    .header("Authorization", bearer_header())
                    .header("content-type", "application/json")
                    .body(redeem_body("aabbccdd00112233aabbccdd00112233"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
