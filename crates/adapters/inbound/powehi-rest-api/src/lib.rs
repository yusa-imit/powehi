//! Axum REST API inbound adapter (Phase 3).
//!
//! Wires the inbound use-case ports (`AuthUseCase`, `MessagingUseCase`,
//! `KeyPackageUseCase`) to HTTP routes. The server never sees plaintext: every
//! payload is opaque E2EE material and is never logged or inspected here.
//!
//! Auth model (Phase 3 stub): protected routes use the `AuthenticatedDevice`
//! extractor, which reads a Bearer token that is currently a raw `DeviceId`.
//! Real Redis-backed session lookup is deferred (see `middleware`).

pub mod error;
pub mod middleware;
pub mod routes;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};
use powehi_port_inbound::{
    auth::AuthUseCase, key_package::KeyPackageUseCase, messaging::MessagingUseCase,
};
use tower_http::trace::TraceLayer;

/// Global body cap. MLS messages are bounded by RFC 9420 limits; OPAQUE blobs
/// are a few hundred bytes. 512 KB covers key-package batches (up to ~250 × 2 KB).
const MAX_BODY_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct AppState {
    pub auth: Arc<dyn AuthUseCase>,
    pub messaging: Arc<dyn MessagingUseCase>,
    pub key_package: Arc<dyn KeyPackageUseCase>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        // auth (public)
        .route("/v1/auth/register/init", post(routes::auth::register_init))
        .route(
            "/v1/auth/register/finish",
            post(routes::auth::register_finish),
        )
        .route("/v1/auth/login/init", post(routes::auth::login_init))
        .route("/v1/auth/login/finish", post(routes::auth::login_finish))
        // messaging (authenticated via AuthenticatedDevice extractor)
        .route(
            "/v1/messages",
            post(routes::messaging::send_message).get(routes::messaging::poll),
        )
        .route("/v1/messages/welcome", post(routes::messaging::send_welcome))
        .route("/v1/messages/commit", post(routes::messaging::send_commit))
        .route("/v1/messages/:id", delete(routes::messaging::ack))
        // key packages (authenticated)
        .route(
            "/v1/key-packages/:device_id",
            post(routes::key_package::upload).get(routes::key_package::fetch_one),
        )
        .route(
            "/v1/key-packages/:device_id/count",
            get(routes::key_package::count),
        )
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(TraceLayer::new_for_http())
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use powehi_domain::{
        device::DeviceId,
        envelope::{Envelope, EnvelopeId},
        error::DomainError,
        group::{Epoch, GroupId},
        key_package::KeyPackageId,
        user::UserId,
    };
    use powehi_port_inbound::auth::{
        DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest, LoginInitResponse,
        RegistrationFinishRequest, RegistrationInitRequest, RegistrationInitResponse, SessionToken,
    };
    use tower::ServiceExt; // for `oneshot`

    struct MockAuth;
    #[async_trait]
    impl AuthUseCase for MockAuth {
        async fn register_init(
            &self,
            _req: RegistrationInitRequest,
        ) -> Result<RegistrationInitResponse, DomainError> {
            unimplemented!()
        }
        async fn register_finish(
            &self,
            _req: RegistrationFinishRequest,
        ) -> Result<UserId, DomainError> {
            unimplemented!()
        }
        async fn login_init(
            &self,
            _req: LoginInitRequest,
        ) -> Result<LoginInitResponse, DomainError> {
            unimplemented!()
        }
        async fn login_finish(
            &self,
            _req: LoginFinishRequest,
        ) -> Result<SessionToken, DomainError> {
            unimplemented!()
        }
        async fn register_device(
            &self,
            _user_id: &UserId,
            _req: DeviceRegistrationRequest,
        ) -> Result<DeviceId, DomainError> {
            unimplemented!()
        }
        async fn revoke_device(
            &self,
            _user_id: &UserId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    struct MockMessaging;
    #[async_trait]
    impl MessagingUseCase for MockMessaging {
        async fn send_message(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _ciphertext: Bytes,
        ) -> Result<EnvelopeId, DomainError> {
            unimplemented!()
        }
        async fn send_welcome(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _welcome: Bytes,
            _target: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn send_commit(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _commit: Bytes,
        ) -> Result<Epoch, DomainError> {
            unimplemented!()
        }
        async fn poll_envelopes(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
        ) -> Result<Vec<Envelope>, DomainError> {
            unimplemented!()
        }
        async fn ack_envelope(
            &self,
            _device_id: &DeviceId,
            _envelope_id: &EnvelopeId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    struct MockKeyPackage;
    #[async_trait]
    impl KeyPackageUseCase for MockKeyPackage {
        async fn upload(
            &self,
            _device_id: &DeviceId,
            _packages: Vec<Bytes>,
        ) -> Result<Vec<KeyPackageId>, DomainError> {
            unimplemented!()
        }
        async fn fetch_one(&self, _target_device_id: &DeviceId) -> Result<Bytes, DomainError> {
            unimplemented!()
        }
        async fn count(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            unimplemented!()
        }
    }

    fn test_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
        })
    }

    #[tokio::test]
    async fn health_returns_200() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn messaging_without_token_returns_401() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn messaging_with_invalid_token_returns_401() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages")
                    .header("authorization", "Bearer not-a-uuid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn key_packages_without_token_returns_401() {
        // Auth-bypass guard for the key-package surface.
        let device = DeviceId::new();
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn oversized_body_returns_413() {
        // Verify the 512 KB cap is enforced before any handler runs.
        let oversized = vec![0u8; MAX_BODY_BYTES + 1];
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register/init")
                    .header("content-type", "application/json")
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
