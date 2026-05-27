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
pub mod rate_limit;
pub mod routes;

use std::sync::Arc;

use axum::{
    extract::DefaultBodyLimit,
    routing::{delete, get, post},
    Router,
};
use powehi_port_inbound::{
    auth::AuthUseCase, key_package::KeyPackageUseCase, media::MediaUseCase,
    messaging::MessagingUseCase,
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
    pub media: Arc<dyn MediaUseCase>,
}

pub fn router(state: AppState) -> Router {
    router_inner(
        state,
        rate_limit::auth_governor(),
        rate_limit::api_governor(),
    )
}

#[cfg(test)]
pub(crate) fn router_for_test(
    state: AppState,
    auth_layer: rate_limit::IpGovernorLayer,
    api_layer: rate_limit::IpGovernorLayer,
) -> Router {
    router_inner(state, auth_layer, api_layer)
}

fn router_inner(
    state: AppState,
    auth_layer: rate_limit::IpGovernorLayer,
    api_layer: rate_limit::IpGovernorLayer,
) -> Router {
    // Auth endpoints — public, strict per-IP rate limit.
    let auth_routes = Router::new()
        .route("/v1/auth/register/init", post(routes::auth::register_init))
        .route(
            "/v1/auth/register/finish",
            post(routes::auth::register_finish),
        )
        .route("/v1/auth/login/init", post(routes::auth::login_init))
        .route("/v1/auth/login/finish", post(routes::auth::login_finish))
        .layer(auth_layer);

    // Authenticated API endpoints — general per-IP rate limit.
    let api_routes = Router::new()
        .route(
            "/v1/messages",
            post(routes::messaging::send_message).get(routes::messaging::poll),
        )
        .route(
            "/v1/messages/welcome",
            post(routes::messaging::send_welcome),
        )
        .route("/v1/messages/commit", post(routes::messaging::send_commit))
        .route("/v1/messages/:id", delete(routes::messaging::ack))
        .route(
            "/v1/key-packages/:device_id",
            post(routes::key_package::upload).get(routes::key_package::fetch_one),
        )
        .route(
            "/v1/key-packages/:device_id/count",
            get(routes::key_package::count),
        )
        .route("/v1/media/upload-url", post(routes::media::request_upload))
        .route("/v1/media/:id/confirm", post(routes::media::confirm_upload))
        .route(
            "/v1/media/:id/download-url",
            get(routes::media::get_download_url),
        )
        .route("/v1/media/:id", delete(routes::media::delete_media))
        .layer(api_layer);

    Router::new()
        .route("/health", get(health))
        .merge(auth_routes)
        .merge(api_routes)
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
    use powehi_domain::media::MediaId;
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
    use powehi_port_inbound::media::MediaUseCase;
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

    struct MockMedia;
    #[async_trait]
    impl MediaUseCase for MockMedia {
        async fn request_upload(
            &self,
            _device: &DeviceId,
            _content_type: &str,
            _size_bytes: u64,
        ) -> Result<(MediaId, String), DomainError> {
            unimplemented!()
        }
        async fn confirm_upload(&self, _id: &MediaId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn get_download_url(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<String, DomainError> {
            unimplemented!()
        }
        async fn delete(&self, _id: &MediaId, _device: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
    }

    fn test_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
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

    // --- Success mocks for handler-level tests ---

    struct MockMessagingSuccess;
    #[async_trait]
    impl MessagingUseCase for MockMessagingSuccess {
        async fn send_message(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _ciphertext: Bytes,
        ) -> Result<EnvelopeId, DomainError> {
            Ok(EnvelopeId::new())
        }
        async fn send_welcome(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _welcome: Bytes,
            _target: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn send_commit(
            &self,
            _sender: &DeviceId,
            _group_id: &GroupId,
            _commit: Bytes,
        ) -> Result<Epoch, DomainError> {
            Ok(Epoch(42))
        }
        async fn poll_envelopes(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
        ) -> Result<Vec<Envelope>, DomainError> {
            Ok(vec![])
        }
        async fn ack_envelope(
            &self,
            _device_id: &DeviceId,
            _envelope_id: &EnvelopeId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
    }

    struct MockKeyPackageSuccess;
    #[async_trait]
    impl KeyPackageUseCase for MockKeyPackageSuccess {
        async fn upload(
            &self,
            _device_id: &DeviceId,
            packages: Vec<Bytes>,
        ) -> Result<Vec<KeyPackageId>, DomainError> {
            Ok(packages.iter().map(|_| KeyPackageId::new()).collect())
        }
        async fn fetch_one(&self, _target_device_id: &DeviceId) -> Result<Bytes, DomainError> {
            Ok(Bytes::from_static(b"kp_bytes"))
        }
        async fn count(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            Ok(3)
        }
    }

    struct MockKeyPackageNotFound;
    #[async_trait]
    impl KeyPackageUseCase for MockKeyPackageNotFound {
        async fn upload(
            &self,
            _device_id: &DeviceId,
            _packages: Vec<Bytes>,
        ) -> Result<Vec<KeyPackageId>, DomainError> {
            unimplemented!()
        }
        async fn fetch_one(&self, _target_device_id: &DeviceId) -> Result<Bytes, DomainError> {
            Err(DomainError::NotFound("no key package".into()))
        }
        async fn count(&self, _device_id: &DeviceId) -> Result<u64, DomainError> {
            unimplemented!()
        }
    }

    fn messaging_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessagingSuccess),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
        })
    }

    fn key_package_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackageSuccess),
            media: Arc::new(MockMedia),
        })
    }

    fn key_package_not_found_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackageNotFound),
            media: Arc::new(MockMedia),
        })
    }

    struct MockMediaSuccess;
    #[async_trait]
    impl MediaUseCase for MockMediaSuccess {
        async fn request_upload(
            &self,
            _device: &DeviceId,
            _content_type: &str,
            _size_bytes: u64,
        ) -> Result<(MediaId, String), DomainError> {
            Ok((MediaId::new(), "https://r2.example/presigned-put".into()))
        }
        async fn confirm_upload(&self, _id: &MediaId) -> Result<(), DomainError> {
            Ok(())
        }
        async fn get_download_url(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<String, DomainError> {
            Ok("https://r2.example/presigned-get".into())
        }
        async fn delete(&self, _id: &MediaId, _device: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    fn media_router() -> Router {
        router(AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMediaSuccess),
        })
    }

    fn bearer(device: &DeviceId) -> String {
        format!("Bearer {device}")
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    // --- Messaging handler tests ---

    #[tokio::test]
    async fn send_message_authenticated_returns_200() {
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "ciphertext": [1u8, 2, 3]
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", bearer(&device))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["envelope_id"].is_string());
    }

    #[tokio::test]
    async fn poll_authenticated_returns_empty_list() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages")
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn poll_with_since_param_returns_200() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages?since=1000000")
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ack_valid_envelope_returns_204() {
        let device = DeviceId::new();
        let envelope_id = EnvelopeId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/messages/{envelope_id}"))
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn ack_invalid_id_returns_400() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/messages/not-a-uuid")
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn send_welcome_returns_204() {
        let device = DeviceId::new();
        let target = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "welcome": [4u8, 5, 6],
            "target_device_id": target.to_string()
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/welcome")
                    .header("authorization", bearer(&device))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn send_commit_returns_epoch() {
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "commit": [7u8, 8, 9]
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/commit")
                    .header("authorization", bearer(&device))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["epoch"], 42u64);
    }

    // --- Key-package handler tests ---

    #[tokio::test]
    async fn upload_key_packages_returns_ids() {
        // caller == device_id: ownership check must pass.
        let caller = DeviceId::new();
        let body = serde_json::json!({ "packages": [[1u8, 2], [3u8, 4]] });
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/key-packages/{caller}"))
                    .header("authorization", bearer(&caller))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["ids"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn upload_key_packages_cross_device_returns_401() {
        // caller != device_id: MLS key substitution attempt → must be rejected.
        let caller = DeviceId::new();
        let other_device = DeviceId::new();
        let body = serde_json::json!({ "packages": [[1u8, 2]] });
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/key-packages/{other_device}"))
                    .header("authorization", bearer(&caller))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn fetch_one_key_package_returns_data() {
        let caller = DeviceId::new();
        let device = DeviceId::new();
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}"))
                    .header("authorization", bearer(&caller))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["data"].is_array());
    }

    #[tokio::test]
    async fn count_key_packages_returns_count() {
        let caller = DeviceId::new();
        let device = DeviceId::new();
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}/count"))
                    .header("authorization", bearer(&caller))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["count"], 3u64);
    }

    #[tokio::test]
    async fn fetch_one_not_found_returns_404() {
        let caller = DeviceId::new();
        let device = DeviceId::new();
        let resp = key_package_not_found_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}"))
                    .header("authorization", bearer(&caller))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // --- Media handler tests ---

    #[tokio::test]
    async fn request_upload_url_authenticated_returns_200_with_url() {
        let device = DeviceId::new();
        let body = serde_json::json!({
            "content_type": "image/jpeg",
            "size_bytes": 4096u64
        });
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/media/upload-url")
                    .header("authorization", bearer(&device))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert!(json["media_id"].is_string());
        assert_eq!(json["upload_url"], "https://r2.example/presigned-put");
    }

    #[tokio::test]
    async fn media_upload_url_without_token_returns_401() {
        let body = serde_json::json!({ "content_type": "image/jpeg", "size_bytes": 512u64 });
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/media/upload-url")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn confirm_upload_returns_204() {
        let device = DeviceId::new();
        let media_id = uuid::Uuid::new_v4();
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/media/{media_id}/confirm"))
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_download_url_returns_200_with_url() {
        let device = DeviceId::new();
        let media_id = uuid::Uuid::new_v4();
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/media/{media_id}/download-url"))
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["download_url"], "https://r2.example/presigned-get");
    }

    #[tokio::test]
    async fn delete_media_returns_204() {
        let device = DeviceId::new();
        let media_id = uuid::Uuid::new_v4();
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/media/{media_id}"))
                    .header("authorization", bearer(&device))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn media_endpoints_without_token_return_401() {
        let media_id = uuid::Uuid::new_v4();
        for (method, uri) in &[
            ("GET", format!("/v1/media/{media_id}/download-url")),
            ("POST", format!("/v1/media/{media_id}/confirm")),
            ("DELETE", format!("/v1/media/{media_id}")),
        ] {
            let resp = media_router()
                .oneshot(
                    Request::builder()
                        .method(*method)
                        .uri(uri)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {uri} without token should be 401"
            );
        }
    }

    // --- Rate-limit tests ---
    //
    // SmartIpKeyExtractor checks X-Forwarded-For first. Tests inject a fake IP
    // via that header so the key extractor has a stable key without a real TCP socket.

    fn minimal_state() -> AppState {
        AppState {
            auth: Arc::new(MockAuth),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
        }
    }

    fn auth_req_with_ip(ip: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/login/init")
            .header("x-forwarded-for", ip)
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    }

    fn api_req_with_ip(ip: &str) -> Request<Body> {
        // DELETE /v1/messages/not-a-uuid: goes through api_governor, auth extractor
        // validates the Bearer UUID, then the handler rejects "not-a-uuid" with 400
        // before ever calling the (unimplemented) mock use case.
        Request::builder()
            .method("DELETE")
            .uri("/v1/messages/not-a-uuid")
            .header("authorization", format!("Bearer {}", uuid::Uuid::new_v4()))
            .header("x-forwarded-for", ip)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn auth_rate_limit_blocks_on_second_request() {
        // burst=1 → first request passes, second is immediately rate-limited.
        let tight = rate_limit::tight_governor();
        let app = router_for_test(minimal_state(), tight.clone(), rate_limit::api_governor());

        let r1 = app
            .clone()
            .oneshot(auth_req_with_ip("10.0.0.1"))
            .await
            .unwrap();
        assert_ne!(
            r1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "first request should not be rate-limited"
        );

        let r2 = app
            .clone()
            .oneshot(auth_req_with_ip("10.0.0.1"))
            .await
            .unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second immediate request should be rate-limited"
        );
    }

    #[tokio::test]
    async fn api_rate_limit_blocks_on_second_request() {
        let tight = rate_limit::tight_governor();
        let app = router_for_test(minimal_state(), rate_limit::auth_governor(), tight);

        let r1 = app
            .clone()
            .oneshot(api_req_with_ip("10.0.0.2"))
            .await
            .unwrap();
        assert_ne!(r1.status(), StatusCode::TOO_MANY_REQUESTS);

        let r2 = app
            .clone()
            .oneshot(api_req_with_ip("10.0.0.2"))
            .await
            .unwrap();
        assert_eq!(r2.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn different_ips_are_rate_limited_independently() {
        let tight = rate_limit::tight_governor();
        let app = router_for_test(minimal_state(), tight, rate_limit::api_governor());

        // exhaust the 1-token bucket for IP A
        let _ = app
            .clone()
            .oneshot(auth_req_with_ip("10.1.0.1"))
            .await
            .unwrap();
        let r_a_limited = app
            .clone()
            .oneshot(auth_req_with_ip("10.1.0.1"))
            .await
            .unwrap();
        assert_eq!(r_a_limited.status(), StatusCode::TOO_MANY_REQUESTS);

        // IP B still has its own full bucket
        let r_b = app
            .clone()
            .oneshot(auth_req_with_ip("10.1.0.2"))
            .await
            .unwrap();
        assert_ne!(
            r_b.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "different IP must not be affected by sibling's rate limit"
        );
    }
}
