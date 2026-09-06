//! Axum REST API inbound adapter (Phase 3).
//!
//! Wires the inbound use-case ports (`AuthUseCase`, `MessagingUseCase`,
//! `KeyPackageUseCase`) to HTTP routes. The server never sees plaintext: every
//! payload is opaque E2EE material and is never logged or inspected here.
//!
//! Auth model: protected routes use the `AuthenticatedDevice` extractor, which
//! validates `Authorization: Bearer <token>` against Redis-backed sessions. The
//! session maps `session:{token}` → DeviceId UUID bytes (16 bytes).

pub mod error;
pub mod http_metrics;
pub mod middleware;
pub mod rate_limit;
pub mod routes;
pub mod security_headers;

use std::sync::Arc;

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, FromRef},
    middleware::from_fn,
    response::Response,
    routing::{delete, get, post},
    Router,
};
use metrics_exporter_prometheus::PrometheusHandle;
use powehi_port_inbound::{
    auth::AuthUseCase, group::GroupUseCase, invite::InviteUseCase, key_package::KeyPackageUseCase,
    media::MediaUseCase, messaging::MessagingUseCase,
};
use powehi_port_outbound::{
    cache::CachePort, device_repo::DeviceRepository,
    push_subscription_repo::PushSubscriptionRepository,
};
use tower_http::trace::TraceLayer;

/// Global body cap. MLS messages are bounded by RFC 9420 limits; OPAQUE blobs
/// are a few hundred bytes. 512 KB covers key-package batches (up to ~250 × 2 KB).
const MAX_BODY_BYTES: usize = 512 * 1024;

#[derive(Clone)]
pub struct AppState {
    /// This server's region identifier (e.g. "eu-de-1", "ap-sin-1").
    /// Returned by `GET /v1/region/detect` so clients can confirm their routed region.
    pub region_id: String,
    /// This server's service tier (Tier1/Tier2/Tier3).
    /// Returned by `GET /v1/region/status` as a small integer (1/2/3) so clients
    /// can choose routing/replication behaviour without learning anything about
    /// users or content. Pure infrastructure metadata — no PII.
    pub region_tier: powehi_domain::region::Tier,
    pub auth: Arc<dyn AuthUseCase>,
    pub group: Arc<dyn GroupUseCase>,
    pub messaging: Arc<dyn MessagingUseCase>,
    pub key_package: Arc<dyn KeyPackageUseCase>,
    pub media: Arc<dyn MediaUseCase>,
    pub push_sub_repo: Arc<dyn PushSubscriptionRepository>,
    pub invite: Arc<dyn InviteUseCase>,
    /// Device store: used by device management handlers to resolve DeviceId → UserId.
    pub device_repo: Arc<dyn DeviceRepository>,
    /// Session store: `session:{token}` → DeviceId UUID bytes. Used by the
    /// `AuthenticatedDevice` extractor to validate Bearer tokens.
    pub cache: Arc<dyn CachePort>,
    /// Per-handle-hash rate limiter — credential-stuffing guard complementing the per-IP limit.
    pub handle_rate_limiter: Arc<rate_limit::HandleRateLimiter>,
}

/// Allows `AuthenticatedDevice` extractor to access the session cache from `AppState`.
impl FromRef<AppState> for Arc<dyn CachePort> {
    fn from_ref(state: &AppState) -> Arc<dyn CachePort> {
        state.cache.clone()
    }
}

pub fn router(state: AppState) -> Router {
    router_inner(
        state,
        rate_limit::auth_governor(),
        rate_limit::api_governor(),
    )
}

/// Build the internal admin router that exposes only `/metrics`.
///
/// This router MUST be bound to `127.0.0.1` (admin port, default 9090) and
/// NEVER merged into the public-facing router. Prometheus scrapes from within
/// the k8s cluster via pod-to-pod. Labels carry no user PII or message content.
pub fn admin_router(handle: PrometheusHandle) -> Router {
    let handle = Arc::new(handle);
    Router::new().route(
        "/metrics",
        get(move || {
            let h = Arc::clone(&handle);
            async move { metrics_response(h) }
        }),
    )
}

fn metrics_response(handle: Arc<PrometheusHandle>) -> Response<Body> {
    let mut resp = Response::new(Body::from(handle.render()));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    resp
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
        .layer(auth_layer.clone());

    // Device management — uses auth_governor (same class as OPAQUE endpoints,
    // shared token bucket via clone) because adding/revoking devices changes
    // auth state. Shared bucket is intentionally stricter: login + device ops
    // draw from the same per-IP allowance, preventing budget-doubling.
    let device_routes = Router::new()
        .route(
            "/v1/auth/devices",
            get(routes::auth::list_devices_handler).post(routes::auth::register_new_device),
        )
        .route(
            "/v1/auth/devices/:id",
            delete(routes::auth::revoke_device_handler),
        )
        .layer(auth_layer);

    // Authenticated API endpoints — general per-IP rate limit.
    let api_routes = Router::new()
        .route("/v1/groups", post(routes::groups::create_group))
        .route(
            "/v1/groups/:group_id/members/:device_id",
            post(routes::groups::add_member).delete(routes::groups::remove_member),
        )
        .route(
            "/v1/groups/:group_id/pending-removals",
            get(routes::groups::list_pending_removals),
        )
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
        .route(
            "/v1/media/:id/confirm-download",
            post(routes::media::confirm_download),
        )
        .route("/v1/media/:id", delete(routes::media::delete_media))
        .route(
            "/v1/push-subscriptions",
            post(routes::push_subscription::register).delete(routes::push_subscription::unregister),
        )
        .route("/v1/invites", post(routes::invite::create))
        .route("/v1/invites/redeem", post(routes::invite::redeem))
        .layer(api_layer);

    // Public endpoints — no auth, no per-IP rate limit (like /health).
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/v1/region/detect", get(routes::region::detect))
        .route("/v1/region/status", get(routes::region::status));

    Router::new()
        .merge(public_routes)
        .merge(auth_routes)
        .merge(device_routes)
        .merge(api_routes)
        .with_state(state)
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .layer(
            // Override make_span_with to omit `uri` — the default span includes
            // `uri = %request.uri()` which exposes UUID path parameters (device IDs,
            // envelope IDs, media IDs) at ALL log levels. Only http.method is recorded
            // in the span; status + latency appear in child events emitted by the
            // default DefaultOnResponse and DefaultOnRequest callbacks, not as span fields.
            // Rule: no-plaintext-logging.md.
            TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<Body>| {
                tracing::info_span!(
                    "http_request",
                    http.method = %request.method(),
                )
            }),
        )
        .layer(from_fn(security_headers::set_security_headers))
        // Outermost layer: zero-knowledge HTTP metrics (prd.md §13.2).
        // Records only {method, status} labels — no URI/path = no device/envelope ID leakage.
        .layer(from_fn(http_metrics::record_http_metrics))
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
#[allow(unused_variables)]
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
        push_subscription::PushSubscription,
        user::UserId,
    };
    use powehi_port_inbound::auth::{
        DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest, LoginInitResponse,
        RegistrationFinishRequest, RegistrationFinishResponse, RegistrationInitRequest,
        RegistrationInitResponse, SessionToken,
    };
    use powehi_port_inbound::invite::{CreatedInvite, RedeemedInvite};
    use powehi_port_inbound::media::MediaUseCase;
    use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;
    use tower::ServiceExt; // for `oneshot`

    use powehi_domain::device::Device;
    use powehi_port_outbound::device_repo::DeviceRepository;

    struct NullDeviceRepo;
    #[async_trait]
    impl DeviceRepository for NullDeviceRepo {
        async fn save(&self, _device: &Device) -> Result<(), DomainError> {
            Ok(())
        }
        async fn find_by_id(&self, _id: &DeviceId) -> Result<Option<Device>, DomainError> {
            Ok(None)
        }
        async fn find_by_user(&self, _user_id: &UserId) -> Result<Vec<Device>, DomainError> {
            Ok(vec![])
        }
        async fn delete(&self, _id: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    fn null_device_repo() -> Arc<dyn DeviceRepository> {
        Arc::new(NullDeviceRepo)
    }

    struct NullPushSubRepo;
    #[async_trait]
    impl PushSubscriptionRepository for NullPushSubRepo {
        async fn upsert(&self, _sub: &PushSubscription) -> Result<(), DomainError> {
            Ok(())
        }
        async fn fetch_by_device(
            &self,
            _device_id: &DeviceId,
        ) -> Result<Option<PushSubscription>, DomainError> {
            Ok(None)
        }
        async fn delete_by_device(&self, _device_id: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    fn null_push_sub_repo() -> Arc<dyn PushSubscriptionRepository> {
        Arc::new(NullPushSubRepo)
    }

    struct NoopInvite;
    #[async_trait]
    impl InviteUseCase for NoopInvite {
        async fn create_invite(
            &self,
            _: &DeviceId,
            _: Vec<u8>,
        ) -> Result<CreatedInvite, DomainError> {
            unimplemented!()
        }
        async fn redeem_invite(&self, _: &str) -> Result<RedeemedInvite, DomainError> {
            unimplemented!()
        }
        async fn revoke_invites_for_device(&self, _: &DeviceId) -> Result<(), DomainError> {
            // Unlike create_invite/redeem_invite (genuinely unexercised by the
            // tests using this stub), revoke_device_handler unconditionally
            // calls this on every successful revocation, so a true no-op is
            // required here for those tests to reach their own assertions.
            Ok(())
        }
    }

    fn noop_invite() -> Arc<dyn InviteUseCase> {
        Arc::new(NoopInvite)
    }

    // ── session cache helpers ────────────────────────────────────────────────

    use powehi_port_outbound::cache::CachePort;
    use std::{collections::HashMap, time::Duration};
    use uuid::Uuid as TestUuid;

    struct FakeCache {
        store: std::sync::Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: std::sync::Mutex::new(HashMap::new()),
            })
        }
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
            _ttl: Option<Duration>,
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

    /// Fixed test token for all router-level tests.
    const TEST_TOKEN: &str = "test-session-token";

    /// Fixed DeviceId that the test session token authenticates as.
    fn test_device_id() -> DeviceId {
        DeviceId::from(TestUuid::from_bytes([1u8; 16]))
    }

    /// Session cache pre-seeded so `"Bearer TEST_TOKEN"` authenticates as `test_device_id()`.
    fn test_session_cache() -> Arc<dyn CachePort> {
        let cache = FakeCache::new();
        let key = format!("session:{TEST_TOKEN}");
        cache
            .store
            .lock()
            .unwrap()
            .insert(key, test_device_id().as_uuid().as_bytes().to_vec());
        cache
    }

    /// An empty session cache — any Bearer token will return 401 (used in auth-bypass tests).
    fn empty_cache() -> Arc<dyn CachePort> {
        FakeCache::new()
    }

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
        ) -> Result<RegistrationFinishResponse, DomainError> {
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
        async fn list_devices(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
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
            _ttl_seconds: Option<u32>,
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
            _expected_epoch: Epoch,
        ) -> Result<Epoch, DomainError> {
            unimplemented!()
        }
        async fn poll_envelopes(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
            _since_id: Option<EnvelopeId>,
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
            _group_id: Option<&GroupId>,
        ) -> Result<(MediaId, String), DomainError> {
            unimplemented!()
        }
        async fn confirm_upload(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn get_download_url(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<String, DomainError> {
            unimplemented!()
        }
        async fn confirm_download(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn delete(&self, _id: &MediaId, _device: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn run_gc(&self) -> Result<usize, DomainError> {
            unimplemented!()
        }
    }

    /// No-op group mock used in tests that don't exercise group creation.
    struct NoopGroup;
    #[async_trait]
    impl GroupUseCase for NoopGroup {
        async fn create_group(
            &self,
            _creator: &DeviceId,
            _group_id: GroupId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn add_member(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
            _device_id: &DeviceId,
            _epoch: powehi_domain::group::Epoch,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn remove_member(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
            _device_id: &DeviceId,
            _epoch: powehi_domain::group::Epoch,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn list_pending_removals(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            Ok(vec![])
        }
    }

    fn noop_group() -> Arc<dyn GroupUseCase> {
        Arc::new(NoopGroup)
    }

    /// Group mock that returns Unauthorized for add/remove (simulates a non-member caller).
    struct MockGroupUnauthorized;
    #[async_trait]
    impl GroupUseCase for MockGroupUnauthorized {
        async fn create_group(
            &self,
            _creator: &DeviceId,
            _group_id: GroupId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn add_member(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
            _device_id: &DeviceId,
            _epoch: powehi_domain::group::Epoch,
        ) -> Result<(), DomainError> {
            Err(DomainError::Unauthorized)
        }
        async fn remove_member(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
            _device_id: &DeviceId,
            _epoch: powehi_domain::group::Epoch,
        ) -> Result<(), DomainError> {
            Err(DomainError::Unauthorized)
        }
        async fn list_pending_removals(
            &self,
            _caller: &DeviceId,
            _group_id: &GroupId,
        ) -> Result<Vec<DeviceId>, DomainError> {
            Err(DomainError::Unauthorized)
        }
    }

    fn groups_router_unauthorized() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: Arc::new(MockGroupUnauthorized),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    fn test_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: empty_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
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
            _ttl_seconds: Option<u32>,
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
            _expected_epoch: Epoch,
        ) -> Result<Epoch, DomainError> {
            Ok(Epoch(42))
        }
        async fn poll_envelopes(
            &self,
            _device_id: &DeviceId,
            _since: Option<DateTime<Utc>>,
            _since_id: Option<EnvelopeId>,
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

    struct MockMessagingUnauthorized;
    #[async_trait]
    impl MessagingUseCase for MockMessagingUnauthorized {
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
            _: Epoch,
        ) -> Result<Epoch, DomainError> {
            unimplemented!()
        }
        async fn poll_envelopes(
            &self,
            _: &DeviceId,
            _: Option<DateTime<Utc>>,
            _since_id: Option<EnvelopeId>,
        ) -> Result<Vec<Envelope>, DomainError> {
            unimplemented!()
        }
        async fn ack_envelope(&self, _: &DeviceId, _: &EnvelopeId) -> Result<(), DomainError> {
            Err(DomainError::Unauthorized)
        }
    }

    fn messaging_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessagingSuccess),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    fn messaging_unauthorized_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessagingUnauthorized),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    fn key_package_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackageSuccess),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    fn key_package_not_found_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackageNotFound),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
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
            _group_id: Option<&GroupId>,
        ) -> Result<(MediaId, String), DomainError> {
            Ok((MediaId::new(), "https://r2.example/presigned-put".into()))
        }
        async fn confirm_upload(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn get_download_url(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<String, DomainError> {
            Ok("https://r2.example/presigned-get".into())
        }
        async fn confirm_download(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn delete(&self, _id: &MediaId, _device: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
        async fn run_gc(&self) -> Result<usize, DomainError> {
            Ok(0)
        }
    }

    struct MockMediaUnauthorized;
    #[async_trait]
    impl MediaUseCase for MockMediaUnauthorized {
        async fn request_upload(
            &self,
            _device: &DeviceId,
            _content_type: &str,
            _size_bytes: u64,
            _group_id: Option<&GroupId>,
        ) -> Result<(MediaId, String), DomainError> {
            Err(DomainError::Unauthorized)
        }
        async fn confirm_upload(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            Err(DomainError::Unauthorized)
        }
        async fn get_download_url(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<String, DomainError> {
            unimplemented!()
        }
        async fn confirm_download(
            &self,
            _id: &MediaId,
            _device: &DeviceId,
        ) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn delete(&self, _id: &MediaId, _device: &DeviceId) -> Result<(), DomainError> {
            unimplemented!()
        }
        async fn run_gc(&self) -> Result<usize, DomainError> {
            unimplemented!()
        }
    }

    fn media_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMediaSuccess),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    fn media_unauthorized_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMediaUnauthorized),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    /// Returns the test session Bearer token (maps to `test_device_id()` in `test_session_cache()`).
    fn bearer() -> String {
        format!("Bearer {TEST_TOKEN}")
    }

    fn groups_router() -> Router {
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
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
                    .header("authorization", bearer())
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
    async fn send_message_with_invalid_ttl_returns_422() {
        // ttl_seconds below the 30s floor must be rejected before the use case
        // runs. The validation surfaces DomainError::InvalidInput, which the
        // ApiError mapping (error.rs, source of truth) renders as 400 Bad Request
        // with a content-free `invalid_input` code — never 200, never a leak.
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "ciphertext": [1u8, 2, 3],
            "ttl_seconds": 5
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn send_message_ttl_at_minimum_boundary_returns_200() {
        // ttl_seconds = 30 is the inclusive minimum — must be accepted.
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "ciphertext": [1u8, 2, 3],
            "ttl_seconds": 30u32
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn send_message_ttl_at_maximum_boundary_returns_200() {
        // ttl_seconds = 604800 (7 days) is the inclusive maximum — must be accepted.
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "ciphertext": [1u8, 2, 3],
            "ttl_seconds": 604800u32
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn send_message_ttl_above_maximum_returns_400() {
        // ttl_seconds = 604801 exceeds the 7-day ceiling — must be rejected.
        let device = DeviceId::new();
        let group = GroupId::new();
        let body = serde_json::json!({
            "group_id": group.to_string(),
            "ciphertext": [1u8, 2, 3],
            "ttl_seconds": 604801u32
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn poll_authenticated_returns_empty_list() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages")
                    .header("authorization", bearer())
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
                    .uri("/v1/messages?since=2026-01-01T00%3A00%3A00Z")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn poll_with_since_and_since_id_returns_200() {
        let device = DeviceId::new();
        let envelope_id = EnvelopeId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!(
                        "/v1/messages?since=2026-01-01T00%3A00%3A00Z&since_id={envelope_id}"
                    ))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn poll_with_malformed_since_returns_400() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages?since=not-a-timestamp")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn poll_with_malformed_since_id_returns_400() {
        let device = DeviceId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/messages?since=2026-01-01T00%3A00%3A00Z&since_id=not-a-uuid")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // since_id without since is meaningless (the keyset cursor is the pair) —
    // must be rejected, not silently ignored/fail-open to a full backlog
    // rescan (security-auditor cycle 353, informational finding 8: this exact
    // case had no test pinning it, so a future refactor could regress it
    // silently).
    #[tokio::test]
    async fn poll_with_since_id_but_no_since_returns_400() {
        let device = DeviceId::new();
        let envelope_id = EnvelopeId::new();
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/messages?since_id={envelope_id}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ack_by_wrong_device_returns_401() {
        let device = DeviceId::new();
        let envelope_id = EnvelopeId::new();
        let resp = messaging_unauthorized_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/messages/{envelope_id}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
                    .header("authorization", bearer())
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
            "commit": [7u8, 8, 9],
            "expected_epoch": 0u64
        });
        let resp = messaging_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages/commit")
                    .header("authorization", bearer())
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
        // caller == authenticated device: ownership check must pass.
        // bearer() authenticates as test_device_id(), so the URL path must match.
        let caller = test_device_id();
        let body = serde_json::json!({ "packages": [[1u8, 2], [3u8, 4]] });
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/key-packages/{caller}"))
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
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
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn confirm_upload_wrong_device_returns_401() {
        let device = DeviceId::new();
        let media_id = uuid::Uuid::new_v4();
        let resp = media_unauthorized_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/media/{media_id}/confirm"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
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
                    .header("authorization", bearer())
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
    async fn confirm_download_returns_204() {
        let device = DeviceId::new();
        let media_id = uuid::Uuid::new_v4();
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/media/{media_id}/confirm-download"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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
                    .header("authorization", bearer())
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
            ("POST", format!("/v1/media/{media_id}/confirm-download")),
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

    #[tokio::test]
    async fn media_upload_size_zero_returns_400() {
        // size_bytes = 0 must be rejected — empty uploads have no valid use case
        // and could be used to enumerate MediaIds cheaply.
        let device = DeviceId::new();
        let body = serde_json::json!({
            "content_type": "image/jpeg",
            "size_bytes": 0u64
        });
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/media/upload-url")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn media_upload_size_too_large_returns_400() {
        // size_bytes > 100MB must be rejected to prevent over-allocation of pre-signed
        // URLs and denial-of-service via massive upload promises.
        let device = DeviceId::new();
        let too_large: u64 = 100 * 1024 * 1024 + 1; // 100MB + 1 byte
        let body = serde_json::json!({
            "content_type": "image/jpeg",
            "size_bytes": too_large
        });
        let resp = media_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/media/upload-url")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn request_upload_non_member_group_returns_401() {
        // Service returns Unauthorized when the uploader is not a member of the
        // claimed group_id. The REST handler must surface this as 401.
        let body = serde_json::json!({
            "content_type": "image/jpeg",
            "size_bytes": 1024u64,
            "group_id": uuid::Uuid::new_v4()
        });
        let resp = media_unauthorized_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/media/upload-url")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // --- Handle rate-limit tests ---
    //
    // MockAuthSuccess returns valid responses so the handler can complete without
    // panicking for the "allowed" request before the rate limit bites.

    struct MockAuthSuccess;

    #[async_trait]
    impl AuthUseCase for MockAuthSuccess {
        async fn register_init(
            &self,
            _req: RegistrationInitRequest,
        ) -> Result<RegistrationInitResponse, DomainError> {
            Ok(RegistrationInitResponse {
                user_id: UserId::new(),
                opaque_response: vec![],
            })
        }
        async fn login_init(
            &self,
            _req: LoginInitRequest,
        ) -> Result<LoginInitResponse, DomainError> {
            Ok(LoginInitResponse {
                user_id: UserId::new(),
                opaque_ke2: vec![],
                login_nonce: "test-nonce".to_string(),
            })
        }
        async fn register_finish(
            &self,
            req: RegistrationFinishRequest,
        ) -> Result<RegistrationFinishResponse, DomainError> {
            Ok(RegistrationFinishResponse {
                user_id: req.user_id,
                device_id: DeviceId::new(),
            })
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
        async fn list_devices(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            unimplemented!()
        }
    }

    fn login_init_body(handle_hash: Vec<u8>) -> String {
        serde_json::json!({
            "handle_hash": handle_hash,
            "opaque_ke1": vec![0u8; 8]
        })
        .to_string()
    }

    fn login_init_req(body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/auth/login/init")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn handle_rate_limit_blocks_second_request_from_same_handle_hash() {
        let tight_rl = Arc::new(rate_limit::HandleRateLimiter::tight());
        let state = AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuthSuccess),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: empty_cache(),
            handle_rate_limiter: Arc::clone(&tight_rl),
        };
        let app = router_for_test(
            state,
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );

        let hash = vec![0xAAu8; 32];
        let r1 = app
            .clone()
            .oneshot(login_init_req(login_init_body(hash.clone())))
            .await
            .unwrap();
        assert_ne!(
            r1.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "first request must not be handle-rate-limited"
        );

        let r2 = app
            .clone()
            .oneshot(login_init_req(login_init_body(hash)))
            .await
            .unwrap();
        assert_eq!(
            r2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second request from same handle_hash must be rate-limited"
        );
    }

    #[tokio::test]
    async fn handle_rate_limit_does_not_affect_different_handle_hashes() {
        let tight_rl = Arc::new(rate_limit::HandleRateLimiter::tight());
        let state = AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuthSuccess),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: empty_cache(),
            handle_rate_limiter: Arc::clone(&tight_rl),
        };
        let app = router_for_test(
            state,
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );

        let hash_a = vec![0x01u8; 32];
        let hash_b = vec![0x02u8; 32];

        // Exhaust handle A's bucket.
        let _ = app
            .clone()
            .oneshot(login_init_req(login_init_body(hash_a.clone())))
            .await
            .unwrap();
        let r_a2 = app
            .clone()
            .oneshot(login_init_req(login_init_body(hash_a)))
            .await
            .unwrap();
        assert_eq!(
            r_a2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "handle A exhausted"
        );

        // Handle B still has its own full bucket.
        let r_b = app
            .clone()
            .oneshot(login_init_req(login_init_body(hash_b)))
            .await
            .unwrap();
        assert_ne!(
            r_b.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "handle B must not be affected by handle A's exhaustion"
        );
    }

    // --- Rate-limit tests ---
    //
    // SmartIpKeyExtractor checks X-Forwarded-For first. Tests inject a fake IP
    // via that header so the key extractor has a stable key without a real TCP socket.

    fn minimal_state() -> AppState {
        AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuth),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: empty_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
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

    // ── Metrics endpoint tests ───────────────────────────────────────────────

    /// Produce a `PrometheusHandle` for tests without touching the global recorder.
    /// Uses `OnceLock` so parallel tests share a single installation.
    fn test_metrics_handle() -> metrics_exporter_prometheus::PrometheusHandle {
        use std::sync::OnceLock;
        static HANDLE: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
        HANDLE
            .get_or_init(|| {
                metrics_exporter_prometheus::PrometheusBuilder::new()
                    .install_recorder()
                    .expect("test prometheus recorder")
            })
            .clone()
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_200_with_prometheus_content_type() {
        let handle = test_metrics_handle();
        let app = admin_router(handle);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .expect("content-type header present")
            .to_str()
            .unwrap();
        assert!(
            ct.contains("text/plain"),
            "content-type must be text/plain, got {ct}"
        );
    }

    #[tokio::test]
    async fn metrics_output_is_prometheus_text_format() {
        let handle = test_metrics_handle();
        let app = admin_router(handle);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        // Prometheus text format: each non-comment line must be "<name> <value>"
        // with no user-supplied strings as label values. Valid output is either
        // empty (no metrics recorded) or lines beginning with "#" or metric names.
        for line in text.lines() {
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Metric lines: name{labels} value [timestamp]
            // Label values in our metrics are always static strings like "success",
            // "failure", "mls", "welcome", "commit" — never UUIDs.
            // A basic heuristic: no line should contain 36-char UUID-shaped strings
            // with four hyphens.
            let has_uuid = line
                .split('"')
                .filter(|s| s.len() == 36)
                .any(|s| s.chars().filter(|&c| c == '-').count() == 4);
            assert!(
                !has_uuid,
                "metrics line contains a UUID-shaped label value (user/device ID leak?): {line}"
            );
        }
    }

    // ── Security headers on the public router ────────────────────────────────

    #[tokio::test]
    async fn health_response_has_x_content_type_options_nosniff() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
        );
    }

    #[tokio::test]
    async fn health_response_has_x_frame_options_deny() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("DENY"),
        );
    }

    #[tokio::test]
    async fn health_response_has_hsts() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let hsts = resp
            .headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            hsts.contains("max-age=63072000"),
            "HSTS max-age must be 2 years, got: {hsts}"
        );
    }

    #[tokio::test]
    async fn register_finish_returns_user_id_and_device_id() {
        let state = AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuthSuccess),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: null_device_repo(),
            cache: empty_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        };
        let app = router_for_test(
            state,
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );

        let body = serde_json::json!({
            "user_id": TestUuid::new_v4(),
            "opaque_record": [1u8, 2, 3],
            "mls_credential": [4u8, 5, 6],
        })
        .to_string();

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register/finish")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json.get("user_id").and_then(|v| v.as_str()).is_some(),
            "response must include user_id"
        );
        assert!(
            json.get("device_id").and_then(|v| v.as_str()).is_some(),
            "response must include device_id (new in this cycle)"
        );
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

    // ── TraceLayer logging-hygiene tests ─────────────────────────────────────

    /// Captures the field NAMES recorded in every new span.
    /// Used to assert that no `uri` or `http.uri` field leaks into HTTP spans.
    #[derive(Clone, Default)]
    struct SpanFieldNames(Arc<std::sync::Mutex<Vec<String>>>);

    impl SpanFieldNames {
        fn names(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::layer::Layer<S> for SpanFieldNames {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldNameVisitor(self.0.clone());
            attrs.record(&mut visitor);
        }

        // Also capture fields added via `span.record(...)` after span creation.
        // tower-http's on_response/on_failure callbacks can use this pattern to
        // add late-bound fields (e.g., status, uri) — we must catch those too.
        fn on_record(
            &self,
            _id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut visitor = FieldNameVisitor(self.0.clone());
            values.record(&mut visitor);
        }
    }

    struct FieldNameVisitor(Arc<std::sync::Mutex<Vec<String>>>);
    impl tracing::field::Visit for FieldNameVisitor {
        fn record_str(&mut self, field: &tracing::field::Field, _value: &str) {
            self.0.lock().unwrap().push(field.name().to_string());
        }
        fn record_debug(&mut self, field: &tracing::field::Field, _value: &dyn std::fmt::Debug) {
            self.0.lock().unwrap().push(field.name().to_string());
        }
    }

    /// Security invariant (no-plaintext-logging.md): the HTTP request span must NOT
    /// contain a `uri` field. The tower-http default span emits `uri = %request.uri()`
    /// which exposes UUID path parameters (device IDs, envelope IDs, media IDs) at
    /// ALL log levels. Our custom make_span_with omits uri; only http.method is recorded.
    #[tokio::test(flavor = "current_thread")]
    async fn trace_span_omits_uri_field_for_path_param_routes() {
        use tracing_subscriber::layer::SubscriberExt;

        let fields = SpanFieldNames::default();
        let subscriber = tracing_subscriber::registry().with(fields.clone());
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);

        let device = test_device_id();
        let _ = key_package_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let names = fields.names();
        assert!(
            !names.iter().any(|n| n == "uri" || n == "http.uri"),
            "HTTP span must not contain a `uri` field; found fields: {names:?}"
        );
    }

    /// Verify that /v1/key-packages/:device_id/count returns 200 when authenticated.
    /// Exercises the custom make_span_with on a nested path-param route.
    #[tokio::test]
    async fn key_package_count_returns_200_when_authenticated() {
        let device = test_device_id();
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/key-packages/{device}/count"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── POST /v1/groups tests ────────────────────────────────────────────────

    /// Auth bypass invariant: unauthenticated request must be rejected before reaching the handler.
    #[tokio::test]
    async fn create_group_without_token_returns_401() {
        let group_id = GroupId::new();
        let body = serde_json::json!({ "group_id": group_id.to_string() });
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/groups")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Happy path: authenticated creator registers a new MLS group — server returns 204.
    #[tokio::test]
    async fn create_group_returns_204() {
        let group_id = GroupId::new();
        let body = serde_json::json!({ "group_id": group_id.to_string() });
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/groups")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// Malformed body (missing required group_id field) must be rejected before the handler runs.
    #[tokio::test]
    async fn create_group_with_missing_group_id_returns_unprocessable() {
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/groups")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    // ── POST /v1/groups/:group_id/members/:device_id tests ───────────────────

    /// Auth bypass invariant: unauthenticated add_member must be rejected before the handler.
    #[tokio::test]
    async fn add_member_without_token_returns_401() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let body = serde_json::json!({ "epoch": 1u64 });
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Auth bypass invariant: unauthenticated remove_member must be rejected before the handler.
    #[tokio::test]
    async fn remove_member_without_token_returns_401() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Membership enforcement: non-member caller must receive 401.
    #[tokio::test]
    async fn add_member_by_non_member_returns_401() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let body = serde_json::json!({ "epoch": 2u64 });
        let resp = groups_router_unauthorized()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Membership enforcement: non-member caller must receive 401 on remove.
    #[tokio::test]
    async fn remove_member_by_non_member_returns_401() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let resp = groups_router_unauthorized()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Happy path: authenticated member adds a new device — server returns 204.
    #[tokio::test]
    async fn add_member_returns_204() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let body = serde_json::json!({ "epoch": 3u64 });
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    /// Happy path: authenticated member removes a device — server returns 204.
    #[tokio::test]
    async fn remove_member_returns_204() {
        let group_id = uuid::Uuid::new_v4();
        let device_id = uuid::Uuid::new_v4();
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/groups/{group_id}/members/{device_id}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // ── GET /v1/groups/:group_id/pending-removals tests ───────────────────────

    /// Happy path: authenticated member gets the pending-removal list (empty is fine).
    #[tokio::test]
    async fn list_pending_removals_returns_ok_for_a_member() {
        let group_id = uuid::Uuid::new_v4();
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/pending-removals"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert!(body["device_ids"].is_array());
    }

    /// Membership enforcement: non-member caller must receive 401 (fail-closed).
    #[tokio::test]
    async fn list_pending_removals_rejects_a_non_member() {
        let group_id = uuid::Uuid::new_v4();
        let resp = groups_router_unauthorized()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/pending-removals"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Auth bypass invariant: unauthenticated request must be rejected before the handler.
    #[tokio::test]
    async fn list_pending_removals_requires_authentication() {
        let group_id = uuid::Uuid::new_v4();
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(format!("/v1/groups/{group_id}/pending-removals"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Path-param validation: a non-UUID group_id must be rejected by extraction.
    #[tokio::test]
    async fn list_pending_removals_rejects_a_malformed_group_id() {
        let resp = groups_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/groups/not-a-uuid/pending-removals")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── Device management endpoint tests ─────────────────────────────────────

    /// FakeDeviceRepo returns a fixed Device when `find_by_id` is called with
    /// `test_device_id()`. All other IDs return None.
    struct FakeDeviceRepo {
        device: powehi_domain::device::Device,
    }

    impl FakeDeviceRepo {
        fn new(user_id: UserId) -> Arc<Self> {
            use chrono::Utc;
            Arc::new(Self {
                device: powehi_domain::device::Device {
                    id: test_device_id(),
                    user_id,
                    mls_credential: vec![],
                    created_at: Utc::now(),
                    last_seen_at: None,
                },
            })
        }
    }

    #[async_trait]
    impl DeviceRepository for FakeDeviceRepo {
        async fn save(&self, _device: &powehi_domain::device::Device) -> Result<(), DomainError> {
            Ok(())
        }
        async fn find_by_id(
            &self,
            id: &DeviceId,
        ) -> Result<Option<powehi_domain::device::Device>, DomainError> {
            if id == &self.device.id {
                Ok(Some(self.device.clone()))
            } else {
                Ok(None)
            }
        }
        async fn find_by_user(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_domain::device::Device>, DomainError> {
            Ok(vec![self.device.clone()])
        }
        async fn delete(&self, _id: &DeviceId) -> Result<(), DomainError> {
            Ok(())
        }
    }

    /// Mock AuthUseCase with functional register_device and revoke_device.
    struct MockAuthDeviceSuccess;

    #[async_trait]
    impl AuthUseCase for MockAuthDeviceSuccess {
        async fn register_init(
            &self,
            _req: RegistrationInitRequest,
        ) -> Result<RegistrationInitResponse, DomainError> {
            unimplemented!()
        }
        async fn register_finish(
            &self,
            _req: RegistrationFinishRequest,
        ) -> Result<RegistrationFinishResponse, DomainError> {
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
            Ok(DeviceId::new())
        }
        async fn revoke_device(
            &self,
            _user_id: &UserId,
            _device_id: &DeviceId,
        ) -> Result<(), DomainError> {
            Ok(())
        }
        async fn list_devices(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            use powehi_port_inbound::auth::DeviceInfo;
            Ok(vec![
                DeviceInfo {
                    device_id: DeviceId::new(),
                    created_at: Utc::now(),
                    last_seen_at: None,
                },
                DeviceInfo {
                    device_id: DeviceId::new(),
                    created_at: Utc::now(),
                    last_seen_at: Some(Utc::now()),
                },
            ])
        }
    }

    fn device_router() -> Router {
        let user_id = UserId::new();
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth: Arc::new(MockAuthDeviceSuccess),
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: FakeDeviceRepo::new(user_id),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    #[tokio::test]
    async fn register_new_device_without_token_returns_401() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/devices")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mls_credential":[1,2,3]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_device_without_token_returns_401() {
        let target = DeviceId::new();
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/auth/devices/{target}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn register_new_device_authenticated_returns_device_id() {
        let resp = device_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/devices")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"mls_credential":[1,2,3]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            json.get("device_id").and_then(|v| v.as_str()).is_some(),
            "response must include device_id"
        );
    }

    #[tokio::test]
    async fn revoke_device_authenticated_returns_204() {
        let target = DeviceId::new();
        let resp = device_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/auth/devices/{target}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn list_devices_returns_device_list() {
        let resp = device_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/auth/devices")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let arr = json.as_array().expect("response must be a JSON array");
        assert_eq!(arr.len(), 2, "MockAuthDeviceSuccess returns 2 devices");
        for entry in arr {
            assert!(
                entry.get("device_id").and_then(|v| v.as_str()).is_some(),
                "each device entry must include device_id"
            );
            assert!(
                entry.get("created_at").is_some(),
                "each device entry must include created_at"
            );
            // last_seen_at is present as a key (may be null)
            assert!(
                entry.get("last_seen_at").is_some(),
                "each device entry must include last_seen_at key"
            );
        }
    }

    #[tokio::test]
    async fn list_devices_without_token_returns_401() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/auth/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Mocks for error-path device management tests.
    struct MockAuthDeviceRevokeNotFound;
    #[async_trait]
    impl AuthUseCase for MockAuthDeviceRevokeNotFound {
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
            Err(DomainError::NotFound("device".into()))
        }
        async fn list_devices(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            unimplemented!()
        }
    }

    struct MockAuthDeviceRevokeUnauthorized;
    #[async_trait]
    impl AuthUseCase for MockAuthDeviceRevokeUnauthorized {
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
            Err(DomainError::Unauthorized)
        }
        async fn list_devices(
            &self,
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            unimplemented!()
        }
    }

    fn device_router_with_auth(auth: Arc<dyn AuthUseCase>) -> Router {
        let user_id = UserId::new();
        router(AppState {
            region_id: "eu-de-1-test".to_string(),
            region_tier: powehi_domain::region::Tier::Tier1,
            auth,
            group: noop_group(),
            messaging: Arc::new(MockMessaging),
            key_package: Arc::new(MockKeyPackage),
            media: Arc::new(MockMedia),
            push_sub_repo: null_push_sub_repo(),
            invite: noop_invite(),
            device_repo: FakeDeviceRepo::new(user_id),
            cache: test_session_cache(),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        })
    }

    /// Security invariant: when `revoke_device` returns `NotFound`, the handler
    /// must return 401 (not 404) to prevent device-existence oracle attacks.
    #[tokio::test]
    async fn revoke_device_not_found_returns_401_not_404() {
        let target = DeviceId::new();
        let resp = device_router_with_auth(Arc::new(MockAuthDeviceRevokeNotFound))
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/auth/devices/{target}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Oracle-closing mapping: DomainError::NotFound → 401 (not 404).
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Security invariant: when `revoke_device` returns `Unauthorized`
    /// (caller does not own the target device), the handler returns 401.
    #[tokio::test]
    async fn revoke_non_owned_device_returns_401() {
        let target = DeviceId::new();
        let resp = device_router_with_auth(Arc::new(MockAuthDeviceRevokeUnauthorized))
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(format!("/v1/auth/devices/{target}"))
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Input validation: register_new_device with missing body returns 400.
    #[tokio::test]
    async fn register_new_device_missing_body_returns_400() {
        let resp = device_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/devices")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── handle_hash length validation tests ──────────────────────────────────
    //
    // SHA-256 output is always exactly 32 bytes. Any other length means the
    // client sent something other than a hash, which must be rejected at the
    // HTTP layer before the OPAQUE state machine ever runs.

    fn register_init_body(handle_hash: Vec<u8>) -> String {
        serde_json::json!({
            "opaque_request": vec![0u8; 8],
            "handle_hash": handle_hash,
        })
        .to_string()
    }

    #[tokio::test]
    async fn register_init_short_handle_hash_returns_400() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register/init")
                    .header("content-type", "application/json")
                    .body(Body::from(register_init_body(vec![0xABu8; 31])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_init_long_handle_hash_returns_400() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register/init")
                    .header("content-type", "application/json")
                    .body(Body::from(register_init_body(vec![0xCDu8; 33])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_init_short_handle_hash_returns_400() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/init")
                    .header("content-type", "application/json")
                    .body(Body::from(login_init_body(vec![0xABu8; 31])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn login_init_long_handle_hash_returns_400() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/init")
                    .header("content-type", "application/json")
                    .body(Body::from(login_init_body(vec![0xCDu8; 33])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── key-package path-param validation tests ───────────────────────────────

    #[tokio::test]
    async fn fetch_key_package_malformed_device_id_returns_400() {
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/key-packages/not-a-uuid")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn upload_key_packages_malformed_device_id_returns_400() {
        let body = serde_json::json!({ "packages": [[1u8, 2]] });
        let resp = key_package_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/key-packages/not-a-uuid")
                    .header("authorization", bearer())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── list_devices error-path tests ─────────────────────────────────────────

    struct MockAuthDeviceListInternalError;
    #[async_trait]
    impl AuthUseCase for MockAuthDeviceListInternalError {
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
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            Err(DomainError::Internal("db unavailable".into()))
        }
    }

    struct MockAuthDeviceListEmpty;
    #[async_trait]
    impl AuthUseCase for MockAuthDeviceListEmpty {
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
            _user_id: &UserId,
        ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
            Ok(vec![])
        }
    }

    /// When the auth service returns Internal error, list_devices_handler must return 500.
    /// Verify that the internal error detail is NOT present in the response body (no-plaintext-logging).
    #[tokio::test]
    async fn list_devices_service_error_returns_500() {
        let resp = device_router_with_auth(Arc::new(MockAuthDeviceListInternalError))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/auth/devices")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        // Internal error detail must never leak into the HTTP response (no-plaintext-logging).
        assert!(
            !body.contains("db unavailable"),
            "internal message must not appear in response"
        );
        assert_eq!(body, r#"{"code":"internal"}"#);
    }

    /// When the user has no linked devices the handler returns 200 OK with an empty JSON array.
    #[tokio::test]
    async fn list_devices_empty_list_returns_200_with_empty_array() {
        let resp = device_router_with_auth(Arc::new(MockAuthDeviceListEmpty))
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/auth/devices")
                    .header("authorization", bearer())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json,
            serde_json::json!([]),
            "empty device list must serialize as []"
        );
    }
}
