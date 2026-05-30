//! Web Push subscription management routes.
//!
//! Devices register their browser PushSubscription here so the server can
//! send empty wake-up notifications (RFC 8291 / RFC 8292 VAPID). The server
//! NEVER sends message content through the push channel — only an opaque
//! "new message" signal. Zero-knowledge: endpoint/keys are stored but never
//! logged (rule: no-plaintext-logging).
//!
//! Routes:
//!   POST   /v1/push-subscriptions  — upsert subscription for caller device
//!   DELETE /v1/push-subscriptions  — remove subscription for caller device

use axum::{extract::State, http::StatusCode, Json};
use base64ct::{Base64UrlUnpadded, Encoding};
use powehi_domain::{error::DomainError, push_subscription::PushSubscription};
use serde::Deserialize;

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

#[derive(Deserialize)]
pub struct RegisterRequest {
    /// HTTPS push service endpoint from the browser's PushSubscription.
    pub endpoint: String,
    /// Browser's P-256 ECDH public key, base64url-unpadded (65 bytes uncompressed).
    pub p256dh: String,
    /// 16-byte auth secret, base64url-unpadded.
    pub auth: String,
}

fn bad_input(msg: &str) -> ApiError {
    ApiError::from(DomainError::InvalidInput(msg.into()))
}

/// Returns `true` if the hostname belongs to a private/internal/loopback range
/// that must never be used as a push endpoint (SSRF guard).
///
/// We reject: loopback (127.x, ::1), link-local (169.254.x, fe80::),
/// RFC-1918 private (10.x, 172.16-31.x, 192.168.x), ULA (fc00::/7),
/// bare "localhost", and IPv4-mapped/compatible IPv6 addresses whose
/// embedded IPv4 address is private (e.g. `::ffff:169.254.169.254`).
fn is_private_host(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    // Bare hostname checks
    if h == "localhost" || h == "ip6-localhost" {
        return true;
    }
    // Parse as IPv4 or IPv6
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => is_private_v4(v4),
            std::net::IpAddr::V6(v6) => {
                // IPv4-mapped (::ffff:a.b.c.d) embeds a real IPv4 address. Check
                // it first so that `::ffff:169.254.169.254` is correctly blocked.
                // We do NOT call to_ipv4() (deprecated compat form ::a.b.c.d) as
                // that matches ::1 as 0.0.0.1 and would skip is_loopback() below.
                if let Some(v4) = v6.to_ipv4_mapped() {
                    return is_private_v4(v4);
                }
                v6.is_loopback()    // ::1
                    || v6.is_unspecified() // ::
                    // Link-local fe80::/10
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
                    // ULA fc00::/7
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        };
    }
    false
}

fn is_private_v4(v4: std::net::Ipv4Addr) -> bool {
    v4.is_loopback()       // 127.0.0.0/8
        || v4.is_private() // 10.x / 172.16-31.x / 192.168.x
        || v4.is_link_local() // 169.254.x.x
        || v4.is_unspecified() // 0.0.0.0
        || v4.is_broadcast() // 255.255.255.255
}

/// Extract just the host (without port) from an `https://host[:port]/...` URL.
fn extract_host(endpoint: &str) -> Option<&str> {
    let rest = endpoint.strip_prefix("https://")?;
    // The authority ends at the first `/` or end-of-string.
    let authority = rest.split('/').next()?;
    // Strip optional port suffix.
    let host = if authority.contains('[') {
        // IPv6 literal: [::1]:port — extract inside brackets
        authority.trim_start_matches('[').split(']').next()?
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// `POST /v1/push-subscriptions` — register (or replace) the caller's push subscription.
pub async fn register(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Json(req): Json<RegisterRequest>,
) -> Result<StatusCode, ApiError> {
    // Validate endpoint scheme — must be https to protect the push channel.
    if !req.endpoint.starts_with("https://") {
        return Err(bad_input("endpoint must use https"));
    }
    // Enforce a reasonable length limit (push endpoints are typically < 512 chars).
    if req.endpoint.len() > 2048 {
        return Err(bad_input("endpoint too long"));
    }
    // SSRF guard: reject private/internal/loopback hosts. Push services are
    // always public-internet domains (FCM, Mozilla, Apple, etc.).
    let host = extract_host(&req.endpoint).ok_or_else(|| bad_input("endpoint missing host"))?;
    if is_private_host(host) {
        return Err(bad_input("endpoint host is not a public push service"));
    }

    let p256dh = Base64UrlUnpadded::decode_vec(&req.p256dh)
        .map_err(|_| bad_input("p256dh: invalid base64url"))?;
    if p256dh.len() != 65 {
        return Err(bad_input("p256dh must be 65 bytes (uncompressed P-256)"));
    }

    let auth_secret = Base64UrlUnpadded::decode_vec(&req.auth)
        .map_err(|_| bad_input("auth: invalid base64url"))?;
    if auth_secret.len() != 16 {
        return Err(bad_input("auth must be 16 bytes"));
    }

    let sub = PushSubscription::new(device_id.clone(), req.endpoint, p256dh, auth_secret);

    state.push_sub_repo.upsert(&sub).await?;
    // Endpoint not logged (device-identifiable).
    tracing::info!(device_id = %device_id, "push_subscription.registered");
    Ok(StatusCode::CREATED)
}

/// `DELETE /v1/push-subscriptions` — remove the caller's push subscription.
pub async fn unregister(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
) -> Result<StatusCode, ApiError> {
    state.push_sub_repo.delete_by_device(&device_id).await?;
    tracing::info!(device_id = %device_id, "push_subscription.removed");
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, Router};
    use bytes::Bytes;
    use chrono::{DateTime, Utc};
    use powehi_domain::{
        device::DeviceId,
        envelope::{Envelope, EnvelopeId},
        group::{Epoch, GroupId},
        key_package::KeyPackageId,
        media::MediaId,
        push_subscription::PushSubscription,
        user::UserId,
    };
    use powehi_port_inbound::{
        auth::{
            AuthUseCase, DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest,
            LoginInitResponse, RegistrationFinishRequest, RegistrationInitRequest,
            RegistrationInitResponse, SessionToken,
        },
        key_package::KeyPackageUseCase,
        media::MediaUseCase,
        messaging::MessagingUseCase,
    };
    use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;

    use crate::AppState;

    struct FakePushSubRepo {
        store: Mutex<Option<PushSubscription>>,
    }
    impl FakePushSubRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(None),
            })
        }
    }

    #[async_trait::async_trait]
    impl PushSubscriptionRepository for FakePushSubRepo {
        async fn upsert(&self, sub: &PushSubscription) -> Result<(), DomainError> {
            *self.store.lock().unwrap() = Some(sub.clone());
            Ok(())
        }
        async fn fetch_by_device(
            &self,
            _device_id: &DeviceId,
        ) -> Result<Option<PushSubscription>, DomainError> {
            Ok(self.store.lock().unwrap().clone())
        }
        async fn delete_by_device(&self, _device_id: &DeviceId) -> Result<(), DomainError> {
            *self.store.lock().unwrap() = None;
            Ok(())
        }
    }

    struct NullUseCase;

    #[async_trait::async_trait]
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
        ) -> Result<UserId, DomainError> {
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
    }

    #[async_trait::async_trait]
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

    #[async_trait::async_trait]
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

    #[async_trait::async_trait]
    impl MediaUseCase for NullUseCase {
        async fn request_upload(
            &self,
            _: &DeviceId,
            _: &str,
            _: u64,
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

    fn make_router(push_sub_repo: Arc<dyn PushSubscriptionRepository>) -> Router {
        use crate::routes;
        use axum::routing::post;

        let null: Arc<NullUseCase> = Arc::new(NullUseCase);
        let state = AppState {
            region_id: "eu-de-1-test".to_string(),
            auth: null.clone(),
            messaging: null.clone(),
            key_package: null.clone(),
            media: null.clone(),
            push_sub_repo,
            handle_rate_limiter: std::sync::Arc::new(crate::rate_limit::HandleRateLimiter::new()),
        };

        Router::new()
            .route(
                "/v1/push-subscriptions",
                post(routes::push_subscription::register)
                    .delete(routes::push_subscription::unregister),
            )
            .with_state(state)
    }

    fn valid_register_body() -> serde_json::Value {
        serde_json::json!({
            "endpoint": "https://push.example.com/abc",
            // 65-byte uncompressed P-256 point: 0x04 prefix + 32 + 32 bytes
            "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
        })
    }

    fn bearer_header() -> String {
        format!("Bearer {}", DeviceId::new())
    }

    #[tokio::test]
    async fn post_valid_subscription_returns_201() {
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(
                        serde_json::to_vec(&valid_register_body()).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn post_http_endpoint_returns_400() {
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let body = serde_json::json!({
            "endpoint": "http://insecure.example/push",
            "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
        });
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_internal_ip_endpoint_returns_400() {
        for bad_endpoint in &[
            "https://169.254.169.254/metadata",          // AWS IMDS (IPv4)
            "https://127.0.0.1/push",                    // loopback
            "https://10.0.0.5/push",                     // RFC-1918 private
            "https://192.168.1.1/push",                  // RFC-1918 private
            "https://localhost/push",                    // bare localhost
            "https://[::ffff:169.254.169.254]/metadata", // IPv4-mapped IPv6 IMDS
            "https://[::ffff:127.0.0.1]/push",           // IPv4-mapped loopback
            "https://[::ffff:10.0.0.5]/push",            // IPv4-mapped RFC-1918
            "https://[::1]/push",                        // IPv6 loopback
        ] {
            let repo = FakePushSubRepo::new();
            let router = make_router(repo);
            let body = serde_json::json!({
                "endpoint": bad_endpoint,
                "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
                "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
            });
            let resp = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/push-subscriptions")
                        .header("Content-Type", "application/json")
                        .header("Authorization", bearer_header())
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "SSRF guard must reject internal endpoint: {bad_endpoint}"
            );
        }
    }

    #[tokio::test]
    async fn delete_subscription_returns_204() {
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/push-subscriptions")
                    .header("Authorization", bearer_header())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn post_p256dh_wrong_length_returns_400() {
        let body = serde_json::json!({
            "endpoint": "https://push.example.com/abc",
            // 64 bytes — must be exactly 65 (uncompressed P-256 prefix + 32+32)
            "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 64]),
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
        });
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_invalid_p256dh_base64_returns_400() {
        let body = serde_json::json!({
            "endpoint": "https://push.example.com/abc",
            "p256dh": "not-valid-base64url!!!",
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
        });
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_auth_wrong_length_returns_400() {
        let body = serde_json::json!({
            "endpoint": "https://push.example.com/abc",
            "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
            // 15 bytes — must be exactly 16
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 15]),
        });
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_endpoint_too_long_returns_400() {
        let endpoint = format!("https://push.example.com/{}", "x".repeat(2050));
        let body = serde_json::json!({
            "endpoint": endpoint,
            "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
            "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
        });
        let repo = FakePushSubRepo::new();
        let router = make_router(repo);
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/push-subscriptions")
                    .header("Content-Type", "application/json")
                    .header("Authorization", bearer_header())
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_ipv6_ula_and_link_local_endpoints_return_400() {
        // SSRF guard must block ULA (fc00::/7) and link-local (fe80::/10) IPv6 addresses
        // in addition to the cases tested in post_internal_ip_endpoint_returns_400.
        for bad_endpoint in &[
            "https://[fc00::1]/push", // ULA fc00::/7
            "https://[fd00::1]/push", // ULA fd00::/8 (within fc00::/7)
            "https://[fe80::1]/push", // link-local fe80::/10
        ] {
            let body = serde_json::json!({
                "endpoint": bad_endpoint,
                "p256dh": base64ct::Base64UrlUnpadded::encode_string(&[4u8; 65]),
                "auth": base64ct::Base64UrlUnpadded::encode_string(&[0u8; 16]),
            });
            let repo = FakePushSubRepo::new();
            let router = make_router(repo);
            let resp = router
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/push-subscriptions")
                        .header("Content-Type", "application/json")
                        .header("Authorization", bearer_header())
                        .body(Body::from(serde_json::to_vec(&body).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "SSRF guard must block IPv6 address: {bad_endpoint}"
            );
        }
    }
}
