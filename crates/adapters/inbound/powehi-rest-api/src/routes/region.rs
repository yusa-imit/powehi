use axum::{extract::State, Json};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
pub struct RegionDetectResponse {
    pub region_id: String,
}

/// Returns the region this server instance belongs to.
///
/// The CF Worker already routed the request to the correct origin, so this
/// handler simply echoes the server's configured region_id. No PII, IP, or
/// country code is included in the response or logged.
pub async fn detect(State(state): State<AppState>) -> Json<RegionDetectResponse> {
    Json(RegionDetectResponse {
        region_id: state.region_id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use crate::{rate_limit, router_for_test, AppState};

    fn region_state(region_id: &str) -> AppState {
        use async_trait::async_trait;
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
            key_package::KeyPackageUseCase,
            media::MediaUseCase,
            messaging::MessagingUseCase,
        };
        use powehi_port_outbound::push_subscription_repo::PushSubscriptionRepository;

        struct Null;

        #[async_trait]
        impl AuthUseCase for Null {
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
            async fn login_init(
                &self,
                _: LoginInitRequest,
            ) -> Result<LoginInitResponse, DomainError> {
                unimplemented!()
            }
            async fn login_finish(
                &self,
                _: LoginFinishRequest,
            ) -> Result<SessionToken, DomainError> {
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

        #[async_trait]
        impl MessagingUseCase for Null {
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
        impl KeyPackageUseCase for Null {
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
        impl MediaUseCase for Null {
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
            async fn get_download_url(
                &self,
                _: &MediaId,
                _: &DeviceId,
            ) -> Result<String, DomainError> {
                unimplemented!()
            }
            async fn delete(&self, _: &MediaId, _: &DeviceId) -> Result<(), DomainError> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl PushSubscriptionRepository for Null {
            async fn upsert(&self, _: &PushSubscription) -> Result<(), DomainError> {
                Ok(())
            }
            async fn fetch_by_device(
                &self,
                _: &DeviceId,
            ) -> Result<Option<PushSubscription>, DomainError> {
                Ok(None)
            }
            async fn delete_by_device(&self, _: &DeviceId) -> Result<(), DomainError> {
                Ok(())
            }
        }

        #[async_trait]
        impl powehi_port_inbound::group::GroupUseCase for Null {
            async fn create_group(
                &self,
                _: &DeviceId,
                _: powehi_domain::group::GroupId,
            ) -> Result<(), DomainError> {
                unimplemented!()
            }
            async fn add_member(
                &self,
                _: &DeviceId,
                _: &powehi_domain::group::GroupId,
                _: &DeviceId,
                _: powehi_domain::group::Epoch,
            ) -> Result<(), DomainError> {
                unimplemented!()
            }
            async fn remove_member(
                &self,
                _: &DeviceId,
                _: &powehi_domain::group::GroupId,
                _: &DeviceId,
                _: powehi_domain::group::Epoch,
            ) -> Result<(), DomainError> {
                unimplemented!()
            }
        }

        #[async_trait]
        impl powehi_port_inbound::invite::InviteUseCase for Null {
            async fn create_invite(
                &self,
                _: &DeviceId,
            ) -> Result<powehi_port_inbound::invite::CreatedInvite, DomainError> {
                unimplemented!()
            }
            async fn redeem_invite(
                &self,
                _: &str,
            ) -> Result<powehi_port_inbound::invite::RedeemedInvite, DomainError> {
                unimplemented!()
            }
        }

        use powehi_port_outbound::cache::CachePort;
        use std::collections::HashMap;
        use std::time::Duration;

        struct EmptyCache;
        #[async_trait]
        impl CachePort for EmptyCache {
            async fn get(&self, _: &str) -> Result<Option<Vec<u8>>, DomainError> {
                Ok(None)
            }
            async fn set(
                &self,
                _: &str,
                _: Vec<u8>,
                _: Option<Duration>,
            ) -> Result<(), DomainError> {
                Ok(())
            }
            async fn delete(&self, _: &str) -> Result<(), DomainError> {
                Ok(())
            }
            async fn exists(&self, _: &str) -> Result<bool, DomainError> {
                Ok(false)
            }
        }
        let _ = HashMap::<String, Vec<u8>>::new(); // suppress unused import warning

        AppState {
            region_id: region_id.to_string(),
            auth: Arc::new(Null),
            group: Arc::new(Null),
            messaging: Arc::new(Null),
            key_package: Arc::new(Null),
            media: Arc::new(Null),
            push_sub_repo: Arc::new(Null),
            invite: Arc::new(Null),
            cache: Arc::new(EmptyCache),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        }
    }

    #[tokio::test]
    async fn detect_returns_configured_region_id() {
        let app = router_for_test(
            region_state("eu-de-1"),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/detect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["region_id"], "eu-de-1");
    }

    #[tokio::test]
    async fn detect_returns_ap_region_id() {
        let app = router_for_test(
            region_state("ap-sin-1"),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/detect")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(json["region_id"], "ap-sin-1");
    }

    #[tokio::test]
    async fn detect_requires_no_authentication() {
        // The endpoint is pre-login (no Bearer token required).
        let app = router_for_test(
            region_state("eu-de-1"),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/detect")
                    // No Authorization header
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Must not 401 — region detection is a pre-login bootstrap endpoint
        assert_ne!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }
}
