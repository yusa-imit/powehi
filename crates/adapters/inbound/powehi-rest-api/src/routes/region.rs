use axum::{extract::State, Json};
use powehi_domain::region::Tier;
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

/// Map the strongly-typed `Tier` enum onto a small wire-stable integer.
///
/// The JSON wire shape is `1` / `2` / `3` (NOT `"Tier1"` / `"Tier2"` / `"Tier3"`),
/// so we serialize the response struct's `tier` field via this helper. Pure
/// infrastructure metadata: the integer reveals nothing about users or content.
fn tier_as_u8(tier: &Tier) -> u8 {
    match tier {
        Tier::Tier1 => 1,
        Tier::Tier2 => 2,
        Tier::Tier3 => 3,
    }
}

fn serialize_tier_as_u8<S: serde::Serializer>(tier: &Tier, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_u8(tier_as_u8(tier))
}

#[derive(Serialize)]
pub struct RegionStatusResponse {
    pub region_id: String,
    /// Always `"active"` while this server is answering — if the server cannot
    /// serve, it cannot reply. No degraded/draining/PII states leak via this field.
    pub status: &'static str,
    /// Service tier as a wire-stable integer (1/2/3). See `tier_as_u8`.
    #[serde(serialize_with = "serialize_tier_as_u8")]
    pub tier: Tier,
}

/// Returns the current operational status of this region — `region_id`, a
/// constant `"active"` status, and the integer service tier.
///
/// Public, pre-login endpoint (prd.md §6.3). No auth, no PII, no logs of any
/// per-request value. Purpose: clients can verify routing + pick replication
/// expectations before login.
pub async fn status(State(state): State<AppState>) -> Json<RegionStatusResponse> {
    Json(RegionStatusResponse {
        region_id: state.region_id.clone(),
        status: "active",
        tier: state.region_tier,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    use crate::{rate_limit, router_for_test, AppState};

    fn region_state(region_id: &str, region_tier: powehi_domain::region::Tier) -> AppState {
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
            async fn list_devices(
                &self,
                _: &UserId,
            ) -> Result<Vec<powehi_port_inbound::auth::DeviceInfo>, DomainError> {
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

        #[async_trait]
        impl powehi_port_outbound::device_repo::DeviceRepository for Null {
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
            region_tier,
            auth: Arc::new(Null),
            group: Arc::new(Null),
            messaging: Arc::new(Null),
            key_package: Arc::new(Null),
            media: Arc::new(Null),
            push_sub_repo: Arc::new(Null),
            invite: Arc::new(Null),
            device_repo: Arc::new(Null),
            cache: Arc::new(EmptyCache),
            handle_rate_limiter: Arc::new(rate_limit::HandleRateLimiter::new()),
        }
    }

    #[tokio::test]
    async fn detect_returns_configured_region_id() {
        let app = router_for_test(
            region_state("eu-de-1", powehi_domain::region::Tier::Tier1),
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
            region_state("ap-sin-1", powehi_domain::region::Tier::Tier1),
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
            region_state("eu-de-1", powehi_domain::region::Tier::Tier1),
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

    // ── GET /v1/region/status tests (prd.md §6.3) ────────────────────────────

    #[tokio::test]
    async fn status_returns_active() {
        // Liveness contract: the only value `status` ever takes is "active".
        // If the server cannot serve, it cannot respond — so any 200 OK to
        // /v1/region/status implies status=="active". No degraded/draining state.
        let app = router_for_test(
            region_state("eu-de-1", powehi_domain::region::Tier::Tier1),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/status")
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
        assert_eq!(json["status"], "active");
    }

    #[tokio::test]
    async fn status_returns_tier1_as_integer_1() {
        // Wire-stability invariant: `tier` is serialized as a small integer
        // (1/2/3), NOT as the Rust enum variant name ("Tier1"). Clients across
        // languages can rely on integer comparison; renaming the Rust enum
        // must never break the JSON contract.
        let app = router_for_test(
            region_state("eu-de-1", powehi_domain::region::Tier::Tier1),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/status")
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
        assert!(
            json["tier"].is_u64(),
            "tier must serialize as an integer, got: {:?}",
            json["tier"]
        );
        assert_eq!(json["tier"].as_u64(), Some(1));
    }

    #[tokio::test]
    async fn status_returns_region_id() {
        // The `region_id` echoed back must exactly match the server config —
        // this is what the client uses to confirm the CF Worker routed it to
        // the intended region.
        let app = router_for_test(
            region_state("ap-sin-1", powehi_domain::region::Tier::Tier2),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/status")
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
        // Sanity: Tier2 also round-trips as integer 2.
        assert_eq!(json["tier"].as_u64(), Some(2));
    }

    #[tokio::test]
    async fn status_requires_no_authentication() {
        // The endpoint is pre-login (no Bearer token required).
        // Auth-bypass invariant: a missing Authorization header MUST NOT 401.
        let app = router_for_test(
            region_state("eu-de-1", powehi_domain::region::Tier::Tier1),
            rate_limit::auth_governor(),
            rate_limit::api_governor(),
        );
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/v1/region/status")
                    // No Authorization header
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    // ── tier_as_u8 helper unit tests ─────────────────────────────────────────

    #[test]
    fn tier_as_u8_maps_each_variant_to_its_integer() {
        // Wire-stability invariant for the JSON contract (prd.md §6.3).
        use powehi_domain::region::Tier;
        assert_eq!(super::tier_as_u8(&Tier::Tier1), 1);
        assert_eq!(super::tier_as_u8(&Tier::Tier2), 2);
        assert_eq!(super::tier_as_u8(&Tier::Tier3), 3);
    }
}
