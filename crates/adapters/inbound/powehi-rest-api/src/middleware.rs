//! Authentication extractor.
//!
//! Phase 3 stub: the Bearer token is interpreted as a raw `DeviceId` UUID.
//! Real session-token lookup (Redis-backed) is deferred until the Redis outbound
//! adapter is wired (see prd.md auth/session section). The extractor contract is
//! stable: any protected route that lists `AuthenticatedDevice` in its signature
//! is guaranteed to receive a 401 when the token is missing or malformed.

use async_trait::async_trait;
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts, StatusCode},
};
use powehi_domain::device::DeviceId;

pub struct AuthenticatedDevice(pub DeviceId);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedDevice {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));

        let device_id = token
            .ok_or(StatusCode::UNAUTHORIZED)?
            .parse::<DeviceId>()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthenticatedDevice(device_id))
    }
}
