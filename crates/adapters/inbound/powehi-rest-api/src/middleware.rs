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

#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use powehi_domain::device::DeviceId;

    async fn extract(auth_header: Option<&str>) -> Result<AuthenticatedDevice, StatusCode> {
        let mut req = Request::builder().uri("/");
        if let Some(v) = auth_header {
            req = req.header(header::AUTHORIZATION, v);
        }
        let (mut parts, _) = req.body(()).unwrap().into_parts();
        AuthenticatedDevice::from_request_parts(&mut parts, &()).await
    }

    #[tokio::test]
    async fn valid_bearer_uuid_extracts_device_id() {
        let device_id = DeviceId::new();
        let token = format!("Bearer {}", device_id);
        let AuthenticatedDevice(extracted) = extract(Some(&token)).await.unwrap();
        assert_eq!(extracted.to_string(), device_id.to_string());
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let err = extract(None).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn non_uuid_token_returns_401() {
        let err = extract(Some("Bearer not-a-uuid")).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_scheme_returns_401() {
        let device_id = DeviceId::new();
        let err = extract(Some(&format!("Basic {}", device_id)))
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_bearer_returns_401() {
        let err = extract(Some("Bearer ")).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }
}
