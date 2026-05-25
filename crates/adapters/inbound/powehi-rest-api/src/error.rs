//! API error mapping.
//!
//! Security invariant: responses expose ONLY a stable machine-readable `code`.
//! Internal `DomainError` messages (which may carry IDs or input fragments) are
//! never serialized into the HTTP body. See rule `no-plaintext-logging` and
//! prd.md threat model.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use powehi_domain::error::DomainError;
use serde::Serialize;

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
}

pub struct ApiError(StatusCode, ErrorBody);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<DomainError> for ApiError {
    fn from(e: DomainError) -> Self {
        let (status, code) = match e {
            DomainError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            DomainError::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),
            DomainError::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            DomainError::InvalidInput(_) => (StatusCode::BAD_REQUEST, "invalid_input"),
            DomainError::EpochMismatch { .. } => (StatusCode::CONFLICT, "epoch_mismatch"),
            DomainError::RegionMismatch { .. } => (StatusCode::BAD_GATEWAY, "region_mismatch"),
            DomainError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        ApiError(status, ErrorBody { code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    async fn body_of(e: DomainError) -> (StatusCode, String) {
        let resp = ApiError::from(e).into_response();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn not_found_maps_to_404_with_code_only() {
        let (status, body) = body_of(DomainError::NotFound("user-secret-id".into())).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, r#"{"code":"not_found"}"#);
        // The internal detail must never leak into the response body.
        assert!(!body.contains("user-secret-id"));
    }

    #[tokio::test]
    async fn invalid_input_body_contains_no_internal_message() {
        let (status, body) = body_of(DomainError::InvalidInput("raw handle abc".into())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!body.contains("raw handle"));
        assert_eq!(body, r#"{"code":"invalid_input"}"#);
    }

    #[tokio::test]
    async fn epoch_mismatch_maps_to_409() {
        let (status, body) = body_of(DomainError::EpochMismatch { expected: 5, got: 3 }).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(body, r#"{"code":"epoch_mismatch"}"#);
        assert!(!body.contains('5') && !body.contains('3'));
    }

    #[tokio::test]
    async fn region_mismatch_maps_to_502() {
        let (status, _) = body_of(DomainError::RegionMismatch {
            target: "ap-seoul".into(),
            local: "eu-central".into(),
        })
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn internal_maps_to_500_without_detail() {
        let (status, body) = body_of(DomainError::Internal("db connection string leaked".into())).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(!body.contains("db connection"));
        assert_eq!(body, r#"{"code":"internal"}"#);
    }
}
