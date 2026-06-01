//! Media pre-signed URL endpoints.
//!
//! Security invariant: the server NEVER receives ciphertext bytes. Clients
//! upload/download directly to/from R2 using short-lived pre-signed URLs.
//!
//! POST  /v1/media/upload-url        — allocate MediaId + get a pre-signed PUT URL
//! POST  /v1/media/:id/confirm       — mark upload complete (metadata only)
//! GET   /v1/media/:id/download-url  — get a pre-signed GET URL (uploader OR group member)
//! DELETE /v1/media/:id              — delete (uploader device only)

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use powehi_domain::{group::GroupId, media::MediaId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

/// 100 MB hard cap on media uploads. Must match `powehi_r2::MAX_MEDIA_BYTES`.
const MAX_UPLOAD_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Deserialize)]
pub struct UploadRequest {
    content_type: String,
    size_bytes: u64,
    /// MLS group this blob is being shared to. When set, any group member may download.
    group_id: Option<Uuid>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    media_id: Uuid,
    upload_url: String,
}

pub async fn request_upload(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Json(body): Json<UploadRequest>,
) -> Result<Json<UploadResponse>, ApiError> {
    if body.size_bytes == 0 || body.size_bytes > MAX_UPLOAD_BYTES {
        return Err(ApiError::from(
            powehi_domain::error::DomainError::InvalidInput("size_bytes out of range".into()),
        ));
    }
    let group_id = body.group_id.map(GroupId::from);
    let (media_id, url) = state
        .media
        .request_upload(
            &device_id,
            &body.content_type,
            body.size_bytes,
            group_id.as_ref(),
        )
        .await
        .map_err(ApiError::from)?;
    Ok(Json(UploadResponse {
        media_id: media_id.as_uuid(),
        upload_url: url,
    }))
}

pub async fn confirm_upload(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let media_id = MediaId::from(id);
    state
        .media
        .confirm_upload(&media_id, &device_id)
        .await
        .map_err(ApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct DownloadUrlResponse {
    download_url: String,
}

pub async fn get_download_url(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Path(id): Path<Uuid>,
) -> Result<Json<DownloadUrlResponse>, ApiError> {
    let media_id = MediaId::from(id);
    let url = state
        .media
        .get_download_url(&media_id, &device_id)
        .await
        .map_err(ApiError::from)?;
    Ok(Json(DownloadUrlResponse { download_url: url }))
}

pub async fn delete_media(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    let media_id = MediaId::from(id);
    state
        .media
        .delete(&media_id, &device_id)
        .await
        .map_err(ApiError::from)?;
    Ok(StatusCode::NO_CONTENT)
}
