//! Authenticated key-package routes (MLS KeyPackage distribution).
//!
//! All handlers require the `AuthenticatedDevice` extractor (401 without a valid
//! Bearer token). KeyPackage bytes are opaque TLS-serialized MLS material; they
//! are never logged. Logs carry only device UUIDs and counts.

use axum::{
    extract::{Path, State},
    Json,
};
use bytes::Bytes;
use powehi_domain::{device::DeviceId, error::DomainError, key_package::KeyPackageId};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

fn parse_device_id(raw: &str) -> Result<DeviceId, ApiError> {
    raw.parse::<DeviceId>()
        .map_err(|_| ApiError::from(DomainError::InvalidInput("malformed device id".into())))
}

#[derive(Deserialize)]
pub struct UploadRequest {
    pub packages: Vec<Vec<u8>>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub ids: Vec<KeyPackageId>,
}

pub async fn upload(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path(device_id): Path<String>,
    Json(req): Json<UploadRequest>,
) -> Result<Json<UploadResponse>, ApiError> {
    let device_id = parse_device_id(&device_id)?;
    // Ownership check: a device may only upload its own KeyPackages.
    // Uploading under a different device_id would enable MLS key substitution.
    if caller != device_id {
        return Err(ApiError::from(DomainError::Unauthorized));
    }
    tracing::info!(
        device_id = %device_id,
        package_count = req.packages.len(),
        "key_package.upload"
    );
    let packages: Vec<Bytes> = req.packages.into_iter().map(Bytes::from).collect();
    let ids = state.key_package.upload(&device_id, packages).await?;
    Ok(Json(UploadResponse { ids }))
}

#[derive(Serialize)]
pub struct FetchOneResponse {
    pub data: Vec<u8>,
}

pub async fn fetch_one(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path(device_id): Path<String>,
) -> Result<Json<FetchOneResponse>, ApiError> {
    let device_id = parse_device_id(&device_id)?;
    tracing::info!(
        caller = %caller,
        device_id = %device_id,
        "key_package.fetch_one"
    );
    let data = state.key_package.fetch_one(&device_id).await?;
    Ok(Json(FetchOneResponse {
        data: data.to_vec(),
    }))
}

#[derive(Serialize)]
pub struct CountResponse {
    pub count: u64,
}

pub async fn count(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path(device_id): Path<String>,
) -> Result<Json<CountResponse>, ApiError> {
    let device_id = parse_device_id(&device_id)?;
    let count = state.key_package.count(&device_id).await?;
    tracing::info!(
        caller = %caller,
        device_id = %device_id,
        count,
        "key_package.count"
    );
    Ok(Json(CountResponse { count }))
}
