//! Public authentication routes (OPAQUE register/login) and authenticated
//! device management routes (multi-device registration and revocation).
//!
//! OPAQUE routes are intentionally unauthenticated: they bootstrap the session.
//! Device management routes require `AuthenticatedDevice` (Bearer token).
//! The server only ever handles OPAQUE blobs and a handle *hash* — never the
//! plaintext handle. Logs record only opaque internal IDs (rule: `no-plaintext-logging`).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use metrics::counter;
use powehi_domain::{device::DeviceId, error::DomainError};
use powehi_port_inbound::auth::{
    DeviceRegistrationRequest, DeviceRegistrationResponse, LoginFinishRequest, LoginInitRequest,
    LoginInitResponse, RegistrationFinishRequest, RegistrationFinishResponse,
    RegistrationInitRequest, RegistrationInitResponse, SessionToken,
};

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

const HANDLE_HASH_LEN: usize = 32; // SHA-256 output is always 32 bytes

pub async fn register_init(
    State(state): State<AppState>,
    Json(req): Json<RegistrationInitRequest>,
) -> Result<Json<RegistrationInitResponse>, ApiError> {
    if req.handle_hash.len() != HANDLE_HASH_LEN {
        return Err(ApiError::from(DomainError::InvalidInput(
            "handle_hash must be 32 bytes".into(),
        )));
    }
    if !state.handle_rate_limiter.check(&req.handle_hash) {
        return Err(ApiError::too_many_requests());
    }
    tracing::info!(
        handle_hash_len = req.handle_hash.len(),
        "auth.register_init"
    );
    let resp = state.auth.register_init(req).await?;
    Ok(Json(resp))
}

pub async fn register_finish(
    State(state): State<AppState>,
    Json(req): Json<RegistrationFinishRequest>,
) -> Result<Json<RegistrationFinishResponse>, ApiError> {
    match state.auth.register_finish(req).await {
        Ok(resp) => {
            counter!("auth_register_total", "result" => "success").increment(1);
            tracing::info!(user_id = %resp.user_id, "auth.register_finish");
            Ok(Json(resp))
        }
        Err(e) => {
            counter!("auth_register_total", "result" => "failure").increment(1);
            Err(ApiError::from(e))
        }
    }
}

pub async fn login_init(
    State(state): State<AppState>,
    Json(req): Json<LoginInitRequest>,
) -> Result<Json<LoginInitResponse>, ApiError> {
    if req.handle_hash.len() != HANDLE_HASH_LEN {
        return Err(ApiError::from(DomainError::InvalidInput(
            "handle_hash must be 32 bytes".into(),
        )));
    }
    if !state.handle_rate_limiter.check(&req.handle_hash) {
        return Err(ApiError::too_many_requests());
    }
    tracing::info!(handle_hash_len = req.handle_hash.len(), "auth.login_init");
    let resp = state.auth.login_init(req).await?;
    Ok(Json(resp))
}

pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<SessionToken>, ApiError> {
    match state.auth.login_finish(req).await {
        Ok(token) => {
            counter!("auth_login_total", "result" => "success").increment(1);
            tracing::info!("auth.login_finish");
            Ok(Json(token))
        }
        Err(e) => {
            counter!("auth_login_total", "result" => "failure").increment(1);
            Err(ApiError::from(e))
        }
    }
}

/// `POST /v1/auth/devices` — register an additional device for the current user.
///
/// Requires an active session (Bearer token). The `mls_credential` field carries
/// the new device's MLS BasicCredential bytes — the server stores this opaque
/// blob without inspection. Returns the server-assigned DeviceId for the new device.
pub async fn register_new_device(
    State(state): State<AppState>,
    AuthenticatedDevice(current_device_id): AuthenticatedDevice,
    Json(req): Json<DeviceRegistrationRequest>,
) -> Result<Json<DeviceRegistrationResponse>, ApiError> {
    let device = state
        .device_repo
        .find_by_id(&current_device_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::from(DomainError::NotFound("device".into())))?;
    let new_device_id = state.auth.register_device(&device.user_id, req).await?;
    tracing::info!("auth.register_new_device");
    Ok(Json(DeviceRegistrationResponse {
        device_id: new_device_id,
    }))
}

/// `DELETE /v1/auth/devices/:id` — revoke a device owned by the current user.
///
/// Requires an active session (Bearer token). Invalidates all active sessions for
/// the target device and removes it from the device store. Returns 401 if the
/// target device does not belong to the authenticated user.
pub async fn revoke_device_handler(
    State(state): State<AppState>,
    AuthenticatedDevice(current_device_id): AuthenticatedDevice,
    Path(target_id): Path<DeviceId>,
) -> Result<StatusCode, ApiError> {
    let device = state
        .device_repo
        .find_by_id(&current_device_id)
        .await
        .map_err(ApiError::from)?
        .ok_or_else(|| ApiError::from(DomainError::NotFound("device".into())))?;
    // Map NotFound → Unauthorized so that "device does not exist" and
    // "device belongs to another user" are indistinguishable to the caller.
    // DeviceIds are 122-bit UUIDs, but a timing/status oracle still shouldn't exist.
    state
        .auth
        .revoke_device(&device.user_id, &target_id)
        .await
        .map_err(|e| match e {
            DomainError::NotFound(_) => ApiError::from(DomainError::Unauthorized),
            other => ApiError::from(other),
        })?;
    tracing::info!("auth.revoke_device");
    Ok(StatusCode::NO_CONTENT)
}
