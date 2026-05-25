//! Public authentication routes (OPAQUE register/login).
//!
//! These routes are intentionally unauthenticated (no `AuthenticatedDevice`):
//! they bootstrap the session. The server only ever handles OPAQUE blobs and a
//! handle *hash* — never the plaintext handle. Logs therefore record only the
//! hash length and opaque internal IDs (rule: `no-plaintext-logging`).

use axum::{extract::State, Json};
use powehi_domain::user::UserId;
use powehi_port_inbound::auth::{
    LoginFinishRequest, LoginInitRequest, LoginInitResponse, RegistrationFinishRequest,
    RegistrationInitRequest, RegistrationInitResponse, SessionToken,
};

use crate::{error::ApiError, AppState};

pub async fn register_init(
    State(state): State<AppState>,
    Json(req): Json<RegistrationInitRequest>,
) -> Result<Json<RegistrationInitResponse>, ApiError> {
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
) -> Result<Json<UserId>, ApiError> {
    tracing::info!(user_id = %req.user_id, "auth.register_finish");
    let user_id = state.auth.register_finish(req).await?;
    Ok(Json(user_id))
}

pub async fn login_init(
    State(state): State<AppState>,
    Json(req): Json<LoginInitRequest>,
) -> Result<Json<LoginInitResponse>, ApiError> {
    tracing::info!(handle_hash_len = req.handle_hash.len(), "auth.login_init");
    let resp = state.auth.login_init(req).await?;
    Ok(Json(resp))
}

pub async fn login_finish(
    State(state): State<AppState>,
    Json(req): Json<LoginFinishRequest>,
) -> Result<Json<SessionToken>, ApiError> {
    tracing::info!(user_id = %req.user_id, "auth.login_finish");
    let token = state.auth.login_finish(req).await?;
    Ok(Json(token))
}
