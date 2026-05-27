//! Public authentication routes (OPAQUE register/login).
//!
//! These routes are intentionally unauthenticated (no `AuthenticatedDevice`):
//! they bootstrap the session. The server only ever handles OPAQUE blobs and a
//! handle *hash* — never the plaintext handle. Logs therefore record only the
//! hash length and opaque internal IDs (rule: `no-plaintext-logging`).

use axum::{extract::State, Json};
use metrics::counter;
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
    match state.auth.register_finish(req).await {
        Ok(user_id) => {
            counter!("auth_register_total", "result" => "success").increment(1);
            tracing::info!(user_id = %user_id, "auth.register_finish");
            Ok(Json(user_id))
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
