//! Group management routes.
//!
//! Clients register their MLS group with the server before sending messages.
//! The creator becomes the first group member, enabling the fail-closed
//! membership check in `MessagingService`.

use axum::{extract::State, http::StatusCode, Json};
use powehi_domain::group::GroupId;
use serde::Deserialize;

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

#[derive(Deserialize)]
pub struct CreateGroupRequest {
    pub group_id: GroupId,
}

pub async fn create_group(
    State(state): State<AppState>,
    AuthenticatedDevice(creator): AuthenticatedDevice,
    Json(req): Json<CreateGroupRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        creator = %creator,
        group_id = %req.group_id,
        "groups.create_group"
    );
    state.group.create_group(&creator, req.group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
