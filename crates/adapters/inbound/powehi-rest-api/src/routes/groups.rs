//! Group management routes.
//!
//! Clients register their MLS group with the server before sending messages.
//! The creator becomes the first group member, enabling the fail-closed
//! membership check in `MessagingService`.
//!
//! Member add/remove are gated on caller membership (fail-closed): only an
//! existing member may add or remove another device.  This mirrors the
//! application-layer check in `GroupService` and prevents hijacking by
//! authenticated-but-non-member devices.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use powehi_domain::{
    device::DeviceId,
    group::{Epoch, GroupId},
};
use serde::Deserialize;
use uuid::Uuid;

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

/// Request body for adding a group member.
///
/// `epoch` is the MLS epoch at which the new member joined.  It is stored by
/// the server as opaque metadata for potential future use (e.g. audit, fan-out
/// scoping).  The server does NOT validate the epoch value; MLS semantics are
/// enforced end-to-end by the clients.
#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub epoch: u64,
}

/// `POST /v1/groups/:group_id/members/:device_id`
///
/// Registers `device_id` as a member of `group_id` at `epoch`.  The caller
/// (authenticated device) must already be a member of the group; the
/// application layer returns `Unauthorized` otherwise.
pub async fn add_member(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path((raw_group_id, raw_device_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<AddMemberRequest>,
) -> Result<StatusCode, ApiError> {
    let group_id = GroupId::from(raw_group_id);
    let target_device_id = DeviceId::from(raw_device_id);
    tracing::info!(
        caller = %caller,
        group_id = %group_id,
        "groups.add_member"
    );
    state
        .group
        .add_member(&caller, &group_id, &target_device_id, Epoch(req.epoch))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `DELETE /v1/groups/:group_id/members/:device_id`
///
/// Removes `device_id` from `group_id`.  The caller must already be a member
/// of the group; the application layer returns `Unauthorized` otherwise.
pub async fn remove_member(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path((raw_group_id, raw_device_id)): Path<(Uuid, Uuid)>,
) -> Result<StatusCode, ApiError> {
    let group_id = GroupId::from(raw_group_id);
    let target_device_id = DeviceId::from(raw_device_id);
    tracing::info!(
        caller = %caller,
        group_id = %group_id,
        "groups.remove_member"
    );
    state
        .group
        .remove_member(&caller, &group_id, &target_device_id, Epoch(0))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
