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
use serde::{Deserialize, Serialize};
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

/// Response body for `GET /v1/groups/:group_id/pending-removals`.
///
/// Device UUIDs only — routing metadata, never key material or ciphertext.
#[derive(Serialize)]
pub struct PendingRemovalsResponse {
    pub device_ids: Vec<DeviceId>,
}

/// `GET /v1/groups/:group_id/pending-removals`
///
/// Returns the devices whose MLS Remove the group's remaining members still
/// owe. The caller must already be a member of `group_id`; the application
/// layer returns `Unauthorized` otherwise, which surfaces as `401
/// Unauthorized` via `ApiError`. The server can never perform the Remove
/// itself (no group state, no keys — prd.md §5.4, §8.5), so this endpoint
/// exists purely so clients can discover the work they must do.
pub async fn list_pending_removals(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path(raw_group_id): Path<Uuid>,
) -> Result<Json<PendingRemovalsResponse>, ApiError> {
    let group_id = GroupId::from(raw_group_id);
    tracing::info!(
        caller = %caller,
        group_id = %group_id,
        "groups.list_pending_removals"
    );
    let device_ids = state
        .group
        .list_pending_removals(&caller, &group_id)
        .await?;
    Ok(Json(PendingRemovalsResponse { device_ids }))
}

/// Maximum number of device ids returned by
/// `GET /v1/groups/:group_id/members` in one response.
///
/// Group membership itself is uncapped in this codebase
/// (`MAX_FAN_OUT_RECIPIENTS` bounds push fan-out, not membership — see
/// `powehi_application::messaging_service`), so without a cap here a single
/// authenticated member could pull O(group size) egress per request at the
/// api_governor's sustained rate. Aligned with `MAX_FAN_OUT_RECIPIENTS`
/// (512) for consistency with the other group-size amplification cap.
/// security-auditor finding, cycle 454.
pub(crate) const MAX_MEMBERS_RESPONSE: usize = 512;

/// Response body for `GET /v1/groups/:group_id/members`.
///
/// Device UUIDs only — routing metadata, never key material or ciphertext.
/// `joined_at_epoch` is deliberately NOT exposed: the domain layer carries
/// it for future use, but no client needs it and it is one more piece of
/// metadata surface (prd.md §3.3 minimalism, P5).
///
/// `device_ids` is sorted by device UUID, NOT by join order. The repository
/// returns rows `ORDER BY joined_at_epoch ASC`; serving that order would
/// leak a monotone function of the very field this response drops, so the
/// handler re-sorts into a canonical, information-free order. It also makes
/// truncation deterministic and stable across calls.
///
/// This "information-free" property holds ONLY because `DeviceId` wraps a
/// random UUIDv4 (`DeviceId::new()` -> `Uuid::new_v4()`). If device-id
/// generation ever moves to a time-sortable UUID (e.g. UUIDv7), sorting by
/// UUID would silently become a monotone function of registration time and
/// reopen the exact join-order channel this sort was added to close.
///
/// `truncated` is `true` when the group has more than
/// `MAX_MEMBERS_RESPONSE` members and `device_ids` is therefore a PREFIX,
/// not the full membership. This flag exists because this endpoint's whole
/// purpose is letting a client reconcile its own MLS ratchet tree against
/// the server's device list (prd.md §5.4): a silently truncated list would
/// make legitimate, present devices look absent — turning the defence into
/// the exact false-eviction attack it is meant to prevent. A client MUST
/// NOT treat absence from a `truncated` response as evidence of anything.
#[derive(Serialize)]
pub struct MembersResponse {
    pub device_ids: Vec<DeviceId>,
    pub truncated: bool,
}

/// `GET /v1/groups/:group_id/members`
///
/// Returns the devices the server records as members of `group_id`. The
/// caller must already be a member; the application layer returns
/// `Unauthorized` otherwise, which surfaces as `401 Unauthorized` via
/// `ApiError` — an unknown group id is answered identically at the response
/// level, so this endpoint is not a group-existence oracle in its status,
/// body, or error code (rejection latency still scales with the real
/// group's size, a side channel shared with the sibling guards this is
/// modeled on). This is intended as one half of the local cross-check for
/// the server-reported `pending-removals` signal (prd.md §5.4): the other
/// half — exposing a device_id-to-MLS-leaf mapping from the WASM crypto
/// layer so a client can actually join this list against its own ratchet
/// tree — does not exist yet, so reconciliation is not yet possible end to
/// end. See `MembersResponse` for the ordering and truncation contract.
pub async fn list_members(
    State(state): State<AppState>,
    AuthenticatedDevice(caller): AuthenticatedDevice,
    Path(raw_group_id): Path<Uuid>,
) -> Result<Json<MembersResponse>, ApiError> {
    let group_id = GroupId::from(raw_group_id);
    tracing::info!(
        caller = %caller,
        group_id = %group_id,
        "groups.list_members"
    );
    let mut device_ids: Vec<DeviceId> = state
        .group
        .list_members(&caller, &group_id)
        .await?
        .into_iter()
        .map(|m| m.device_id)
        .collect();
    // Canonical order first, then truncate: truncation must not depend on
    // the repository's join-order sort (see `MembersResponse` doc).
    device_ids.sort_by_key(|d| d.as_uuid());
    let truncated = device_ids.len() > MAX_MEMBERS_RESPONSE;
    device_ids.truncate(MAX_MEMBERS_RESPONSE);
    Ok(Json(MembersResponse {
        device_ids,
        truncated,
    }))
}
