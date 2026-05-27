//! Authenticated messaging routes.
//!
//! Every handler requires the `AuthenticatedDevice` extractor; a request without
//! a valid Bearer token is rejected with 401 before the handler body runs.
//!
//! Security invariant: the opaque MLS payloads (`ciphertext`, `welcome`,
//! `commit`) are NEVER logged. Logs carry only internal UUIDs and a coarse size
//! bucket (rule: `no-plaintext-logging`).

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use metrics::counter;
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId},
    error::DomainError,
    group::GroupId,
};
use serde::{Deserialize, Serialize};

use crate::{error::ApiError, middleware::AuthenticatedDevice, AppState};

/// Coarse size bucket for logging — never the exact byte count, never the bytes.
fn size_bucket(len: usize) -> &'static str {
    match len {
        0..=1_024 => "<=1KB",
        1_025..=10_240 => "<=10KB",
        10_241..=102_400 => "<=100KB",
        _ => ">100KB",
    }
}

fn bad_input() -> ApiError {
    ApiError::from(DomainError::InvalidInput("malformed parameter".into()))
}

#[derive(Deserialize)]
pub struct SendMessageRequest {
    pub group_id: GroupId,
    pub ciphertext: Vec<u8>,
}

#[derive(Serialize)]
pub struct SendMessageResponse {
    pub envelope_id: EnvelopeId,
}

pub async fn send_message(
    State(state): State<AppState>,
    AuthenticatedDevice(sender): AuthenticatedDevice,
    Json(req): Json<SendMessageRequest>,
) -> Result<Json<SendMessageResponse>, ApiError> {
    tracing::info!(
        sender = %sender,
        group_id = %req.group_id,
        size_bucket = size_bucket(req.ciphertext.len()),
        "messaging.send_message"
    );
    let envelope_id = state
        .messaging
        .send_message(&sender, &req.group_id, Bytes::from(req.ciphertext))
        .await?;
    counter!("messages_sent_total", "kind" => "mls").increment(1);
    Ok(Json(SendMessageResponse { envelope_id }))
}

#[derive(Deserialize)]
pub struct SendWelcomeRequest {
    pub group_id: GroupId,
    pub welcome: Vec<u8>,
    pub target_device_id: DeviceId,
}

pub async fn send_welcome(
    State(state): State<AppState>,
    AuthenticatedDevice(sender): AuthenticatedDevice,
    Json(req): Json<SendWelcomeRequest>,
) -> Result<StatusCode, ApiError> {
    tracing::info!(
        sender = %sender,
        group_id = %req.group_id,
        target = %req.target_device_id,
        size_bucket = size_bucket(req.welcome.len()),
        "messaging.send_welcome"
    );
    state
        .messaging
        .send_welcome(
            &sender,
            &req.group_id,
            Bytes::from(req.welcome),
            &req.target_device_id,
        )
        .await?;
    counter!("messages_sent_total", "kind" => "welcome").increment(1);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct SendCommitRequest {
    pub group_id: GroupId,
    pub commit: Vec<u8>,
}

#[derive(Serialize)]
pub struct SendCommitResponse {
    pub epoch: u64,
}

pub async fn send_commit(
    State(state): State<AppState>,
    AuthenticatedDevice(sender): AuthenticatedDevice,
    Json(req): Json<SendCommitRequest>,
) -> Result<Json<SendCommitResponse>, ApiError> {
    tracing::info!(
        sender = %sender,
        group_id = %req.group_id,
        size_bucket = size_bucket(req.commit.len()),
        "messaging.send_commit"
    );
    let epoch = state
        .messaging
        .send_commit(&sender, &req.group_id, Bytes::from(req.commit))
        .await?;
    counter!("messages_sent_total", "kind" => "commit").increment(1);
    Ok(Json(SendCommitResponse { epoch: epoch.0 }))
}

#[derive(Deserialize)]
pub struct PollQuery {
    /// Unix timestamp (seconds). Only envelopes created after this are returned.
    pub since: Option<i64>,
}

pub async fn poll(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Query(query): Query<PollQuery>,
) -> Result<Json<Vec<Envelope>>, ApiError> {
    let since: Option<DateTime<Utc>> = match query.since {
        Some(ts) => Some(DateTime::<Utc>::from_timestamp(ts, 0).ok_or_else(bad_input)?),
        None => None,
    };
    let envelopes = state.messaging.poll_envelopes(&device_id, since).await?;
    tracing::info!(
        device_id = %device_id,
        returned = envelopes.len(),
        "messaging.poll"
    );
    Ok(Json(envelopes))
}

pub async fn ack(
    State(state): State<AppState>,
    AuthenticatedDevice(device_id): AuthenticatedDevice,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let envelope_id = id.parse::<EnvelopeId>().map_err(|_| bad_input())?;
    tracing::info!(
        device_id = %device_id,
        envelope_id = %envelope_id,
        "messaging.ack"
    );
    state
        .messaging
        .ack_envelope(&device_id, &envelope_id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
