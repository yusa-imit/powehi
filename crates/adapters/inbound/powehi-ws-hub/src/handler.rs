//! WebSocket upgrade handler.
//!
//! Auth: same `Bearer <device_id_uuid>` scheme as the REST API.
//! After upgrade the socket streams `WsNotification` JSON frames.
//! The socket loop exits cleanly on client close or channel shutdown.

use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::sync::broadcast;
use tracing::instrument;

use powehi_domain::device::DeviceId;

use crate::{WsHub, WsNotification};

#[instrument(skip_all)]
pub async fn ws_handler(
    upgrade: WebSocketUpgrade,
    State(hub): State<Arc<WsHub>>,
    headers: HeaderMap,
) -> Response {
    match extract_device_id(&headers) {
        Ok(device_id) => {
            let rx = hub.subscribe();
            upgrade.on_upgrade(move |socket| handle_socket(socket, device_id, rx))
        }
        Err(status) => status.into_response(),
    }
}

fn extract_device_id(headers: &HeaderMap) -> Result<DeviceId, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;
    token
        .parse::<DeviceId>()
        .map_err(|_| StatusCode::UNAUTHORIZED)
}

async fn handle_socket(
    mut socket: WebSocket,
    _device_id: DeviceId,
    mut rx: broadcast::Receiver<WsNotification>,
) {
    loop {
        tokio::select! {
            biased;
            // Incoming client frame (close / ping / etc.)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            // Outgoing notification
            notification = rx.recv() => {
                match notification {
                    Ok(n) => {
                        match serde_json::to_string(&n) {
                            Ok(json) => {
                                if socket.send(Message::Text(json)).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // ring buffer overflowed; skip missed frames, keep connection alive
                        continue;
                    }
                }
            }
        }
    }
}
