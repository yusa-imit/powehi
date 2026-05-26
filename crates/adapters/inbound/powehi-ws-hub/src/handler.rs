//! WebSocket upgrade handler.
//!
//! Auth: same `Bearer <device_id_uuid>` scheme as the REST API.
//! After upgrade the socket streams `WsNotification` JSON frames.
//! The socket loop exits cleanly on client close or channel shutdown.
//!
//! Known deferred (Phase 5): notifications are broadcast globally (all devices
//! get every notification regardless of group membership). Clients filter by
//! polling the REST API. Per-group fan-out is scoped to Phase 5 hardening.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::{sync::broadcast, time::timeout};
use tracing::instrument;

use powehi_domain::device::DeviceId;

use crate::{WsHub, WsNotification};

/// Max inbound frame size: 4 KiB. The protocol is server-push only; clients
/// only send Close/Ping. Large frames from clients are a sign of abuse.
const MAX_FRAME_BYTES: usize = 4 * 1024;

/// Max time to wait for a single `socket.send` to complete.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[instrument(skip_all)]
pub async fn ws_handler(
    upgrade: WebSocketUpgrade,
    State(hub): State<Arc<WsHub>>,
    headers: HeaderMap,
) -> Response {
    match extract_device_id(&headers) {
        Ok(device_id) => {
            let rx = hub.subscribe();
            upgrade
                .max_message_size(MAX_FRAME_BYTES)
                .on_upgrade(move |socket| handle_socket(socket, device_id, rx))
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
            // Incoming client frame (close / ping / unexpected)
            msg = socket.recv() => {
                let should_break = match msg {
                    Some(Ok(Message::Close(_))) | None => true,
                    Some(Ok(Message::Ping(data))) => {
                        timeout(SEND_TIMEOUT, socket.send(Message::Pong(data)))
                            .await
                            .map_or(true, |r| r.is_err())
                    }
                    // Server-push only: disconnect on unexpected client frames
                    Some(Ok(_)) => true,
                    Some(Err(_)) => true,
                };
                if should_break {
                    break;
                }
            }
            // Outgoing notification
            notification = rx.recv() => {
                match notification {
                    Ok(n) => {
                        match serde_json::to_string(&n) {
                            Ok(json) => {
                                let sent = timeout(
                                    SEND_TIMEOUT,
                                    socket.send(Message::Text(json)),
                                )
                                .await;
                                if sent.map_or(true, |r| r.is_err()) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{header, HeaderMap, HeaderValue};

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
        );
        h
    }

    #[test]
    fn valid_device_uuid_accepted() {
        let id = uuid::Uuid::new_v4().to_string();
        let h = headers_with_bearer(&id);
        assert!(extract_device_id(&h).is_ok());
    }

    #[test]
    fn missing_authorization_header_is_401() {
        let h = HeaderMap::new();
        assert_eq!(extract_device_id(&h), Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn wrong_scheme_is_401() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(extract_device_id(&h), Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn non_uuid_bearer_token_is_401() {
        let h = headers_with_bearer("not-a-uuid");
        assert_eq!(extract_device_id(&h), Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn empty_bearer_is_401() {
        let h = headers_with_bearer("");
        assert_eq!(extract_device_id(&h), Err(StatusCode::UNAUTHORIZED));
    }
}
