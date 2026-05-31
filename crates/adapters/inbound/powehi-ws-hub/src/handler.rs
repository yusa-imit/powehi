//! WebSocket upgrade handler.
//!
//! Auth: `Authorization: Bearer <session_token>` resolved against the Redis
//! session store (same store used by the REST API middleware).  Any raw UUID
//! that is not a live session entry is rejected with 401.
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
use uuid::Uuid;

use powehi_domain::device::DeviceId;
use powehi_port_outbound::cache::CachePort;

use crate::{WsHubState, WsNotification};

/// Max inbound frame size: 4 KiB. The protocol is server-push only; clients
/// only send Close/Ping. Large frames from clients are a sign of abuse.
const MAX_FRAME_BYTES: usize = 4 * 1024;

/// Max time to wait for a single `socket.send` to complete.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

#[instrument(skip_all)]
pub async fn ws_handler(
    upgrade: WebSocketUpgrade,
    State(state): State<WsHubState>,
    headers: HeaderMap,
) -> Response {
    match extract_device_id(&headers, &state.cache).await {
        Ok(device_id) => {
            let rx = state.hub.subscribe();
            upgrade
                .max_message_size(MAX_FRAME_BYTES)
                .on_upgrade(move |socket| handle_socket(socket, device_id, rx))
        }
        Err(status) => status.into_response(),
    }
}

async fn extract_device_id(
    headers: &HeaderMap,
    cache: &Arc<dyn CachePort>,
) -> Result<DeviceId, StatusCode> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|t| !t.is_empty())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let key = format!("session:{token}");
    let raw = cache
        .get(&key)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let bytes: [u8; 16] = raw.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(DeviceId::from(Uuid::from_bytes(bytes)))
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
    use async_trait::async_trait;
    use axum::http::{header, HeaderMap, HeaderValue};
    use powehi_domain::error::DomainError;
    use std::{collections::HashMap, sync::Mutex};

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl CachePort for FakeCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().get(key).cloned())
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            _ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
    }

    fn empty_cache() -> Arc<dyn CachePort> {
        Arc::new(FakeCache {
            store: Mutex::new(HashMap::new()),
        })
    }

    fn seeded_cache(token: &str, device_id: &DeviceId) -> Arc<dyn CachePort> {
        let c = FakeCache {
            store: Mutex::new(HashMap::new()),
        };
        c.store.lock().unwrap().insert(
            format!("session:{token}"),
            device_id.as_uuid().as_bytes().to_vec(),
        );
        Arc::new(c)
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn valid_session_token_resolves_device_id() {
        let device_id = DeviceId::new();
        let token = "valid-session-token";
        let cache = seeded_cache(token, &device_id);
        let h = headers_with_bearer(token);
        let result = extract_device_id(&h, &cache).await.unwrap();
        assert_eq!(result.to_string(), device_id.to_string());
    }

    #[tokio::test]
    async fn missing_authorization_header_is_401() {
        let cache = empty_cache();
        let h = HeaderMap::new();
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn wrong_scheme_is_401() {
        let cache = empty_cache();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn unknown_token_is_401() {
        let cache = empty_cache();
        let h = headers_with_bearer("unknown-token");
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn empty_bearer_is_401() {
        let cache = empty_cache();
        let h = headers_with_bearer("");
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn raw_device_uuid_without_session_is_401() {
        // Regression: R-1 fix — a bare DeviceId UUID that is not a live session
        // entry must be rejected. Previously the stub parsed Bearer as raw UUID.
        let cache = empty_cache();
        let device_id = DeviceId::new();
        let h = headers_with_bearer(&device_id.to_string());
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }
}
