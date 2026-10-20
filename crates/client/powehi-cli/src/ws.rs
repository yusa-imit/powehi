//! Realtime wake-ups over `GET /v1/ws` (prd.md §7.6, §7A.2).
//!
//! The server pushes opaque metadata only (type, group id, envelope id): never ciphertext. A
//! frame for our conversation is therefore just a hint to fetch through the normal inbox path,
//! which is also the catch-up path after a reconnect. The socket is authenticated with the
//! Bearer header at upgrade time; the token is never logged or put in the URL. At most
//! [`MAX_RETRIES`] consecutive failed connects are attempted before the caller is told
//! realtime delivery is gone.

use std::time::Duration;

use futures_util::StreamExt as _;
use tokio::sync::mpsc::Sender;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::client::IntoClientRequest as _;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use url::Url;
use uuid::Uuid;

use crate::chat::Event;
use crate::pinning::{self, PinPolicy};

/// Consecutive failed (re)connects before giving up (prd.md §7.6).
pub const MAX_RETRIES: u32 = 3;
/// Largest frame accepted; notifications are a few hundred bytes.
const MAX_FRAME_BYTES: usize = 16 * 1024;
/// A connection that lasted less than this did not work: it does not refill the retry budget,
/// so a server that accepts and drops at once cannot keep us reconnecting forever.
const STABLE_AFTER: Duration = Duration::from_secs(5);
/// Wake-ups forwarded per connection, a hard bound so a hostile server cannot spin us forever.
const MAX_FRAMES_PER_CONNECTION: u64 = 1_000_000;

/// The `/v1/ws` URL for a server base URL (`http` -> `ws`, `https` -> `wss`).
pub fn ws_url(server: &Url) -> Option<Url> {
    let mut url = server.join("/v1/ws").ok()?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return None,
    };
    url.set_scheme(scheme).ok()?;
    Some(url)
}

/// True when `text` is a notification about `group_id`.
pub fn is_wake_for(text: &str, group_id: Uuid) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.get("group_id")?.as_str()?.parse::<Uuid>().ok())
        == Some(group_id)
}

/// Bound on TCP + TLS + upgrade, matching the REST client's request timeout in spirit.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// TLS for `wss://` only (`ws://` ignores it): the REST client's roots, TLS 1.3 only and the
/// same certificate pins (8.7).
fn tls_connector() -> Option<tokio_tungstenite::Connector> {
    let policy = PinPolicy::production().ok()?;
    let config = pinning::tls_config(pinning::webpki_roots_store(), &policy).ok()?;
    Some(tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(
        config,
    )))
}

/// Why one connection ended.
enum Ended {
    /// Connected and then dropped: the retry budget starts over.
    AfterConnect,
    NeverConnected,
    /// The receiver is gone: stop quietly.
    Closed,
}

/// Keeps a socket open, sending [`Event::Wake`] for each notification about `group_id` and
/// after every successful (re)connect (catch-up). Sends [`Event::RealtimeLost`] and returns
/// after [`MAX_RETRIES`] consecutive failures. `backoff` is the first delay; it doubles.
pub async fn wake_loop(
    server: Url,
    bearer: zeroize::Zeroizing<String>,
    group_id: Uuid,
    tx: Sender<Event>,
    backoff: Duration,
) {
    let Some(url) = ws_url(&server) else {
        let _ = tx.send(Event::RealtimeLost).await;
        return;
    };
    let mut failures = 0u32;
    loop {
        match one_connection(&url, &bearer, group_id, &tx).await {
            Ended::Closed => return,
            Ended::AfterConnect => failures = 0,
            Ended::NeverConnected => {}
        }
        if failures >= MAX_RETRIES {
            let _ = tx.send(Event::RealtimeLost).await;
            return;
        }
        sleep(backoff.saturating_mul(1 << failures)).await;
        failures += 1;
    }
}

/// The upgrade `Authorization` value, marked sensitive so header `Debug` output redacts it
/// (tungstenite's own trace-level raw-request log is not covered: never install a trace logger).
fn auth_header(bearer: &str) -> Option<tokio_tungstenite::tungstenite::http::HeaderValue> {
    let mut value = tokio_tungstenite::tungstenite::http::HeaderValue::from_str(bearer).ok()?;
    value.set_sensitive(true);
    debug_assert!(value.is_sensitive());
    Some(value)
}

async fn one_connection(url: &Url, bearer: &str, group_id: Uuid, tx: &Sender<Event>) -> Ended {
    let Ok(mut request) = url.as_str().into_client_request() else {
        return Ended::NeverConnected;
    };
    let Some(value) = auth_header(bearer) else {
        return Ended::NeverConnected;
    };
    request.headers_mut().insert("authorization", value);
    let config = WebSocketConfig {
        max_message_size: Some(MAX_FRAME_BYTES),
        max_frame_size: Some(MAX_FRAME_BYTES),
        ..WebSocketConfig::default()
    };
    let Some(connector) = tls_connector() else {
        return Ended::NeverConnected;
    };
    let connecting = tokio_tungstenite::connect_async_tls_with_config(
        request,
        Some(config),
        false,
        Some(connector),
    );
    let Ok(Ok((mut socket, _))) = tokio::time::timeout(CONNECT_TIMEOUT, connecting).await else {
        return Ended::NeverConnected;
    };
    // Anything that arrived while we were disconnected is fetched now.
    if tx.send(Event::Wake).await.is_err() {
        return Ended::Closed;
    }
    let started = tokio::time::Instant::now();
    for _ in 0..MAX_FRAMES_PER_CONNECTION {
        match socket.next().await {
            Some(Ok(Message::Text(text))) if is_wake_for(&text, group_id) => {
                if tx.send(Event::Wake).await.is_err() {
                    return Ended::Closed;
                }
            }
            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
            Some(Ok(_)) => {}
        }
    }
    if started.elapsed() >= STABLE_AFTER {
        Ended::AfterConnect
    } else {
        Ended::NeverConnected
    }
}

#[cfg(test)]
mod tests;
