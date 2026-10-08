//! `powehi status`: server health and routed region (prd.md §7A.2, §7.6).

use std::time::Duration;

use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Per-request deadline.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// Responses larger than this are rejected; both endpoints return a few bytes.
pub const MAX_RESPONSE_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum StatusError {
    #[error("could not reach the server")]
    Unreachable,
    #[error("server returned HTTP {0}")]
    HttpStatus(u16),
    #[error("response exceeded {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("unexpected response from the server")]
    BadResponse,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ServerStatus {
    pub healthy: bool,
    pub region_id: String,
}

#[derive(Deserialize)]
struct RegionDetect {
    region_id: String,
}

/// Builds the HTTP client used for all server calls: bounded timeout, no redirects (a
/// redirect could move a bearer token to another origin), rustls only.
pub fn http_client() -> Result<Client, StatusError> {
    Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| StatusError::Unreachable)
}

async fn get_bounded(client: &Client, url: Url) -> Result<Vec<u8>, StatusError> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|_| StatusError::Unreachable)?;
    if !resp.status().is_success() {
        return Err(StatusError::HttpStatus(resp.status().as_u16()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|_| StatusError::Unreachable)? {
        if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(StatusError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Region ids come from an untrusted server and are printed to the terminal, so only a
/// strict charset is accepted (no control characters, no escape sequences).
fn valid_region_id(id: &str) -> bool {
    (1..=32).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Queries `/health` and `/v1/region/detect`.
pub async fn fetch(client: &Client, server: &Url) -> Result<ServerStatus, StatusError> {
    let join = |p: &str| server.join(p).map_err(|_| StatusError::BadResponse);
    let health = get_bounded(client, join("/health")?).await?;
    let region = get_bounded(client, join("/v1/region/detect")?).await?;
    let region: RegionDetect =
        serde_json::from_slice(&region).map_err(|_| StatusError::BadResponse)?;
    if !valid_region_id(&region.region_id) {
        return Err(StatusError::BadResponse);
    }
    Ok(ServerStatus {
        healthy: health == b"ok",
        region_id: region.region_id,
    })
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// Serves canned `(status line, body)` per path until dropped.
    async fn serve(routes: Vec<(&'static str, &'static str, String)>) -> Url {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let routes = routes.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split_whitespace().nth(1).unwrap_or("").to_string();
                    let (status, body) = routes
                        .iter()
                        .find(|(p, _, _)| *p == path)
                        .map(|(_, s, b)| (*s, b.clone()))
                        .unwrap_or(("404 Not Found", String::new()));
                    let resp = format!(
                        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        Url::parse(&format!("http://{addr}")).unwrap()
    }

    fn ok(path: &'static str, body: &str) -> (&'static str, &'static str, String) {
        (path, "200 OK", body.to_string())
    }

    #[tokio::test]
    async fn healthy_server() {
        let url = serve(vec![
            ok("/health", "ok"),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert_eq!(
            s,
            ServerStatus {
                healthy: true,
                region_id: "eu-de-1".into()
            }
        );
    }

    #[tokio::test]
    async fn http_error_is_typed() {
        let url = serve(vec![("/health", "503 Service Unavailable", String::new())]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(503)));
    }

    #[tokio::test]
    async fn garbage_region_body_is_bad_response() {
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", "<html>")]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    #[tokio::test]
    async fn escape_sequences_in_region_are_rejected() {
        let url = serve(vec![
            ok("/health", "ok"),
            ok(
                "/v1/region/detect",
                r#"{"region_id":"x\u001b]0;PWNED\u0007"}"#,
            ),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    #[tokio::test]
    async fn oversized_body_is_rejected() {
        let url = serve(vec![ok("/health", &"x".repeat(MAX_RESPONSE_BYTES + 1))]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::TooLarge));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let url = serve(vec![("/health", "302 Found", String::new())]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(302)));
    }

    #[tokio::test]
    async fn unreachable_server() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", l.local_addr().unwrap())).unwrap();
        drop(l);
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::Unreachable));
    }
}
