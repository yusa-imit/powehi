//! `powehi status`: server health and routed region (prd.md §7A.2, §7.6).

use std::time::Duration;

use reqwest::Client;
use rustls::RootCertStore;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::pinning::{self, PinPolicy};

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
/// redirect could move a bearer token to another origin), rustls, TLS 1.3 only (7.11 F11),
/// narrowed by the compiled-in certificate pins (8.7).
pub fn http_client() -> Result<Client, StatusError> {
    let policy = PinPolicy::production().map_err(|_| StatusError::Unreachable)?;
    http_client_with(pinning::webpki_roots_store(), &policy)
}

/// [`http_client`] over explicit roots and pin policy; tests inject a private CA here.
pub fn http_client_with(roots: RootCertStore, policy: &PinPolicy) -> Result<Client, StatusError> {
    let tls = pinning::tls_config(roots, policy).map_err(|_| StatusError::Unreachable)?;
    Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .use_preconfigured_tls(tls)
        .build()
        .map_err(|_| StatusError::Unreachable)
}

/// Client for the pre-signed object-storage PUT: system web roots, no pin, no redirects, no
/// proxy, and a timeout sized for a 64 MiB body. It never carries the bearer token.
pub fn upload_client() -> Result<Client, StatusError> {
    Client::builder()
        .timeout(Duration::from_secs(600))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .https_only(false)
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

/// Writes the report: `key:  value` lines, or one JSON object with `--json`.
pub fn write_report(
    server: &Url,
    s: &ServerStatus,
    json: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    if json {
        let v = serde_json::json!({
            "server": server.as_str(),
            "healthy": s.healthy,
            "region": s.region_id,
        });
        return writeln!(out, "{v}");
    }
    writeln!(out, "server:  {server}")?;
    let health = if s.healthy {
        "ok"
    } else {
        "unexpected response"
    };
    writeln!(out, "health:  {health}")?;
    writeln!(out, "region:  {}", s.region_id)
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn http_client_offers_only_tls13() {
        let (port, hello) = crate::testsrv::client_hello_listener().await;
        let url = Url::parse(&format!("https://127.0.0.1:{port}/")).unwrap();
        assert!(http_client().unwrap().get(url).send().await.is_err());
        let hello = tokio::time::timeout(Duration::from_secs(5), hello)
            .await
            .unwrap()
            .unwrap();
        assert!(
            crate::testsrv::offers_only_tls13(&hello),
            "ClientHello offers more than TLS 1.3"
        );
    }

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

    /// A base path on the server URL is dropped: both endpoints are absolute paths.
    #[tokio::test]
    async fn base_path_on_the_server_url_is_ignored() {
        let root = serve(vec![
            ok("/health", "ok"),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let url = root.join("/prefix/").unwrap();
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(s.healthy);
        assert_eq!(s.region_id, "eu-de-1");
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
    async fn a_body_of_exactly_the_limit_is_accepted() {
        let url = serve(vec![
            ok("/health", &"x".repeat(MAX_RESPONSE_BYTES)),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(!s.healthy);
    }

    #[tokio::test]
    async fn an_oversized_region_body_is_rejected() {
        let url = serve(vec![
            ok("/health", "ok"),
            ok("/v1/region/detect", &"x".repeat(MAX_RESPONSE_BYTES + 1)),
        ])
        .await;
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
    async fn the_upload_client_does_not_follow_redirects() {
        let url = serve(vec![("/put", "307 Temporary Redirect", String::new())]).await;
        let resp = upload_client()
            .unwrap()
            .get(url.join("/put").unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 307);
    }

    #[tokio::test]
    async fn unreachable_server() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", l.local_addr().unwrap())).unwrap();
        drop(l);
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::Unreachable));
    }

    #[test]
    fn region_id_length_and_charset_boundaries() {
        assert!(valid_region_id("a"));
        assert!(valid_region_id(&"a".repeat(32)));
        assert!(!valid_region_id(""));
        assert!(!valid_region_id(&"a".repeat(33)));
        assert!(!valid_region_id("EU-de-1"));
        assert!(!valid_region_id("eu_de"));
        assert!(!valid_region_id("eu de"));
        assert!(!valid_region_id("eu\n"));
    }

    #[tokio::test]
    async fn non_ok_health_body_reports_unhealthy() {
        let url = serve(vec![
            ok("/health", "degraded"),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(!s.healthy);
        assert_eq!(s.region_id, "eu-de-1");
    }

    #[test]
    fn report_text_and_json() {
        let url = Url::parse("https://example.test/").unwrap();
        let st = ServerStatus {
            healthy: true,
            region_id: "eu-1".into(),
        };
        let mut t = Vec::new();
        write_report(&url, &st, false, &mut t).unwrap();
        assert_eq!(
            String::from_utf8(t).unwrap(),
            "server:  https://example.test/\nhealth:  ok\nregion:  eu-1\n"
        );
        let mut j = Vec::new();
        write_report(&url, &st, true, &mut j).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
        assert_eq!(v["healthy"], true);
        assert_eq!(v["region"], "eu-1");
        assert_eq!(v["server"], "https://example.test/");
        assert_eq!(j.iter().filter(|b| **b == b'\n').count(), 1);
    }

    #[test]
    fn unhealthy_report_says_unexpected_response() {
        let url = Url::parse("https://example.test/").unwrap();
        let st = ServerStatus {
            healthy: false,
            region_id: "eu-1".into(),
        };
        let mut t = Vec::new();
        write_report(&url, &st, false, &mut t).unwrap();
        assert_eq!(
            String::from_utf8(t).unwrap(),
            "server:  https://example.test/\nhealth:  unexpected response\nregion:  eu-1\n"
        );
        let mut j = Vec::new();
        write_report(&url, &st, true, &mut j).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
        assert_eq!(v["healthy"], false);
    }

    #[tokio::test]
    async fn region_endpoint_http_error_is_typed() {
        let url = serve(vec![ok("/health", "ok")]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(404)));
    }

    /// A 5xx on the region endpoint carries its status code, not a parse error.
    #[tokio::test]
    async fn region_5xx_is_http_status_with_the_code() {
        let url = serve(vec![
            ok("/health", "ok"),
            (
                "/v1/region/detect",
                "503 Service Unavailable",
                r#"{"region_id":"eu-de-1"}"#.to_string(),
            ),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(503)));
    }

    /// Unknown fields in the region reply are ignored, so the server can extend it.
    #[tokio::test]
    async fn extra_region_fields_are_ignored() {
        let url = serve(vec![
            ok("/health", "ok"),
            ok(
                "/v1/region/detect",
                r#"{"region_id":"eu-de-1","latency_ms":12,"note":"x"}"#,
            ),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(s.healthy);
        assert_eq!(s.region_id, "eu-de-1");
    }

    #[tokio::test]
    async fn region_json_without_region_id_is_bad_response() {
        let url = serve(vec![
            ok("/health", "ok"),
            ok("/v1/region/detect", r#"{"region":"eu-de-1"}"#),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    /// An empty region_id and a non-object top level are both refused, never shown.
    #[tokio::test]
    async fn empty_region_id_and_non_object_body_are_bad_response() {
        for body in [r#"{"region_id":""}"#, "[]", "null", r#""eu-de-1""#] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "body {body}");
        }
    }

    /// A 200 region response with an empty or whitespace-only body is `BadResponse`.
    #[tokio::test]
    async fn empty_region_body_is_bad_response() {
        for body in ["", " ", "\n"] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "body {body:?}");
        }
    }

    #[tokio::test]
    async fn region_id_of_a_non_string_type_is_bad_response() {
        for body in [
            r#"{"region_id":7}"#,
            r#"{"region_id":null}"#,
            r#"{"region_id":["a"]}"#,
        ] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "{body}");
        }
    }

    #[tokio::test]
    async fn duplicate_region_id_key_is_bad_response() {
        let body = r#"{"region_id":"kr-seoul","region_id":"kr-busan"}"#;
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    /// JSON whitespace around a valid region object is not trailing garbage.
    #[tokio::test]
    async fn whitespace_around_region_json_is_accepted() {
        let body = " \r\n{\"region_id\":\"kr-seoul\"}\n\t ";
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(s.healthy);
        assert_eq!(s.region_id, "kr-seoul");
    }

    #[tokio::test]
    async fn trailing_bytes_after_region_json_are_bad_response() {
        for body in [
            r#"{"region_id":"kr-seoul"} x"#,
            r#"{"region_id":"kr-seoul"}{}"#,
        ] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "{body}");
        }
    }

    #[tokio::test]
    async fn utf8_bom_before_region_json_is_bad_response() {
        let body = "\u{feff}{\"region_id\":\"kr-seoul\"}";
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    #[tokio::test]
    async fn out_of_charset_region_id_is_bad_response() {
        for body in [
            r#"{"region_id":""}"#,
            r#"{"region_id":"KR-Seoul"}"#,
            r#"{"region_id":"kr_seoul"}"#,
        ] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "{body}");
        }
    }

    /// JSON escapes that decode to terminal control bytes or non-ASCII never reach the screen.
    #[tokio::test]
    async fn json_escaped_control_and_unicode_region_id_is_bad_response() {
        for body in [
            r#"{"region_id":"\u001b[2Jx"}"#,
            r#"{"region_id":"kr\u0000seoul"}"#,
            r#"{"region_id":"kr-s\u00e9oul"}"#,
            r#"{"region_id":"kr-seoul\n"}"#,
        ] {
            let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", body)]).await;
            let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
            assert!(matches!(e, StatusError::BadResponse), "{body}");
        }
    }

    #[tokio::test]
    async fn region_id_length_limit_holds_end_to_end() {
        let ok32 = format!(r#"{{"region_id":"{}"}}"#, "a".repeat(32));
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", &ok32)]).await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert_eq!(s.region_id.len(), 32);
        let long = format!(r#"{{"region_id":"{}"}}"#, "a".repeat(33));
        let url = serve(vec![ok("/health", "ok"), ok("/v1/region/detect", &long)]).await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    #[tokio::test]
    async fn health_body_must_be_exactly_ok() {
        let url = serve(vec![
            ok("/health", "ok\n"),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(!s.healthy);
    }

    /// Only the exact bytes `ok` mean healthy: case, padding, and an empty body do not.
    #[tokio::test]
    async fn health_body_lookalikes_report_unhealthy() {
        for body in ["OK", "Ok", " ok", "ok ", "okk", ""] {
            let url = serve(vec![
                ok("/health", body),
                ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
            ])
            .await;
            let s = fetch(&http_client().unwrap(), &url).await.unwrap();
            assert!(!s.healthy, "{body:?}");
            assert_eq!(s.region_id, "eu-de-1");
        }
    }

    /// A trailing newline or CRLF after `ok` is not the exact health body.
    #[tokio::test]
    async fn health_body_with_line_ending_reports_unhealthy() {
        for body in ["ok\n", "ok\r\n", "\nok"] {
            let url = serve(vec![
                ok("/health", body),
                ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
            ])
            .await;
            let s = fetch(&http_client().unwrap(), &url).await.unwrap();
            assert!(!s.healthy, "{body:?}");
        }
    }

    /// Any 2xx health reply counts as reachable; only the exact `ok` body is healthy.
    #[tokio::test]
    async fn non_200_success_health_status_reports_unhealthy() {
        let url = serve(vec![
            ("/health", "204 No Content", String::new()),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let s = fetch(&http_client().unwrap(), &url).await.unwrap();
        assert!(!s.healthy);
        assert_eq!(s.region_id, "eu-de-1");
    }

    /// A 2xx region reply without a body (204) is `BadResponse`, not a status error.
    #[tokio::test]
    async fn region_204_no_content_is_bad_response() {
        let url = serve(vec![
            ok("/health", "ok"),
            ("/v1/region/detect", "204 No Content", String::new()),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::BadResponse));
    }

    /// A failing health check is an error even when the region endpoint would answer.
    #[tokio::test]
    async fn health_404_is_http_status_even_with_region_available() {
        let url = serve(vec![
            ("/health", "404 Not Found", String::new()),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(404)));
    }

    /// A 503 on /health is `HttpStatus(503)` even when the region endpoint would answer.
    #[tokio::test]
    async fn health_5xx_is_http_status_even_with_region_available() {
        let url = serve(vec![
            ("/health", "503 Service Unavailable", String::new()),
            ok("/v1/region/detect", r#"{"region_id":"eu-de-1"}"#),
        ])
        .await;
        let e = fetch(&http_client().unwrap(), &url).await.unwrap_err();
        assert!(matches!(e, StatusError::HttpStatus(503)));
    }

    /// A writer that fails on every write.
    struct Broken;

    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn report_write_failure_is_returned_in_both_formats() {
        let url = Url::parse("https://example.test/").unwrap();
        let st = ServerStatus {
            healthy: true,
            region_id: "eu-1".into(),
        };
        assert!(write_report(&url, &st, false, &mut Broken).is_err());
        assert!(write_report(&url, &st, true, &mut Broken).is_err());
    }

    mod props {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// The charset gate is exactly `[a-z0-9-]{1,32}`, whatever the server sends.
            #[test]
            fn region_id_matches_grammar(id in ".{0,40}") {
                let model = (1..=32).contains(&id.len())
                    && id.chars().all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'));
                prop_assert_eq!(valid_region_id(&id), model);
            }

            /// An accepted id never carries a control byte into either report format, and the
            /// JSON report stays one line that round-trips the id.
            #[test]
            fn accepted_ids_print_clean(id in "[a-z0-9-]{1,32}", healthy in any::<bool>()) {
                prop_assert!(valid_region_id(&id));
                let url = Url::parse("https://example.test/").unwrap();
                let st = ServerStatus { healthy, region_id: id.clone() };
                let mut t = Vec::new();
                write_report(&url, &st, false, &mut t).unwrap();
                prop_assert!(t.iter().all(|b| *b == b'\n' || (0x20..0x7f).contains(b)));
                prop_assert_eq!(t.iter().filter(|b| **b == b'\n').count(), 3);
                let mut j = Vec::new();
                write_report(&url, &st, true, &mut j).unwrap();
                prop_assert_eq!(j.iter().filter(|b| **b == b'\n').count(), 1);
                let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
                prop_assert_eq!(v["region"].as_str(), Some(id.as_str()));
                prop_assert_eq!(v["healthy"].as_bool(), Some(healthy));
            }
        }
    }
}
