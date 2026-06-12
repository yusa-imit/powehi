//! Zero-knowledge HTTP request metrics middleware.
//!
//! Records per-request counters and latency histograms that satisfy the
//! no-plaintext-logging invariant (prd.md §13.2): labels are limited to HTTP
//! method and numeric status code — **never** the request URI or any path
//! parameter that could carry a device ID, envelope ID, or user token.
//!
//! Emitted metrics:
//! - `http_requests_total{method, status}` — request count
//! - `http_request_duration_seconds{method, status}` — latency histogram
//!
//! These are scraped by Prometheus on the internal admin port (`:9090/metrics`);
//! the admin router is never exposed through the public ingress.

use axum::{extract::Request, middleware::Next, response::Response};
use metrics::{counter, histogram};
use std::time::Instant;

/// Tower middleware that records `http_requests_total` and
/// `http_request_duration_seconds` for every request.
///
/// # Security invariant (prd.md §13.2 + no-plaintext-logging rule)
///
/// Labels are restricted to:
/// - `method`: the HTTP verb (GET / POST / DELETE / …).  Comes from
///   `request.method()` — a fixed ASCII vocabulary, never user-supplied.
/// - `status`: the 3-digit numeric HTTP status code ("200", "401", …).
///   Comes from `response.status().as_u16()` — a bounded integer, not
///   a path parameter and not user-controlled content.
///
/// The request URI is deliberately **not** recorded: routes like
/// `/v1/messages/:id` or `/v1/auth/devices/:id` embed UUID path parameters
/// that would expose device IDs and envelope IDs in aggregated metrics.
pub async fn record_http_metrics(request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_owned();
    let start = Instant::now();

    let response = next.run(request).await;

    let elapsed = start.elapsed().as_secs_f64();
    let status = response.status().as_u16().to_string();

    counter!(
        "http_requests_total",
        "method" => method.clone(),
        "status" => status.clone()
    )
    .increment(1);

    histogram!(
        "http_request_duration_seconds",
        "method" => method,
        "status" => status
    )
    .record(elapsed);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware, routing::get, Router};
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/health", get(|| async { "ok" }))
            .route(
                "/v1/devices/:id",
                get(|| async { axum::http::StatusCode::NOT_FOUND }),
            )
            .layer(middleware::from_fn(record_http_metrics))
    }

    // ── Behavioural tests (no global recorder required) ───────────────────────
    //
    // Security invariant (prd.md §13.2 + no-plaintext-logging rule):
    // Label values are `request.method().as_str()` (fixed ASCII HTTP verb
    // vocabulary) and `response.status().as_u16().to_string()` (bounded
    // 3-digit integer).  Neither can ever contain a UUID or any portion of the
    // request URI — this is guaranteed by the types, not by filtering.
    //
    // The existing lib.rs test `metrics_output_is_prometheus_text_format`
    // verifies that no UUID-shaped values appear in the rendered registry.
    // These tests focus on pass-through correctness (the middleware must not
    // alter the response status or body).

    #[tokio::test]
    async fn response_passes_through_with_correct_200_status() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn not_found_response_passes_through_unchanged() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn path_param_route_passes_through_without_leaking_path_into_labels() {
        // Makes a request whose path contains a UUID that looks like a device ID.
        // The response code (404) is the only label derived from this request;
        // the UUID itself never enters the label set (see module-level comment).
        let fake_device_uuid = "c0ffee00-dead-beef-cafe-000000000001";
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/devices/{fake_device_uuid}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_method_passes_through() {
        let resp = test_router()
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // The router has no DELETE /health → 405 or 404; status should pass through.
        assert!(
            resp.status().as_u16() >= 400,
            "DELETE on a GET-only route must return an error status"
        );
    }
}
