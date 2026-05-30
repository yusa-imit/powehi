//! HTTP security headers middleware for all API responses.
//!
//! This layer adds defense-in-depth HTTP security headers to every response.
//! CSP is not set here because this server returns JSON, not HTML; the HTML
//! document is served by Cloudflare Pages which sets CSP via the `_headers` file.

use axum::{extract::Request, middleware::Next, response::Response};

pub async fn set_security_headers(req: Request, next: Next) -> Response {
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();

    // Prevents browsers from MIME-sniffing a response away from the declared type.
    h.insert(
        "x-content-type-options",
        axum::http::HeaderValue::from_static("nosniff"),
    );
    // Disallows this API from being loaded in any frame (clickjacking guard).
    h.insert(
        "x-frame-options",
        axum::http::HeaderValue::from_static("DENY"),
    );
    // Sends no referrer on cross-origin requests — prevents leaking API paths.
    h.insert(
        "referrer-policy",
        axum::http::HeaderValue::from_static("no-referrer"),
    );
    // Disables access to sensors/camera/mic — this is a JSON API, not a media app.
    h.insert(
        "permissions-policy",
        axum::http::HeaderValue::from_static("geolocation=(), camera=(), microphone=()"),
    );
    // HSTS: 2 years, subdomains, preload — enforces TLS on all future requests.
    h.insert(
        "strict-transport-security",
        axum::http::HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );

    resp
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware, routing::get, Router};
    use tower::ServiceExt;

    fn test_router() -> Router {
        Router::new()
            .route("/test", get(|| async { "ok" }))
            .layer(middleware::from_fn(set_security_headers))
    }

    async fn get_test_response() -> axum::response::Response {
        test_router()
            .oneshot(Request::builder().uri("/test").body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn sets_x_content_type_options_nosniff() {
        let resp = get_test_response().await;
        assert_eq!(
            resp.headers()
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff"),
        );
    }

    #[tokio::test]
    async fn sets_x_frame_options_deny() {
        let resp = get_test_response().await;
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("DENY"),
        );
    }

    #[tokio::test]
    async fn sets_referrer_policy_no_referrer() {
        let resp = get_test_response().await;
        assert_eq!(
            resp.headers()
                .get("referrer-policy")
                .and_then(|v| v.to_str().ok()),
            Some("no-referrer"),
        );
    }

    #[tokio::test]
    async fn sets_permissions_policy() {
        let resp = get_test_response().await;
        let val = resp
            .headers()
            .get("permissions-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            val.contains("geolocation=()"),
            "geolocation must be disabled"
        );
        assert!(val.contains("camera=()"), "camera must be disabled");
        assert!(val.contains("microphone=()"), "microphone must be disabled");
    }

    #[tokio::test]
    async fn sets_hsts_with_long_max_age() {
        let resp = get_test_response().await;
        let hsts = resp
            .headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            hsts.contains("max-age=63072000"),
            "HSTS max-age must be 2 years (63072000s), got: {hsts}"
        );
        assert!(
            hsts.contains("includeSubDomains"),
            "HSTS must include subdomains"
        );
        assert!(hsts.contains("preload"), "HSTS must be preload-eligible");
    }
}
