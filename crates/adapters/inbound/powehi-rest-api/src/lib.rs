// Axum REST API adapter — Phase 3 implementation.
// Stub: exposes health check only.

use axum::{routing::get, Router};

pub fn router() -> Router {
    Router::new().route("/health", get(health))
}

async fn health() -> &'static str {
    "ok"
}
