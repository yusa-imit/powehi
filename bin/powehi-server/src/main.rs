use anyhow::Result;
use axum::{routing::get, Router};
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    powehi_telemetry::init();
    info!("Powehi server starting — Phase 3 (REST API layer landed)");

    // The REST API router (`powehi_rest_api::router(state)`) is implemented and
    // tested, but it requires an `AppState` carrying the inbound use-case
    // implementations, which in turn need the outbound Postgres/Redis adapters.
    // Full DI wiring (composition root) is the next composition-root task; until
    // the outbound adapters are constructed here, the binary serves only the
    // liveness probe so deployment/health checks keep working.
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let addr = "0.0.0.0:8080";
    info!(addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
