use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    powehi_telemetry::init();
    info!("Powehi server starting — Phase 1 skeleton");

    // Full DI wiring implemented in Phase 3.
    // For now: start the health-check router only.
    let app = powehi_rest_api::router();
    let addr = "0.0.0.0:8080";
    info!(addr, "listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}
