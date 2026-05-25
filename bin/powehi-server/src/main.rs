use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;

use powehi_application::{
    auth_service::AuthService, key_package_service::KeyPackageService,
    messaging_service::MessagingService,
};
use powehi_postgres::{
    connect as pg_connect, run_migrations, PgDeviceRepository, PgEnvelopeRepository,
    PgGroupRepository, PgKeyPackageRepository, PgUserRepository,
};
use powehi_redis::{RedisCache, RedisEventBus};
use powehi_rest_api::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    powehi_telemetry::init();

    let cfg = powehi_config::load().context("load config")?;

    // ── Outbound infrastructure ─────────────────────────────────────────────

    let pool = pg_connect(&cfg.database_url)
        .await
        .context("connect postgres")?;
    run_migrations(&pool).await.context("run db migrations")?;

    let cache = Arc::new(
        RedisCache::new(&cfg.redis_url)
            .await
            .context("connect redis cache")?,
    );
    let event_bus = Arc::new(
        RedisEventBus::new(&cfg.redis_url)
            .await
            .context("connect redis event bus")?,
    );

    // ── Outbound repositories ───────────────────────────────────────────────

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let device_repo = Arc::new(PgDeviceRepository::new(pool.clone()));
    let envelope_repo = Arc::new(PgEnvelopeRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let key_package_repo = Arc::new(PgKeyPackageRepository::new(pool.clone()));

    // ── Application services ────────────────────────────────────────────────

    let auth: Arc<dyn powehi_port_inbound::auth::AuthUseCase> =
        Arc::new(AuthService::new(user_repo, device_repo));

    let messaging: Arc<dyn powehi_port_inbound::messaging::MessagingUseCase> =
        Arc::new(MessagingService::new(envelope_repo, group_repo, event_bus));

    let key_package: Arc<dyn powehi_port_inbound::key_package::KeyPackageUseCase> =
        Arc::new(KeyPackageService::new(key_package_repo));

    // ── HTTP server ─────────────────────────────────────────────────────────

    let state = AppState {
        auth,
        messaging,
        key_package,
    };

    let app = powehi_rest_api::router(state);
    let addr = format!("{}:{}", cfg.host, cfg.port);
    info!(addr = %addr, "listening");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;
    axum::serve(listener, app).await?;

    // suppress unused-variable warnings for cache (used in future WS hub wiring)
    drop(cache);
    Ok(())
}
