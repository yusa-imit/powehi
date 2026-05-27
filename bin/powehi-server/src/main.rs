use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;

use powehi_application::{
    auth_service::AuthService, key_package_service::KeyPackageService, media_service::MediaService,
    messaging_service::MessagingService,
};
use powehi_opaque::OpaqueServer;
use powehi_postgres::{
    connect as pg_connect, run_migrations, PgDeviceRepository, PgEnvelopeRepository,
    PgGroupRepository, PgKeyPackageRepository, PgUserRepository,
};
use powehi_r2::R2MediaAdapter;
use powehi_redis::{RedisCache, RedisEventBus};
use powehi_rest_api::AppState;
use powehi_ws_hub::{event_bus::WsEventBus, WsHub};

#[tokio::main]
async fn main() -> Result<()> {
    powehi_telemetry::init();
    let metrics_handle =
        powehi_telemetry::install_prometheus().context("install prometheus recorder")?;

    let cfg = powehi_config::load().context("load config")?;

    // ── Outbound infrastructure ─────────────────────────────────────────────

    let pool = pg_connect(&cfg.database_url)
        .await
        .context("connect postgres")?;
    run_migrations(&pool).await.context("run db migrations")?;

    let cache: Arc<dyn powehi_port_outbound::cache::CachePort> = Arc::new(
        RedisCache::new(&cfg.redis_url)
            .await
            .context("connect redis cache")?,
    );
    let redis_bus: Arc<dyn powehi_port_outbound::event_bus::DomainEventBus> = Arc::new(
        RedisEventBus::new(&cfg.redis_url)
            .await
            .context("connect redis event bus")?,
    );

    // ── WS hub + composed event bus ─────────────────────────────────────────

    let ws_hub = Arc::new(WsHub::new());
    let event_bus: Arc<dyn powehi_port_outbound::event_bus::DomainEventBus> =
        Arc::new(WsEventBus::new(redis_bus, ws_hub.clone()));

    // ── Outbound repositories ───────────────────────────────────────────────

    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let device_repo = Arc::new(PgDeviceRepository::new(pool.clone()));
    let envelope_repo = Arc::new(PgEnvelopeRepository::new(pool.clone()));
    let group_repo = Arc::new(PgGroupRepository::new(pool.clone()));
    let key_package_repo = Arc::new(PgKeyPackageRepository::new(pool.clone()));

    // ── Application services ────────────────────────────────────────────────

    let opaque: Arc<dyn powehi_port_outbound::opaque::OpaqueServerPort> =
        Arc::new(OpaqueServer::new());

    let auth: Arc<dyn powehi_port_inbound::auth::AuthUseCase> =
        Arc::new(AuthService::new(user_repo, device_repo, opaque, cache));

    let messaging: Arc<dyn powehi_port_inbound::messaging::MessagingUseCase> =
        Arc::new(MessagingService::new(envelope_repo, group_repo, event_bus));

    let key_package: Arc<dyn powehi_port_inbound::key_package::KeyPackageUseCase> =
        Arc::new(KeyPackageService::new(key_package_repo));

    let media_r2 = Arc::new(R2MediaAdapter::new(
        pool.clone(),
        &cfg.r2_endpoint,
        &cfg.r2_bucket,
        &cfg.r2_access_key_id,
        &cfg.r2_secret_access_key,
        cfg.r2_presign_upload_ttl_secs,
        cfg.r2_presign_download_ttl_secs,
    ));
    let media: Arc<dyn powehi_port_inbound::media::MediaUseCase> =
        Arc::new(MediaService::new(media_r2));

    // ── HTTP + WS server ────────────────────────────────────────────────────

    let state = AppState {
        auth,
        messaging,
        key_package,
        media,
    };

    let ws_rl = powehi_rest_api::rate_limit::api_governor();
    let app = powehi_rest_api::router(state).merge(powehi_ws_hub::router(ws_hub).layer(ws_rl));

    // Admin server: internal-only, Prometheus scrape target.
    // Bound to 127.0.0.1 so it is never reachable from outside the pod.
    let admin_app = powehi_rest_api::admin_router(metrics_handle);
    let admin_addr = format!("127.0.0.1:{}", cfg.admin_port);
    info!(admin_addr = %admin_addr, "admin (metrics) listening");
    let admin_listener = tokio::net::TcpListener::bind(&admin_addr)
        .await
        .with_context(|| format!("bind admin {admin_addr}"))?;

    let addr = format!("{}:{}", cfg.host, cfg.port);
    info!(addr = %addr, "listening");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("bind {addr}"))?;

    tokio::try_join!(
        async { axum::serve(listener, app).await.context("public server") },
        async {
            axum::serve(admin_listener, admin_app)
                .await
                .context("admin server")
        },
    )?;
    Ok(())
}
