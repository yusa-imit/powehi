use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::info;

use powehi_application::{
    auth_service::AuthService, group_service::GroupService, key_package_service::KeyPackageService,
    media_service::MediaService, messaging_service::MessagingService,
};
use powehi_grpc::{RegionGrpcServer, TlsConfig};
use powehi_opaque::OpaqueServer;
use powehi_postgres::{
    connect as pg_connect, run_migrations, PgDeviceRepository, PgEnvelopeRepository,
    PgGroupRepository, PgKeyPackageRepository, PgPushSubscriptionRepository, PgUserRepository,
};
use powehi_proto::region::region_service_server::RegionServiceServer;
use powehi_r2::R2MediaAdapter;
use powehi_redis::{RedisCache, RedisEventBus};
use powehi_rest_api::AppState;
use powehi_webpush::{VapidConfig, VapidWebPushAdapter};
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
    let push_sub_repo = Arc::new(PgPushSubscriptionRepository::new(pool.clone()));

    // ── Application services ────────────────────────────────────────────────

    let opaque: Arc<dyn powehi_port_outbound::opaque::OpaqueServerPort> =
        Arc::new(OpaqueServer::new());

    // ── Web Push VAPID adapter ──────────────────────────────────────────────
    // If VAPID config is absent (dev / no push keys), the adapter degrades to a
    // no-op and never fails the message flow.
    let web_push_adapter: Arc<VapidWebPushAdapter> =
        Arc::new(match (&cfg.vapid_private_key_pem, &cfg.vapid_contact) {
            (Some(pem), Some(contact)) => match VapidConfig::from_pem(pem, contact.clone()) {
                Ok(vapid) => {
                    info!("VAPID Web Push: enabled");
                    VapidWebPushAdapter::new(vapid)
                }
                Err(e) => {
                    tracing::warn!(
                        error_kind = "vapid_config",
                        "invalid VAPID config: {e}; push disabled"
                    );
                    VapidWebPushAdapter::disabled()
                }
            },
            _ => {
                info!("VAPID Web Push: disabled (no keys configured)");
                VapidWebPushAdapter::disabled()
            }
        });

    // Derive the 32-byte HMAC key for the handle-oracle anti-enumeration defence.
    // If the operator supplies POWEHI__HANDLE_ORACLE_SECRET_TOKEN, derive from it
    // via SHA256 so the key is stable across restarts. If unset, use a random key
    // (per-restart only — the oracle is closed, but across restarts a known handle
    // would get a different synthetic user_id on login_init, which is benign).
    let handle_oracle_secret: [u8; 32] = if cfg.handle_oracle_secret_token.is_empty() {
        tracing::warn!(
            "POWEHI__HANDLE_ORACLE_SECRET_TOKEN not configured — \
             using ephemeral random oracle key; set this env var for stable behavior"
        );
        let a = uuid::Uuid::new_v4();
        let b = uuid::Uuid::new_v4();
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(a.as_bytes());
        key[16..].copy_from_slice(b.as_bytes());
        key
    } else {
        let digest = Sha256::digest(
            format!("powehi-oracle-v1:{}", cfg.handle_oracle_secret_token).as_bytes(),
        );
        digest.into()
    };

    let auth: Arc<dyn powehi_port_inbound::auth::AuthUseCase> = Arc::new(AuthService::new(
        user_repo,
        device_repo,
        opaque,
        cache.clone(),
        handle_oracle_secret,
    ));

    let group_repo_grpc: Arc<dyn powehi_port_outbound::group_repo::GroupRepository> =
        group_repo.clone();
    let group_repo_media: Arc<dyn powehi_port_outbound::group_repo::GroupRepository> =
        group_repo.clone();
    let group_repo_rest: Arc<dyn powehi_port_outbound::group_repo::GroupRepository> =
        group_repo.clone();
    let group: Arc<dyn powehi_port_inbound::group::GroupUseCase> = Arc::new(GroupService::new(
        group_repo_rest,
        powehi_domain::region::RegionId::new(&cfg.region_id),
    ));
    let messaging: Arc<dyn powehi_port_inbound::messaging::MessagingUseCase> = Arc::new(
        MessagingService::new(envelope_repo.clone(), group_repo, event_bus.clone())
            .with_push(push_sub_repo.clone(), web_push_adapter),
    );

    let key_package: Arc<dyn powehi_port_inbound::key_package::KeyPackageUseCase> =
        Arc::new(KeyPackageService::new(key_package_repo.clone()));

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
        Arc::new(MediaService::new(media_r2, group_repo_media));

    // ── gRPC inter-region mesh server ──────────────────────────────────────

    // Security: refuse to start with plaintext gRPC when peer regions are configured.
    // Single-region deployments (no peers) may skip TLS for local dev.
    if !cfg.grpc_peer_list().is_empty() && !cfg.grpc_tls_enabled() {
        anyhow::bail!(
            "SECURITY: grpc_peers is set but gRPC mTLS is not configured. \
             Set POWEHI__GRPC_TLS_CERT, POWEHI__GRPC_TLS_KEY, POWEHI__GRPC_TLS_CA \
             to enable mutual TLS for inter-region communication."
        );
    }

    let tls_cfg: Option<TlsConfig> = if cfg.grpc_tls_enabled() {
        Some(
            TlsConfig::from_pem_files(&cfg.grpc_tls_cert, &cfg.grpc_tls_key, &cfg.grpc_tls_ca)
                .context("load gRPC TLS config")?,
        )
    } else {
        None
    };

    let grpc_server_impl = RegionGrpcServer::new(
        cfg.region(),
        envelope_repo.clone(),
        event_bus,
        key_package_repo,
        group_repo_grpc,
        cfg.grpc_tls_enabled(),
    );
    // Max message size = 64 KiB for MLS ciphertext (prd.md §6.4).
    // This caps memory usage per in-flight RPC and matches the envelope size limit.
    const GRPC_MAX_MSG_BYTES: usize = 64 * 1024;
    let grpc_svc =
        RegionServiceServer::new(grpc_server_impl).max_decoding_message_size(GRPC_MAX_MSG_BYTES);
    let grpc_addr: std::net::SocketAddr = format!("0.0.0.0:{}", cfg.grpc_port)
        .parse()
        .context("parse gRPC listen addr")?;
    info!(grpc_addr = %grpc_addr, tls = cfg.grpc_tls_enabled(), "gRPC region service listening");

    let grpc_future: std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), tonic::transport::Error>> + Send>,
    > = if let Some(tls) = &tls_cfg {
        let tls_config = tls.server_tls().context("build server TLS config")?;
        Box::pin(
            tonic::transport::Server::builder()
                .tls_config(tls_config)
                .context("apply gRPC TLS")?
                .add_service(grpc_svc)
                .serve(grpc_addr),
        )
    } else {
        Box::pin(
            tonic::transport::Server::builder()
                .add_service(grpc_svc)
                .serve(grpc_addr),
        )
    };

    // ── HTTP + WS server ────────────────────────────────────────────────────

    let handle_rate_limiter = Arc::new(powehi_rest_api::rate_limit::HandleRateLimiter::new());
    let state = AppState {
        region_id: cfg.region_id.clone(),
        auth,
        group,
        messaging,
        key_package,
        media,
        push_sub_repo,
        cache: Arc::clone(&cache),
        handle_rate_limiter: Arc::clone(&handle_rate_limiter),
    };

    let ws_rl = powehi_rest_api::rate_limit::api_governor();
    let app = powehi_rest_api::router(state)
        .merge(powehi_ws_hub::router(ws_hub, Arc::clone(&cache)).layer(ws_rl));

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

    // ── Background GC: disappearing messages ────────────────────────────────
    // Delete expired envelopes every 5 minutes. ZK invariant preserved: this
    // task only runs `delete_expired` (a bare DELETE ... WHERE expires_at < NOW())
    // and reads no message content. Logs carry only the deleted count — never
    // device IDs, content, or TTL values.
    let envelope_repo_gc: Arc<dyn powehi_port_outbound::envelope_repo::EnvelopeRepository> =
        envelope_repo.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            match envelope_repo_gc.delete_expired().await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "gc.envelopes_expired"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error_kind = "gc", error = %e, "gc.delete_expired_failed"),
            }
        }
    });

    // ── Background GC: per-handle rate-limiter DashMap ──────────────────────
    // Prune stale handle-hash buckets every hour to bound memory growth.
    // Calls retain_recent() which drops entries older than the quota period.
    let handle_rl_gc = Arc::clone(&handle_rate_limiter);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            handle_rl_gc.retain_recent();
        }
    });

    tokio::try_join!(
        async { axum::serve(listener, app).await.context("public server") },
        async {
            axum::serve(admin_listener, admin_app)
                .await
                .context("admin server")
        },
        async { grpc_future.await.context("gRPC region server") },
    )?;
    Ok(())
}
