use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tracing::{info, warn};

/// TLS handshake timeout for inbound gRPC connections (finding 1 / slow-loris DoS mitigation).
/// A peer that sends a partial ClientHello and stalls would block the accept loop indefinitely
/// without this cap. 10 s is generous for any legitimate peer on the inter-region mesh.
const GRPC_TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Returns `true` for transient socket errors that should not crash the gRPC accept loop.
fn is_transient_accept_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionAborted | ConnectionReset | BrokenPipe | Interrupted
    )
}

use powehi_application::{
    auth_service::AuthService, group_service::GroupService, invite_service::InviteService,
    key_package_service::KeyPackageService, media_service::MediaService,
    messaging_service::MessagingService,
};
use powehi_grpc::{RegionGrpcServer, TlsConfig};
use powehi_opaque::OpaqueServer;
use powehi_postgres::{
    connect as pg_connect, run_migrations, PgDeviceRepository, PgEnvelopeRepository,
    PgGroupRepository, PgKeyPackageRepository, PgPushSubscriptionRepository,
    PgServerConfigRepository, PgUserRepository,
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

    let server_config_repo = Arc::new(PgServerConfigRepository::new(pool.clone()));
    let user_repo = Arc::new(PgUserRepository::new(pool.clone()));
    let device_repo: Arc<dyn powehi_port_outbound::device_repo::DeviceRepository> =
        Arc::new(PgDeviceRepository::new(pool.clone()));
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
    //
    // Priority:
    //   1. POWEHI__HANDLE_ORACLE_SECRET_TOKEN set → derive via SHA-256 (operator-controlled,
    //      stable across all instances).
    //   2. Not set → load from server_config table (generated once, persisted across restarts).
    //   3. Not in DB → generate, persist, then use (first-boot path).
    //
    // This closes YELLOW-2: even without the env var the key is now stable across restarts,
    // so consecutive login_init calls for an unknown handle return the same synthetic user_id.
    const ORACLE_SECRET_DB_KEY: &str = "handle_oracle_secret";
    let handle_oracle_secret: [u8; 32] = if !cfg.handle_oracle_secret_token.is_empty() {
        let digest = Sha256::digest(
            format!("powehi-oracle-v1:{}", cfg.handle_oracle_secret_token).as_bytes(),
        );
        digest.into()
    } else {
        use powehi_port_outbound::server_config_repo::ServerConfigRepository;
        match server_config_repo
            .get_bytes(ORACLE_SECRET_DB_KEY)
            .await
            .context("load handle_oracle_secret from server_config")?
        {
            Some(bytes) => bytes.try_into().map_err(|_| {
                anyhow::anyhow!(
                    "handle_oracle_secret in server_config is not 32 bytes — \
                         delete the row and restart to regenerate"
                )
            })?,
            None => {
                // First boot: generate a candidate 32-byte secret from two UUIDv4s
                // (uuid::Uuid::new_v4 is backed by OsRng — ~244 bits of entropy).
                let a = uuid::Uuid::new_v4();
                let b = uuid::Uuid::new_v4();
                let mut candidate = [0u8; 32];
                candidate[..16].copy_from_slice(a.as_bytes());
                candidate[16..].copy_from_slice(b.as_bytes());

                // INSERT ... DO NOTHING: first-boot concurrent instances do not
                // overwrite each other. After the attempt, re-read the winner's
                // value so all instances converge on the same key regardless of
                // which pod inserted it.
                server_config_repo
                    .upsert_bytes(ORACLE_SECRET_DB_KEY, &candidate)
                    .await
                    .context("persist handle_oracle_secret to server_config")?;
                let winner = server_config_repo
                    .get_bytes(ORACLE_SECRET_DB_KEY)
                    .await
                    .context("re-read handle_oracle_secret from server_config")?
                    .ok_or_else(|| {
                        anyhow::anyhow!("handle_oracle_secret disappeared immediately after insert")
                    })?;
                tracing::info!(
                    "generated and persisted handle_oracle_secret; \
                     set POWEHI__HANDLE_ORACLE_SECRET_TOKEN to control this value"
                );
                winner.try_into().map_err(|_| {
                    anyhow::anyhow!("persisted handle_oracle_secret is not 32 bytes")
                })?
            }
        }
    };

    let auth: Arc<dyn powehi_port_inbound::auth::AuthUseCase> = Arc::new(AuthService::new(
        user_repo,
        Arc::clone(&device_repo),
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
    let group_repo_ws: Arc<dyn powehi_port_outbound::group_repo::GroupRepository> =
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
    let media_repo_gc: Arc<dyn powehi_port_outbound::media_repo::MediaRepository> =
        media_r2.clone();
    let media: Arc<dyn powehi_port_inbound::media::MediaUseCase> =
        Arc::new(MediaService::new(media_r2, group_repo_media));
    let media_gc = Arc::clone(&media);

    let invite: Arc<dyn powehi_port_inbound::invite::InviteUseCase> =
        Arc::new(InviteService::new(cache.clone()));

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
    // Y-TLS-VERSION: pin the gRPC inter-region listener to TLS 1.3 minimum.
    // tonic 0.12's ServerTlsConfig doesn't expose protocol-version selection, so we
    // bypass it and drive the TLS handshake via tokio-rustls with a custom ServerConfig.
    // tokio_rustls::server::TlsStream<TcpStream> implements tonic's `Connected` trait,
    // so TlsConnectInfo (peer certs) is injected identically to tonic's own TLS path.
    let grpc_future: std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), tonic::transport::Error>> + Send>,
    > = if let Some(tls) = &tls_cfg {
        let rustls_cfg = tls
            .server_rustls_config()
            .context("build TLS 1.3 gRPC server config")?;
        let acceptor = tokio_rustls::TlsAcceptor::from(rustls_cfg);
        let listener = tokio::net::TcpListener::bind(grpc_addr)
            .await
            .context("bind gRPC TLS listener")?;
        info!(grpc_addr = %grpc_addr, tls = true, "gRPC region service listening (TLS 1.3 minimum)");

        let tls_incoming = async_stream::stream! {
            loop {
                let (tcp, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(e) if is_transient_accept_error(&e) => continue,
                    // Non-transient accept errors (e.g. EMFILE, ENOMEM): log the error kind
                    // and continue rather than terminating serve_with_incoming (finding 3).
                    // serve_with_incoming returning Ok(()) would cause tokio::try_join! to
                    // silently shut down the HTTP+admin servers — keep the loop alive instead.
                    Err(e) => {
                        warn!(error_kind = %e.kind(), "gRPC accept error — continuing");
                        continue;
                    }
                };
                // Enforce a handshake timeout to prevent slow-loris DoS (finding 1).
                // A stalled partial ClientHello would block the accept loop without this cap.
                let handshake = tokio::time::timeout(
                    GRPC_TLS_HANDSHAKE_TIMEOUT,
                    acceptor.accept(tcp),
                );
                match handshake.await {
                    Ok(Ok(stream)) => yield Ok::<_, std::io::Error>(stream),
                    // TLS handshake rejected (TLS 1.2 ClientHello, bad cert, timeout).
                    // Emit a structured warning so operators can observe TLS 1.2 rejection
                    // attempts without logging plaintext or PII (finding 2).
                    Ok(Err(_)) => {
                        warn!(error_kind = "tls_handshake", "gRPC TLS handshake failed — peer rejected");
                        continue;
                    }
                    Err(_elapsed) => {
                        warn!(error_kind = "tls_handshake_timeout", "gRPC TLS handshake timed out");
                        continue;
                    }
                }
            }
        };
        Box::pin(
            tonic::transport::Server::builder()
                .add_service(grpc_svc)
                .serve_with_incoming(tls_incoming),
        )
    } else {
        info!(grpc_addr = %grpc_addr, tls = false, "gRPC region service listening");
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
        region_tier: cfg.tier,
        auth,
        group,
        messaging,
        key_package,
        media,
        push_sub_repo,
        invite,
        device_repo,
        cache: Arc::clone(&cache),
        handle_rate_limiter: Arc::clone(&handle_rate_limiter),
    };

    let ws_rl = powehi_rest_api::rate_limit::api_governor();
    let app = powehi_rest_api::router(state)
        .merge(powehi_ws_hub::router(ws_hub, Arc::clone(&cache), group_repo_ws).layer(ws_rl));

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

    // ── Background GC: disappearing messages + default retention floor ─────
    // Delete expired envelopes every 5 minutes: explicit disappearing-message
    // TTLs, plus (as of the envelope_acks fix) a default 30-day retention floor
    // for envelopes with no TTL — a backstop for broadcasts that never reach
    // all-current-members-acked (e.g. a member who left without polling).
    // ZK invariant preserved: `delete_expired` reads no message content; logs
    // carry only the deleted count — never device IDs, content, or TTL values.
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

    // ── Background GC: media blobs (prd.md §9.4.3) ──────────────────────────
    // Delete blobs once every required recipient has acknowledged a download
    // and the retention grace period has elapsed (or, absent full ack, once
    // the retention ceiling alone has elapsed). ZK invariant preserved: this
    // task only reads/writes opaque UUIDs (media_id, device_id, timestamps) —
    // never content, filenames, or plaintext. Logs carry only a count.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match media_gc.run_gc().await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "gc.media_expired"),
                Ok(_) => {}
                Err(e) => tracing::warn!(error_kind = "gc", error = %e, "gc.media_run_failed"),
            }
        }
    });

    // ── Background GC: media upload ledger (cycle 362 residual gap) ────────
    // `media_upload_ledger` is deliberately append-only for quota correctness
    // (`MediaService::request_upload`'s rolling 24h window reads it, never
    // deletes from it) but must not grow forever. Trim rows once a day, with
    // a cutoff reusing `GC_RETENTION_DAYS` (30, prd.md §11.4) — the same
    // constant media blob GC uses, so the two windows can't silently drift
    // apart — a large safety margin past the 24h window any live quota
    // check could still be reading. ZK invariant preserved: only opaque
    // UUIDs/timestamps/byte counts are touched; logs carry only a deleted-
    // row count.
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(86400));
        loop {
            interval.tick().await;
            let cutoff = chrono::Utc::now()
                - chrono::Duration::days(powehi_application::media_service::GC_RETENTION_DAYS);
            match media_repo_gc.trim_upload_ledger_older_than(cutoff).await {
                Ok(n) if n > 0 => tracing::info!(deleted = n, "gc.media_upload_ledger_trimmed"),
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!(error_kind = "gc", error = %e, "gc.media_upload_ledger_trim_failed")
                }
            }
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
