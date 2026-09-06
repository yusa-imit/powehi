//! Postgres session-scoped advisory locks used for leader election among
//! server replicas (cycle 368; moved here cycle 373 — this is a pure Postgres
//! primitive with no R2/media dependency, and previously lived on
//! `powehi-r2::R2MediaAdapter` only because that was the first caller).
//! Guards background GC/trim jobs against multiple replicas racing the same
//! job concurrently — see `bin/powehi-server/src/main.rs`'s background-job
//! loops for the callers.

use powehi_domain::error::DomainError;
use sqlx::postgres::PgPool;

use crate::map_err;

/// Advisory-lock keys guarding GC/trim background jobs (cycle 368). One key
/// per job so the two jobs never block each other, only concurrent runs of
/// the *same* job across server replicas.
pub const GC_LOCK_MEDIA_BLOBS: i64 = 0x706f_7765_6869_0001;
pub const GC_LOCK_MEDIA_LEDGER: i64 = 0x706f_7765_6869_0002;
pub const GC_LOCK_MEDIA_ORPHANS: i64 = 0x706f_7765_6869_0003;
pub const GC_LOCK_PENDING_REMOVALS: i64 = 0x706f_7765_6869_0004;

/// Holds a session-scoped Postgres advisory lock acquired via
/// `PgLeaderLock::try_lock`. `pg_advisory_lock`/`pg_advisory_unlock` are tied
/// to the underlying connection (session), not the query, so this guard keeps
/// a dedicated `PoolConnection` alive for its whole lifetime instead of
/// borrowing one per-query from the shared pool — returning it to the pool
/// between acquire and unlock would let some other caller's query run on that
/// same session and would leave the unlock call (issued from a different
/// pooled connection) unable to find the lock at all.
///
/// Deployment invariant: this only works against a real Postgres session — a
/// transaction-pooling proxy in front of the DB (PgBouncer/RDS Proxy in
/// transaction mode) would silently multiplex queries from this guard's
/// "session" across different real backends, breaking the lock with no
/// compile-time signal. None is deployed today (checked `infra/`); if one is
/// ever introduced, `try_lock` needs a session-mode exception or a different
/// locking primitive (e.g. a plain row lock table).
#[must_use = "the advisory lock is released as soon as this guard is dropped — hold it for the job's duration, or call release() explicitly"]
pub struct GcLockGuard {
    conn: Option<sqlx::pool::PoolConnection<sqlx::Postgres>>,
    key: i64,
}

impl GcLockGuard {
    /// Unlock and return the connection to the pool. Prefer this over letting
    /// the guard drop on the happy path.
    pub async fn release(mut self) {
        if let Some(mut conn) = self.conn.take() {
            match sqlx::query("SELECT pg_advisory_unlock($1)")
                .bind(self.key)
                .execute(&mut *conn)
                .await
            {
                Ok(_) => {}
                Err(e) => {
                    // Don't return a connection to the pool that might still
                    // hold the lock — fall back to the same detach-and-drop
                    // path Drop uses, which is guaranteed to release it.
                    tracing::warn!(error_kind = "gc_lock", error = %e, "gc.advisory_unlock_failed");
                    let _ = conn.detach();
                }
            }
        }
    }
}

impl Drop for GcLockGuard {
    fn drop(&mut self) {
        // release() wasn't called (early return / panic in the guarded job):
        // detach and drop the raw connection instead of returning it to the
        // pool. Ending the session server-side is what actually releases a
        // session-scoped advisory lock — an explicit unlock query issued
        // later from a *different* pooled connection would not find it.
        //
        // detach() (not a plain `drop(conn)`) is also what makes this safe
        // to call from a sync Drop impl at all: PoolConnection's own Drop
        // spawns an async task to return itself to the pool, which panics if
        // invoked while the Tokio runtime is shutting down. detach() takes
        // the connection out of pool bookkeeping first (decrementing the
        // pool's size permit, which the pool immediately backfills), so the
        // raw connection's drop that follows is just an fd close — no spawn,
        // runtime-agnostic. This relies on the pool's `min_connections` being
        // 0 (the default, and what `connect()` uses today) — a nonzero
        // `min_connections` would make even the post-detach empty
        // `PoolConnection` guard spawn on drop again.
        if let Some(conn) = self.conn.take() {
            let _ = conn.detach();
        }
    }
}

/// Leader-election lock backed by Postgres session-scoped advisory locks.
/// Cheap to construct (wraps a shared `PgPool` clone) — background jobs hold
/// one alongside their other repository handles.
pub struct PgLeaderLock {
    pool: PgPool,
}

impl PgLeaderLock {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Attempt to acquire advisory lock `key` (one of the `GC_LOCK_*`
    /// constants) without blocking, guarding a GC/trim background job
    /// against multiple server replicas racing the same job concurrently — a
    /// benign but wasteful race (early exit can undercount and leave stale
    /// rows for the next scheduled tick, self-healing but avoidable).
    /// `Ok(None)` means another session already holds it — caller should
    /// skip this run.
    pub async fn try_lock(&self, key: i64) -> Result<Option<GcLockGuard>, DomainError> {
        let mut conn = self.pool.acquire().await.map_err(map_err)?;
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await
            .map_err(map_err)?;
        Ok(if acquired {
            Some(GcLockGuard {
                conn: Some(conn),
                key,
            })
        } else {
            None
        })
    }
}
