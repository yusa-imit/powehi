// Postgres adapter — Phase 3 implementation.
// Stub: exposes connect helper only.

use sqlx::postgres::PgPool;

pub async fn connect(url: &str) -> Result<PgPool, sqlx::Error> {
    PgPool::connect(url).await
}
