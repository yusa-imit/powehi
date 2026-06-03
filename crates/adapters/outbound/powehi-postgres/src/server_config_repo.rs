use async_trait::async_trait;
use powehi_domain::error::DomainError;
use powehi_port_outbound::server_config_repo::ServerConfigRepository;
use sqlx::postgres::PgPool;

use crate::map_err;

pub struct PgServerConfigRepository {
    pool: PgPool,
}

impl PgServerConfigRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ServerConfigRepository for PgServerConfigRepository {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
        let row: Option<(Vec<u8>,)> =
            sqlx::query_as("SELECT value_bytes FROM server_config WHERE key = $1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_err)?;
        Ok(row.map(|(v,)| v))
    }

    async fn upsert_bytes(&self, key: &str, value: &[u8]) -> Result<(), DomainError> {
        // ON CONFLICT DO NOTHING: the first writer wins. Callers that need the
        // winner's value must call get_bytes() after this returns (handles the
        // concurrent first-boot race — see main.rs handle_oracle_secret setup).
        sqlx::query(
            "INSERT INTO server_config (key, value_bytes)
             VALUES ($1, $2)
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(key)
        .bind(value)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: ServerConfigRepository>() {}

    #[test]
    fn pg_server_config_repo_impl_trait() {
        assert_impl::<PgServerConfigRepository>();
    }
}
