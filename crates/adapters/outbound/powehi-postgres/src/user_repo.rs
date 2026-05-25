use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    error::DomainError,
    user::{User, UserId},
};
use powehi_port_outbound::user_repo::UserRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::map_err;

#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    handle_hash: Vec<u8>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        User {
            id: UserId::from(r.id),
            handle_hash: r.handle_hash,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    async fn save(&self, user: &User) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO users (id, handle_hash, created_at, updated_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE
               SET handle_hash = EXCLUDED.handle_hash,
                   updated_at  = EXCLUDED.updated_at",
        )
        .bind(user.id.as_uuid())
        .bind(&user.handle_hash)
        .bind(user.created_at)
        .bind(user.updated_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, handle_hash, created_at, updated_at FROM users WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(User::from))
    }

    async fn find_by_handle_hash(&self, hash: &[u8]) -> Result<Option<User>, DomainError> {
        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, handle_hash, created_at, updated_at FROM users WHERE handle_hash = $1",
        )
        .bind(hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(User::from))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: UserRepository>() {}

    #[test]
    fn pg_user_repo_impl_trait() {
        assert_impl::<PgUserRepository>();
    }
}
