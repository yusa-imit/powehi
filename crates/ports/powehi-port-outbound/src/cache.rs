use async_trait::async_trait;
use powehi_domain::error::DomainError;
use std::time::Duration;

#[async_trait]
pub trait CachePort: Send + Sync {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError>;
    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), DomainError>;
    async fn delete(&self, key: &str) -> Result<(), DomainError>;
    async fn exists(&self, key: &str) -> Result<bool, DomainError>;

    /// Atomically GET then DELETE a key. Falls back to sequential get+delete in
    /// the default implementation; production adapters (Redis) should override
    /// with an atomic GETDEL to eliminate the TOCTOU window.
    async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
        let val = self.get(key).await?;
        if val.is_some() {
            self.delete(key).await?;
        }
        Ok(val)
    }

    /// Add `member` to the set stored at `key`. No-op by default; production
    /// adapters override with SADD.
    async fn set_add(&self, _key: &str, _member: &str) -> Result<(), DomainError> {
        Ok(())
    }

    /// Remove `member` from the set stored at `key`. No-op by default;
    /// production adapters override with SREM.
    async fn set_remove(&self, _key: &str, _member: &str) -> Result<(), DomainError> {
        Ok(())
    }

    /// Set the TTL of `key` to `ttl`. No-op by default; production adapters
    /// override with EXPIRE.
    async fn set_expire(&self, _key: &str, _ttl: Duration) -> Result<(), DomainError> {
        Ok(())
    }

    /// Return all members of the set at `key`. Returns an empty vec by default;
    /// production adapters override with SMEMBERS.
    async fn set_members(&self, _key: &str) -> Result<Vec<String>, DomainError> {
        Ok(vec![])
    }
}
