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
}
