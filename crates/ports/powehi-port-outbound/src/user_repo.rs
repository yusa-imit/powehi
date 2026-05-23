use async_trait::async_trait;
use powehi_domain::{error::DomainError, user::{User, UserId}};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn save(&self, user: &User) -> Result<(), DomainError>;
    async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, DomainError>;
    async fn find_by_handle_hash(&self, hash: &[u8]) -> Result<Option<User>, DomainError>;
}
