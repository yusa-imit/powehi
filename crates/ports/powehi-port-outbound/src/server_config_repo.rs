use async_trait::async_trait;
use powehi_domain::error::DomainError;

/// Persistent opaque server configuration blobs.
/// Keys are static ASCII labels; values are raw bytes — never plaintext content,
/// PII, or ciphertext.  Used for the handle-oracle HMAC secret so it survives
/// restarts even when POWEHI__HANDLE_ORACLE_SECRET_TOKEN is not set.
#[async_trait]
pub trait ServerConfigRepository: Send + Sync {
    async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError>;
    async fn upsert_bytes(&self, key: &str, value: &[u8]) -> Result<(), DomainError>;
}
