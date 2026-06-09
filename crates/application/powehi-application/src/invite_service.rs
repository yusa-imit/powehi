use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError};
use powehi_port_inbound::invite::{CreatedInvite, InviteUseCase, RedeemedInvite};
use powehi_port_outbound::cache::CachePort;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// One-time invite tokens live in Redis for 24 hours.
const INVITE_TTL: Duration = Duration::from_secs(24 * 60 * 60);

/// Store H(code) not the raw code so a Redis dump yields no usable tokens.
fn cache_key(code: &str) -> String {
    let hash = Sha256::digest(code.as_bytes());
    let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
    format!("invite:{hex}")
}

pub struct InviteService {
    cache: Arc<dyn CachePort>,
}

impl InviteService {
    pub fn new(cache: Arc<dyn CachePort>) -> Self {
        Self { cache }
    }
}

#[async_trait]
impl InviteUseCase for InviteService {
    async fn create_invite(&self, device_id: &DeviceId) -> Result<CreatedInvite, DomainError> {
        // 32 lowercase hex chars (UUID v4 simple form) — 122-bit CSPRNG entropy.
        let code = Uuid::new_v4().simple().to_string();
        let key = cache_key(&code);
        // Store the inviting device's UUID bytes. 16 bytes is enough to reconstruct
        // any DeviceId; no other identity material is stored.
        let value = device_id.as_uuid().as_bytes().to_vec();
        self.cache.set(&key, value, Some(INVITE_TTL)).await?;
        // Invite code itself is never logged — only the creating device.
        tracing::info!(device_id = %device_id, "invite.created");
        Ok(CreatedInvite { code })
    }

    async fn redeem_invite(&self, code: &str) -> Result<RedeemedInvite, DomainError> {
        let key = cache_key(code);
        // Atomic get-then-delete: Redis GETDEL in production, sequential get+delete in tests.
        // Either way, the code is consumed on first use.
        let bytes = self
            .cache
            .get_del(&key)
            .await?
            .ok_or_else(|| DomainError::NotFound("invite code not found".into()))?;
        let arr: [u8; 16] = bytes
            .try_into()
            .map_err(|_| DomainError::Internal("malformed invite payload".into()))?;
        let device_id = DeviceId::from(Uuid::from_bytes(arr));
        // Debug-level: logs the inviter's device_id, which combined with
        // create logs could reveal a social-graph edge. Kept below INFO to
        // limit metadata exposure in production log pipelines.
        tracing::debug!(device_id = %device_id, "invite.redeemed");
        Ok(RedeemedInvite { device_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }

    #[async_trait]
    impl CachePort for FakeCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().get(key).cloned())
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            _ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
    }

    fn test_device_id() -> DeviceId {
        DeviceId::from(Uuid::from_bytes([7u8; 16]))
    }

    #[tokio::test]
    async fn create_invite_stores_in_cache() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache.clone());
        let device_id = test_device_id();

        let invite = svc.create_invite(&device_id).await.unwrap();

        // Code must be 32 lowercase hex chars (UUID simple form)
        assert_eq!(invite.code.len(), 32);
        assert!(invite.code.chars().all(|c| c.is_ascii_hexdigit()));
        // Cache must hold the device_id bytes under invite:{sha256(code)} — not the raw code.
        let hash = Sha256::digest(invite.code.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let key = format!("invite:{hex}");
        let stored = cache.get(&key).await.unwrap().expect("code in cache");
        assert_eq!(stored, device_id.as_uuid().as_bytes().to_vec());
    }

    #[tokio::test]
    async fn redeem_invite_returns_device_id() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache.clone());
        let device_id = test_device_id();

        let invite = svc.create_invite(&device_id).await.unwrap();
        let redeemed = svc.redeem_invite(&invite.code).await.unwrap();

        assert_eq!(redeemed.device_id.as_uuid(), device_id.as_uuid());
    }

    #[tokio::test]
    async fn redeem_invite_consumes_code() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache.clone());
        let device_id = test_device_id();

        let invite = svc.create_invite(&device_id).await.unwrap();
        // First redemption succeeds
        svc.redeem_invite(&invite.code).await.unwrap();
        // Second redemption fails — code consumed
        let result = svc.redeem_invite(&invite.code).await;
        assert!(matches!(result, Err(DomainError::NotFound(_))));
    }

    #[tokio::test]
    async fn redeem_unknown_code_returns_not_found() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);

        let result = svc.redeem_invite("00000000000000000000000000000000").await;
        assert!(matches!(result, Err(DomainError::NotFound(_))));
    }
}
