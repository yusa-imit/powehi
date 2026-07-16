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

/// A real MLS KeyPackage is ~1-2KB; this bounds the amount of Redis storage an
/// authenticated caller can consume per invite (24h TTL) beyond the global
/// per-request body limit. Flagged by security-auditor cycle 299 (prd.md §8.3).
const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;

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
    async fn create_invite(
        &self,
        device_id: &DeviceId,
        key_package: Vec<u8>,
    ) -> Result<CreatedInvite, DomainError> {
        // This service intentionally does NOT touch the shared KeyPackage pool
        // (`KeyPackageRepository`) and does NOT compute or return a hash. The
        // caller (inviting client) generated `key_package` itself and is
        // expected to have already hashed it locally, before this call, for
        // embedding in the invite URL's fragment — see the trait doc comment.
        // If this service computed the hash instead, a compromised server
        // could return an attacker-controlled KeyPackage + a matching hash for
        // both this response AND the later `redeem_invite` call, defeating the
        // verification entirely (caught in review — do not reintroduce this).
        if key_package.is_empty() {
            return Err(DomainError::InvalidInput("empty key package".into()));
        }
        if key_package.len() > MAX_KEY_PACKAGE_BYTES {
            return Err(DomainError::InvalidInput("key package too large".into()));
        }

        // 32 lowercase hex chars (UUID v4 simple form) — 122-bit CSPRNG entropy.
        let code = Uuid::new_v4().simple().to_string();
        let key = cache_key(&code);
        // Store the inviting device's UUID bytes (fixed 16-byte prefix) followed
        // by the pinned KeyPackage's raw bytes.
        let mut value = Vec::with_capacity(16 + key_package.len());
        value.extend_from_slice(device_id.as_uuid().as_bytes());
        value.extend_from_slice(&key_package);
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
        if bytes.len() < 16 {
            return Err(DomainError::Internal("malformed invite payload".into()));
        }
        let (device_bytes, key_package) = bytes.split_at(16);
        let arr: [u8; 16] = device_bytes
            .try_into()
            .map_err(|_| DomainError::Internal("malformed invite payload".into()))?;
        let device_id = DeviceId::from(Uuid::from_bytes(arr));
        // Debug-level: logs the inviter's device_id, which combined with
        // create logs could reveal a social-graph edge. Kept below INFO to
        // limit metadata exposure in production log pipelines.
        tracing::debug!(device_id = %device_id, "invite.redeemed");
        Ok(RedeemedInvite {
            device_id,
            key_package: key_package.to_vec(),
        })
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

    fn test_key_package_bytes() -> Vec<u8> {
        (0u8..64).collect()
    }

    #[tokio::test]
    async fn create_invite_stores_device_id_and_key_package_in_cache() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache.clone());
        let device_id = test_device_id();

        let invite = svc
            .create_invite(&device_id, test_key_package_bytes())
            .await
            .unwrap();

        // Code must be 32 lowercase hex chars (UUID simple form)
        assert_eq!(invite.code.len(), 32);
        assert!(invite.code.chars().all(|c| c.is_ascii_hexdigit()));
        // Cache must hold device_id bytes (16-byte prefix) + KeyPackage bytes under
        // invite:{sha256(code)} — not the raw code.
        let hash = Sha256::digest(invite.code.as_bytes());
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        let key = format!("invite:{hex}");
        let stored = cache.get(&key).await.unwrap().expect("code in cache");
        assert_eq!(&stored[..16], device_id.as_uuid().as_bytes());
        assert_eq!(&stored[16..], test_key_package_bytes().as_slice());
    }

    #[tokio::test]
    async fn create_invite_with_empty_key_package_fails() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);
        let device_id = test_device_id();

        let result = svc.create_invite(&device_id, Vec::new()).await;
        assert!(matches!(result, Err(DomainError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn create_invite_with_oversized_key_package_fails() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);
        let device_id = test_device_id();

        let oversized = vec![0u8; MAX_KEY_PACKAGE_BYTES + 1];
        let result = svc.create_invite(&device_id, oversized).await;
        assert!(matches!(result, Err(DomainError::InvalidInput(_))));
    }

    #[tokio::test]
    async fn create_invite_at_max_key_package_size_succeeds() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);
        let device_id = test_device_id();

        let at_limit = vec![0u8; MAX_KEY_PACKAGE_BYTES];
        let result = svc.create_invite(&device_id, at_limit).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn redeem_invite_returns_device_id_and_the_pinned_key_package() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);
        let device_id = test_device_id();

        let invite = svc
            .create_invite(&device_id, test_key_package_bytes())
            .await
            .unwrap();
        let redeemed = svc.redeem_invite(&invite.code).await.unwrap();

        assert_eq!(redeemed.device_id.as_uuid(), device_id.as_uuid());
        assert_eq!(redeemed.key_package, test_key_package_bytes());
    }

    #[tokio::test]
    async fn redeem_invite_consumes_code() {
        let cache = FakeCache::new();
        let svc = InviteService::new(cache);
        let device_id = test_device_id();

        let invite = svc
            .create_invite(&device_id, test_key_package_bytes())
            .await
            .unwrap();
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
