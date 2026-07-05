use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    user::{User, UserId},
};
use powehi_port_inbound::auth::{
    AuthUseCase, DeviceInfo, DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest,
    LoginInitResponse, RegistrationFinishRequest, RegistrationFinishResponse,
    RegistrationInitRequest, RegistrationInitResponse, SessionToken,
};
use powehi_port_outbound::{
    cache::CachePort, device_repo::DeviceRepository, opaque::OpaqueServerPort,
    user_repo::UserRepository,
};
use sha2::Sha256;
use tracing::instrument;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

const REG_TTL: Duration = Duration::from_secs(300);
const LOGIN_NONCE_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(86_400);
/// Buffer added to `device_sessions` set TTL so it outlives any session it tracks.
const DEVICE_SESSIONS_TTL: Duration = Duration::from_secs(86_400 + 300);
/// Maximum number of devices a single user account may register. Prevents
/// unbounded device proliferation and limits per-user KeyPackage storage.
const MAX_DEVICES_PER_USER: usize = 10;

pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    device_repo: Arc<dyn DeviceRepository>,
    opaque: Arc<dyn OpaqueServerPort>,
    cache: Arc<dyn CachePort>,
    /// Server-side secret for HMAC-SHA256 synthetic user_id derivation.
    /// Prevents handle-existence timing oracle: unknown handles always map to the
    /// same deterministic UUID (per secret), indistinguishable from known handles.
    handle_oracle_secret: [u8; 32],
}

impl AuthService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        device_repo: Arc<dyn DeviceRepository>,
        opaque: Arc<dyn OpaqueServerPort>,
        cache: Arc<dyn CachePort>,
        handle_oracle_secret: [u8; 32],
    ) -> Self {
        Self {
            user_repo,
            device_repo,
            opaque,
            cache,
            handle_oracle_secret,
        }
    }

    /// Derives a deterministic UserId from `handle_hash` using HMAC-SHA256 keyed
    /// with `handle_oracle_secret`. The result is stable across calls within a
    /// server lifetime (or across restarts when the secret is persisted in config),
    /// closing the handle-enumeration oracle in `login_init`.
    fn synthetic_user_id(&self, handle_hash: &[u8]) -> UserId {
        let mut mac = HmacSha256::new_from_slice(&self.handle_oracle_secret)
            .expect("HMAC accepts any key size");
        mac.update(handle_hash);
        let digest: [u8; 32] = mac.finalize().into_bytes().into();
        // Interpret first 16 bytes as a UUID v4 (version + variant bits set per RFC 4122).
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&digest[..16]);
        id_bytes[6] = (id_bytes[6] & 0x0f) | 0x40; // version 4
        id_bytes[8] = (id_bytes[8] & 0x3f) | 0x80; // RFC 4122 variant
        UserId::from(Uuid::from_bytes(id_bytes))
    }
}

#[async_trait]
impl AuthUseCase for AuthService {
    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn register_init(
        &self,
        req: RegistrationInitRequest,
    ) -> Result<RegistrationInitResponse, DomainError> {
        let user_id = UserId::new();
        let ke2 = self
            .opaque
            .registration_start(&req.opaque_request, user_id.as_uuid().as_bytes())?;
        let cache_key = format!("reg:{}", user_id.as_uuid());
        self.cache
            .set(&cache_key, req.handle_hash, Some(REG_TTL))
            .await?;
        Ok(RegistrationInitResponse {
            user_id,
            opaque_response: ke2,
        })
    }

    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    async fn register_finish(
        &self,
        req: RegistrationFinishRequest,
    ) -> Result<RegistrationFinishResponse, DomainError> {
        let password_file = self.opaque.registration_finish(&req.opaque_record)?;
        let cache_key = format!("reg:{}", req.user_id.as_uuid());
        // Atomically consume the registration session — prevents concurrent-finish
        // races and nonce replay within the TTL window (audit finding sec-F1).
        let handle_hash = self
            .cache
            .get_del(&cache_key)
            .await?
            .ok_or_else(|| DomainError::NotFound("registration session".into()))?;

        let user = User::registered(req.user_id.clone(), handle_hash, password_file);
        self.user_repo.save(&user).await?;

        // Create the first device for this user. The client supplies its MLS
        // credential bytes (raw BasicCredential identity). The server assigns a
        // fresh DeviceId so the client can present it in subsequent LoginFinishRequests.
        let device_id = DeviceId::new();
        let device = Device::new(device_id.clone(), req.user_id.clone(), req.mls_credential);
        self.device_repo.save(&device).await?;

        Ok(RegistrationFinishResponse {
            user_id: req.user_id,
            device_id,
        })
    }

    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn login_init(&self, req: LoginInitRequest) -> Result<LoginInitResponse, DomainError> {
        // Look up user; for unknown handles use a synthetic identity so we
        // still call login_start(None) → synthetic KE2 (R-3: anti-oracle).
        let (user_id, password_file_opt) =
            match self.user_repo.find_by_handle_hash(&req.handle_hash).await? {
                Some(user) => (user.id, Some(user.opaque_password_file)),
                // Deterministic synthetic path: same handle_hash always yields the same
                // UserId so consecutive login_init calls for an unknown handle are
                // indistinguishable from known-handle calls (closes handle-oracle).
                None => (self.synthetic_user_id(&req.handle_hash), None),
            };

        let identity = user_id.as_uuid().as_bytes().to_vec();
        let login_nonce = Uuid::new_v4().to_string();

        let ke2 = self.opaque.login_start(
            password_file_opt.as_deref(),
            &req.opaque_ke1,
            &identity,
            login_nonce.as_bytes(),
        )?;

        // Cache nonce → user_id so login_finish can look up the authenticated user
        // without trusting the client-supplied req.user_id.
        let nonce_key = format!("login_nonce:{}", login_nonce);
        self.cache
            .set(
                &nonce_key,
                user_id.as_uuid().as_bytes().to_vec(),
                Some(LOGIN_NONCE_TTL),
            )
            .await?;

        Ok(LoginInitResponse {
            user_id,
            opaque_ke2: ke2,
            login_nonce,
        })
    }

    // device_id not logged before ownership verification — added after (Y-4).
    #[instrument(skip(self, req))]
    async fn login_finish(&self, req: LoginFinishRequest) -> Result<SessionToken, DomainError> {
        // Collapse all OPAQUE errors to Unauthorized (no error oracle).
        self.opaque
            .login_finish(req.login_nonce.as_bytes(), &req.opaque_ke3)
            .map_err(|_| DomainError::Unauthorized)?;

        // Atomically consume the nonce — GETDEL prevents replay within the same
        // TTL window (Y-3: no TOCTOU between get and delete).
        let nonce_key = format!("login_nonce:{}", req.login_nonce);
        let user_id_bytes = self
            .cache
            .get_del(&nonce_key)
            .await
            .map_err(|_| DomainError::Unauthorized)?
            .ok_or(DomainError::Unauthorized)?;
        let user_uuid = Uuid::from_slice(&user_id_bytes).map_err(|_| DomainError::Unauthorized)?;
        let authenticated_user_id = UserId::from(user_uuid);

        // Verify the claimed device belongs to the authenticated user.
        // Log device_id only after this ownership check passes (Y-4).
        let device = self
            .device_repo
            .find_by_id(&req.device_id)
            .await?
            .ok_or(DomainError::Unauthorized)?;
        if device.user_id != authenticated_user_id {
            return Err(DomainError::Unauthorized);
        }
        tracing::debug!(device_id = %req.device_id, "login_finish.device_verified");

        // Session maps token → DeviceId. All protected routes need DeviceId;
        // storing it here avoids a DB lookup per request.
        let token = Uuid::new_v4().to_string();
        let session_cache_key = format!("session:{}", token);
        self.cache
            .set(
                &session_cache_key,
                req.device_id.as_uuid().as_bytes().to_vec(),
                Some(SESSION_TTL),
            )
            .await
            .map_err(|_| DomainError::Unauthorized)?;

        // Track token in per-device set so revoke_device can invalidate it (Y-1).
        // Fail hard — a tracking failure leaves an unrevocable orphan session.
        // On error: delete the session we already wrote before returning Unauthorized.
        let device_sessions_key = format!("device_sessions:{}", req.device_id.as_uuid());
        if self
            .cache
            .set_add(&device_sessions_key, &token)
            .await
            .is_err()
        {
            // Best-effort cleanup: token is never returned to client so the
            // orphan session cannot be used, but log to surface cache partitions.
            if self.cache.delete(&session_cache_key).await.is_err() {
                tracing::warn!(
                    "login_finish: set_add failed and cleanup delete also failed — \
                     orphan session may persist until SESSION_TTL expires"
                );
            }
            return Err(DomainError::Unauthorized);
        }
        let _ = self
            .cache
            .set_expire(&device_sessions_key, DEVICE_SESSIONS_TTL)
            .await;

        // Re-verify device still exists after session write (R-1: closes the
        // revoke↔login_finish race — if revoke_device deleted the device between
        // our first ownership check and here, we detect it and clean up).
        if self.device_repo.find_by_id(&req.device_id).await?.is_none() {
            if self.cache.delete(&session_cache_key).await.is_err() {
                tracing::warn!(
                    "login_finish: revoked-device race and cleanup delete failed — \
                     orphan session may persist until SESSION_TTL expires"
                );
            }
            let _ = self.cache.delete(&device_sessions_key).await;
            return Err(DomainError::Unauthorized);
        }

        Ok(SessionToken(token))
    }

    #[instrument(skip(self, user_id, req))]
    async fn register_device(
        &self,
        user_id: &UserId,
        req: DeviceRegistrationRequest,
    ) -> Result<DeviceId, DomainError> {
        // Soft cap: count-then-insert is not wrapped in a serializable
        // transaction, so a race between two concurrent registrations could
        // temporarily exceed MAX_DEVICES_PER_USER by one. This is acceptable
        // at the application layer — a hard DB-level invariant would require a
        // serializable transaction in the outbound adapter (future hardening).
        // Practical risk is very low: registration requires an active session
        // and is governed by auth_governor (burst=5, 1 token/6s).
        let existing = self.device_repo.find_by_user(user_id).await?;
        if existing.len() >= MAX_DEVICES_PER_USER {
            return Err(DomainError::InvalidInput("device_limit_exceeded".into()));
        }
        let device_id = DeviceId::new();
        let device = Device::new(device_id.clone(), user_id.clone(), req.mls_credential);
        self.device_repo.save(&device).await?;
        Ok(device_id)
    }

    #[instrument(skip(self, user_id))]
    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceInfo>, DomainError> {
        let devices = self.device_repo.find_by_user(user_id).await?;
        Ok(devices
            .into_iter()
            .map(|d| DeviceInfo {
                device_id: d.id,
                created_at: d.created_at,
                last_seen_at: d.last_seen_at,
            })
            .collect())
    }

    #[instrument(skip(self, user_id, device_id))]
    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError> {
        let device = self
            .device_repo
            .find_by_id(device_id)
            .await?
            .ok_or_else(|| DomainError::NotFound("device".into()))?;
        if &device.user_id != user_id {
            return Err(DomainError::Unauthorized);
        }
        self.device_repo.delete(device_id).await?;

        // Immediately invalidate all active sessions for the revoked device (Y-1).
        // Propagate set_members error — silently succeeding on cache failure
        // would leave live session tokens for a revoked device (Y-5).
        let device_sessions_key = format!("device_sessions:{}", device_id.as_uuid());
        let tokens = self.cache.set_members(&device_sessions_key).await?;
        for token in &tokens {
            if self
                .cache
                .delete(&format!("session:{token}"))
                .await
                .is_err()
            {
                // Best-effort: continue revoking other tokens but surface the
                // cache failure so ops can detect a partially-revoked device.
                tracing::warn!(
                    "revoke_device: failed to delete session token — \
                     token may persist until SESSION_TTL expires"
                );
            }
        }
        let _ = self.cache.delete(&device_sessions_key).await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_port_outbound::{
        cache::CachePort, device_repo::DeviceRepository, opaque::OpaqueServerPort,
        user_repo::UserRepository,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    // ── fake repos ──────────────────────────────────────────────────────────

    struct FakeUserRepo {
        store: Mutex<HashMap<UserId, User>>,
    }
    impl FakeUserRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl UserRepository for FakeUserRepo {
        async fn save(&self, user: &User) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(user.id.clone(), user.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &UserId) -> Result<Option<User>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn find_by_handle_hash(&self, hash: &[u8]) -> Result<Option<User>, DomainError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .values()
                .find(|u| u.handle_hash == hash)
                .cloned())
        }
    }

    struct FakeDeviceRepo {
        store: Mutex<HashMap<DeviceId, Device>>,
    }
    impl FakeDeviceRepo {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
    impl DeviceRepository for FakeDeviceRepo {
        async fn save(&self, device: &Device) -> Result<(), DomainError> {
            self.store
                .lock()
                .unwrap()
                .insert(device.id.clone(), device.clone());
            Ok(())
        }
        async fn find_by_id(&self, id: &DeviceId) -> Result<Option<Device>, DomainError> {
            Ok(self.store.lock().unwrap().get(id).cloned())
        }
        async fn find_by_user(&self, user_id: &UserId) -> Result<Vec<Device>, DomainError> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .values()
                .filter(|d| &d.user_id == user_id)
                .cloned()
                .collect())
        }
        async fn delete(&self, id: &DeviceId) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(id);
            Ok(())
        }
    }

    // ── fake OPAQUE port (echo / always-succeeds stub) ───────────────────────

    struct FakeOpaque;
    impl OpaqueServerPort for FakeOpaque {
        fn registration_start(&self, ke1: &[u8], _id: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(ke1.to_vec())
        }
        fn registration_finish(&self, upload: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(upload.to_vec())
        }
        fn login_start(
            &self,
            _pf: Option<&[u8]>,
            ke1: &[u8],
            _id: &[u8],
            _nonce: &[u8],
        ) -> Result<Vec<u8>, DomainError> {
            Ok(ke1.to_vec())
        }
        fn login_finish(
            &self,
            _nonce: &[u8],
            _ke3: &[u8],
        ) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
            Ok((vec![0u8; 64], b"fake-user-identity".to_vec()))
        }
    }

    // ── fake cache ───────────────────────────────────────────────────────────

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
        sets: Mutex<HashMap<String, Vec<String>>>,
    }
    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
                sets: Mutex::new(HashMap::new()),
            })
        }
    }
    #[async_trait::async_trait]
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
            self.sets.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().remove(key))
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.sets
                .lock()
                .unwrap()
                .entry(key.to_owned())
                .or_default()
                .push(member.to_owned());
            Ok(())
        }
        async fn set_expire(&self, _key: &str, _ttl: Duration) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            Ok(self
                .sets
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .unwrap_or_default())
        }
    }

    /// A FakeCache variant that fails on `set_add` to test the hard-fail path.
    struct SetAddFailCache {
        inner: Arc<FakeCache>,
    }
    impl SetAddFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SetAddFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, _key: &str, _member: &str) -> Result<(), DomainError> {
            Err(DomainError::Internal("set_add injected failure".into()))
        }
        async fn set_expire(&self, _key: &str, _ttl: Duration) -> Result<(), DomainError> {
            Ok(())
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            self.inner.set_members(key).await
        }
    }

    /// A FakeCache variant whose `delete` fails for any key starting with "session:".
    /// Used to test the revoke_device per-token deletion failure path.
    struct SessionDeleteFailCache {
        inner: Arc<FakeCache>,
    }
    impl SessionDeleteFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SessionDeleteFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            if key.starts_with("session:") {
                return Err(DomainError::Internal(
                    "injected session delete failure".into(),
                ));
            }
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.inner.set_add(key, member).await
        }
        async fn set_expire(&self, key: &str, ttl: Duration) -> Result<(), DomainError> {
            self.inner.set_expire(key, ttl).await
        }
        async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
            self.inner.set_members(key).await
        }
    }

    /// A FakeCache variant that fails on `set_members` to test the propagation path.
    struct SetMembersFailCache {
        inner: Arc<FakeCache>,
    }
    impl SetMembersFailCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: FakeCache::new(),
            })
        }
    }
    #[async_trait::async_trait]
    impl CachePort for SetMembersFailCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get(key).await
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.inner.set(key, value, ttl).await
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.inner.delete(key).await
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            self.inner.exists(key).await
        }
        async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            self.inner.get_del(key).await
        }
        async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
            self.inner.set_add(key, member).await
        }
        async fn set_expire(&self, key: &str, ttl: Duration) -> Result<(), DomainError> {
            self.inner.set_expire(key, ttl).await
        }
        async fn set_members(&self, _key: &str) -> Result<Vec<String>, DomainError> {
            Err(DomainError::Internal("injected set_members failure".into()))
        }
    }

    const TEST_ORACLE_SECRET: [u8; 32] = [42u8; 32];

    fn make_svc() -> (
        AuthService,
        Arc<FakeUserRepo>,
        Arc<FakeDeviceRepo>,
        Arc<FakeCache>,
    ) {
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let cache = FakeCache::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            opaque,
            cache.clone(),
            TEST_ORACLE_SECRET,
        );
        (svc, user_repo, device_repo, cache)
    }

    #[tokio::test]
    async fn register_init_caches_handle_hash() {
        let (svc, _, _, cache) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let cache_key = format!("reg:{}", resp.user_id.as_uuid());
        let stored = cache.get(&cache_key).await.unwrap().unwrap();
        assert_eq!(stored, handle_hash);
    }

    #[tokio::test]
    async fn register_finish_persists_user_with_opaque_file() {
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let resp = svc
            .register_init(RegistrationInitRequest {
                opaque_request: vec![1u8; 32],
                handle_hash: handle_hash.clone(),
            })
            .await
            .unwrap();
        let uid = resp.user_id.clone();
        svc.register_finish(RegistrationFinishRequest {
            user_id: uid.clone(),
            opaque_record: vec![2u8; 32],
            mls_credential: vec![],
        })
        .await
        .unwrap();
        let user = user_repo.find_by_id(&uid).await.unwrap().unwrap();
        assert_eq!(user.handle_hash, handle_hash);
        assert_eq!(user.opaque_password_file, vec![2u8; 32]);
    }

    #[tokio::test]
    async fn register_finish_without_init_returns_not_found() {
        let (svc, _, _, _) = make_svc();
        let err = svc
            .register_finish(RegistrationFinishRequest {
                user_id: UserId::new(),
                opaque_record: vec![],
                mls_credential: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn login_init_returns_user_id_for_known_handle_hash() {
        let (svc, user_repo, _, _) = make_svc();
        let handle_hash = b"sha256-of-alice".to_vec();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), handle_hash.clone()))
            .await
            .unwrap();
        let resp = svc
            .login_init(LoginInitRequest {
                handle_hash: handle_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert_eq!(resp.user_id, uid);
        assert!(!resp.login_nonce.is_empty(), "nonce must be set");
    }

    #[tokio::test]
    async fn login_init_unknown_handle_returns_synthetic_response() {
        // R-3: unknown user must NOT return an error; it returns a synthetic ke2+nonce.
        let (svc, _, _, _) = make_svc();
        let resp = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0u8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        assert!(!resp.login_nonce.is_empty());
        // ke2 is non-empty (echo stub returns ke1)
        assert!(!resp.opaque_ke2.is_empty());
    }

    #[tokio::test]
    async fn login_finish_issues_session_token_bound_to_device() {
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let token = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
            })
            .await
            .unwrap();
        let session_key = format!("session:{}", token.0);
        let stored = cache
            .get(&session_key)
            .await
            .unwrap()
            .expect("session stored");
        assert_eq!(
            stored,
            device_id.as_uuid().as_bytes().to_vec(),
            "session must store DeviceId bytes"
        );
    }

    #[tokio::test]
    async fn login_finish_wrong_device_owner_returns_unauthorized() {
        let (svc, user_repo, _, _) = make_svc();
        let uid = UserId::new();
        let other_uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        // Register a device under a DIFFERENT user.
        let other_device = svc
            .register_device(
                &other_uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: other_device,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn login_finish_nonce_cannot_be_reused() {
        // Y-3: nonce must be consumed atomically; a second login_finish with the
        // same nonce must return Unauthorized even if OPAQUE ke3 verifies.
        let (svc, user_repo, _, _) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let nonce = init.login_nonce.clone();

        // First use succeeds.
        svc.login_finish(LoginFinishRequest {
            opaque_ke3: vec![0u8; 32],
            login_nonce: nonce.clone(),
            device_id: device_id.clone(),
        })
        .await
        .unwrap();

        // Second use with the same nonce must fail (nonce was consumed).
        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: nonce,
                device_id: device_id.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
    }

    #[tokio::test]
    async fn revoke_device_invalidates_active_sessions() {
        // Y-1: revoking a device must delete all live session tokens for that device.
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        // Log in once to create a session.
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let token = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
            })
            .await
            .unwrap();

        // Session exists before revocation.
        let session_key = format!("session:{}", token.0);
        assert!(
            cache.get(&session_key).await.unwrap().is_some(),
            "session must exist before revoke"
        );

        // Revoke the device.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        // Session must be deleted.
        assert!(
            cache.get(&session_key).await.unwrap().is_none(),
            "session must be deleted after device revoke"
        );
    }

    #[tokio::test]
    async fn login_finish_after_device_revoked_returns_unauthorized() {
        // R-1 race-close: if the device is revoked between the ownership check
        // and the final re-verify in login_finish, the session must NOT be issued.
        // We simulate this by revoking the device before login_finish runs.
        let (svc, user_repo, _, cache) = make_svc();
        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        // Revoke the device before login_finish.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));

        // No session must have been left in the cache.
        let session_count = cache
            .store
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("session:"))
            .count();
        assert_eq!(session_count, 0, "no orphan session after revoke");
    }

    #[tokio::test]
    async fn login_finish_set_add_failure_returns_unauthorized_and_cleans_session() {
        // Hard-fail invariant: if set_add (session tracking) fails, login_finish must
        // return Unauthorized and must NOT leave an orphan session in the cache.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetAddFailCache::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            opaque,
            fail_cache.clone(),
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let init = svc
            .login_init(LoginInitRequest {
                handle_hash: b"hash".to_vec(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        let err = svc
            .login_finish(LoginFinishRequest {
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: device_id.clone(),
            })
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::Unauthorized),
            "set_add failure must return Unauthorized"
        );

        // No orphan session must remain after the hard-fail.
        let session_count = fail_cache
            .inner
            .store
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("session:"))
            .count();
        assert_eq!(session_count, 0, "no orphan session after set_add failure");
    }

    #[tokio::test]
    async fn register_device_creates_and_persists_device() {
        let (svc, _, device_repo, _) = make_svc();
        let uid = UserId::new();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![1u8; 16],
                },
            )
            .await
            .unwrap();
        let stored = device_repo
            .find_by_id(&device_id)
            .await
            .unwrap()
            .expect("device saved");
        assert_eq!(stored.user_id, uid);
        assert_eq!(stored.mls_credential, vec![1u8; 16]);
    }

    #[tokio::test]
    async fn register_device_rejects_when_user_at_device_limit() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        // Fill up to MAX_DEVICES_PER_USER successfully.
        for _ in 0..MAX_DEVICES_PER_USER {
            svc.register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        }
        // The next registration must be rejected.
        let err = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, DomainError::InvalidInput(ref s) if s.contains("device_limit_exceeded")),
            "expected device_limit_exceeded, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn revoke_device_rejects_wrong_owner() {
        let (svc, _, device_repo, _) = make_svc();
        let owner = UserId::new();
        let attacker = UserId::new();
        let device_id = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        let err = svc.revoke_device(&attacker, &device_id).await.unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
        assert!(device_repo.find_by_id(&device_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_device_owner_succeeds() {
        let (svc, _, device_repo, _) = make_svc();
        let owner = UserId::new();
        let device_id = svc
            .register_device(
                &owner,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();
        svc.revoke_device(&owner, &device_id).await.unwrap();
        assert!(device_repo.find_by_id(&device_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn revoke_device_not_found_returns_error() {
        let (svc, _, _, _) = make_svc();
        let err = svc
            .revoke_device(&UserId::new(), &DeviceId::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn revoke_device_partial_session_delete_failure_still_returns_ok() {
        // Per-token delete failures (e.g. cache partition) must not abort the
        // revocation — the device must be deleted and the function must return Ok.
        // Surviving tokens will expire after SESSION_TTL.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SessionDeleteFailCache::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            opaque,
            fail_cache.clone(),
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        // Inject a token into the device_sessions set directly so the loop has
        // something to try to delete.
        let device_sessions_key = format!("device_sessions:{}", device_id.as_uuid());
        fail_cache
            .inner
            .set_add(&device_sessions_key, "fake-token-abc")
            .await
            .unwrap();

        // revoke_device must succeed even though the session delete will fail.
        svc.revoke_device(&uid, &device_id).await.unwrap();

        // Device must have been deleted despite the cache error.
        assert!(
            device_repo.find_by_id(&device_id).await.unwrap().is_none(),
            "device must be deleted even when session delete fails"
        );
    }

    #[tokio::test]
    async fn login_init_unknown_handle_returns_consistent_synthetic_user_id() {
        // Handle-oracle invariant: two consecutive login_init calls with the same
        // unknown handle_hash must return the SAME user_id (deterministic synthetic UUID).
        // If they returned different UUIDs, an attacker could enumerate valid handles.
        let (svc, _, _, _) = make_svc();
        let unknown_hash = vec![0xabu8; 32];

        let resp1 = svc
            .login_init(LoginInitRequest {
                handle_hash: unknown_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let resp2 = svc
            .login_init(LoginInitRequest {
                handle_hash: unknown_hash.clone(),
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        assert_eq!(
            resp1.user_id, resp2.user_id,
            "unknown handle must map to the same synthetic user_id across calls"
        );
    }

    #[tokio::test]
    async fn login_init_different_unknown_handles_return_different_synthetic_ids() {
        // Different unknown handles must map to different synthetic user_ids so they
        // are not collapsed to the same nonce cache slot.
        let (svc, _, _, _) = make_svc();
        let resp1 = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0xaau8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();
        let resp2 = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0xbbu8; 32],
                opaque_ke1: vec![0u8; 32],
            })
            .await
            .unwrap();

        assert_ne!(
            resp1.user_id, resp2.user_id,
            "different unknown handles must produce different synthetic user_ids"
        );
    }

    #[tokio::test]
    async fn revoke_device_set_members_failure_propagates_error() {
        // If we cannot enumerate active sessions the revocation fails — silently
        // leaving live tokens for a revoked device is worse than returning an error.
        // NOTE: the device delete happens BEFORE the cache enumeration, so the
        // device will be gone even if this returns an error.
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let opaque = Arc::new(FakeOpaque);
        let fail_cache = SetMembersFailCache::new();
        let svc = AuthService::new(
            user_repo.clone(),
            device_repo.clone(),
            opaque,
            fail_cache.clone(),
            TEST_ORACLE_SECRET,
        );

        let uid = UserId::new();
        user_repo
            .save(&User::new(uid.clone(), b"hash".to_vec()))
            .await
            .unwrap();
        let device_id = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let err = svc.revoke_device(&uid, &device_id).await.unwrap_err();
        assert!(
            matches!(err, DomainError::Internal(_)),
            "set_members failure must propagate"
        );
    }

    // ── list_devices ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_devices_empty_when_user_has_no_devices() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        let devices = svc.list_devices(&uid).await.unwrap();
        assert!(devices.is_empty());
    }

    #[tokio::test]
    async fn list_devices_returns_all_registered_devices() {
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        let id1 = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![1],
                },
            )
            .await
            .unwrap();
        let id2 = svc
            .register_device(
                &uid,
                DeviceRegistrationRequest {
                    mls_credential: vec![2],
                },
            )
            .await
            .unwrap();

        let mut devices = svc.list_devices(&uid).await.unwrap();
        assert_eq!(devices.len(), 2);
        devices.sort_by_key(|d| d.device_id.as_uuid());
        let mut expected = [id1, id2];
        expected.sort_by_key(|d| d.as_uuid());
        assert_eq!(devices[0].device_id, expected[0]);
        assert_eq!(devices[1].device_id, expected[1]);
    }

    #[tokio::test]
    async fn list_devices_isolates_by_user() {
        // Security invariant: user A's devices must never appear in user B's list.
        let (svc, _, _, _) = make_svc();
        let user_a = UserId::new();
        let user_b = UserId::new();
        svc.register_device(
            &user_a,
            DeviceRegistrationRequest {
                mls_credential: vec![],
            },
        )
        .await
        .unwrap();
        let device_b = svc
            .register_device(
                &user_b,
                DeviceRegistrationRequest {
                    mls_credential: vec![],
                },
            )
            .await
            .unwrap();

        let list_a = svc.list_devices(&user_a).await.unwrap();
        let list_b = svc.list_devices(&user_b).await.unwrap();

        assert_eq!(list_a.len(), 1);
        assert_eq!(list_b.len(), 1);
        assert_eq!(list_b[0].device_id, device_b);
        // user_b's device must not appear in user_a's list.
        assert!(
            !list_a.iter().any(|d| d.device_id == device_b),
            "user_b device must not appear in user_a list"
        );
    }

    #[tokio::test]
    async fn list_devices_last_seen_at_is_none_at_registration() {
        // Freshly registered devices have no last_seen_at.
        let (svc, _, _, _) = make_svc();
        let uid = UserId::new();
        svc.register_device(
            &uid,
            DeviceRegistrationRequest {
                mls_credential: vec![],
            },
        )
        .await
        .unwrap();
        let devices = svc.list_devices(&uid).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert!(
            devices[0].last_seen_at.is_none(),
            "newly registered device has no last_seen_at"
        );
    }
}
