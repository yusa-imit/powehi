use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use powehi_domain::{
    device::{Device, DeviceId},
    error::DomainError,
    user::{User, UserId},
};
use powehi_port_inbound::auth::{
    AuthUseCase, DeviceRegistrationRequest, LoginFinishRequest, LoginInitRequest,
    LoginInitResponse, RegistrationFinishRequest, RegistrationInitRequest,
    RegistrationInitResponse, SessionToken,
};
use powehi_port_outbound::{
    cache::CachePort, device_repo::DeviceRepository, opaque::OpaqueServerPort,
    user_repo::UserRepository,
};
use tracing::instrument;
use uuid::Uuid;

const REG_TTL: Duration = Duration::from_secs(300);
const SESSION_TTL: Duration = Duration::from_secs(86_400);

pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    device_repo: Arc<dyn DeviceRepository>,
    opaque: Arc<dyn OpaqueServerPort>,
    cache: Arc<dyn CachePort>,
}

impl AuthService {
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        device_repo: Arc<dyn DeviceRepository>,
        opaque: Arc<dyn OpaqueServerPort>,
        cache: Arc<dyn CachePort>,
    ) -> Self {
        Self {
            user_repo,
            device_repo,
            opaque,
            cache,
        }
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
    async fn register_finish(&self, req: RegistrationFinishRequest) -> Result<UserId, DomainError> {
        let password_file = self.opaque.registration_finish(&req.opaque_record)?;
        let cache_key = format!("reg:{}", req.user_id.as_uuid());
        let handle_hash = self
            .cache
            .get(&cache_key)
            .await?
            .ok_or_else(|| DomainError::NotFound("registration session".into()))?;

        // Save user before evicting the cache entry — if save fails the client
        // can retry (finding #5: delete after save, not before).
        let user = User::registered(req.user_id.clone(), handle_hash, password_file);
        self.user_repo.save(&user).await?;
        let _ = self.cache.delete(&cache_key).await; // best-effort cleanup
        Ok(req.user_id)
    }

    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn login_init(&self, req: LoginInitRequest) -> Result<LoginInitResponse, DomainError> {
        // Look up user; for unknown handles use a synthetic identity so we
        // still call login_start(None) → synthetic KE2 (R-3: anti-oracle).
        let (user_id, password_file_opt) =
            match self.user_repo.find_by_handle_hash(&req.handle_hash).await? {
                Some(user) => (user.id, Some(user.opaque_password_file)),
                None => (UserId::new(), None), // synthetic path — client will fail ke3
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
                Some(REG_TTL),
            )
            .await?;

        Ok(LoginInitResponse {
            user_id,
            opaque_ke2: ke2,
            login_nonce,
        })
    }

    #[instrument(skip(self, req), fields(device_id = %req.device_id))]
    async fn login_finish(&self, req: LoginFinishRequest) -> Result<SessionToken, DomainError> {
        // Collapse all OPAQUE errors to Unauthorized (Y-5: no error oracle).
        self.opaque
            .login_finish(req.login_nonce.as_bytes(), &req.opaque_ke3)
            .map_err(|_| DomainError::Unauthorized)?;

        // Resolve the authenticated user_id from the server-controlled nonce cache —
        // never from req.user_id which is client-supplied (security-auditor finding #1).
        let nonce_key = format!("login_nonce:{}", req.login_nonce);
        let user_id_bytes = self
            .cache
            .get(&nonce_key)
            .await
            .map_err(|_| DomainError::Unauthorized)?
            .ok_or(DomainError::Unauthorized)?;
        let _ = self.cache.delete(&nonce_key).await; // consume nonce — prevents replay
        let user_uuid = Uuid::from_slice(&user_id_bytes).map_err(|_| DomainError::Unauthorized)?;
        let authenticated_user_id = UserId::from(user_uuid);

        // Verify the claimed device belongs to the authenticated user.
        let device = self
            .device_repo
            .find_by_id(&req.device_id)
            .await?
            .ok_or(DomainError::Unauthorized)?;
        if device.user_id != authenticated_user_id {
            return Err(DomainError::Unauthorized);
        }

        // Session maps token → DeviceId (not UserId). All protected API routes
        // require a DeviceId; storing it here avoids an extra lookup per request.
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

        Ok(SessionToken(token))
    }

    #[instrument(skip(self, req), fields(user_id = %user_id))]
    async fn register_device(
        &self,
        user_id: &UserId,
        req: DeviceRegistrationRequest,
    ) -> Result<DeviceId, DomainError> {
        let device_id = DeviceId::new();
        let device = Device::new(device_id.clone(), user_id.clone(), req.mls_credential);
        self.device_repo.save(&device).await?;
        Ok(device_id)
    }

    #[instrument(skip(self), fields(user_id = %user_id, device_id = %device_id))]
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
        self.device_repo.delete(device_id).await
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
    }
    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
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
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
    }

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
                user_id: uid.clone(),
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
                user_id: uid.clone(),
                opaque_ke3: vec![0u8; 32],
                login_nonce: init.login_nonce,
                device_id: other_device,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::Unauthorized));
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
}
