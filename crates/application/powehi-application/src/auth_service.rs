use std::sync::Arc;

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
use powehi_port_outbound::{device_repo::DeviceRepository, user_repo::UserRepository};
use tracing::instrument;

pub struct AuthService {
    user_repo: Arc<dyn UserRepository>,
    device_repo: Arc<dyn DeviceRepository>,
}

impl AuthService {
    pub fn new(user_repo: Arc<dyn UserRepository>, device_repo: Arc<dyn DeviceRepository>) -> Self {
        Self {
            user_repo,
            device_repo,
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
        // OPAQUE server-side registration init is implemented in powehi-opaque adapter.
        // This stub wires the use-case boundary; full implementation in Phase 2.
        let user_id = UserId::new();
        Ok(RegistrationInitResponse {
            user_id,
            opaque_response: req.opaque_request, // stub: echoed back; real impl in Phase 2
        })
    }

    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    async fn register_finish(&self, req: RegistrationFinishRequest) -> Result<UserId, DomainError> {
        let user = User::new(req.user_id.clone(), vec![]);
        self.user_repo.save(&user).await?;
        Ok(req.user_id)
    }

    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn login_init(&self, req: LoginInitRequest) -> Result<LoginInitResponse, DomainError> {
        let user = self
            .user_repo
            .find_by_handle_hash(&req.handle_hash)
            .await?
            .ok_or_else(|| DomainError::NotFound("user".into()))?;
        Ok(LoginInitResponse {
            user_id: user.id,
            opaque_ke2: req.opaque_ke1,
        })
    }

    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    async fn login_finish(&self, req: LoginFinishRequest) -> Result<SessionToken, DomainError> {
        // Session token generation handled by adapter layer; stub returns placeholder.
        Ok(SessionToken(format!("session:{}", req.user_id)))
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
    use powehi_port_inbound::auth::{DeviceRegistrationRequest, LoginInitRequest};
    use powehi_port_outbound::{device_repo::DeviceRepository, user_repo::UserRepository};
    use std::collections::HashMap;
    use std::sync::Mutex;

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

    fn make_svc() -> (AuthService, Arc<FakeUserRepo>, Arc<FakeDeviceRepo>) {
        let user_repo = FakeUserRepo::new();
        let device_repo = FakeDeviceRepo::new();
        let svc = AuthService::new(user_repo.clone(), device_repo.clone());
        (svc, user_repo, device_repo)
    }

    #[tokio::test]
    async fn register_finish_persists_user() {
        let (svc, user_repo, _) = make_svc();
        let uid = UserId::new();
        svc.register_finish(RegistrationFinishRequest {
            user_id: uid.clone(),
            opaque_record: vec![],
            mls_credential: vec![],
        })
        .await
        .unwrap();
        assert!(user_repo.store.lock().unwrap().contains_key(&uid));
    }

    #[tokio::test]
    async fn login_init_returns_user_id_for_known_handle_hash() {
        let (svc, user_repo, _) = make_svc();
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
    }

    #[tokio::test]
    async fn login_init_unknown_handle_returns_not_found() {
        let (svc, _, _) = make_svc();
        let err = svc
            .login_init(LoginInitRequest {
                handle_hash: vec![0u8; 32],
                opaque_ke1: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }

    #[tokio::test]
    async fn register_device_creates_and_persists_device() {
        let (svc, _, device_repo) = make_svc();
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
        let (svc, _, device_repo) = make_svc();
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
        // device still present
        assert!(device_repo.find_by_id(&device_id).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn revoke_device_owner_succeeds() {
        let (svc, _, device_repo) = make_svc();
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
        let (svc, _, _) = make_svc();
        let err = svc
            .revoke_device(&UserId::new(), &DeviceId::new())
            .await
            .unwrap_err();
        assert!(matches!(err, DomainError::NotFound(_)));
    }
}
