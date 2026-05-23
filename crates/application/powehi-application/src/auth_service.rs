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
    pub fn new(
        user_repo: Arc<dyn UserRepository>,
        device_repo: Arc<dyn DeviceRepository>,
    ) -> Self {
        Self { user_repo, device_repo }
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
    async fn register_finish(
        &self,
        req: RegistrationFinishRequest,
    ) -> Result<UserId, DomainError> {
        let user = User::new(req.user_id.clone(), vec![]);
        self.user_repo.save(&user).await?;
        Ok(req.user_id)
    }

    #[instrument(skip(self, req), fields(handle_hash_len = req.handle_hash.len()))]
    async fn login_init(
        &self,
        req: LoginInitRequest,
    ) -> Result<LoginInitResponse, DomainError> {
        let user = self
            .user_repo
            .find_by_handle_hash(&req.handle_hash)
            .await?
            .ok_or_else(|| DomainError::NotFound("user".into()))?;
        Ok(LoginInitResponse { user_id: user.id, opaque_ke2: req.opaque_ke1 })
    }

    #[instrument(skip(self, req), fields(user_id = %req.user_id))]
    async fn login_finish(
        &self,
        req: LoginFinishRequest,
    ) -> Result<SessionToken, DomainError> {
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
