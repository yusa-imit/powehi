use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError, user::UserId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInitRequest {
    /// Client-provided OPAQUE registration request bytes.
    pub opaque_request: Vec<u8>,
    /// SHA-256 of the plaintext handle — server stores only the hash.
    pub handle_hash: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationInitResponse {
    pub user_id: UserId,
    pub opaque_response: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishRequest {
    pub user_id: UserId,
    pub opaque_record: Vec<u8>,
    pub mls_credential: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginInitRequest {
    pub handle_hash: Vec<u8>,
    pub opaque_ke1: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginInitResponse {
    pub user_id: UserId,
    pub opaque_ke2: Vec<u8>,
    /// Server-issued single-use nonce. Client MUST return it in LoginFinishRequest.
    /// Binds the ke1→ke3 handshake to this server-side pending state; prevents
    /// cross-session hijack (see OpaqueServer pending map, keyed by nonce).
    pub login_nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub user_id: UserId,
    pub opaque_ke3: Vec<u8>,
    /// Must match the `login_nonce` returned by `login_init`.
    pub login_nonce: String,
    /// The device the user is authenticating from. Server verifies ownership before
    /// issuing a device-scoped session token.
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken(pub String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    pub mls_credential: Vec<u8>,
}

#[async_trait]
pub trait AuthUseCase: Send + Sync {
    async fn register_init(
        &self,
        req: RegistrationInitRequest,
    ) -> Result<RegistrationInitResponse, DomainError>;
    async fn register_finish(&self, req: RegistrationFinishRequest) -> Result<UserId, DomainError>;
    async fn login_init(&self, req: LoginInitRequest) -> Result<LoginInitResponse, DomainError>;
    async fn login_finish(&self, req: LoginFinishRequest) -> Result<SessionToken, DomainError>;
    async fn register_device(
        &self,
        user_id: &UserId,
        req: DeviceRegistrationRequest,
    ) -> Result<DeviceId, DomainError>;
    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError>;
}
