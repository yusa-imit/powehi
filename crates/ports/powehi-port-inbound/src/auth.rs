use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
    /// Optional raw 32-byte Ed25519 verifying key derived from the client's BIP-39
    /// recovery phrase (prd.md §8.5). Enrolls the account in phrase-based account
    /// restore. `#[serde(default)]` so pre-existing JSON bodies without the field
    /// still deserialize (clients that don't send it simply opt out of recovery).
    #[serde(default)]
    pub recovery_pubkey: Option<Vec<u8>>,
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

/// Proof of possession of the BIP-39 recovery phrase, presented during a
/// lost-everything account restore (prd.md §8.5). The client re-derives the
/// deterministic Ed25519 keypair from the phrase and signs the server-issued
/// `login_nonce`; the server verifies `signature` against the `recovery_pubkey`
/// stored at registration and, only if valid, mints a brand-new device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProof {
    /// The new device's BasicCredential identity label (same role/shape as
    /// `RegistrationFinishRequest.mls_credential`). Opaque to the server.
    pub mls_credential: Vec<u8>,
    /// 64-byte Ed25519 signature over
    /// `b"powehi-recovery-challenge-v1" || 0x00 || login_nonce.as_bytes()`.
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishRequest {
    pub opaque_ke3: Vec<u8>,
    /// Must match the `login_nonce` returned by `login_init`.
    pub login_nonce: String,
    /// The device the user is authenticating from. Server verifies ownership before
    /// issuing a device-scoped session token.
    pub device_id: DeviceId,
    /// Optional recovery-phrase proof. When present AND `device_id` is unknown, the
    /// server attempts a §8.5 account restore: verify the phrase signature against
    /// the user's stored `recovery_pubkey` and mint `device_id` as a new device.
    /// `#[serde(default)]` so normal login bodies without the field still deserialize.
    #[serde(default)]
    pub recovery_proof: Option<RecoveryProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionToken(pub String);

/// Returned by `register_finish`. Carries both the user's persistent ID and the
/// newly-created device ID that the client must store for subsequent logins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationFinishResponse {
    pub user_id: UserId,
    /// Server-assigned device ID. Client stores this in LocalIdentity and presents
    /// it as `device_id` in every `LoginFinishRequest`.
    pub device_id: DeviceId,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationRequest {
    pub mls_credential: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRegistrationResponse {
    pub device_id: DeviceId,
}

/// A single device entry returned by `list_devices`.
///
/// `mls_credential` is intentionally omitted — callers don't need the raw
/// credential bytes to render the device list, and excluding it shrinks the
/// response and avoids sending extra crypto material over the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: DeviceId,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

#[async_trait]
pub trait AuthUseCase: Send + Sync {
    async fn register_init(
        &self,
        req: RegistrationInitRequest,
    ) -> Result<RegistrationInitResponse, DomainError>;
    async fn register_finish(
        &self,
        req: RegistrationFinishRequest,
    ) -> Result<RegistrationFinishResponse, DomainError>;
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
    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceInfo>, DomainError>;
}
