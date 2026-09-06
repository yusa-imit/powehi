use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::{ConsumeResult, KeyPackage, KeyPackageId},
};

#[async_trait]
pub trait KeyPackageRepository: Send + Sync {
    async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError>;
    /// Atomically fetch one unconsumed KeyPackage and mark it consumed.
    async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError>;
    async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError>;
    async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError>;
    /// Mark a specific KeyPackage consumed by ID (cross-region dedup).
    /// Idempotent: returns AlreadyConsumed if already consumed, NotFound if absent.
    /// Callers MUST treat `NotFound` as fail-closed (never proceed with the Add)
    /// exactly like `AlreadyConsumed` — after `delete_by_device` runs on device
    /// revocation, a previously-consumed id now also reads back as `NotFound`,
    /// not `AlreadyConsumed`.
    async fn mark_consumed(&self, id: &KeyPackageId) -> Result<ConsumeResult, DomainError>;
    /// Delete every KeyPackage (consumed or not) belonging to `device_id` from
    /// the shared pool table. Called on device revocation so a revoked
    /// device's credential can never be handed out again via a stale
    /// `fetch_one`/gRPC `ConsumeKeyPackage` on this path. Does NOT cover
    /// invite-pinned KeyPackage copies (`InviteUseCase::revoke_invites_for_device`
    /// closes that separate path). Idempotent: a device with zero KeyPackages
    /// returns `Ok(0)`, not an error.
    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<u64, DomainError>;
}
