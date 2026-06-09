use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError};

pub struct CreatedInvite {
    pub code: String,
}

pub struct RedeemedInvite {
    pub device_id: DeviceId,
}

#[async_trait]
pub trait InviteUseCase: Send + Sync {
    /// Create a one-time 24-hour invite code for the given device.
    async fn create_invite(&self, device_id: &DeviceId) -> Result<CreatedInvite, DomainError>;

    /// Redeem an invite code atomically (one-time use). Returns the inviting device's ID
    /// so the caller can fetch their KeyPackages and initiate an MLS Welcome.
    async fn redeem_invite(&self, code: &str) -> Result<RedeemedInvite, DomainError>;
}
