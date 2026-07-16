use async_trait::async_trait;
use powehi_domain::{device::DeviceId, error::DomainError};

pub struct CreatedInvite {
    pub code: String,
}

pub struct RedeemedInvite {
    pub device_id: DeviceId,
    /// The exact KeyPackage bytes the inviting client supplied to `create_invite`.
    pub key_package: Vec<u8>,
}

#[async_trait]
pub trait InviteUseCase: Send + Sync {
    /// Create a one-time 24-hour invite code for the given device, pinning it to
    /// `key_package` — a KeyPackage the CALLING CLIENT generated itself (never
    /// chosen or authored by the server).
    ///
    /// prd.md §8.3/§8.4: the caller is expected to hash `key_package` locally
    /// (before this call, from bytes it generated itself) and embed that hash
    /// in the shareable invite URL's fragment, which the browser never sends to
    /// the server. The recipient later recomputes the hash over the
    /// `key_package` bytes `redeem_invite` returns and compares against the
    /// fragment's hash. Critically, the server never sees or authors the hash
    /// itself — only relays the bytes — so it cannot forge a (bytes, hash) pair
    /// that passes verification. Binding the hash to server-returned data
    /// instead (e.g. hashing server-supplied bytes, or trusting a server-
    /// computed hash) would NOT provide this property, since a compromised
    /// server could simply lie consistently about both.
    async fn create_invite(
        &self,
        device_id: &DeviceId,
        key_package: Vec<u8>,
    ) -> Result<CreatedInvite, DomainError>;

    /// Redeem an invite code atomically (one-time use). Returns the inviting
    /// device's ID and the KeyPackage pinned at creation time.
    async fn redeem_invite(&self, code: &str) -> Result<RedeemedInvite, DomainError>;
}
