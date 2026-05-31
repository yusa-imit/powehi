use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    envelope::{Envelope, EnvelopeId},
    error::DomainError,
};

#[async_trait]
pub trait EnvelopeRepository: Send + Sync {
    async fn save(&self, envelope: &Envelope) -> Result<(), DomainError>;
    async fn find_pending(
        &self,
        device_id: &DeviceId,
        since: Option<DateTime<Utc>>,
    ) -> Result<Vec<Envelope>, DomainError>;
    async fn find_by_id(&self, id: &EnvelopeId) -> Result<Option<Envelope>, DomainError>;
    async fn delete(&self, id: &EnvelopeId) -> Result<(), DomainError>;
    async fn delete_expired(&self) -> Result<u64, DomainError>;
}
