use async_trait::async_trait;
use futures_core::Stream;
use powehi_domain::{error::DomainError, event::DomainEvent};
use std::pin::Pin;

pub type EventStream = Pin<Box<dyn Stream<Item = Result<DomainEvent, DomainError>> + Send>>;

#[async_trait]
pub trait DomainEventBus: Send + Sync {
    async fn publish(&self, event: DomainEvent) -> Result<(), DomainError>;
    async fn subscribe(&self, topic: &str) -> Result<EventStream, DomainError>;
}
