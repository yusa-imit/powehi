//! Redis outbound adapters.
//!
//! - `RedisCache` implements `CachePort` (GET / SET / DEL / EXISTS).
//! - `RedisEventBus` implements `DomainEventBus` (PUBLISH; subscribe returns
//!   an empty stream — real fan-out wired when WS hub lands in Phase 3).
//!
//! Security invariant: values stored in Redis are opaque bytes; no logging of
//! cache values or event payloads (rule: no-plaintext-logging).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;
use powehi_domain::{error::DomainError, event::DomainEvent};
use powehi_port_outbound::{
    cache::CachePort,
    event_bus::{DomainEventBus, EventStream},
};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;

fn map_err(e: redis::RedisError) -> DomainError {
    tracing::error!(error_kind = "redis", "cache error");
    DomainError::Internal(e.to_string())
}

fn map_serde(e: serde_json::Error) -> DomainError {
    DomainError::Internal(format!("event serialize: {e}"))
}

// ── CachePort ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RedisCache {
    conn: ConnectionManager,
}

impl RedisCache {
    pub async fn new(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }
}

#[async_trait]
impl CachePort for RedisCache {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
        let mut conn = self.conn.clone();
        let val: Option<Vec<u8>> = conn.get(key).await.map_err(map_err)?;
        Ok(val)
    }

    async fn set(
        &self,
        key: &str,
        value: Vec<u8>,
        ttl: Option<Duration>,
    ) -> Result<(), DomainError> {
        let mut conn = self.conn.clone();
        if let Some(ttl) = ttl {
            let secs = ttl.as_secs().max(1);
            conn.set_ex::<_, _, ()>(key, value, secs)
                .await
                .map_err(map_err)?;
        } else {
            conn.set::<_, _, ()>(key, value).await.map_err(map_err)?;
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), DomainError> {
        let mut conn = self.conn.clone();
        conn.del::<_, ()>(key).await.map_err(map_err)?;
        Ok(())
    }

    async fn exists(&self, key: &str) -> Result<bool, DomainError> {
        let mut conn = self.conn.clone();
        let n: u32 = conn.exists(key).await.map_err(map_err)?;
        Ok(n > 0)
    }
}

// ── DomainEventBus ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct RedisEventBus {
    conn: ConnectionManager,
}

impl RedisEventBus {
    pub async fn new(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;
        let conn = ConnectionManager::new(client).await?;
        Ok(Self { conn })
    }
}

struct EmptyStream;

impl Stream for EmptyStream {
    type Item = Result<DomainEvent, DomainError>;
    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

#[async_trait]
impl DomainEventBus for RedisEventBus {
    async fn publish(&self, event: DomainEvent) -> Result<(), DomainError> {
        let topic = event_topic(&event);
        let payload = serde_json::to_vec(&event).map_err(map_serde)?;
        let mut conn = self.conn.clone();
        conn.publish::<_, _, ()>(topic, payload)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn subscribe(&self, _topic: &str) -> Result<EventStream, DomainError> {
        // Real Redis pub/sub fan-out is wired in Phase 3 WS Hub task.
        Ok(Box::pin(EmptyStream))
    }
}

fn event_topic(event: &DomainEvent) -> &'static str {
    match event {
        DomainEvent::UserRegistered { .. } => "user.registered",
        DomainEvent::DeviceRegistered { .. } => "device.registered",
        DomainEvent::DeviceRevoked { .. } => "device.revoked",
        DomainEvent::EnvelopeReceived { .. } => "envelope.received",
        DomainEvent::EpochAdvanced { .. } => "epoch.advanced",
        DomainEvent::MemberAdded { .. } => "member.added",
        DomainEvent::MemberRemoved { .. } => "member.removed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_cache<T: CachePort>() {}
    fn assert_bus<T: DomainEventBus>() {}

    #[test]
    fn redis_cache_impl_trait() {
        assert_cache::<RedisCache>();
    }

    #[test]
    fn redis_event_bus_impl_trait() {
        assert_bus::<RedisEventBus>();
    }
}
