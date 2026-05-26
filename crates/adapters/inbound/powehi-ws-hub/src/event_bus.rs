//! `WsEventBus` — composes the Redis event bus with the in-process WS hub.
//!
//! On every `publish()` call the event is:
//!   1. Dispatched to the `WsHub` (in-process fan-out to open WebSocket connections).
//!   2. Published to the underlying Redis pub/sub bus (for future cross-node delivery).
//!
//! The `subscribe()` delegate passes through to the inner bus.

use std::sync::Arc;

use async_trait::async_trait;
use powehi_domain::{error::DomainError, event::DomainEvent};
use powehi_port_outbound::event_bus::{DomainEventBus, EventStream};

use crate::WsHub;

pub struct WsEventBus {
    inner: Arc<dyn DomainEventBus>,
    hub: Arc<WsHub>,
}

impl WsEventBus {
    pub fn new(inner: Arc<dyn DomainEventBus>, hub: Arc<WsHub>) -> Self {
        Self { inner, hub }
    }
}

#[async_trait]
impl DomainEventBus for WsEventBus {
    async fn publish(&self, event: DomainEvent) -> Result<(), DomainError> {
        self.hub.dispatch(&event);
        self.inner.publish(event).await
    }

    async fn subscribe(&self, topic: &str) -> Result<EventStream, DomainError> {
        self.inner.subscribe(topic).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::{envelope::EnvelopeId, event::DomainEvent, group::GroupId};
    use powehi_port_outbound::event_bus::EventStream;
    use std::sync::Mutex;

    struct RecordingBus {
        events: Mutex<Vec<DomainEvent>>,
    }

    impl RecordingBus {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: Mutex::new(vec![]),
            })
        }
        fn recorded(&self) -> Vec<DomainEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl DomainEventBus for RecordingBus {
        async fn publish(&self, event: DomainEvent) -> Result<(), DomainError> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
        async fn subscribe(&self, _topic: &str) -> Result<EventStream, DomainError> {
            Ok(Box::pin(futures_util::stream::empty()))
        }
    }

    #[tokio::test]
    async fn publish_dispatches_to_hub_and_inner() {
        let inner = RecordingBus::new();
        let hub = Arc::new(WsHub::new());
        let mut rx = hub.subscribe();

        let bus = WsEventBus::new(inner.clone(), hub);
        let gid = GroupId::new();
        let eid = EnvelopeId::new();
        bus.publish(DomainEvent::EnvelopeReceived {
            envelope_id: eid.clone(),
            group_id: gid.clone(),
            at: chrono::Utc::now(),
        })
        .await
        .unwrap();

        // inner bus received the event
        assert_eq!(inner.recorded().len(), 1);

        // hub broadcast received the notification
        assert!(rx.try_recv().is_ok());
    }

    #[tokio::test]
    async fn subscribe_delegates_to_inner() {
        let inner = RecordingBus::new();
        let hub = Arc::new(WsHub::new());
        let bus = WsEventBus::new(inner, hub);
        // inner returns empty stream; should not error
        let _stream = bus.subscribe("envelope.received").await.unwrap();
    }
}
