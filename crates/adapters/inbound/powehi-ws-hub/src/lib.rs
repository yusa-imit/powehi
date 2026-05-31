//! WebSocket hub inbound adapter.
//!
//! Pushes opaque delivery notifications to connected devices via WebSocket.
//! The hub dispatches only metadata (UUIDs, epoch numbers) — no ciphertext, no PII.
//!
//! Design: a single `tokio::sync::broadcast` channel fans out to all open sockets.
//! Clients receive a "there is something new" signal and then call the REST poll API
//! to fetch their device-specific envelopes.  Simpler than per-device channels,
//! correct for Phase 3, and naturally narrows to group/device fan-out in Phase 5.
//!
//! Security invariant (rule: no-plaintext-logging):
//!   Log only opaque IDs; never log ciphertext or message content.

pub mod event_bus;
mod handler;

use std::sync::Arc;

use axum::{routing::get, Router};
use serde::Serialize;
use tokio::sync::broadcast;

use powehi_domain::event::DomainEvent;
use powehi_port_outbound::cache::CachePort;

/// Capacity of the broadcast ring buffer.
const HUB_CAPACITY: usize = 512;

/// Opaque WebSocket notification pushed to all connected devices.
///
/// Contains only group/envelope UUIDs and epoch numbers — never ciphertext.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsNotification {
    EnvelopeReceived {
        group_id: String,
        envelope_id: String,
    },
    EpochAdvanced {
        group_id: String,
        new_epoch: u64,
    },
    MemberAdded {
        group_id: String,
    },
    MemberRemoved {
        group_id: String,
    },
}

/// State shared by every WebSocket connection: the broadcast hub and the
/// session cache used to resolve Bearer tokens to DeviceIds.
#[derive(Clone)]
pub(crate) struct WsHubState {
    pub(crate) hub: Arc<WsHub>,
    pub(crate) cache: Arc<dyn CachePort>,
}

/// Global fan-out hub.  All authenticated WS connections share one broadcast sender.
#[derive(Clone)]
pub struct WsHub {
    tx: broadcast::Sender<WsNotification>,
}

impl WsHub {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(HUB_CAPACITY);
        Self { tx }
    }

    /// Subscribe to incoming notifications (one receiver per WS connection).
    pub fn subscribe(&self) -> broadcast::Receiver<WsNotification> {
        self.tx.subscribe()
    }

    /// Translate a `DomainEvent` into a `WsNotification` and broadcast it.
    /// Silently no-ops for events that don't produce a WS notification.
    pub fn dispatch(&self, event: &DomainEvent) {
        let notif = match event {
            DomainEvent::EnvelopeReceived {
                envelope_id,
                group_id,
                ..
            } => Some(WsNotification::EnvelopeReceived {
                group_id: group_id.to_string(),
                envelope_id: envelope_id.to_string(),
            }),
            DomainEvent::EpochAdvanced {
                group_id,
                new_epoch,
                ..
            } => Some(WsNotification::EpochAdvanced {
                group_id: group_id.to_string(),
                new_epoch: new_epoch.0,
            }),
            DomainEvent::MemberAdded { group_id, .. } => Some(WsNotification::MemberAdded {
                group_id: group_id.to_string(),
            }),
            DomainEvent::MemberRemoved { group_id, .. } => Some(WsNotification::MemberRemoved {
                group_id: group_id.to_string(),
            }),
            _ => None,
        };
        if let Some(n) = notif {
            let _ = self.tx.send(n); // ok to ignore if no receivers
        }
    }
}

impl Default for WsHub {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the axum router fragment for the WS endpoint (`GET /v1/ws`).
pub fn router(hub: Arc<WsHub>, cache: Arc<dyn CachePort>) -> Router {
    Router::new()
        .route("/v1/ws", get(handler::ws_handler))
        .with_state(WsHubState { hub, cache })
}

#[cfg(test)]
mod tests {
    use super::*;
    use powehi_domain::{
        envelope::EnvelopeId,
        event::DomainEvent,
        group::{Epoch, GroupId},
    };

    #[test]
    fn dispatch_envelope_received_produces_notification() {
        let hub = WsHub::new();
        let mut rx = hub.subscribe();

        let gid = GroupId::new();
        let eid = EnvelopeId::new();
        hub.dispatch(&DomainEvent::EnvelopeReceived {
            envelope_id: eid.clone(),
            group_id: gid.clone(),
            at: chrono::Utc::now(),
        });

        let notif = rx.try_recv().expect("notification sent");
        match notif {
            WsNotification::EnvelopeReceived {
                group_id,
                envelope_id,
            } => {
                assert_eq!(group_id, gid.to_string());
                assert_eq!(envelope_id, eid.to_string());
            }
            other => panic!("unexpected notification: {:?}", other),
        }
    }

    #[test]
    fn dispatch_epoch_advanced_produces_notification() {
        let hub = WsHub::new();
        let mut rx = hub.subscribe();

        let gid = GroupId::new();
        hub.dispatch(&DomainEvent::EpochAdvanced {
            group_id: gid.clone(),
            new_epoch: Epoch(7),
            at: chrono::Utc::now(),
        });

        let notif = rx.try_recv().expect("notification sent");
        match notif {
            WsNotification::EpochAdvanced {
                group_id,
                new_epoch,
            } => {
                assert_eq!(group_id, gid.to_string());
                assert_eq!(new_epoch, 7);
            }
            other => panic!("unexpected notification: {:?}", other),
        }
    }

    #[test]
    fn user_registered_event_produces_no_notification() {
        let hub = WsHub::new();
        let mut rx = hub.subscribe();

        hub.dispatch(&DomainEvent::UserRegistered {
            user_id: powehi_domain::user::UserId::new(),
            at: chrono::Utc::now(),
        });

        assert!(rx.try_recv().is_err(), "no notification for UserRegistered");
    }

    #[test]
    fn no_subscribers_dispatch_is_silent() {
        let hub = WsHub::new();
        // No subscribers — should not panic
        hub.dispatch(&DomainEvent::EpochAdvanced {
            group_id: GroupId::new(),
            new_epoch: Epoch(1),
            at: chrono::Utc::now(),
        });
    }

    #[test]
    fn notification_is_json_serializable() {
        let n = WsNotification::EnvelopeReceived {
            group_id: "abc".into(),
            envelope_id: "def".into(),
        };
        let json = serde_json::to_string(&n).unwrap();
        assert!(json.contains("\"type\":\"envelope_received\""));
        assert!(json.contains("\"group_id\":\"abc\""));
        assert!(!json.contains("ciphertext"));
    }

    #[test]
    fn ws_hub_default_works() {
        let _hub = WsHub::default();
    }
}
