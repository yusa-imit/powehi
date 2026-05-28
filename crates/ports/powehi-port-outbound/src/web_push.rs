use async_trait::async_trait;
use powehi_domain::{error::DomainError, push_subscription::PushSubscription};

/// Outbound port for delivering a wake-up push notification.
///
/// The notification body is ALWAYS empty (zero-knowledge: no message content
/// reaches the push service). The Service Worker renders a fixed string. The
/// adapter signs a VAPID JWT (RFC 8292) and POSTs an empty body to the
/// subscription endpoint (RFC 8291 §5, but with no ECE-encrypted payload).
#[async_trait]
pub trait WebPushPort: Send + Sync {
    /// Send an empty wake-up notification. Body is always empty (ZK: no content).
    async fn notify(&self, sub: &PushSubscription) -> Result<(), DomainError>;
}
