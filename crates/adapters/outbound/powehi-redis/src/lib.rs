//! Redis outbound adapters.
//!
//! - `RedisCache` implements `CachePort` (GET / SET / DEL / EXISTS) and
//!   `AbuseSignalStore` (region-local cross-region abuse blocks, prd.md §6.4).
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
use powehi_domain::{
    abuse::{AbuseReason, AbuseSubject},
    error::DomainError,
    event::DomainEvent,
    region::RegionId,
};
use powehi_port_outbound::{
    abuse_signal::AbuseSignalStore,
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

    async fn get_del(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
        let mut conn = self.conn.clone();
        let val: Option<Vec<u8>> = redis::cmd("GETDEL")
            .arg(key)
            .query_async(&mut conn)
            .await
            .map_err(map_err)?;
        Ok(val)
    }

    async fn set_add(&self, key: &str, member: &str) -> Result<(), DomainError> {
        let mut conn = self.conn.clone();
        conn.sadd::<_, _, ()>(key, member).await.map_err(map_err)?;
        Ok(())
    }

    async fn set_expire(&self, key: &str, ttl: Duration) -> Result<(), DomainError> {
        let mut conn = self.conn.clone();
        let secs = i64::try_from(ttl.as_secs().max(1)).unwrap_or(i64::MAX);
        conn.expire::<_, ()>(key, secs).await.map_err(map_err)?;
        Ok(())
    }

    async fn set_remove(&self, key: &str, member: &str) -> Result<(), DomainError> {
        let mut conn = self.conn.clone();
        conn.srem::<_, _, ()>(key, member).await.map_err(map_err)?;
        Ok(())
    }

    async fn set_members(&self, key: &str) -> Result<Vec<String>, DomainError> {
        let mut conn = self.conn.clone();
        let members: Vec<String> = conn.smembers(key).await.map_err(map_err)?;
        Ok(members)
    }
}

// ── AbuseSignalStore ────────────────────────────────────────────────────────

/// Key namespace for abuse blocks. Separate prefixes per subject kind so an
/// IP digest and a user UUID can never collide, and so an operator can scan
/// one class without touching the other.
const ABUSE_IP_PREFIX: &str = "abuse:ip:";
const ABUSE_USER_PREFIX: &str = "abuse:user:";

/// Stored value for an abuse block.
///
/// Deliberately minimal: the subject itself is already encoded in the key, so
/// the value carries only *why* and *who decided*. No raw IP, no handle, no
/// content — the same zero-knowledge rule the rest of this adapter follows.
#[derive(serde::Serialize, serde::Deserialize)]
struct AbuseBlockValue<'a> {
    reason: &'a str,
    origin_region: &'a str,
}

fn abuse_key(subject: &AbuseSubject) -> String {
    let prefix = match subject {
        AbuseSubject::IpHash(_) => ABUSE_IP_PREFIX,
        AbuseSubject::User(_) => ABUSE_USER_PREFIX,
    };
    // `opaque_key()` is hex(SHA-256(ip)) or the user UUID — never a raw address.
    format!("{prefix}{}", subject.opaque_key())
}

#[async_trait]
impl AbuseSignalStore for RedisCache {
    async fn block(
        &self,
        subject: &AbuseSubject,
        reason: AbuseReason,
        ttl: Duration,
        origin_region: RegionId,
    ) -> Result<(), DomainError> {
        let key = abuse_key(subject);
        let payload = serde_json::to_vec(&AbuseBlockValue {
            reason: reason.as_str(),
            origin_region: origin_region.as_str(),
        })
        .map_err(map_serde)?;

        // Redis rejects EX 0, and a zero TTL would mean "never expires" if we
        // fell through to a plain SET — clamp to at least one second so a block
        // is always bounded. Also clamp the upper end to MAX_ABUSE_SIGNAL_TTL as
        // defense in depth: the gRPC receiving path already clamps a
        // peer-supplied TTL before calling `block()`, but this adapter must not
        // rely on every future caller remembering to do the same
        // (security-auditor finding, cycle 433).
        let secs = ttl
            .min(powehi_port_outbound::abuse_signal::MAX_ABUSE_SIGNAL_TTL)
            .as_secs()
            .max(1);
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(&key, payload, secs)
            .await
            .map_err(map_err)?;

        // Opaque fields only (rule: no-plaintext-logging): the subject kind and
        // the deciding region, never the digest, the UUID or a raw address.
        tracing::debug!(
            subject_kind = subject.kind(),
            reason = reason.as_str(),
            origin_region = origin_region.as_str(),
            ttl_secs = secs,
            "abuse block stored"
        );
        Ok(())
    }

    async fn is_blocked(&self, subject: &AbuseSubject) -> Result<bool, DomainError> {
        let key = abuse_key(subject);
        let mut conn = self.conn.clone();
        let n: u32 = conn.exists(&key).await.map_err(map_err)?;
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
    use std::pin::Pin;

    use chrono::Utc;
    use futures_core::Stream;
    use powehi_domain::{
        device::DeviceId,
        envelope::EnvelopeId,
        group::{Epoch, GroupId},
        user::UserId,
    };
    use uuid::Uuid;

    use super::*;

    fn assert_cache<T: CachePort>() {}
    fn assert_bus<T: DomainEventBus>() {}
    fn assert_abuse_store<T: AbuseSignalStore>() {}

    #[test]
    fn redis_cache_impl_trait() {
        assert_cache::<RedisCache>();
    }

    #[test]
    fn redis_cache_impl_abuse_signal_store() {
        assert_abuse_store::<RedisCache>();
    }

    #[test]
    fn redis_event_bus_impl_trait() {
        assert_bus::<RedisEventBus>();
    }

    // ── event_topic routing ──────────────────────────────────────────────────

    #[test]
    fn event_topic_user_registered() {
        let e = DomainEvent::UserRegistered {
            user_id: UserId::from(Uuid::new_v4()),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "user.registered");
    }

    #[test]
    fn event_topic_device_registered() {
        let e = DomainEvent::DeviceRegistered {
            device_id: DeviceId::from(Uuid::new_v4()),
            user_id: UserId::from(Uuid::new_v4()),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "device.registered");
    }

    #[test]
    fn event_topic_device_revoked() {
        let e = DomainEvent::DeviceRevoked {
            device_id: DeviceId::from(Uuid::new_v4()),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "device.revoked");
    }

    #[test]
    fn event_topic_envelope_received() {
        let e = DomainEvent::EnvelopeReceived {
            envelope_id: EnvelopeId::from(Uuid::new_v4()),
            group_id: GroupId::from(Uuid::new_v4()),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "envelope.received");
    }

    #[test]
    fn event_topic_epoch_advanced() {
        let e = DomainEvent::EpochAdvanced {
            group_id: GroupId::from(Uuid::new_v4()),
            new_epoch: Epoch(3),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "epoch.advanced");
    }

    #[test]
    fn event_topic_member_added() {
        let e = DomainEvent::MemberAdded {
            group_id: GroupId::from(Uuid::new_v4()),
            device_id: DeviceId::from(Uuid::new_v4()),
            epoch: Epoch(1),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "member.added");
    }

    #[test]
    fn event_topic_member_removed() {
        let e = DomainEvent::MemberRemoved {
            group_id: GroupId::from(Uuid::new_v4()),
            device_id: DeviceId::from(Uuid::new_v4()),
            epoch: Epoch(2),
            at: Utc::now(),
        };
        assert_eq!(event_topic(&e), "member.removed");
    }

    // ── DomainEvent serde round-trips ────────────────────────────────────────

    fn round_trip(event: &DomainEvent) -> DomainEvent {
        let bytes = serde_json::to_vec(event).expect("serialize");
        serde_json::from_slice(&bytes).expect("deserialize")
    }

    #[test]
    fn serde_round_trip_user_registered() {
        let raw = Uuid::new_v4();
        let e = DomainEvent::UserRegistered {
            user_id: UserId::from(raw),
            at: Utc::now(),
        };
        let rt = round_trip(&e);
        assert_eq!(event_topic(&rt), "user.registered");
        if let DomainEvent::UserRegistered { user_id, .. } = rt {
            assert_eq!(user_id.as_uuid(), raw);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serde_round_trip_envelope_received() {
        let raw_env = Uuid::new_v4();
        let raw_grp = Uuid::new_v4();
        let e = DomainEvent::EnvelopeReceived {
            envelope_id: EnvelopeId::from(raw_env),
            group_id: GroupId::from(raw_grp),
            at: Utc::now(),
        };
        let rt = round_trip(&e);
        if let DomainEvent::EnvelopeReceived {
            envelope_id,
            group_id,
            ..
        } = rt
        {
            assert_eq!(envelope_id.as_uuid(), raw_env);
            assert_eq!(group_id.as_uuid(), raw_grp);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn serde_round_trip_epoch_advanced() {
        let grp_id = GroupId::from(Uuid::new_v4());
        let e = DomainEvent::EpochAdvanced {
            group_id: grp_id,
            new_epoch: Epoch(7),
            at: Utc::now(),
        };
        let rt = round_trip(&e);
        if let DomainEvent::EpochAdvanced { new_epoch, .. } = rt {
            assert_eq!(new_epoch, Epoch(7));
        } else {
            panic!("wrong variant");
        }
    }

    // ── JSON payload must not contain plaintext user content ─────────────────

    #[test]
    fn serde_envelope_payload_contains_only_opaque_ids() {
        let raw_env = Uuid::new_v4();
        let raw_grp = Uuid::new_v4();
        let e = DomainEvent::EnvelopeReceived {
            envelope_id: EnvelopeId::from(raw_env),
            group_id: GroupId::from(raw_grp),
            at: Utc::now(),
        };
        let json = serde_json::to_string(&e).expect("serialize");
        // Must contain the UUIDs — opaque identifiers only, no human-readable names.
        assert!(json.contains(&raw_env.to_string()));
        assert!(json.contains(&raw_grp.to_string()));
        // Must NOT contain any "content", "ciphertext", or "plaintext" keys.
        assert!(!json.contains("content"));
        assert!(!json.contains("ciphertext"));
        assert!(!json.contains("plaintext"));
    }

    // ── EmptyStream ──────────────────────────────────────────────────────────

    #[test]
    fn empty_stream_returns_none() {
        use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        fn no_op(_: *const ()) {}
        fn clone(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);

        let waker = unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut stream = EmptyStream;
        let pin = Pin::new(&mut stream);
        assert!(matches!(pin.poll_next(&mut cx), Poll::Ready(None)));
    }

    // ── abuse key scheme (prd.md §6.4) ───────────────────────────────────────

    #[test]
    fn abuse_key_for_ip_uses_hashed_prefix() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let key = abuse_key(&AbuseSubject::from_ip(&ip));
        assert!(key.starts_with("abuse:ip:"));
        // 64 hex chars of SHA-256 follow the prefix.
        assert_eq!(key.len(), "abuse:ip:".len() + 64);
        // The raw address must never appear in a Redis key.
        assert!(!key.contains("203.0.113.7"));
    }

    #[test]
    fn abuse_key_for_user_uses_uuid() {
        let id = UserId::from(Uuid::new_v4());
        let key = abuse_key(&AbuseSubject::User(id.clone()));
        assert_eq!(key, format!("abuse:user:{}", id.as_uuid()));
    }

    #[test]
    fn abuse_keys_for_ip_and_user_never_collide() {
        use std::net::{IpAddr, Ipv4Addr};
        let ip_key = abuse_key(&AbuseSubject::from_ip(&IpAddr::V4(Ipv4Addr::new(
            198, 51, 100, 1,
        ))));
        let user_key = abuse_key(&AbuseSubject::User(UserId::from(Uuid::new_v4())));
        assert_ne!(ip_key, user_key);
        assert!(ip_key.starts_with("abuse:ip:"));
        assert!(user_key.starts_with("abuse:user:"));
    }

    #[test]
    fn abuse_block_value_contains_only_reason_and_region() {
        let json = serde_json::to_string(&AbuseBlockValue {
            reason: AbuseReason::KeyPackageFlood.as_str(),
            origin_region: "eu-central-1",
        })
        .expect("serialize");
        assert!(json.contains("key_package_flood"));
        assert!(json.contains("eu-central-1"));
        // No subject material, no content.
        assert!(!json.contains("ip"));
        assert!(!json.contains("hash"));
        assert!(!json.contains("plaintext"));
    }
}
