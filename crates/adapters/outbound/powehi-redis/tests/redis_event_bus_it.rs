//! Testcontainers integration tests for powehi-redis `RedisEventBus`.
//!
//! `RedisCache` (same crate) already has thorough testcontainers coverage in
//! `redis_cache_it.rs`. `RedisEventBus::publish` had ZERO integration coverage
//! anywhere in the workspace — only pure-function unit tests (`event_topic`,
//! serde round-trips) exist in `src/lib.rs`, which never touch a real Redis
//! connection or the actual PUBLISH wire behavior. These tests close that gap
//! by publishing through the real adapter and observing the message on a
//! separate raw `redis::aio::PubSub` subscriber connection — exercising:
//!   - `publish()` actually reaches Redis and returns `Ok(())`.
//!   - The message is delivered on the exact channel `event_topic()` names
//!     (topic routing is correct end-to-end, not just in the pure match).
//!   - The payload on the wire round-trips back to the original `DomainEvent`.
//!   - `publish()` with zero subscribers still succeeds (Redis PUBLISH returns
//!     a receiver count, not an error, when no one is listening).
//!   - The wire payload carries only opaque IDs — no plaintext content keys
//!     (rule: no-plaintext-logging) — verified on the bytes actually
//!     transmitted over the real connection, not just a local serialization.
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers), same
//! convention as `redis_cache_it.rs`.
//! Run them in CI via: `cargo nextest run -p powehi-redis --run-ignored all
//!                       -E 'binary(redis_event_bus_it)'`

use std::time::Duration;

use chrono::Utc;
use futures_util::StreamExt;
use powehi_domain::{
    device::DeviceId,
    envelope::EnvelopeId,
    event::DomainEvent,
    group::{Epoch, GroupId},
};
use powehi_port_outbound::event_bus::DomainEventBus;
use powehi_redis::RedisEventBus;
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::redis::Redis;

/// Start a throwaway Redis container and return a connection URL plus a
/// connected `RedisEventBus`. Caller must keep the returned container alive
/// for the duration of the test.
async fn setup() -> (testcontainers::ContainerAsync<Redis>, String, RedisEventBus) {
    let container = Redis::default()
        .with_tag("7-alpine")
        .start()
        .await
        .expect("Redis container started");
    let port = container.get_host_port_ipv4(6379).await.expect("host port");
    let url = format!("redis://127.0.0.1:{port}");
    let bus = RedisEventBus::new(&url)
        .await
        .expect("connect RedisEventBus");
    (container, url, bus)
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn publish_is_received_on_the_correct_topic_channel() {
    let (_c, url, bus) = setup().await;

    // Independent raw subscriber connection — proves the message actually
    // travels over the wire via PUBLISH, not just an in-process call.
    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut pubsub = client.get_async_pubsub().await.expect("pubsub connection");
    pubsub
        .subscribe("envelope.received")
        .await
        .expect("subscribe to envelope.received");
    let mut msgs = pubsub.into_on_message();

    let envelope_id = EnvelopeId::new();
    let group_id = GroupId::new();
    let event = DomainEvent::EnvelopeReceived {
        envelope_id: envelope_id.clone(),
        group_id: group_id.clone(),
        at: Utc::now(),
    };

    bus.publish(event).await.expect("publish must succeed");

    let received = tokio::time::timeout(Duration::from_secs(5), msgs.next())
        .await
        .expect("must receive a pubsub message before timeout")
        .expect("stream must yield Some(msg)");

    assert_eq!(received.get_channel_name(), "envelope.received");
    let payload: Vec<u8> = received.get_payload().expect("payload bytes");
    let decoded: DomainEvent = serde_json::from_slice(&payload).expect("deserialize event");
    match decoded {
        DomainEvent::EnvelopeReceived {
            envelope_id: got_env,
            group_id: got_grp,
            ..
        } => {
            assert_eq!(got_env, envelope_id);
            assert_eq!(got_grp, group_id);
        }
        other => panic!("wrong variant received: {other:?}"),
    }
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn publish_with_no_subscribers_still_succeeds() {
    // Redis PUBLISH returns the number of clients that received the message
    // (which is legitimately 0 when nobody is subscribed) — this must not be
    // surfaced as an error by the adapter.
    let (_c, _url, bus) = setup().await;
    let event = DomainEvent::MemberRemoved {
        group_id: GroupId::new(),
        device_id: DeviceId::new(),
        epoch: Epoch(1),
        at: Utc::now(),
    };
    let result = bus.publish(event).await;
    assert!(
        result.is_ok(),
        "publish with zero subscribers must still be Ok, got {result:?}"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn published_wire_payload_contains_only_opaque_ids() {
    let (_c, url, bus) = setup().await;

    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut pubsub = client.get_async_pubsub().await.expect("pubsub connection");
    pubsub
        .subscribe("member.added")
        .await
        .expect("subscribe to member.added");
    let mut msgs = pubsub.into_on_message();

    let group_id = GroupId::new();
    let device_id = DeviceId::new();
    let event = DomainEvent::MemberAdded {
        group_id: group_id.clone(),
        device_id: device_id.clone(),
        epoch: Epoch(4),
        at: Utc::now(),
    };
    bus.publish(event).await.expect("publish must succeed");

    let received = tokio::time::timeout(Duration::from_secs(5), msgs.next())
        .await
        .expect("must receive a pubsub message before timeout")
        .expect("stream must yield Some(msg)");
    let payload: Vec<u8> = received.get_payload().expect("payload bytes");
    let json = String::from_utf8(payload).expect("payload is valid utf8 json");

    // Opaque identifiers must be present...
    assert!(json.contains(&group_id.to_string()));
    assert!(json.contains(&device_id.to_string()));
    // ...but no plaintext content/ciphertext keys ever leave the process.
    assert!(!json.contains("content"));
    assert!(!json.contains("ciphertext"));
    assert!(!json.contains("plaintext"));
}
