//! Testcontainers integration tests for `RedisCache`'s `AbuseSignalStore` impl
//! (prd.md §6.4 — cross-region abuse signal propagation).
//!
//! The unit tests in `src/lib.rs` only cover the pure key-scheme function; they
//! never touch a real connection. These tests drive `block()` / `is_blocked()`
//! against a real Redis and assert the behaviour the cross-region primitive
//! depends on:
//!   - a block becomes visible immediately and is scoped to its exact subject,
//!   - blocks actually carry a Redis TTL (a block is never permanent),
//!   - re-blocking is idempotent and refreshes the entry,
//!   - IP and user subjects live in disjoint key namespaces,
//!   - the stored key AND value contain no raw IP address (zero-knowledge /
//!     no-plaintext rule), verified on what is really in Redis rather than on
//!     a local serialization.
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers), same
//! convention as `redis_cache_it.rs` / `redis_event_bus_it.rs`.
//! Run them in CI via: `cargo nextest run -p powehi-redis --run-ignored all
//!                       -E 'binary(redis_abuse_signal_it)'`

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use powehi_domain::{
    abuse::{AbuseReason, AbuseSubject},
    region::RegionId,
    user::UserId,
};
use powehi_port_outbound::abuse_signal::AbuseSignalStore;
use powehi_redis::RedisCache;
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::redis::Redis;

/// Start a throwaway Redis container and return a connection URL plus a
/// connected `RedisCache`. Caller must keep the container alive for the test.
async fn setup() -> (testcontainers::ContainerAsync<Redis>, String, RedisCache) {
    let container = Redis::default()
        .with_tag("7-alpine")
        .start()
        .await
        .expect("Redis container started");
    let port = container.get_host_port_ipv4(6379).await.expect("host port");
    let url = format!("redis://127.0.0.1:{port}");
    let cache = RedisCache::new(&url).await.expect("connect RedisCache");
    (container, url, cache)
}

fn test_ip() -> IpAddr {
    // TEST-NET-3 (RFC 5737) — documentation range, never a real client.
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))
}

fn region() -> RegionId {
    RegionId::new("eu-central-1")
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn unblocked_subject_is_not_blocked() {
    let (_c, _url, cache) = setup().await;
    let subject = AbuseSubject::from_ip(&test_ip());
    assert!(
        !cache.is_blocked(&subject).await.expect("is_blocked"),
        "a subject with no entry must not be blocked"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn block_makes_subject_blocked() {
    let (_c, _url, cache) = setup().await;
    let subject = AbuseSubject::from_ip(&test_ip());

    cache
        .block(
            &subject,
            AbuseReason::RateLimitExceeded,
            Duration::from_secs(60),
            region(),
        )
        .await
        .expect("block");

    assert!(cache.is_blocked(&subject).await.expect("is_blocked"));
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn block_is_scoped_to_the_exact_subject() {
    let (_c, _url, cache) = setup().await;
    let blocked = AbuseSubject::from_ip(&test_ip());
    let other = AbuseSubject::from_ip(&IpAddr::V4(Ipv4Addr::new(203, 0, 113, 8)));

    cache
        .block(
            &blocked,
            AbuseReason::KeyPackageFlood,
            Duration::from_secs(60),
            region(),
        )
        .await
        .expect("block");

    assert!(cache.is_blocked(&blocked).await.expect("is_blocked"));
    assert!(
        !cache.is_blocked(&other).await.expect("is_blocked"),
        "blocking one IP must not block a neighbouring IP"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn ip_and_user_subjects_are_independent() {
    let (_c, _url, cache) = setup().await;
    let ip_subject = AbuseSubject::from_ip(&test_ip());
    let user_subject = AbuseSubject::User(UserId::new());

    cache
        .block(
            &user_subject,
            AbuseReason::AuthBruteForce,
            Duration::from_secs(60),
            region(),
        )
        .await
        .expect("block user");

    assert!(cache.is_blocked(&user_subject).await.expect("is_blocked"));
    assert!(
        !cache.is_blocked(&ip_subject).await.expect("is_blocked"),
        "user and IP namespaces must be disjoint"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn block_sets_a_bounded_ttl() {
    let (_c, url, cache) = setup().await;
    let subject = AbuseSubject::from_ip(&test_ip());

    cache
        .block(
            &subject,
            AbuseReason::RateLimitExceeded,
            Duration::from_secs(120),
            region(),
        )
        .await
        .expect("block");

    let key = format!("abuse:ip:{}", subject.opaque_key());
    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL");

    // -1 = no expiry, -2 = missing. A block must always be bounded.
    assert!(
        ttl > 0 && ttl <= 120,
        "block must carry a bounded TTL, got {ttl}"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn zero_ttl_is_clamped_to_at_least_one_second() {
    let (_c, url, cache) = setup().await;
    let subject = AbuseSubject::User(UserId::new());

    cache
        .block(
            &subject,
            AbuseReason::AuthBruteForce,
            Duration::from_secs(0),
            region(),
        )
        .await
        .expect("block with zero ttl must not error");

    let key = format!("abuse:user:{}", subject.opaque_key());
    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL");

    assert!(
        ttl > 0,
        "a zero TTL must be clamped, never stored as permanent (got {ttl})"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn re_blocking_is_idempotent_and_refreshes_ttl() {
    let (_c, url, cache) = setup().await;
    let subject = AbuseSubject::from_ip(&test_ip());
    let key = format!("abuse:ip:{}", subject.opaque_key());

    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");

    cache
        .block(
            &subject,
            AbuseReason::RateLimitExceeded,
            Duration::from_secs(10),
            region(),
        )
        .await
        .expect("first block");
    let first_ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL");

    cache
        .block(
            &subject,
            AbuseReason::KeyPackageFlood,
            Duration::from_secs(300),
            RegionId::new("ap-seoul-1"),
        )
        .await
        .expect("second block");
    let second_ttl: i64 = redis::cmd("TTL")
        .arg(&key)
        .query_async(&mut conn)
        .await
        .expect("TTL");

    assert!(cache.is_blocked(&subject).await.expect("is_blocked"));
    assert!(
        second_ttl > first_ttl,
        "re-blocking must refresh the TTL ({first_ttl} -> {second_ttl})"
    );

    // Exactly one key per subject — re-blocking must not accumulate entries.
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("abuse:*")
        .query_async(&mut conn)
        .await
        .expect("KEYS");
    assert_eq!(keys.len(), 1, "one entry per subject, got {keys:?}");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn stored_key_and_value_contain_no_raw_ip() {
    let (_c, url, cache) = setup().await;
    let ip = test_ip();
    let subject = AbuseSubject::from_ip(&ip);

    cache
        .block(
            &subject,
            AbuseReason::KeyPackageFlood,
            Duration::from_secs(60),
            region(),
        )
        .await
        .expect("block");

    let client = redis::Client::open(url.as_str()).expect("open redis client");
    let mut conn = client
        .get_multiplexed_async_connection()
        .await
        .expect("redis connection");
    let keys: Vec<String> = redis::cmd("KEYS")
        .arg("abuse:*")
        .query_async(&mut conn)
        .await
        .expect("KEYS");
    assert_eq!(keys.len(), 1);

    let raw_ip = ip.to_string();
    for key in &keys {
        assert!(
            !key.contains(&raw_ip),
            "raw IP must never appear in a Redis key"
        );
    }

    let value: String = redis::cmd("GET")
        .arg(&keys[0])
        .query_async(&mut conn)
        .await
        .expect("GET");
    assert!(
        !value.contains(&raw_ip),
        "raw IP must never appear in a stored value"
    );
    // The value carries only the reason and the deciding region.
    assert!(value.contains("key_package_flood"));
    assert!(value.contains("eu-central-1"));
}
