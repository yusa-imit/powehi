//! Testcontainers integration tests for powehi-redis `RedisCache`.
//!
//! Each test spins up an ephemeral Redis container and exercises the
//! `CachePort` implementation against REAL Redis semantics that a mock could
//! never validate:
//!   - SET/GET byte round-trips and missing-key `None`.
//!   - TTL expiry (SET EX / EXPIRE) actually removing keys after the deadline.
//!   - GETDEL atomicity (read-and-remove in a single command).
//!   - SADD / SMEMBERS set round-trips.
//!   - DEL idempotency and EXISTS presence tracking.
//!
//! Uses redis:7-alpine explicitly — the testcontainers-modules default (5.0)
//! predates GETDEL (added in Redis 6.2), which `RedisCache::get_del` issues.
//!
//! Tests are `#[ignore]` because they require Docker (testcontainers).
//! Run them in CI via: `cargo nextest run -p powehi-redis --run-ignored all
//!                       -E 'binary(redis_cache_it)'`
//!
//! SECURITY: the cached values here are opaque bytes / set members supplied by
//! the test itself — not real message plaintext. This file tests STORAGE
//! CORRECTNESS, not content confidentiality (the latter is the
//! `no-plaintext-logging` rule's job, unaffected by this change).

use std::time::Duration;

use powehi_port_outbound::cache::CachePort;
use powehi_redis::RedisCache;
use testcontainers::{runners::AsyncRunner, ImageExt};
use testcontainers_modules::redis::Redis;
use uuid::Uuid;

// ── Container setup ───────────────────────────────────────────────────────────

/// Start a throwaway Redis container and return a connected `RedisCache`.
/// Caller must keep the returned container alive for the duration of the test.
///
/// Uses redis:7-alpine explicitly — the testcontainers-modules default (5.0)
/// predates GETDEL (Redis 6.2), which `RedisCache::get_del` issues.
async fn setup() -> (testcontainers::ContainerAsync<Redis>, RedisCache) {
    let container = Redis::default()
        .with_tag("7-alpine")
        .start()
        .await
        .expect("Redis container started");
    let port = container.get_host_port_ipv4(6379).await.expect("host port");
    let url = format!("redis://127.0.0.1:{port}");
    let cache = RedisCache::new(&url).await.expect("connect RedisCache");
    (container, cache)
}

/// A per-test unique key prefix so tests never collide on the keyspace.
/// Containers are per-test, so this is defensive/consistent with the postgres
/// file's per-test unique-fixture style.
fn unique_key(name: &str) -> String {
    format!("it:{}:{name}", Uuid::new_v4())
}

// ── CachePort round-trip tests ────────────────────────────────────────────────

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn set_then_get_round_trips_value() {
    let (_c, cache) = setup().await;
    let key = unique_key("mykey");
    let value = b"opaque-ciphertext-bytes".to_vec();
    cache.set(&key, value.clone(), None).await.expect("set");
    let got = cache.get(&key).await.expect("get");
    assert_eq!(got, Some(value), "get must return the stored bytes");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn get_on_missing_key_returns_none() {
    let (_c, cache) = setup().await;
    let key = unique_key("missing");
    let got = cache.get(&key).await.expect("get");
    assert!(got.is_none(), "unset key must return None");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn set_with_ttl_expires() {
    let (_c, cache) = setup().await;
    let key = unique_key("ttl");
    cache
        .set(&key, b"ephemeral".to_vec(), Some(Duration::from_secs(1)))
        .await
        .expect("set with ttl");
    // Sleep well past the 1s TTL so Redis has expired the key.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let got = cache.get(&key).await.expect("get after ttl");
    assert!(got.is_none(), "value must be gone after its TTL elapses");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn delete_removes_key() {
    let (_c, cache) = setup().await;
    let key = unique_key("del");
    cache.set(&key, b"x".to_vec(), None).await.expect("set");
    cache.delete(&key).await.expect("delete");
    let got = cache.get(&key).await.expect("get");
    assert!(got.is_none(), "deleted key must return None");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn delete_on_missing_key_is_ok() {
    let (_c, cache) = setup().await;
    let key = unique_key("del-missing");
    // DEL on a non-existent key is a no-op in Redis and must not error.
    cache
        .delete(&key)
        .await
        .expect("delete on missing key must be idempotent");
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn exists_reflects_key_presence() {
    let (_c, cache) = setup().await;
    let key = unique_key("exists");
    assert!(
        !cache.exists(&key).await.expect("exists before"),
        "key must not exist before set"
    );
    cache.set(&key, b"here".to_vec(), None).await.expect("set");
    assert!(
        cache.exists(&key).await.expect("exists after set"),
        "key must exist after set"
    );
    cache.delete(&key).await.expect("delete");
    assert!(
        !cache.exists(&key).await.expect("exists after delete"),
        "key must not exist after delete"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn get_del_atomically_returns_and_removes() {
    let (_c, cache) = setup().await;
    let key = unique_key("getdel");
    let value = b"one-shot-token".to_vec();
    cache.set(&key, value.clone(), None).await.expect("set");
    let got = cache.get_del(&key).await.expect("get_del");
    assert_eq!(got, Some(value), "get_del must return the stored value");
    let after = cache.get(&key).await.expect("get after get_del");
    assert!(
        after.is_none(),
        "get_del must remove the key atomically (GETDEL, not GET+DEL)"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn set_add_and_set_members_round_trip() {
    let (_c, cache) = setup().await;
    let key = unique_key("set");
    cache.set_add(&key, "alpha").await.expect("sadd alpha");
    cache.set_add(&key, "beta").await.expect("sadd beta");
    cache.set_add(&key, "gamma").await.expect("sadd gamma");
    let mut members = cache.set_members(&key).await.expect("smembers");
    members.sort();
    assert_eq!(
        members,
        vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()],
        "set_members must return all added members (order-independent)"
    );
}

#[tokio::test]
#[ignore = "requires Docker (testcontainers)"]
async fn set_expire_applies_ttl_to_existing_key() {
    let (_c, cache) = setup().await;
    let key = unique_key("set-expire");
    // SADD creates the set key with no TTL.
    cache
        .set_add(&key, "member")
        .await
        .expect("sadd creates the key");
    cache
        .set_expire(&key, Duration::from_secs(1))
        .await
        .expect("set_expire");
    // Sleep past the TTL; the whole set key must be gone.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let members = cache
        .set_members(&key)
        .await
        .expect("smembers after expire");
    assert!(
        members.is_empty(),
        "set key must be empty after its TTL elapses"
    );
    assert!(
        !cache.exists(&key).await.expect("exists after expire"),
        "expired set key must not exist"
    );
}
