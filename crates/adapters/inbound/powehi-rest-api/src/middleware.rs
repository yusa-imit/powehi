//! Authentication extractor.
//!
//! `AuthenticatedDevice` is an axum `FromRequestParts` extractor that validates
//! the `Authorization: Bearer <token>` header against a Redis-backed session store.
//! The session maps `session:{token}` → DeviceId UUID bytes (16 bytes).
//!
//! The extractor is generic over any state `S` from which `Arc<dyn CachePort>`
//! can be extracted via axum's `FromRef` trait. This keeps the extractor
//! decoupled from the concrete `AppState` and makes it testable with a minimal
//! test state.

use std::sync::Arc;

use async_trait::async_trait;
use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
};
use powehi_domain::device::DeviceId;
use powehi_port_outbound::cache::CachePort;
use uuid::Uuid;

#[derive(Debug)]
pub struct AuthenticatedDevice(pub DeviceId);

#[async_trait]
impl<S> FromRequestParts<S> for AuthenticatedDevice
where
    Arc<dyn CachePort>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let cache = Arc::<dyn CachePort>::from_ref(state);

        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|t| !t.is_empty())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let key = format!("session:{token}");
        let raw = cache
            .get(&key)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let bytes: [u8; 16] = raw.try_into().map_err(|_| StatusCode::UNAUTHORIZED)?;
        let device_id = DeviceId::from(Uuid::from_bytes(bytes));

        Ok(AuthenticatedDevice(device_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use powehi_domain::{device::DeviceId, error::DomainError};
    use std::{collections::HashMap, sync::Mutex, time::Duration};

    // ── minimal fake cache for middleware tests ──────────────────────────────

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
    }

    impl FakeCache {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                store: Mutex::new(HashMap::new()),
            })
        }

        fn seed_session(&self, token: &str, device_id: &DeviceId) {
            let key = format!("session:{token}");
            self.store
                .lock()
                .unwrap()
                .insert(key, device_id.as_uuid().as_bytes().to_vec());
        }
    }

    #[async_trait]
    impl CachePort for FakeCache {
        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, DomainError> {
            Ok(self.store.lock().unwrap().get(key).cloned())
        }
        async fn set(
            &self,
            key: &str,
            value: Vec<u8>,
            _ttl: Option<Duration>,
        ) -> Result<(), DomainError> {
            self.store.lock().unwrap().insert(key.to_owned(), value);
            Ok(())
        }
        async fn delete(&self, key: &str) -> Result<(), DomainError> {
            self.store.lock().unwrap().remove(key);
            Ok(())
        }
        async fn exists(&self, key: &str) -> Result<bool, DomainError> {
            Ok(self.store.lock().unwrap().contains_key(key))
        }
    }

    // ── test state that satisfies the FromRef bound ──────────────────────────

    #[derive(Clone)]
    struct TestState {
        cache: Arc<dyn CachePort>,
    }

    impl FromRef<TestState> for Arc<dyn CachePort> {
        fn from_ref(s: &TestState) -> Arc<dyn CachePort> {
            s.cache.clone()
        }
    }

    async fn extract(
        auth_header: Option<&str>,
        state: &TestState,
    ) -> Result<AuthenticatedDevice, StatusCode> {
        let mut req = Request::builder().uri("/");
        if let Some(v) = auth_header {
            req = req.header(header::AUTHORIZATION, v);
        }
        let (mut parts, _) = req.body(()).unwrap().into_parts();
        AuthenticatedDevice::from_request_parts(&mut parts, state).await
    }

    #[tokio::test]
    async fn valid_session_token_extracts_device_id() {
        let cache = FakeCache::new();
        let device_id = DeviceId::new();
        let token = "valid-session-token";
        cache.seed_session(token, &device_id);
        let state = TestState { cache };

        let AuthenticatedDevice(extracted) = extract(Some(&format!("Bearer {token}")), &state)
            .await
            .unwrap();
        assert_eq!(extracted.to_string(), device_id.to_string());
    }

    #[tokio::test]
    async fn missing_header_returns_401() {
        let state = TestState {
            cache: FakeCache::new(),
        };
        let err = extract(None, &state).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_token_returns_401() {
        let state = TestState {
            cache: FakeCache::new(),
        };
        let err = extract(Some("Bearer unknown-token"), &state)
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_scheme_returns_401() {
        let cache = FakeCache::new();
        let device_id = DeviceId::new();
        cache.seed_session("mytoken", &device_id);
        let state = TestState { cache };
        let err = extract(Some("Basic mytoken"), &state).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_bearer_returns_401() {
        let state = TestState {
            cache: FakeCache::new(),
        };
        let err = extract(Some("Bearer "), &state).await.unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn raw_device_uuid_without_session_returns_401() {
        // Regression: old stub accepted raw DeviceId UUID as token. Any UUID
        // that isn't a live session entry must return 401.
        let state = TestState {
            cache: FakeCache::new(),
        };
        let device_id = DeviceId::new();
        let err = extract(Some(&format!("Bearer {device_id}")), &state)
            .await
            .unwrap_err();
        assert_eq!(err, StatusCode::UNAUTHORIZED);
    }
}
