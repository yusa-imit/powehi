//! Integration tests for `handle_socket`'s real connection loop, driven
//! through an actual TCP + WebSocket upgrade (not just the pure
//! `filter_notification`/`PingRateLimiter` unit tests in `handler.rs`).
//!
//! Covers three behaviors that only exist in the loop itself, per
//! `.claude/rules/testing-conventions.md`'s "Security-invariant tests" gate:
//!   1. Fail-closed group-membership load: if `GroupRepository::
//!      list_groups_for_device` errors, the socket still upgrades but the
//!      device must receive no notifications for groups it didn't already
//!      know about until reconnect (a self-addressed `MemberAdded` still
//!      repopulates membership live, per `handler.rs`'s own documented,
//!      deliberate race-acceptance — this test does not contradict that).
//!   2. `RecvError::Lagged` handling: when a slow/stalled receiver falls
//!      behind the broadcast ring buffer, the connection must stay alive and
//!      keep delivering subsequent in-scope notifications rather than
//!      dropping the socket.
//!   3. Auth bypass impossible: a WS upgrade attempt with no `Authorization`
//!      header must be rejected with 401, not silently accepted.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue};

use powehi_domain::{
    device::DeviceId,
    envelope::EnvelopeId,
    error::DomainError,
    event::DomainEvent,
    group::{Epoch, Group, GroupId, GroupMember},
};
use powehi_port_outbound::{cache::CachePort, group_repo::GroupRepository};
use powehi_ws_hub::{router, WsHub};

struct FakeCache {
    store: Mutex<HashMap<String, Vec<u8>>>,
}

impl FakeCache {
    fn seeded(token: &str, device_id: &DeviceId) -> Arc<dyn CachePort> {
        let mut store = HashMap::new();
        store.insert(
            format!("session:{token}"),
            device_id.as_uuid().as_bytes().to_vec(),
        );
        Arc::new(Self {
            store: Mutex::new(store),
        })
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

/// Membership lookup either succeeds with a fixed group set, or always fails
/// (simulating a DB outage) depending on construction. Every other
/// `GroupRepository` method is unused by the WS handler and left
/// `unimplemented!()`.
enum MembershipFixture {
    Groups(Vec<GroupId>),
    AlwaysErrors,
}

struct FakeGroupRepo(MembershipFixture);

#[async_trait]
impl GroupRepository for FakeGroupRepo {
    async fn save(&self, _group: &Group) -> Result<(), DomainError> {
        unimplemented!()
    }
    async fn advance_epoch(
        &self,
        _group_id: &GroupId,
        _expected: Epoch,
    ) -> Result<Option<Epoch>, DomainError> {
        unimplemented!()
    }
    async fn create_if_absent(&self, _group: &Group) -> Result<bool, DomainError> {
        unimplemented!()
    }
    async fn create_with_creator(
        &self,
        _group: &Group,
        _creator: &GroupMember,
    ) -> Result<bool, DomainError> {
        unimplemented!()
    }
    async fn find_by_id(&self, _id: &GroupId) -> Result<Option<Group>, DomainError> {
        unimplemented!()
    }
    async fn add_member(&self, _member: &GroupMember) -> Result<(), DomainError> {
        unimplemented!()
    }
    async fn remove_member(
        &self,
        _group_id: &GroupId,
        _device_id: &DeviceId,
    ) -> Result<(), DomainError> {
        unimplemented!()
    }
    async fn list_members(&self, _group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
        unimplemented!()
    }
    async fn list_groups_for_device(
        &self,
        _device_id: &DeviceId,
    ) -> Result<Vec<GroupId>, DomainError> {
        match &self.0 {
            MembershipFixture::Groups(groups) => Ok(groups.clone()),
            MembershipFixture::AlwaysErrors => {
                Err(DomainError::Internal("simulated db outage".into()))
            }
        }
    }
    async fn upsert_members(
        &self,
        _group: &Group,
        _members: &[GroupMember],
    ) -> Result<(), DomainError> {
        unimplemented!()
    }
}

const TEST_TOKEN: &str = "ws-loop-test-token";

/// Bind a real TCP listener, serve the WS router on it, and return the
/// `ws://` base URL plus the hub used to publish notifications.
async fn spawn_server(
    group_repo: Arc<dyn GroupRepository>,
    device_id: &DeviceId,
) -> (String, Arc<WsHub>) {
    let hub = Arc::new(WsHub::new());
    let cache = FakeCache::seeded(TEST_TOKEN, device_id);
    let app = router(hub.clone(), cache, group_repo);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("ws://{addr}/v1/ws"), hub)
}

async fn connect(
    url: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let mut request = url.into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {TEST_TOKEN}")).unwrap(),
    );
    let (stream, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .expect("ws handshake should succeed");
    stream
}

/// A DB outage during membership load must not fail the upgrade, but must
/// leave the device with an empty starting group set — so a notification for
/// a group it isn't already known to belong to is not delivered (rule:
/// fail-closed, never fail-open on missing membership data).
#[tokio::test]
async fn membership_load_failure_upgrades_but_delivers_nothing() {
    let device_id = DeviceId::new();
    let target_group = GroupId::new();
    let repo: Arc<dyn GroupRepository> = Arc::new(FakeGroupRepo(MembershipFixture::AlwaysErrors));
    let (url, hub) = spawn_server(repo, &device_id).await;

    let mut ws = connect(&url).await;

    hub.dispatch(&DomainEvent::EnvelopeReceived {
        envelope_id: EnvelopeId::new(),
        group_id: target_group,
        at: chrono::Utc::now(),
    });

    let outcome = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        outcome.is_err(),
        "device with a failed membership load must receive no frames, got: {outcome:?}"
    );

    // Positive control: prove the timeout above reflects correct filtering,
    // not a hung/dead connection that would time out on ANY notification. A
    // self-addressed MemberAdded is unconditionally forwarded regardless of
    // membership state (handler.rs's documented behavior), so the connection
    // must still be alive and responsive to receive it.
    let barrier_group = GroupId::new();
    hub.dispatch(&DomainEvent::MemberAdded {
        group_id: barrier_group.clone(),
        device_id: device_id.clone(),
        epoch: powehi_domain::group::Epoch(1),
        at: chrono::Utc::now(),
    });
    let frame = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("connection must still be alive after the fail-closed window")
        .expect("stream must yield a frame, not end")
        .expect("frame must not be a protocol error");
    let json: serde_json::Value = serde_json::from_str(&frame.into_text().unwrap()).unwrap();
    assert_eq!(json["type"], "member_added");
    assert_eq!(json["group_id"], barrier_group.to_string());
}

/// A WS upgrade attempt without a Bearer token must be rejected before the
/// socket is ever accepted (rule: auth bypass impossible — unauthenticated
/// request to a protected endpoint returns 401, per testing-conventions.md).
#[tokio::test]
async fn upgrade_without_authorization_header_returns_401() {
    let device_id = DeviceId::new();
    let repo: Arc<dyn GroupRepository> = Arc::new(FakeGroupRepo(MembershipFixture::Groups(vec![])));
    let (url, _hub) = spawn_server(repo, &device_id).await;

    let request = url.into_client_request().unwrap();
    // No `authorization` header inserted — this is the case under test.
    let err = tokio_tungstenite::connect_async(request)
        .await
        .expect_err("upgrade without a Bearer token must be rejected, not accepted");

    match err {
        tokio_tungstenite::tungstenite::Error::Http(resp) => {
            assert_eq!(
                resp.status(),
                401,
                "expected 401 Unauthorized, got {resp:?}"
            );
        }
        other => panic!("expected an HTTP-level rejection, got: {other:?}"),
    }
}

/// A receiver that falls behind the broadcast ring buffer (`Lagged`) must not
/// be disconnected — the loop skips the missed frames and keeps delivering
/// subsequent in-scope notifications.
#[tokio::test(flavor = "current_thread")]
async fn lagged_receiver_stays_connected_and_keeps_receiving() {
    let device_id = DeviceId::new();
    let my_group = GroupId::new();
    let other_group = GroupId::new();
    let repo: Arc<dyn GroupRepository> = Arc::new(FakeGroupRepo(MembershipFixture::Groups(vec![
        my_group.clone(),
    ])));
    let (url, hub) = spawn_server(repo, &device_id).await;

    let mut ws = connect(&url).await;

    // Flood the ring buffer (capacity 512) with notifications for a group this
    // device does NOT belong to, entirely synchronously (no `.await` in this
    // loop) so the current-thread executor cannot let `handle_socket`'s task
    // drain any of them in between — this deterministically forces the
    // client's next `rx.recv()` to observe `RecvError::Lagged`.
    for _ in 0..(512 + 50) {
        hub.dispatch(&DomainEvent::EnvelopeReceived {
            envelope_id: EnvelopeId::new(),
            group_id: other_group.clone(),
            at: chrono::Utc::now(),
        });
    }

    // The one notification that should survive and reach the client: for a
    // group the device IS a member of, sent last so it's still in the ring.
    let expected_envelope = EnvelopeId::new();
    hub.dispatch(&DomainEvent::EnvelopeReceived {
        envelope_id: expected_envelope.clone(),
        group_id: my_group,
        at: chrono::Utc::now(),
    });

    // The connection must survive the lag and eventually deliver the one
    // relevant notification (every flood frame is for a foreign group and is
    // filtered out server-side, so this must be the only frame received).
    let frame = tokio::time::timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("connection must stay alive across a Lagged event, not hang or close")
        .expect("stream must yield a frame, not end")
        .expect("frame must not be a protocol error");

    let text = frame.into_text().expect("expected a text frame");
    let json: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["type"], "envelope_received");
    assert_eq!(json["envelope_id"], expected_envelope.to_string());
}
