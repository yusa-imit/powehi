//! WebSocket upgrade handler.
//!
//! Auth: `Authorization: Bearer <session_token>` resolved against the Redis
//! session store (same store used by the REST API middleware).  Any raw UUID
//! that is not a live session entry is rejected with 401.
//! After upgrade the socket streams `WsNotification` JSON frames.
//!
//! Group-scoped fan-out: on connect the handler loads the device's current
//! group memberships and only forwards notifications for those groups.
//! `MemberAdded`/`MemberRemoved` events update the in-memory set so that
//! membership changes while the socket is open are reflected immediately
//! without a reconnect.

use std::{
    collections::HashSet,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use tokio::{sync::broadcast, time::timeout};
use tracing::instrument;
use uuid::Uuid;

use powehi_domain::{device::DeviceId, group::GroupId};
use powehi_port_outbound::{cache::CachePort, group_repo::GroupRepository};

/// Parse a DeviceId from a UUID string. Used in `filter_notification` to avoid
/// stringly-typed identity comparison (auditor Y-1: string equality of UUIDs
/// is format-sensitive; typed comparison is canonical).
fn parse_device_id(s: &str) -> Option<DeviceId> {
    s.parse::<DeviceId>().ok()
}

use crate::{WsHubState, WsNotification};

/// Max inbound frame size: 4 KiB. The protocol is server-push only; clients
/// only send Close/Ping. Large frames from clients are a sign of abuse.
const MAX_FRAME_BYTES: usize = 4 * 1024;

/// Max time to wait for a single `socket.send` to complete.
const SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Max Ping frames per connection within PING_WINDOW.
const PING_BURST: u32 = 5;
/// Sliding window size for Ping rate limiting.
const PING_WINDOW: Duration = Duration::from_secs(10);

/// Per-connection fixed-window Ping rate limiter.
///
/// Limits abusive clients that flood Ping frames to amplify Pong responses.
/// Uses a fixed window (not sliding): a client can send up to `2 * PING_BURST`
/// pings across a window boundary in quick succession. At current values
/// (5 pings / 10 s) that worst case (10 pings in ~0 s) is still harmless —
/// Pong work is negligible and `SEND_TIMEOUT` bounds backpressure.
/// Legitimate clients send one keepalive Ping per ~30 s.
struct PingRateLimiter {
    window_start: Instant,
    count: u32,
}

impl PingRateLimiter {
    fn new() -> Self {
        Self {
            window_start: Instant::now(),
            count: 0,
        }
    }

    /// Returns `true` if the Ping is allowed, `false` if the limit is exceeded.
    fn check(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= PING_WINDOW {
            self.window_start = now;
            self.count = 0;
        }
        self.count += 1;
        self.count <= PING_BURST
    }
}

#[instrument(skip_all)]
pub async fn ws_handler(
    upgrade: WebSocketUpgrade,
    State(state): State<WsHubState>,
    headers: HeaderMap,
) -> Response {
    match extract_device_id(&headers, &state.cache).await {
        Ok(device_id) => {
            let rx = state.hub.subscribe();
            let group_repo = state.group_repo.clone();
            upgrade
                .max_message_size(MAX_FRAME_BYTES)
                .on_upgrade(move |socket| handle_socket(socket, device_id, rx, group_repo))
        }
        Err(status) => status.into_response(),
    }
}

async fn extract_device_id(
    headers: &HeaderMap,
    cache: &Arc<dyn CachePort>,
) -> Result<DeviceId, StatusCode> {
    let token = headers
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
    Ok(DeviceId::from(Uuid::from_bytes(bytes)))
}

async fn handle_socket(
    mut socket: WebSocket,
    device_id: DeviceId,
    mut rx: broadcast::Receiver<WsNotification>,
    group_repo: Arc<dyn GroupRepository>,
) {
    // Load initial group memberships — fail-closed: if the DB is unreachable,
    // the device gets an empty set and receives no notifications until reconnect
    // (no fail-open: missing membership data must not grant notifications).
    // A warn log surfaces DB outages that are otherwise silent from the client side.
    //
    // Race note (accepted): the broadcast subscription (`hub.subscribe()`) is taken
    // before this DB call. Notifications for groups the device was added to AFTER
    // the subscribe but BEFORE the DB load completes will have device_id == this
    // device in the MemberAdded notification, and `filter_notification` will insert
    // the group and return true — correct. A MemberAdded for another device in a
    // group the device was added to in the same window may be dropped (only affects
    // a member-list notification, not message delivery). Reconnect resolves.
    let initial: Vec<GroupId> = match group_repo.list_groups_for_device(&device_id).await {
        Ok(groups) => groups,
        Err(_) => {
            tracing::warn!(
                error_kind = "db_error",
                "ws.group_membership_load_failed; no notifications delivered until reconnect"
            );
            Vec::new()
        }
    };
    let mut my_groups: HashSet<GroupId> = initial.into_iter().collect();

    let mut ping_limiter = PingRateLimiter::new();
    loop {
        tokio::select! {
            biased;
            // Incoming client frame (close / ping / unexpected)
            msg = socket.recv() => {
                let should_break = match msg {
                    Some(Ok(Message::Close(_))) | None => true,
                    Some(Ok(Message::Ping(data))) => {
                        if !ping_limiter.check() {
                            // Rate limit exceeded: disconnect abusive client.
                            tracing::warn!("ws ping rate limit exceeded; closing connection");
                            break;
                        }
                        timeout(SEND_TIMEOUT, socket.send(Message::Pong(data)))
                            .await
                            .map_or(true, |r| r.is_err())
                    }
                    // Server-push only: disconnect on unexpected client frames
                    Some(Ok(_)) => true,
                    Some(Err(_)) => true,
                };
                if should_break {
                    break;
                }
            }
            // Outgoing notification
            notification = rx.recv() => {
                match notification {
                    Ok(n) => {
                        if !filter_notification(&mut my_groups, &n, &device_id) {
                            continue;
                        }
                        match serde_json::to_string(&n) {
                            Ok(json) => {
                                let sent = timeout(
                                    SEND_TIMEOUT,
                                    socket.send(Message::Text(json)),
                                )
                                .await;
                                if sent.map_or(true, |r| r.is_err()) {
                                    break;
                                }
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // ring buffer overflowed; skip missed frames, keep connection alive
                        continue;
                    }
                }
            }
        }
    }
}

/// Decide whether `notification` should be forwarded to `device_id` and
/// update `my_groups` for membership-change events.
///
/// Security invariant: a device only receives notifications for groups it
/// currently belongs to. `MemberAdded` for this device expands the set
/// (so the device immediately receives subsequent group events), while
/// `MemberRemoved` shrinks it (future events are suppressed).
fn filter_notification(
    my_groups: &mut HashSet<GroupId>,
    notification: &WsNotification,
    device_id: &DeviceId,
) -> bool {
    match notification {
        WsNotification::MemberAdded {
            group_id,
            device_id: added_device,
        } => {
            let gid = match parse_group_id(group_id) {
                Some(g) => g,
                None => return false,
            };
            if parse_device_id(added_device).as_ref() == Some(device_id) {
                // This device was added: update set first, then always notify it.
                my_groups.insert(gid);
                return true;
            }
            // Another device was added: only relevant if this device is already a member.
            my_groups.contains(&gid)
        }
        WsNotification::MemberRemoved {
            group_id,
            device_id: removed_device,
        } => {
            let gid = match parse_group_id(group_id) {
                Some(g) => g,
                None => return false,
            };
            if parse_device_id(removed_device).as_ref() == Some(device_id) {
                // This device was removed: notify it of removal, then drop the group.
                let was_member = my_groups.remove(&gid);
                return was_member;
            }
            // Another device was removed: only relevant if this device is a member.
            my_groups.contains(&gid)
        }
        WsNotification::EnvelopeReceived { group_id, .. }
        | WsNotification::EpochAdvanced { group_id, .. } => {
            parse_group_id(group_id).is_some_and(|gid| my_groups.contains(&gid))
        }
    }
}

fn parse_group_id(s: &str) -> Option<GroupId> {
    Uuid::parse_str(s).ok().map(GroupId::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::{header, HeaderMap, HeaderValue};
    use powehi_domain::error::DomainError;
    use std::{collections::HashMap, sync::Mutex};

    struct FakeCache {
        store: Mutex<HashMap<String, Vec<u8>>>,
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

    fn empty_cache() -> Arc<dyn CachePort> {
        Arc::new(FakeCache {
            store: Mutex::new(HashMap::new()),
        })
    }

    fn seeded_cache(token: &str, device_id: &DeviceId) -> Arc<dyn CachePort> {
        let c = FakeCache {
            store: Mutex::new(HashMap::new()),
        };
        c.store.lock().unwrap().insert(
            format!("session:{token}"),
            device_id.as_uuid().as_bytes().to_vec(),
        );
        Arc::new(c)
    }

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    #[tokio::test]
    async fn valid_session_token_resolves_device_id() {
        let device_id = DeviceId::new();
        let token = "valid-session-token";
        let cache = seeded_cache(token, &device_id);
        let h = headers_with_bearer(token);
        let result = extract_device_id(&h, &cache).await.unwrap();
        assert_eq!(result.to_string(), device_id.to_string());
    }

    #[tokio::test]
    async fn missing_authorization_header_is_401() {
        let cache = empty_cache();
        let h = HeaderMap::new();
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn wrong_scheme_is_401() {
        let cache = empty_cache();
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn unknown_token_is_401() {
        let cache = empty_cache();
        let h = headers_with_bearer("unknown-token");
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn empty_bearer_is_401() {
        let cache = empty_cache();
        let h = headers_with_bearer("");
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    #[tokio::test]
    async fn raw_device_uuid_without_session_is_401() {
        // Regression: R-1 fix — a bare DeviceId UUID that is not a live session
        // entry must be rejected. Previously the stub parsed Bearer as raw UUID.
        let cache = empty_cache();
        let device_id = DeviceId::new();
        let h = headers_with_bearer(&device_id.to_string());
        assert_eq!(
            extract_device_id(&h, &cache).await,
            Err(StatusCode::UNAUTHORIZED)
        );
    }

    // --- PingRateLimiter unit tests ---

    #[test]
    fn ping_rate_limiter_allows_pings_within_burst() {
        let mut limiter = PingRateLimiter::new();
        for _ in 0..PING_BURST {
            assert!(limiter.check(), "ping within burst should be allowed");
        }
    }

    #[test]
    fn ping_rate_limiter_rejects_ping_over_burst() {
        let mut limiter = PingRateLimiter::new();
        for _ in 0..PING_BURST {
            limiter.check();
        }
        assert!(
            !limiter.check(),
            "ping exceeding burst in same window should be rejected"
        );
    }

    #[test]
    fn ping_rate_limiter_resets_after_window_expires() {
        let mut limiter = PingRateLimiter {
            window_start: Instant::now() - PING_WINDOW - Duration::from_millis(1),
            count: PING_BURST,
        };
        // Window has elapsed; next check should reset and allow.
        assert!(
            limiter.check(),
            "after window expiry, first ping should be allowed"
        );
        assert_eq!(
            limiter.count, 1,
            "count should reset to 1 after window reset"
        );
    }

    #[test]
    fn ping_rate_limiter_boundary_exactly_at_burst_is_allowed() {
        let mut limiter = PingRateLimiter::new();
        for i in 1..=PING_BURST {
            let allowed = limiter.check();
            assert!(allowed, "ping {i} of {PING_BURST} should be allowed");
        }
    }

    // --- filter_notification security-invariant tests ---

    fn make_groups(ids: &[GroupId]) -> HashSet<GroupId> {
        ids.iter().cloned().collect()
    }

    #[test]
    fn member_receives_envelope_for_their_group() {
        let device = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(std::slice::from_ref(&group));

        let notif = WsNotification::EnvelopeReceived {
            group_id: group.to_string(),
            envelope_id: "env-id".into(),
        };
        assert!(
            filter_notification(&mut groups, &notif, &device),
            "member should receive notification for their group"
        );
    }

    #[test]
    fn non_member_does_not_receive_envelope_notification() {
        let device = DeviceId::new();
        let other_group = GroupId::new();
        let mut groups = make_groups(&[]); // device is in no groups

        let notif = WsNotification::EnvelopeReceived {
            group_id: other_group.to_string(),
            envelope_id: "env-id".into(),
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "non-member must not receive group notification"
        );
    }

    #[test]
    fn member_added_for_this_device_grants_future_notifications() {
        let device = DeviceId::new();
        let new_group = GroupId::new();
        let mut groups = make_groups(&[]); // starts with no groups

        // MemberAdded for this device → should be forwarded and expand the set
        let added = WsNotification::MemberAdded {
            group_id: new_group.to_string(),
            device_id: device.to_string(),
        };
        assert!(
            filter_notification(&mut groups, &added, &device),
            "device should receive its own MemberAdded notification"
        );
        assert!(
            groups.contains(&new_group),
            "new group should be in the membership set"
        );

        // Subsequent envelope for that group should now be relevant
        let env = WsNotification::EnvelopeReceived {
            group_id: new_group.to_string(),
            envelope_id: "e".into(),
        };
        assert!(
            filter_notification(&mut groups, &env, &device),
            "after being added, device should receive group notifications"
        );
    }

    #[test]
    fn member_removed_for_this_device_revokes_future_notifications() {
        let device = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(std::slice::from_ref(&group));

        // MemberRemoved for this device → should be forwarded and shrink the set
        let removed = WsNotification::MemberRemoved {
            group_id: group.to_string(),
            device_id: device.to_string(),
        };
        assert!(
            filter_notification(&mut groups, &removed, &device),
            "device should receive its own MemberRemoved notification"
        );
        assert!(
            !groups.contains(&group),
            "removed group should no longer be in the membership set"
        );

        // Subsequent envelope for that group should now be irrelevant
        let env = WsNotification::EnvelopeReceived {
            group_id: group.to_string(),
            envelope_id: "e".into(),
        };
        assert!(
            !filter_notification(&mut groups, &env, &device),
            "after being removed, device must not receive group notifications"
        );
    }

    #[test]
    fn member_added_for_other_device_only_relevant_if_already_member() {
        let device = DeviceId::new();
        let other_device = DeviceId::new();
        let group = GroupId::new();
        let mut groups_with = make_groups(std::slice::from_ref(&group));
        let mut groups_without = make_groups(&[]);

        let notif = WsNotification::MemberAdded {
            group_id: group.to_string(),
            device_id: other_device.to_string(),
        };

        assert!(
            filter_notification(&mut groups_with, &notif.clone(), &device),
            "existing member should see someone else being added to their group"
        );
        assert!(
            !filter_notification(&mut groups_without, &notif, &device),
            "non-member must not see MemberAdded for a group they don't belong to"
        );
    }

    #[test]
    fn invalid_group_id_in_notification_is_filtered_out() {
        let device = DeviceId::new();
        let mut groups = make_groups(&[]);

        let notif = WsNotification::EnvelopeReceived {
            group_id: "not-a-uuid".into(),
            envelope_id: "e".into(),
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "notification with invalid group_id must be dropped"
        );
    }

    // --- EpochAdvanced notification filtering ---

    #[test]
    fn epoch_advanced_for_member_group_is_forwarded() {
        let device = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(std::slice::from_ref(&group));

        let notif = WsNotification::EpochAdvanced {
            group_id: group.to_string(),
            new_epoch: 7,
        };
        assert!(
            filter_notification(&mut groups, &notif, &device),
            "member must receive EpochAdvanced for their group"
        );
    }

    #[test]
    fn epoch_advanced_for_non_member_group_is_suppressed() {
        let device = DeviceId::new();
        let other_group = GroupId::new();
        let mut groups = make_groups(&[]); // device belongs to no groups

        let notif = WsNotification::EpochAdvanced {
            group_id: other_group.to_string(),
            new_epoch: 3,
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "non-member must not receive EpochAdvanced for a foreign group"
        );
    }

    #[test]
    fn epoch_advanced_with_invalid_group_id_is_filtered_out() {
        let device = DeviceId::new();
        let mut groups = make_groups(&[]);

        let notif = WsNotification::EpochAdvanced {
            group_id: "bad-uuid".into(),
            new_epoch: 1,
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "EpochAdvanced with unparseable group_id must be dropped"
        );
    }

    // --- MemberRemoved edge cases ---

    #[test]
    fn member_removed_for_other_device_notifies_remaining_members() {
        let device = DeviceId::new();
        let other = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(std::slice::from_ref(&group));

        let notif = WsNotification::MemberRemoved {
            group_id: group.to_string(),
            device_id: other.to_string(),
        };
        assert!(
            filter_notification(&mut groups, &notif, &device),
            "remaining member must see MemberRemoved for another device"
        );
        // Device itself must still be in the group after the removal
        assert!(
            groups.contains(&group),
            "device's own membership must not be affected by another device's removal"
        );
    }

    #[test]
    fn member_removed_for_other_device_not_in_group_is_suppressed() {
        let device = DeviceId::new();
        let other = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(&[]); // device is not in this group

        let notif = WsNotification::MemberRemoved {
            group_id: group.to_string(),
            device_id: other.to_string(),
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "non-member must not receive MemberRemoved for a foreign group"
        );
    }

    #[test]
    fn member_removed_for_this_device_when_not_member_returns_false() {
        // Security edge case: spurious MemberRemoved for this device in a group
        // it never joined must return false (no phantom notification).
        let device = DeviceId::new();
        let group = GroupId::new();
        let mut groups = make_groups(&[]); // device is NOT in this group

        let notif = WsNotification::MemberRemoved {
            group_id: group.to_string(),
            device_id: device.to_string(),
        };
        assert!(
            !filter_notification(&mut groups, &notif, &device),
            "spurious MemberRemoved for a group this device never joined must not be forwarded"
        );
    }
}
