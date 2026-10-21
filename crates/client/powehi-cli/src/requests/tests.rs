use std::sync::{Arc, Mutex};

use super::*;
use crate::invite;
use crate::testsrv::{serve, session, Backend};

fn client() -> Client {
    crate::status::http_client().unwrap()
}

fn req(group: u128, at: u64) -> Request {
    Request::new(
        Uuid::from_u128(group),
        Uuid::from_u128(9),
        Uuid::from_u128(8),
        at,
        [group.to_le_bytes(), group.to_le_bytes()].concat(),
        vec![1, 2, 3],
    )
}

fn open_store() -> (tempfile::TempDir, ProfileStore) {
    let tmp = tempfile::tempdir().unwrap();
    let paths = crate::profile::ProfilePaths::resolve(tmp.path(), "work").unwrap();
    let store = ProfileStore::open(&paths, &[7u8; 32]).unwrap();
    (tmp, store)
}

/// Bob's Welcome for one of Alice's KeyPackages, with the invite marker removed so it looks
/// like a pool KeyPackage handed out by the server rather than an invite.
async fn stranger_welcome() -> (tempfile::TempDir, Session, Arc<Mutex<Backend>>, Url, Uuid) {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, _) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
    for name in alice.store.names().unwrap() {
        if name.starts_with("invite-kp-") {
            alice.store.remove(&name).unwrap();
        }
    }
    (tmp, alice, state, url, gid)
}

#[test]
fn save_new_keeps_the_first_welcome_per_group_and_caps_the_list() {
    let (_tmp, store) = open_store();
    assert!(save_new(&store, &req(1, 10)).unwrap());
    assert!(!save_new(&store, &req(1, 11)).unwrap(), "first one wins");
    assert_eq!(
        load(&store, &Uuid::from_u128(1))
            .unwrap()
            .unwrap()
            .received_at,
        10
    );
    for g in 2..=MAX_REQUESTS as u128 {
        assert!(save_new(&store, &req(g, 10)).unwrap());
    }
    assert!(!save_new(&store, &req(1000, 10)).unwrap(), "cap reached");
    assert_eq!(list(&store).unwrap().len(), MAX_REQUESTS);
}

#[test]
fn a_second_welcome_for_the_same_key_package_is_not_stored() {
    let (_tmp, store) = open_store();
    assert!(save_new(&store, &req(1, 10)).unwrap());
    let mut dup = req(2, 10);
    dup.key_package_ref = req(1, 10).key_package_ref;
    assert!(!save_new(&store, &dup).unwrap());
}

#[test]
fn oversized_and_empty_welcomes_are_not_stored() {
    let (_tmp, store) = open_store();
    let mut big = req(1, 10);
    big.welcome = vec![0; MAX_WELCOME_LEN + 1];
    assert!(!save_new(&store, &big).unwrap());
    big.welcome.clear();
    assert!(!save_new(&store, &big).unwrap());
    assert!(list(&store).unwrap().is_empty());
}

#[test]
fn expired_and_malformed_requests_are_pruned() {
    let tmp = tempfile::tempdir().unwrap();
    let store = session(&tmp, "alice", 1).store;
    save_new(&store, &req(1, 100)).unwrap();
    save_new(&store, &req(2, 100 + REQUEST_TTL_SECS)).unwrap();
    store.put(&record_name(&Uuid::from_u128(3)), b"{").unwrap();
    assert_eq!(
        prune_expired(&store, 100 + REQUEST_TTL_SECS + 1)
            .unwrap()
            .len(),
        1
    );
    let left = list(&store).unwrap();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].group_id, Uuid::from_u128(2));
}

#[test]
fn resolve_takes_a_unique_prefix_of_four_or_more_characters() {
    let (_tmp, store) = open_store();
    save_new(&store, &req(0xabcd_0000 << 96, 1)).unwrap();
    save_new(&store, &req(0xabce_0000 << 96, 1)).unwrap();
    assert!(matches!(resolve(&store, "abcd"), Ok(id) if id == Uuid::from_u128(0xabcd_0000 << 96)));
    assert!(matches!(
        resolve(&store, "abc"),
        Err(RequestError::NoSuchRequest)
    ));
    assert!(matches!(
        resolve(&store, "zzzz"),
        Err(RequestError::NoSuchRequest)
    ));
    assert!(matches!(
        resolve(&store, "ffff"),
        Err(RequestError::NoSuchRequest)
    ));
}

#[test]
fn a_record_stored_under_another_group_id_is_malformed() {
    let (_tmp, store) = open_store();
    let bytes = serde_json::to_vec(&req(1, 1)).unwrap();
    store
        .put(&record_name(&Uuid::from_u128(2)), &bytes)
        .unwrap();
    assert!(matches!(
        load(&store, &Uuid::from_u128(2)),
        Err(RequestError::Malformed)
    ));
}

#[tokio::test]
async fn a_pool_welcome_becomes_a_request_and_is_neither_joined_nor_acked() {
    let (_tmp, alice, state, url, gid) = stranger_welcome().await;
    let r = welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    assert_eq!((r.joined.len(), r.requested, r.skipped), (0, 1, 0));
    assert!(crate::conversation::list(&alice.store).unwrap().is_empty());
    assert_eq!(state.lock().unwrap().welcome_count(), 1);
    assert!(!state
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|c| c.ends_with("/accept")));
    assert_eq!(list(&alice.store).unwrap()[0].group_id, gid);
    let again = welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    assert_eq!((again.requested, again.skipped), (0, 1), "dedup by group");
}

#[tokio::test]
async fn accept_joins_confirms_the_membership_and_drops_the_request() {
    let (_tmp, alice, state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    accept(&client(), &url, &alice, gid).await.unwrap();
    assert!(crate::conversation::load(&alice.store, &gid)
        .unwrap()
        .is_some());
    assert!(list(&alice.store).unwrap().is_empty());
    {
        let st = state.lock().unwrap();
        assert_eq!(st.welcome_count(), 0, "Welcome acked");
        assert!(st.calls.contains(&format!("POST /v1/groups/{gid}/accept")));
    }
    assert!(matches!(
        accept(&client(), &url, &alice, gid).await,
        Err(RequestError::NoSuchRequest)
    ));
}

#[tokio::test]
async fn accept_after_a_join_whose_confirm_failed_only_retries_the_confirm() {
    let (_tmp, alice, state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    // The join landed (e.g. an earlier `accept` lost its confirm response) but the request stayed.
    let joined = welcome::join_pending(&client(), &url, &alice, None)
        .await
        .unwrap();
    assert_eq!(joined.joined, vec![gid]);
    accept(&client(), &url, &alice, gid).await.unwrap();
    assert!(list(&alice.store).unwrap().is_empty());
    let n = state
        .lock()
        .unwrap()
        .calls
        .iter()
        .filter(|c| c.ends_with("/accept"))
        .count();
    assert_eq!(n, 2);
}

#[tokio::test]
async fn decline_tells_the_server_acks_and_never_joins() {
    let (_tmp, alice, state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    decline(&client(), &url, &alice, gid).await.unwrap();
    assert!(list(&alice.store).unwrap().is_empty());
    assert!(crate::conversation::list(&alice.store).unwrap().is_empty());
    let st = state.lock().unwrap();
    assert_eq!(st.welcome_count(), 0);
    assert!(st.calls.contains(&format!("POST /v1/groups/{gid}/decline")));
}

#[tokio::test]
async fn decline_retires_the_keys_so_the_welcome_cannot_return_as_a_request() {
    let (_tmp, alice, _state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    let r = load(&alice.store, &gid).unwrap().unwrap();
    decline(&client(), &url, &alice, gid).await.unwrap();
    assert!(identity::pq_key_for(&alice.store, &r.key_package_ref)
        .unwrap()
        .is_none());
    let again = welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    assert_eq!((again.requested, again.joined.len()), (0, 0));
}

#[tokio::test]
async fn decline_after_a_join_is_refused() {
    let (_tmp, alice, _state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    welcome::join_pending(&client(), &url, &alice, None)
        .await
        .unwrap();
    assert!(matches!(
        decline(&client(), &url, &alice, gid).await,
        Err(RequestError::AlreadyJoined)
    ));
}

#[tokio::test]
async fn an_unjoinable_request_is_refused_and_can_be_declined() {
    let (_tmp, alice, _state, url, _gid) = stranger_welcome().await;
    let gid = Uuid::from_u128(77);
    save_new(&alice.store, &req(77, now_secs())).unwrap();
    assert!(matches!(
        accept(&client(), &url, &alice, gid).await,
        Err(RequestError::Unjoinable)
    ));
    decline(&client(), &url, &alice, gid).await.unwrap();
    assert!(load(&alice.store, &gid).unwrap().is_none());
}

#[tokio::test]
async fn expired_requests_are_not_accepted_and_their_welcome_is_acked_by_inbox() {
    let (_tmp, alice, state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    let mut r = load(&alice.store, &gid).unwrap().unwrap();
    r.received_at = 1;
    let bytes = serde_json::to_vec(&r).unwrap();
    alice.store.put(&record_name(&gid), &bytes).unwrap();
    assert!(matches!(
        accept(&client(), &url, &alice, gid).await,
        Err(RequestError::Expired)
    ));
    let dropped = prune_expired(&alice.store, now_secs()).unwrap();
    assert_eq!(dropped, vec![r.envelope_id]);
    assert!(
        identity::pq_key_for(&alice.store, &r.key_package_ref)
            .unwrap()
            .is_none(),
        "expiry retires the keys"
    );
    assert!(list(&alice.store).unwrap().is_empty());
    assert_eq!(state.lock().unwrap().welcome_count(), 1, "caller acks");
}

#[test]
fn report_prints_ids_and_ages_only() {
    let mut out = Vec::new();
    report(&mut out, &[req(1, 90)], 100, false).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("10s ago") && text.contains(&Uuid::from_u128(1).to_string()));
    let mut out = Vec::new();
    report(&mut out, &[req(1, 90)], 100, true).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["received_at"], 90);
}
