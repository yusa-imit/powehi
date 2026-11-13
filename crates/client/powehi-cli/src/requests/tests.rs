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

/// The pending-request policy is documented in prd §3 (8.12): at most 32 requests, a 5-day local
/// TTL (shorter than the server's 30-day Welcome retention, so an expired request can be acked),
/// and the `req-` record prefix. Changing any of them is a policy change, not a refactor.
#[test]
fn policy_constants_match_the_prd() {
    assert_eq!(MAX_REQUESTS, 32);
    assert_eq!(REQUEST_TTL_SECS, 5 * 24 * 60 * 60);
    const { assert!(REQUEST_TTL_SECS < 30 * 24 * 60 * 60) };
    assert!(record_name(&Uuid::from_u128(1)).starts_with("req-"));
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
fn a_welcome_at_the_server_limit_is_stored() {
    let (_tmp, store) = open_store();
    let mut max = req(1, 10);
    max.welcome = vec![7; MAX_WELCOME_LEN];
    assert_eq!(MAX_WELCOME_LEN, 256 * 1024);
    assert!(save_new(&store, &max).unwrap());
    assert_eq!(list(&store).unwrap()[0].welcome.len(), MAX_WELCOME_LEN);
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
fn list_skips_unreadable_records_and_orders_ties_by_group_id() {
    let (_tmp, store) = open_store();
    save_new(&store, &req(5, 10)).unwrap();
    save_new(&store, &req(3, 10)).unwrap();
    save_new(&store, &req(4, 1)).unwrap();
    store.put(&record_name(&Uuid::from_u128(6)), b"{").unwrap();
    let misfiled = serde_json::to_vec(&req(1, 0)).unwrap();
    store
        .put(&record_name(&Uuid::from_u128(7)), &misfiled)
        .unwrap();
    let got: Vec<u128> = list(&store)
        .unwrap()
        .iter()
        .map(|r| r.group_id.as_u128())
        .collect();
    assert_eq!(got, vec![4, 3, 5]);
}

#[test]
fn an_expired_request_whose_keys_cannot_be_retired_is_kept_and_not_acked() {
    // No identity in this store: retire_keys fails, so the request must stay (its keys are
    // still held) and its envelope must not be reported for acking.
    let (_tmp, store) = open_store();
    save_new(&store, &req(1, 100)).unwrap();
    let acked = prune_expired(&store, 100 + REQUEST_TTL_SECS + 1).unwrap();
    assert!(acked.is_empty());
    assert_eq!(list(&store).unwrap().len(), 1);
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
async fn decline_removes_the_invite_marker_of_the_retired_key_package() {
    let (_tmp, alice, _state, url, gid) = stranger_welcome().await;
    welcome::join_invited(&client(), &url, &alice)
        .await
        .unwrap();
    let r = load(&alice.store, &gid).unwrap().unwrap();
    let marker = welcome::invite_marker(&r.key_package_ref);
    alice.store.put(&marker, b"1").unwrap();
    decline(&client(), &url, &alice, gid).await.unwrap();
    assert!(alice.store.get(&marker).unwrap().is_none());
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

#[test]
fn report_json_is_one_line_per_request_with_the_sender_and_no_welcome_bytes() {
    let mut out = Vec::new();
    report(&mut out, &[req(1, 90), req(2, 95)], 100, true).unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(text.lines().count(), 2);
    let v: serde_json::Value = serde_json::from_str(text.lines().next().unwrap()).unwrap();
    assert_eq!(v["id"], Uuid::from_u128(1).to_string());
    assert_eq!(v["from"], Uuid::from_u128(9).to_string());
    assert_eq!(v.as_object().unwrap().len(), 3, "ids and times only");
}

#[test]
fn report_of_nothing_writes_nothing_and_a_future_timestamp_ages_to_zero() {
    let mut out = Vec::new();
    report(&mut out, &[], 100, false).unwrap();
    assert!(out.is_empty());
    report(&mut out, &[req(1, 500)], 100, false).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("  0s ago"));
}

#[test]
fn report_returns_a_failing_writer_error_in_both_formats() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for json in [false, true] {
        let err = report(&mut Broken, &[req(1, 90)], 100, json).unwrap_err();
        assert_eq!(err.to_string(), "closed");
    }
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

    /// `resolve` agrees with a plain model: a case-insensitive, trimmed prefix of at least four
    /// hex/hyphen characters names exactly the stored ids it prefixes; zero hits is
    /// `NoSuchRequest`, two or more is `Ambiguous`, and it never panics on any text.
    #[test]
    fn resolve_matches_a_prefix_model(
        ids in proptest::collection::btree_set(proptest::prelude::any::<u128>(), 1..6),
        pick in 0usize..6,
        cut in 0usize..=36,
        upper in proptest::prelude::any::<bool>(),
        junk in "\\PC{0,12}",
        use_junk in proptest::prelude::any::<bool>(),
    ) {
        let (_tmp, store) = open_store();
        for id in &ids {
            save_new(&store, &req(*id, 1)).unwrap();
        }
        let ids: Vec<Uuid> = ids.into_iter().map(Uuid::from_u128).collect();
        let full = ids[pick % ids.len()].hyphenated().to_string();
        let mut typed = if use_junk { junk } else { full[..cut].to_string() };
        if upper {
            typed = typed.to_ascii_uppercase();
        }
        let wanted = typed.trim().to_ascii_lowercase();
        let valid = wanted.len() >= MIN_PREFIX_LEN
            && wanted.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-');
        let hits: Vec<&Uuid> = ids
            .iter()
            .filter(|i| valid && i.hyphenated().to_string().starts_with(&wanted))
            .collect();
        match (resolve(&store, &typed), hits.as_slice()) {
            (Ok(got), [one]) => proptest::prop_assert_eq!(got, **one),
            (Err(RequestError::NoSuchRequest), []) => {}
            (Err(RequestError::Ambiguous), [_, _, ..]) => {}
            (other, hits) => proptest::prop_assert!(false, "{other:?} vs {} hits", hits.len()),
        }
    }

    /// A request is expired exactly when its age exceeds the TTL; a clock before the receipt
    /// (skew) is never expired, and no input overflows.
    #[test]
    fn expiry_is_the_age_threshold(at in proptest::prelude::any::<u64>(), now in proptest::prelude::any::<u64>()) {
        let expired = is_expired(&req(1, at), now);
        proptest::prop_assert_eq!(expired, now > at && now - at > REQUEST_TTL_SECS);
    }

    /// `save_new`/`remove`/`list` agree with a plain model under any op sequence: one request
    /// per group and per KeyPackage (first wins), empty Welcomes refused, removal frees both
    /// keys, and `list` is ordered by `(received_at, group_id)`.
    #[test]
    fn save_remove_list_match_a_model(
        ops in proptest::collection::vec(
            (0u8..3, 1u128..7, 1u8..7, 0u64..4, proptest::prelude::any::<bool>()),
            1..40,
        ),
    ) {
        let (_tmp, store) = open_store();
        // (group, key package, received_at)
        let mut model: Vec<(u128, u8, u64)> = Vec::new();
        for (op, group, kp, at, empty) in ops {
            if op == 0 {
                remove(&store, &Uuid::from_u128(group)).unwrap();
                model.retain(|m| m.0 != group);
                continue;
            }
            let welcome = if empty { Vec::new() } else { vec![1, 2, 3] };
            let r = Request::new(
                Uuid::from_u128(group), Uuid::from_u128(9), Uuid::from_u128(8), at,
                vec![kp; 4], welcome,
            );
            let expect = !empty
                && model.len() < MAX_REQUESTS
                && !model.iter().any(|m| m.0 == group || m.1 == kp);
            proptest::prop_assert_eq!(save_new(&store, &r).unwrap(), expect);
            if expect {
                model.push((group, kp, at));
            }
        }
        model.sort_by_key(|m| (m.2, m.0));
        let got: Vec<(u128, u64)> = list(&store)
            .unwrap()
            .iter()
            .map(|r| (r.group_id.as_u128(), r.received_at))
            .collect();
        let want: Vec<(u128, u64)> = model.iter().map(|m| (m.0, m.2)).collect();
        proptest::prop_assert_eq!(got, want);
    }
}
