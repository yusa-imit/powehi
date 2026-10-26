use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::identity::PQ_KEYS_RECORD;
use crate::invite;
use crate::testsrv::{serve, session, Backend};

fn client() -> Client {
    crate::status::http_client().unwrap()
}

/// Alice invites, Bob redeems; returns (alice, state, url, group id) with the Welcome pending.
async fn pending_welcome() -> (tempfile::TempDir, Session, Arc<Mutex<Backend>>, Url, Uuid) {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, _) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
    (tmp, alice, state, url, gid)
}

#[tokio::test]
async fn tampered_decap_key_is_skipped_unacked_and_not_joined() {
    let (_tmp, alice, state, url, _gid) = pending_welcome().await;
    let mut raw = alice.store.get(PQ_KEYS_RECORD).unwrap().unwrap().to_vec();
    // header(3) + ref(32) + dk_PKE(1152) + 5: inside the embedded ek.
    raw[3 + 32 + 1152 + 5] ^= 1;
    alice.store.put(PQ_KEYS_RECORD, &raw).unwrap();
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!(report.joined, Vec::<Uuid>::new());
    assert_eq!(report.skipped, 1);
    assert_eq!(
        state.lock().unwrap().welcome_count(),
        1,
        "left for expiry, not acked"
    );
    assert!(
        !state
            .lock()
            .unwrap()
            .calls
            .iter()
            .any(|c| c.ends_with("/accept")),
        "a Welcome we did not join is never consented to"
    );
    assert!(crate::conversation::list(&alice.store).unwrap().is_empty());
    assert_eq!(
        alice.store.get(PQ_KEYS_RECORD).unwrap().unwrap().to_vec(),
        raw
    );
}

#[tokio::test]
async fn missing_decap_key_is_skipped() {
    let (_tmp, alice, state, url, _gid) = pending_welcome().await;
    alice.store.remove(PQ_KEYS_RECORD).unwrap();
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!((report.joined.len(), report.skipped), (0, 1));
    assert_eq!(state.lock().unwrap().welcome_count(), 1);
}

#[tokio::test]
async fn envelope_labelled_with_another_group_is_skipped() {
    let (_tmp, alice, state, url, _gid) = pending_welcome().await;
    state.lock().unwrap().inbox[0]["group_id"] = json!(Uuid::new_v4());
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!((report.joined.len(), report.skipped), (0, 1));
    assert!(crate::conversation::list(&alice.store).unwrap().is_empty());
    // The rejected join must not have persisted anything for the group.
    assert!(alice.store.get(PQ_KEYS_RECORD).unwrap().unwrap().len() > 3);
}

#[tokio::test]
async fn garbage_and_non_welcome_envelopes_are_ignored() {
    let (_tmp, alice, state, url, gid) = pending_welcome().await;
    {
        let mut st = state.lock().unwrap();
        let me = alice.device_id.to_string();
        st.inbox.push(json!({
            "id": Uuid::new_v4(), "group_id": gid, "sender": Uuid::new_v4(), "recipient": me,
            "message_type": "Application", "ciphertext": [1, 2, 3],
        }));
        st.inbox.push(json!({
            "id": Uuid::new_v4(), "group_id": gid, "sender": Uuid::new_v4(), "recipient": me,
            "message_type": "Welcome", "ciphertext": [1, 2, 3],
        }));
        st.inbox
            .push(json!({"recipient": me, "message_type": "Welcome"}));
    }
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!(report.joined, vec![gid]);
    assert_eq!(report.skipped, 2);
    // Only the good Welcome was acked.
    assert_eq!(
        state.lock().unwrap().inbox.len(),
        4,
        "3 junk + pq_init remain"
    );
}

#[tokio::test]
async fn oversized_poll_response_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let me = alice.device_id.to_string();
    state.lock().unwrap().inbox.push(json!({
        "recipient": me, "message_type": "Application",
        // A string body is cheap to serialize; a 4M-element number array took >10s in CI
        // debug builds and tripped the client's request timeout instead of the size cap.
        "ciphertext": "A".repeat(MAX_POLL_BYTES + 1),
    }));
    let err = join_pending(&client(), &url, &alice, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        InviteError::Identity(IdentityError::BadResponse)
    ));
}

#[tokio::test]
async fn interrupted_join_is_finished_by_the_same_welcome() {
    use crate::conversation::{self, Conversation, Role};
    // Crash window: conversation record saved, MLS state not yet.
    let (_tmp, alice, _state, url, gid) = pending_welcome().await;
    let stale = Conversation::new(gid, Uuid::new_v4(), Role::Creator, None);
    conversation::save(&alice.store, &stale).unwrap();
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!(report.joined, vec![gid]);
    let conv = conversation::load(&alice.store, &gid).unwrap().unwrap();
    assert_eq!(conv.role, Role::Joiner);
}

#[tokio::test]
async fn a_held_group_is_refused_with_or_without_its_conversation_record() {
    use crate::identity::LocalIdentity;
    let (_tmp, alice, _state, url, gid) = pending_welcome().await;
    let fresh = || LocalIdentity::load(&alice.store).unwrap();
    assert!(check_group_not_held(&alice.store, &fresh(), gid).is_ok());
    assert_eq!(
        join_pending(&client(), &url, &alice, None)
            .await
            .unwrap()
            .joined,
        vec![gid]
    );
    let held = check_group_not_held(&alice.store, &fresh(), gid);
    assert!(matches!(held, Err(JoinOutcome::Skip)));
    // Orphan group: the MLS state survives without the conversation record.
    alice
        .store
        .remove(&format!("conv-{}", gid.hyphenated()))
        .unwrap();
    assert!(crate::conversation::load(&alice.store, &gid)
        .unwrap()
        .is_none());
    let held = check_group_not_held(&alice.store, &fresh(), gid);
    assert!(matches!(held, Err(JoinOutcome::Skip)));
    assert!(check_group_not_held(&alice.store, &fresh(), Uuid::new_v4()).is_ok());
}

#[tokio::test]
async fn joined_conversation_records_the_peers_credential_identity() {
    let (_tmp, alice, _state, url, gid) = pending_welcome().await;
    let report = join_pending(&client(), &url, &alice, None).await.unwrap();
    assert_eq!(report.joined, vec![gid]);
    let conv = crate::conversation::load(&alice.store, &gid)
        .unwrap()
        .unwrap();
    // Bob's test session carries the label [2; 16] (testsrv::session).
    assert_eq!(conv.peer_credential(), Some([2u8; 16].as_slice()));
}

#[tokio::test]
async fn joining_confirms_the_pending_membership_with_the_server() {
    let (_tmp, alice, state, url, gid) = pending_welcome().await;
    join_pending(&client(), &url, &alice, None).await.unwrap();
    let calls = state.lock().unwrap().calls.clone();
    let accept = format!("POST /v1/groups/{gid}/accept");
    assert_eq!(calls.iter().filter(|c| **c == accept).count(), 1);
}

#[test]
fn a_two_member_group_welcome_is_not_a_pair() {
    use powehi_crypto_core::mls_group::{self as m, GroupKind, Provider};
    let (ap, bp) = (Provider::default(), Provider::default());
    let alice = m::generate_identity(b"alice", &ap).unwrap();
    let bob = m::generate_identity(b"bob", &bp).unwrap();
    for (kind, joins) in [(GroupKind::Pair, true), (GroupKind::Group, false)] {
        let pq = m::generate_pq_key_package(&bob, &bp).unwrap();
        let mut g = m::create_group_of_kind(&alice, &ap, kind).unwrap();
        let w = m::add_member_from_bytes(&mut g, &alice.signer, &pq.key_package, &ap).unwrap();
        let joined = m::join_group(&w, &bp).unwrap();
        assert!(
            m::is_fresh_pair(&joined),
            "the member count alone cannot tell them apart"
        );
        assert_eq!(ensure_pair_kind(&joined).is_ok(), joins);
    }
}
