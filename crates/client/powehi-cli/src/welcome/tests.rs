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
    let gid = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
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
        state.lock().unwrap().inbox.len(),
        1,
        "left for expiry, not acked"
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
    assert_eq!(state.lock().unwrap().inbox.len(), 1);
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
    assert_eq!(state.lock().unwrap().inbox.len(), 3);
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
        "ciphertext": vec![255u8; MAX_POLL_BYTES / 4],
    }));
    let err = join_pending(&client(), &url, &alice, None)
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        InviteError::Identity(IdentityError::BadResponse)
    ));
}
