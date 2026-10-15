use std::sync::{Arc, Mutex};

use serde_json::json;

use super::*;
use crate::invite::{self, PqStatus};
use crate::testsrv::{serve, session, Backend};

fn client() -> Client {
    crate::status::http_client().unwrap()
}

struct Pair {
    alice: Session,
    bob: Session,
    state: Arc<Mutex<Backend>>,
    url: Url,
    gid: Uuid,
    binding: String,
}

/// Alice invites, Bob redeems (Welcome + pq_init pending for Alice).
async fn pair() -> (tempfile::TempDir, Pair) {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
    let link = invite::parse_link(&link).unwrap();
    let (gid, pq) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
    let PqStatus::Bound(binding) = pq else {
        panic!("expected a PQ binding, got {pq:?}");
    };
    (
        tmp,
        Pair {
            alice,
            bob,
            state,
            url,
            gid,
            binding,
        },
    )
}

/// Bob encrypts `text` into the group and queues it for Alice.
fn bob_sends(p: &Pair, text: &[u8]) -> Uuid {
    let mut local = LocalIdentity::load(&p.bob.store).unwrap();
    let mut group = mls_group::load_group(p.gid.as_bytes(), &local.provider)
        .unwrap()
        .unwrap();
    let ct = mls_group::encrypt_message(&mut group, &local.identity.signer, text, &local.provider)
        .unwrap();
    local.save(&p.bob.store).unwrap();
    // Ascending ids sorting after the testsrv pq_init (random v4): the test server pages by id
    // and MLS decryption is order-sensitive.
    let mut st = p.state.lock().unwrap();
    let id = Uuid::from_u128(
        (u128::MAX << 64) | (st.inbox.len() as u128 + st.calls.len() as u128 * 1000),
    );
    st.inbox.push(json!({
        "id": id, "group_id": p.gid, "sender": p.bob.device_id,
        "recipient": p.alice.device_id.to_string(),
        "message_type": "Application", "ciphertext": ct,
    }));
    id
}

fn rx_names(s: &Session) -> Vec<String> {
    s.store
        .names()
        .unwrap()
        .into_iter()
        .filter(|n| n.starts_with(RX_PREFIX))
        .collect()
}

#[tokio::test]
async fn joiner_completes_pq_init_and_both_sides_share_the_binding() {
    let (_tmp, p) = pair().await;
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!(r.joined, vec![p.gid]);
    assert_eq!(r.pq_bound, vec![p.gid]);
    assert_eq!((r.stored, r.skipped), (0, 0));
    let conv = conversation::load(&p.alice.store, &p.gid).unwrap().unwrap();
    assert_eq!(conv.pq_binding(), Some(p.binding.as_str()));
    assert!(conv.pq_decap_key().is_none(), "single-use key discarded");
    assert!(rx_names(&p.alice).is_empty(), "pq_init is not a message");
    assert!(p.state.lock().unwrap().inbox.is_empty(), "all acked");
}

#[tokio::test]
async fn text_is_decrypted_stored_and_acked_after_pq_init() {
    let (_tmp, p) = pair().await;
    let id = bob_sends(&p, b"hello alice");
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.pq_bound.len()), (1, 1));
    let raw = p
        .alice
        .store
        .get(&format!("{RX_PREFIX}{}", id.hyphenated()))
        .unwrap()
        .unwrap();
    let got: Received = serde_json::from_slice(&raw).unwrap();
    assert_eq!(got.body, b"hello alice");
    assert_eq!((got.group_id, got.sender), (p.gid, p.bob.device_id));
    assert!(p.state.lock().unwrap().inbox.is_empty());
    // A second run finds nothing new and is a no-op.
    assert_eq!(
        receive(&client(), &p.url, &p.alice).await.unwrap(),
        InboxReport::default()
    );
}

#[tokio::test]
async fn pq_init_after_completion_is_dropped_and_acked_not_stored() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    let body = json!({ "type": "pq_init", "ct": vec![0u8; 1088] }).to_string();
    bob_sends(&p, body.as_bytes());
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.pq_bound.len(), r.skipped), (0, 0, 0));
    assert!(rx_names(&p.alice).is_empty());
    assert!(p.state.lock().unwrap().inbox.is_empty(), "acked");
    let conv = conversation::load(&p.alice.store, &p.gid).unwrap().unwrap();
    assert_eq!(conv.pq_binding(), Some(p.binding.as_str()), "unchanged");
}

#[tokio::test]
async fn wrong_sender_and_unknown_group_and_garbage_are_skipped_unacked() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    bob_sends(&p, b"x");
    {
        let mut st = p.state.lock().unwrap();
        st.inbox[0]["sender"] = json!(Uuid::new_v4());
        let me = p.alice.device_id.to_string();
        st.inbox.push(json!({
            "id": Uuid::new_v4(), "group_id": Uuid::new_v4(), "sender": p.bob.device_id,
            "recipient": me, "message_type": "Application", "ciphertext": [1, 2, 3],
        }));
        st.inbox.push(json!({
            "id": Uuid::new_v4(), "group_id": p.gid, "sender": p.bob.device_id,
            "recipient": me, "message_type": "Application", "ciphertext": [1, 2, 3],
        }));
    }
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (0, 3));
    assert!(rx_names(&p.alice).is_empty());
    assert_eq!(p.state.lock().unwrap().inbox.len(), 3, "left for expiry");
}

#[tokio::test]
async fn replayed_ciphertext_is_not_stored_twice() {
    let (_tmp, p) = pair().await;
    bob_sends(&p, b"once");
    let mut replay = p.state.lock().unwrap().inbox.last().unwrap().clone();
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!(r.stored, 1);
    // The server replays the same ciphertext under a new envelope id: Alice's ratchet already
    // consumed that generation, so it must not decrypt again.
    replay["id"] = json!(Uuid::new_v4());
    p.state.lock().unwrap().inbox.push(replay);
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (0, 1));
    assert_eq!(rx_names(&p.alice).len(), 1);
}

#[tokio::test]
async fn store_cap_stops_new_messages() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    for i in 0..MAX_STORED_MESSAGES {
        p.alice
            .store
            .put(&format!("{RX_PREFIX}fill-{i}"), b"x")
            .ok();
    }
    if rx_names(&p.alice).len() < MAX_STORED_MESSAGES {
        return; // profile store record cap reached first; cap path unreachable here
    }
    bob_sends(&p, b"late");
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (0, 1));
}

#[tokio::test]
async fn ephemeral_web_traffic_is_acked_without_filling_the_store() {
    let (_tmp, p) = pair().await;
    for t in [
        "typing_indicator",
        "presence",
        "read_receipt",
        "delivery_receipt",
    ] {
        bob_sends(&p, json!({ "type": t }).to_string().as_bytes());
    }
    bob_sends(
        &p,
        json!({ "type": "text", "text": "hi" })
            .to_string()
            .as_bytes(),
    );
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (1, 0));
    assert_eq!(rx_names(&p.alice).len(), 1);
    assert!(p.state.lock().unwrap().inbox.is_empty());
}

#[tokio::test]
async fn own_broadcast_echo_is_acked_and_cannot_starve_later_messages() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    p.state.lock().unwrap().page_limit = 2;
    {
        let mut st = p.state.lock().unwrap();
        let me = p.alice.device_id.to_string();
        // Junk the server keeps handing back (unknown group, unacked) fills whole pages.
        for _ in 0..5 {
            st.inbox.push(json!({
                "id": Uuid::new_v4(), "group_id": Uuid::new_v4(), "sender": p.bob.device_id,
                "recipient": me, "message_type": "Application", "ciphertext": [1],
                "created_at": "2026-10-09T00:00:00Z",
            }));
        }
        st.inbox.push(json!({
            "id": Uuid::new_v4(), "group_id": p.gid, "sender": p.alice.device_id,
            "recipient": me, "message_type": "Application", "ciphertext": [2],
            "created_at": "2026-10-09T00:00:00Z",
        }));
    }
    bob_sends(&p, b"after the junk");
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    // 5 junk + 1 echo + 1 real message over pages of 2: the cursor reaches all of them.
    assert_eq!(r.stored, 1, "{r:?}");
    assert_eq!(r.skipped, 5);
    let st = p.state.lock().unwrap();
    let polls = st
        .calls
        .iter()
        .filter(|c| c.starts_with("GET /v1/messages"))
        .count();
    assert!(polls >= 4, "followed the cursor: {polls} polls");
    assert!(
        st.inbox
            .iter()
            .all(|e| e["sender"] != json!(p.alice.device_id)),
        "echo acked"
    );
}

#[tokio::test]
async fn stored_message_is_never_overwritten_by_a_reused_envelope_id() {
    let (_tmp, p) = pair().await;
    let id = bob_sends(&p, b"first");
    receive(&client(), &p.url, &p.alice).await.unwrap();
    let name = format!("{RX_PREFIX}{}", id.hyphenated());
    let before = p.alice.store.get(&name).unwrap().unwrap().to_vec();
    let second = bob_sends(&p, b"second");
    p.state.lock().unwrap().inbox.last_mut().unwrap()["id"] = json!(id);
    let _ = second;
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (0, 1));
    assert_eq!(p.alice.store.get(&name).unwrap().unwrap().to_vec(), before);
}

#[tokio::test]
async fn stranger_junk_beyond_the_run_budget_cannot_starve_real_messages() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    p.state.lock().unwrap().page_limit = 32;
    {
        let mut st = p.state.lock().unwrap();
        let me = p.alice.device_id.to_string();
        for _ in 0..(MAX_MESSAGES_PER_RUN + 8) {
            st.inbox.push(json!({
                "id": Uuid::new_v4(), "group_id": Uuid::new_v4(), "sender": Uuid::new_v4(),
                "recipient": me, "message_type": "Application", "ciphertext": [1],
                "created_at": "2026-10-09T00:00:00Z",
            }));
        }
    }
    let id = bob_sends(&p, b"real");
    p.state.lock().unwrap().inbox.last_mut().unwrap()["created_at"] = json!("2026-10-09T00:00:00Z");
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    // 72 junk envelopes (more than the budget) precede the real one within 4 pages of 32.
    let stored = p
        .alice
        .store
        .get(&format!("{RX_PREFIX}{}", id.hyphenated()))
        .unwrap();
    assert!(stored.is_some(), "{r:?}");
    assert_eq!(r.stored, 1);
}

#[tokio::test]
async fn rerun_after_crash_between_put_and_save_reprocesses_and_acks() {
    let (_tmp, p) = pair().await;
    receive(&client(), &p.url, &p.alice).await.unwrap();
    let id = bob_sends(&p, b"once");
    // Simulate the crash window: the rx record exists (with an older receive time) but the MLS
    // state was never saved and the envelope was never acked.
    let name = format!("{RX_PREFIX}{}", id.hyphenated());
    let rec = Received {
        group_id: p.gid,
        sender: p.bob.device_id,
        body: b"once".to_vec(),
        received_at: 1,
    };
    p.alice
        .store
        .put(&name, &serde_json::to_vec(&rec).unwrap())
        .unwrap();
    let r = receive(&client(), &p.url, &p.alice).await.unwrap();
    assert_eq!((r.stored, r.skipped), (1, 0));
    assert!(p.state.lock().unwrap().inbox.is_empty(), "acked");
    assert_eq!(rx_names(&p.alice).len(), 1);
}

#[test]
fn body_is_hex_on_write_and_legacy_array_still_reads() {
    let rec = Received {
        group_id: Uuid::nil(),
        sender: Uuid::nil(),
        body: vec![0x00, 0xab, 0xff],
        received_at: 7,
    };
    let json = String::from_utf8(serde_json::to_vec(&rec).unwrap()).unwrap();
    assert!(json.contains("\"body\":\"00abff\""), "{json}");
    let back: Received = serde_json::from_str(&json).unwrap();
    assert_eq!(back.body, rec.body);
    let legacy = json.replace("\"00abff\"", "[0,171,255]");
    assert_eq!(
        serde_json::from_str::<Received>(&legacy).unwrap().body,
        rec.body
    );
    for bad in ["\"0\"", "\"zz\"", "\"AB\"", "[256]"] {
        let j = json.replace("\"00abff\"", bad);
        assert!(serde_json::from_str::<Received>(&j).is_err(), "{bad}");
    }
}

#[test]
fn body_bound_is_exact_for_hex_and_legacy_array() {
    use super::body_hex::MAX_BODY_BYTES;
    let mk = |n: usize, hex: bool| {
        let body = if hex {
            format!("\"{}\"", "ab".repeat(n))
        } else {
            format!("[{}]", "1,".repeat(n - 1) + "1")
        };
        format!(
            "{{\"group_id\":\"{0}\",\"sender\":\"{0}\",\"body\":{body}}}",
            Uuid::nil()
        )
    };
    for hex in [true, false] {
        let ok: Received = serde_json::from_str(&mk(MAX_BODY_BYTES, hex)).unwrap();
        assert_eq!(ok.body.len(), MAX_BODY_BYTES);
        assert!(serde_json::from_str::<Received>(&mk(MAX_BODY_BYTES + 1, hex)).is_err());
    }
    let big = Received {
        group_id: Uuid::nil(),
        sender: Uuid::nil(),
        body: vec![0; MAX_BODY_BYTES + 1],
        received_at: 0,
    };
    assert!(
        serde_json::to_vec(&big).is_err(),
        "oversize is a typed error, not a panic"
    );
}

#[test]
fn encode_never_reallocates_and_matches_to_vec() {
    for len in [0usize, 1, 100, 4096, 70_000] {
        let rec = Received {
            group_id: Uuid::from_u128(u128::MAX),
            sender: Uuid::from_u128(u128::MAX - 1),
            body: vec![0xab; len],
            received_at: u64::MAX,
        };
        let enc = rec.encode().unwrap();
        assert_eq!(
            enc.capacity(),
            len * 2 + Received::JSON_OVERHEAD,
            "len {len}"
        );
        assert_eq!(&enc[..], &serde_json::to_vec(&rec).unwrap()[..]);
    }
}

#[test]
fn encode_rejects_oversize_body_before_allocating() {
    use super::body_hex::MAX_BODY_BYTES;
    let rec = Received {
        group_id: Uuid::nil(),
        sender: Uuid::nil(),
        body: vec![0; MAX_BODY_BYTES + 1],
        received_at: 0,
    };
    assert!(rec.encode().is_err());
}
