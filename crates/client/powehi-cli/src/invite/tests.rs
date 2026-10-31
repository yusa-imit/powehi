use std::sync::{Arc, Mutex};

use openmls::prelude::OpenMlsProvider as _;

use super::*;
use crate::conversation;
use crate::identity::{LocalIdentity, PQ_KEYS_RECORD};
use crate::testsrv::{serve, session, Backend};
use crate::welcome;

fn client() -> Client {
    crate::status::http_client().unwrap()
}

const CODE: &str = "0123456789abcdef0123456789abcdef";
const HASH: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

#[test]
fn parses_full_url_and_bare_fragment_and_round_trips() {
    let server = Url::parse("https://chat.example:8443/").unwrap();
    let link = build_link(&server, CODE, HASH).unwrap();
    assert_eq!(
        link,
        format!("https://chat.example:8443/i/connect#{CODE}.{HASH}")
    );
    let parsed = parse_link(&link).unwrap();
    assert_eq!(parsed.code, CODE);
    assert_eq!(parsed.kp_hash, HASH);
    let bare = parse_link(&format!("  {CODE}.{HASH}\n")).unwrap();
    assert_eq!((&bare.code, &bare.kp_hash), (&parsed.code, &parsed.kp_hash));
    assert!(bare.origin.is_none());
    assert!(!format!("{parsed:?}").contains(CODE));
}

#[test]
fn rejects_malformed_links() {
    let long = "a".repeat(MAX_LINK_LEN + 1);
    for bad in [
        "",
        "nodot",
        &format!("{CODE}-{HASH}"),
        &format!("{}.{HASH}", &CODE[1..]),
        &format!("{CODE}.{}", &HASH[1..]),
        &format!("{}.{HASH}", CODE.to_uppercase()),
        &format!("{CODE}.{}", "g".repeat(64)),
        &long,
    ] {
        assert!(
            matches!(parse_link(bad), Err(InviteError::BadLink)),
            "{bad}"
        );
    }
    let server = Url::parse("https://h/").unwrap();
    assert!(build_link(&server, "short", HASH).is_err());
    assert!(build_link(&server, CODE, "short").is_err());
}

/// Alice creates an invite, Bob redeems it, Alice joins: both ends hold the same group.
#[tokio::test]
async fn invite_to_joined_conversation_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;

    let (link, key_ref) = create(&client(), &url, &alice).await.unwrap();
    let parsed = parse_link(&link).unwrap();
    {
        let st = state.lock().unwrap();
        let (inviter, pinned) = st.invites.get(&parsed.code).unwrap();
        assert_eq!(*inviter, alice.device_id);
        // The hash in the link is over exactly the bytes the server pinned.
        assert_eq!(hex(&Sha256::digest(pinned)), parsed.kp_hash);
    }
    assert!(alice.store.get(PQ_KEYS_RECORD).unwrap().is_some());

    let (group_id, binding) = redeem(&client(), &url, &bob, &parsed).await.unwrap();
    let PqStatus::Bound(binding) = binding else {
        panic!("both KeyPackages are PQ-capable: {binding:?}");
    };
    {
        let st = state.lock().unwrap();
        assert_eq!(st.groups, vec![group_id]);
        assert_eq!(st.members, vec![(group_id, alice.device_id, 1)]);
        assert_eq!(st.welcome_count(), 1);
        assert_eq!(st.inbox.len(), 2, "Welcome + pq_init");
        assert_eq!(st.inbox[0]["recipient"], alice.device_id.to_string());
        assert!(st.invites.is_empty(), "code is single use");
    }
    let bob_conv = conversation::load(&bob.store, &group_id).unwrap().unwrap();
    assert_eq!(bob_conv.role, Role::Creator);
    assert_eq!(bob_conv.peer_device_id, alice.device_id);
    // The inviter's credential comes from the hash-pinned KeyPackage (test label [1; 16]).
    assert_eq!(bob_conv.peer_credential(), Some([1u8; 16].as_slice()));

    let report = welcome::join_pending(&client(), &url, &alice, Some(&key_ref))
        .await
        .unwrap();
    assert_eq!(report.joined, vec![group_id]);
    assert_eq!(report.skipped, 0);
    let conv = conversation::load(&alice.store, &group_id)
        .unwrap()
        .unwrap();
    assert_eq!(conv.role, Role::Joiner);
    assert_eq!(conv.peer_device_id, bob.device_id);
    assert_eq!(conv.peer_credential(), Some([2u8; 16].as_slice()));
    assert!(conv.pq_decap_key().is_some());
    // The consumed KeyPackage's key moved into the conversation and left `pq-keys`.
    assert_eq!(state.lock().unwrap().welcome_count(), 0, "welcome acked");
    let left = alice.store.get(PQ_KEYS_RECORD).unwrap().unwrap();
    assert_eq!(left.len(), 3, "no decap keys remain: header only");

    // Both sides now share the group: Bob's application message decrypts for Alice.
    let b = LocalIdentity::load(&bob.store).unwrap();
    let a = LocalIdentity::load(&alice.store).unwrap();
    let gid = openmls_group_id(&group_id);
    let mut bg = load_group(&b, &gid);
    let mut ag = load_group(&a, &gid);
    let ct = mls_group::encrypt_message(&mut bg, &b.identity.signer, b"hi", &b.provider).unwrap();
    assert_eq!(
        mls_group::decrypt_message(&mut ag, &ct, &a.provider)
            .unwrap()
            .to_vec(),
        b"hi"
    );

    // The pq_init envelope decrypts for Alice, and decapsulating with her stored key yields
    // the same binding Bob recorded (prd.md §5.3 Phase B).
    let env = state.lock().unwrap().inbox[0].clone();
    assert_eq!(env["message_type"], "Application");
    let ct: Vec<u8> = serde_json::from_value(env["ciphertext"].clone()).unwrap();
    let plain = mls_group::decrypt_message(&mut ag, &ct, &a.provider).unwrap();
    let init: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    assert_eq!(init["type"], "pq_init");
    let kem_ct: Vec<u8> = serde_json::from_value(init["ct"].clone()).unwrap();
    let ss = kem::decapsulate(conv.pq_decap_key().unwrap(), &kem_ct).unwrap();
    let theirs = kem::derive_pq_binding(&ss, &group_id.hyphenated().to_string()).unwrap();
    assert_eq!(theirs, binding);
    let bob_conv = conversation::load(&bob.store, &group_id).unwrap().unwrap();
    assert_eq!(bob_conv.pq_binding(), Some(binding.as_str()));
    assert!(
        !String::from_utf8_lossy(&ct).contains("pq_init"),
        "ciphertext only"
    );

    // A second poll finds nothing and does not rejoin.
    let again = welcome::join_pending(&client(), &url, &alice, None)
        .await
        .unwrap();
    assert_eq!(again, welcome::JoinReport::default());
}

fn openmls_group_id(id: &Uuid) -> Vec<u8> {
    id.as_bytes().to_vec()
}

fn load_group(local: &LocalIdentity, gid: &[u8]) -> openmls::prelude::MlsGroup {
    openmls::prelude::MlsGroup::load(
        local.provider.storage(),
        &openmls::prelude::GroupId::from_slice(gid),
    )
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn tampered_key_package_is_rejected_before_any_group_work() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let link = parse_link(&create(&client(), &url, &alice).await.unwrap().0).unwrap();
    state.lock().unwrap().tamper_redeem = true;
    let err = redeem(&client(), &url, &bob, &link).await.unwrap_err();
    assert!(matches!(err, InviteError::HashMismatch));
    let st = state.lock().unwrap();
    assert!(st.groups.is_empty() && st.members.is_empty() && st.inbox.is_empty());
    assert!(bob
        .store
        .get(crate::identity::PROVIDER_RECORD)
        .unwrap()
        .is_none());
    assert!(conversation::list(&bob.store).unwrap().is_empty());
}

#[tokio::test]
async fn unknown_code_and_self_invite_are_typed_errors() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let unknown = parse_link(&format!("{CODE}.{HASH}")).unwrap();
    assert!(matches!(
        redeem(&client(), &url, &bob, &unknown).await,
        Err(InviteError::NotFound)
    ));
    let link = parse_link(&create(&client(), &url, &alice).await.unwrap().0).unwrap();
    assert!(matches!(
        redeem(&client(), &url, &alice, &link).await,
        Err(InviteError::SelfInvite)
    ));
    assert!(state.lock().unwrap().groups.is_empty());
}

#[tokio::test]
async fn bearer_is_sent_and_sensitive_paths_never_carry_the_code() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let (link, _) = create(&client(), &url, &alice).await.unwrap();
    let parsed = parse_link(&link).unwrap();
    redeem(&client(), &url, &bob, &parsed).await.unwrap();
    let st = state.lock().unwrap();
    assert!(
        st.calls.iter().all(|c| !c.contains(&parsed.code)),
        "{:?}",
        st.calls
    );
}

/// `--wait` must only accept the Welcome for the invite's own KeyPackage.
#[tokio::test]
async fn wait_filter_ignores_welcomes_for_other_key_packages() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let (link, key_ref) = create(&client(), &url, &alice).await.unwrap();
    redeem(&client(), &url, &bob, &parse_link(&link).unwrap())
        .await
        .unwrap();
    let wrong = vec![0u8; 32];
    let r = welcome::join_pending(&client(), &url, &alice, Some(&wrong))
        .await
        .unwrap();
    assert_eq!((r.joined.len(), r.skipped), (0, 1));
    assert_eq!(state.lock().unwrap().welcome_count(), 1);
    let r = welcome::join_pending(&client(), &url, &alice, Some(&key_ref))
        .await
        .unwrap();
    assert_eq!(r.joined.len(), 1);
}

#[tokio::test]
async fn link_for_another_server_is_refused_before_any_request() {
    let tmp = tempfile::tempdir().unwrap();
    let bob = session(&tmp, "bob", 2);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let link = parse_link(&format!("https://other.example/i/connect#{CODE}.{HASH}")).unwrap();
    assert!(matches!(
        redeem(&client(), &url, &bob, &link).await,
        Err(InviteError::WrongServer)
    ));
    assert!(state.lock().unwrap().calls.is_empty());
}

/// A peer whose KeyPackage has no PQ extension gets a classical-only conversation: no
/// `pq_init` leaves, no binding is recorded.
#[tokio::test]
async fn classical_only_peer_gets_no_pq_init_and_no_binding() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let a = LocalIdentity::load(&alice.store).unwrap();
    let plain = mls_group::generate_key_package(&a.identity, &a.provider).unwrap();
    let kp = openmls::prelude::MlsMessageOut::from(plain)
        .to_bytes()
        .unwrap();
    let code = "ab".repeat(16);
    state
        .lock()
        .unwrap()
        .invites
        .insert(code.clone(), (alice.device_id, kp.clone()));
    let link = build_link(&url, &code, &hex(&Sha256::digest(&kp))).unwrap();
    let (gid, binding) = redeem(&client(), &url, &bob, &parse_link(&link).unwrap())
        .await
        .unwrap();
    assert_eq!(binding, PqStatus::PeerClassical);
    let st = state.lock().unwrap();
    assert_eq!((st.welcome_count(), st.inbox.len()), (1, 1));
    drop(st);
    let conv = conversation::load(&bob.store, &gid).unwrap().unwrap();
    assert_eq!(conv.pq_binding(), None);
}

/// A KeyPackage whose PQ extension was signed by someone other than the group's peer is a key
/// substitution: no encapsulation to it, classical fallback.
#[tokio::test]
async fn pq_key_signed_by_someone_else_is_not_used() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob, mallory) = (
        session(&tmp, "alice", 1),
        session(&tmp, "bob", 2),
        session(&tmp, "mallory", 3),
    );
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    // Alice's leaf identity, Mallory's signature over the encap key: build a payload by hand.
    let (a, m) = (
        LocalIdentity::load(&alice.store).unwrap(),
        LocalIdentity::load(&mallory.store).unwrap(),
    );
    let pair = kem::generate();
    let sig =
        powehi_crypto_core::kem_credential::sign_encap_key(&pair.encap_key, &m.identity.signer)
            .unwrap();
    let mut payload = pair.encap_key.to_vec();
    payload.extend_from_slice(&sig);
    let bundle =
        mls_group::generate_key_package_with_pq_ext(&a.identity, &a.provider, &payload).unwrap();
    let kp = openmls::prelude::MlsMessageOut::from(bundle)
        .to_bytes()
        .unwrap();
    let code = "cd".repeat(16);
    state
        .lock()
        .unwrap()
        .invites
        .insert(code.clone(), (alice.device_id, kp.clone()));
    let link = build_link(&url, &code, &hex(&Sha256::digest(&kp))).unwrap();
    let (_, binding) = redeem(&client(), &url, &bob, &parse_link(&link).unwrap())
        .await
        .unwrap();
    assert_eq!(binding, PqStatus::KeyRejected);
    assert_eq!(state.lock().unwrap().inbox.len(), 1, "Welcome only");
}

/// If `pq_init` cannot be sent the conversation still works, and no binding is recorded.
#[tokio::test]
async fn failed_pq_init_send_records_no_binding() {
    let tmp = tempfile::tempdir().unwrap();
    let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
    let state = Arc::new(Mutex::new(Backend::default()));
    state.lock().unwrap().fail_messages = true;
    let url = serve(state.clone()).await;
    let (link, _) = create(&client(), &url, &alice).await.unwrap();
    let (gid, status) = redeem(&client(), &url, &bob, &parse_link(&link).unwrap())
        .await
        .unwrap();
    assert_eq!(status, PqStatus::NotSent);
    assert_eq!(state.lock().unwrap().welcome_count(), 1);
    let conv = conversation::load(&bob.store, &gid).unwrap().unwrap();
    assert_eq!(conv.pq_binding(), None);
}

#[test]
fn created_report_text_is_the_bare_link_and_json_is_one_object() {
    let mut out = Vec::new();
    write_created("https://x.test/i/connect#a.b", false, &mut out).unwrap();
    assert_eq!(out, b"https://x.test/i/connect#a.b\n");
    let mut out = Vec::new();
    write_created("https://x.test/i/connect#a.b", true, &mut out).unwrap();
    let s = String::from_utf8(out).unwrap();
    assert_eq!(s.lines().count(), 1);
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v["invite"], "https://x.test/i/connect#a.b");
    assert_eq!(v.as_object().unwrap().len(), 1);
}

#[test]
fn joined_report_text_and_json_cover_both_outcomes() {
    let id = Uuid::from_u128(7);
    let mut out = Vec::new();
    write_joined(Some(id), false, &mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        format!("conversation {id}\n")
    );
    let mut out = Vec::new();
    write_joined(Some(id), true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["conversation"], id.to_string());
    let mut out = Vec::new();
    write_joined(None, true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(v["conversation"].is_null());
    let mut out = Vec::new();
    write_joined(None, false, &mut out).unwrap();
    assert!(String::from_utf8(out)
        .unwrap()
        .starts_with("no one has redeemed"));
}

#[test]
fn redeemed_report_json_names_every_pq_outcome() {
    let id = Uuid::from_u128(9);
    let cases = [
        (PqStatus::Bound("ab12".into()), "bound", Some("ab12")),
        (PqStatus::PeerClassical, "peer_classical", None),
        (PqStatus::KeyRejected, "key_rejected", None),
        (PqStatus::NotSent, "not_sent", None),
    ];
    for (pq, state, binding) in cases {
        let mut out = Vec::new();
        write_redeemed(id, &pq, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), 1);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["conversation"], id.to_string());
        assert_eq!(v["pq"], state);
        assert_eq!(v["pq_binding"].as_str(), binding);
        assert_eq!(v.as_object().unwrap().len(), 3);
    }
}

#[test]
fn only_a_known_pre_store_status_on_a_first_post_is_a_commit_rejection() {
    for code in [400, 401, 404, 409, 413, 415, 422, 429] {
        assert_eq!(
            commit_status_outcome(code, false),
            CommitOutcome::Rejected,
            "{code}"
        );
        assert_eq!(
            commit_status_outcome(code, true),
            CommitOutcome::Unknown,
            "{code}"
        );
    }
    for code in [301, 403, 408, 410, 499, 500, 502, 503, 504, 600] {
        assert_eq!(
            commit_status_outcome(code, false),
            CommitOutcome::Unknown,
            "{code}"
        );
    }
}

#[tokio::test]
async fn send_commit_maps_the_server_answer_to_an_outcome() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let group = Uuid::new_v4();
    let http = client();
    let post = |epoch| send_commit(&http, &url, &alice, group, b"opaque", epoch, false);
    assert_eq!(post(4).await, CommitOutcome::Accepted);
    state.lock().unwrap().commit_reply_epoch = Some(9);
    assert_eq!(
        post(4).await,
        CommitOutcome::Unknown,
        "a wrong epoch is not an acceptance"
    );
    {
        let mut st = state.lock().unwrap();
        st.commit_reply_epoch = None;
        st.commit_status = 409;
    }
    assert_eq!(post(4).await, CommitOutcome::Rejected);
    assert_eq!(
        send_commit(&http, &url, &alice, group, b"opaque", 4, true).await,
        CommitOutcome::Unknown,
        "a 409 on a re-post is not a rejection"
    );
    state.lock().unwrap().commit_status = 503;
    assert_eq!(post(4).await, CommitOutcome::Unknown);
    assert_eq!(state.lock().unwrap().commits, vec![4; 5]);
}

mod props {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any text is classified without panic, and an accepted link is the canonical shape.
        #[test]
        fn arbitrary_text_never_panics_and_accepts_only_canonical_links(
            text in ".{0,600}",
        ) {
            if let Ok(link) = parse_link(&text) {
                prop_assert!(is_lower_hex(&link.code, CODE_LEN));
                prop_assert!(is_lower_hex(&link.kp_hash, HASH_HEX_LEN));
            }
        }

        /// build_link output always parses back to the same code and hash.
        #[test]
        fn built_links_round_trip(
            code in proptest::collection::vec(any::<u8>(), CODE_LEN / 2),
            hash in proptest::collection::vec(any::<u8>(), HASH_HEX_LEN / 2),
        ) {
            let (code, hash) = (hex(&code), hex(&hash));
            let server = Url::parse("https://chat.example/").unwrap();
            let link = build_link(&server, &code, &hash).unwrap();
            let parsed = parse_link(&link).unwrap();
            prop_assert_eq!(parsed.code, code);
            prop_assert_eq!(parsed.kp_hash, hash);
        }

        /// A single non-lowercase-hex byte anywhere in code or hash is rejected.
        #[test]
        fn one_corrupt_character_is_rejected(pos in 0usize..(CODE_LEN + 1 + HASH_HEX_LEN)) {
            let mut bytes = format!("{CODE}.{HASH}").into_bytes();
            prop_assume!(bytes[pos] != b'.');
            bytes[pos] = b'G';
            let s = String::from_utf8(bytes).unwrap();
            prop_assert!(parse_link(&s).is_err());
        }
    }
}
