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

    let group_id = redeem(&client(), &url, &bob, &parsed).await.unwrap();
    {
        let st = state.lock().unwrap();
        assert_eq!(st.groups, vec![group_id]);
        assert_eq!(st.members, vec![(group_id, alice.device_id, 1)]);
        assert_eq!(st.inbox.len(), 1);
        assert_eq!(st.inbox[0]["recipient"], alice.device_id.to_string());
        assert!(st.invites.is_empty(), "code is single use");
    }
    let bob_conv = conversation::load(&bob.store, &group_id).unwrap().unwrap();
    assert_eq!(bob_conv.role, Role::Creator);
    assert_eq!(bob_conv.peer_device_id, alice.device_id);

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
    assert!(conv.pq_decap_key().is_some());
    // The consumed KeyPackage's key moved into the conversation and left `pq-keys`.
    assert!(state.lock().unwrap().inbox.is_empty(), "welcome acked");
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
        mls_group::decrypt_message(&mut ag, &ct, &a.provider).unwrap(),
        b"hi"
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
    assert_eq!(state.lock().unwrap().inbox.len(), 1);
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
