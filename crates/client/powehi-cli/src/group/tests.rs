use std::sync::{Arc, Mutex};

use super::*;
use crate::conversation::Kind;
use crate::testsrv::{serve, session, Backend};

#[tokio::test]
async fn create_registers_a_group_kind_conversation_with_only_the_creator() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let client = crate::status::http_client().unwrap();

    let id = create(&client, &url, &alice).await.unwrap();

    let conv = conversation::load(&alice.store, &id).unwrap().unwrap();
    assert_eq!(conv.kind(), Kind::Group);
    assert!(state.lock().unwrap().groups.contains(&id));
    let local = LocalIdentity::load(&alice.store).unwrap();
    let group = mls_group::load_group(id.as_bytes(), &local.provider)
        .unwrap()
        .unwrap();
    assert_eq!(mls_group::group_kind(&group).unwrap(), GroupKind::Group);
    assert_eq!(group.members().count(), 1);
    assert!(!mls_group::is_pair_with(
        &group,
        &local.identity.signer.to_public_vec()
    ));
}

#[tokio::test]
async fn a_rejected_registration_leaves_no_conversation_record() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let dead = Url::parse("http://127.0.0.1:1/").unwrap();
    let client = crate::status::http_client().unwrap();

    assert!(create(&client, &dead, &alice).await.is_err());
    assert!(conversation::list(&alice.store).unwrap().is_empty());
}

#[tokio::test]
async fn at_the_conversation_cap_nothing_reaches_the_server() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    for _ in 0..conversation::MAX_CONVERSATIONS {
        let c = Conversation::new(Uuid::new_v4(), Uuid::new_v4(), Role::Creator, None);
        conversation::save(&alice.store, &c).unwrap();
    }
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let client = crate::status::http_client().unwrap();

    let err = create(&client, &url, &alice).await.unwrap_err();
    assert!(matches!(
        err,
        InviteError::Conversation(ConversationError::TooMany)
    ));
    assert!(state.lock().unwrap().groups.is_empty());
}

#[tokio::test]
async fn a_solo_group_refuses_send() {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let client = crate::status::http_client().unwrap();
    let id = create(&client, &url, &alice).await.unwrap();

    let err = crate::message::send(&client, &url, &alice, id, b"hi").await;
    assert!(matches!(
        err,
        Err(crate::message::MessageError::GroupUnusable)
    ));
}
