use std::sync::{Arc, Mutex};

use super::*;
use crate::group::{add, create};
use crate::identity::LocalIdentity;
use crate::invite::parse_link;
use crate::testsrv::{serve, session, Backend};

struct World {
    tmp: tempfile::TempDir,
    alice: Session,
    url: Url,
    state: Arc<Mutex<Backend>>,
    gid: Uuid,
}

fn client() -> Client {
    crate::status::http_client().unwrap()
}

/// A group of alice plus `n` members added one by one (leaves 1..=n).
async fn world(n: u8) -> World {
    let tmp = tempfile::tempdir().unwrap();
    let alice = session(&tmp, "alice", 1);
    let state = Arc::new(Mutex::new(Backend::default()));
    let url = serve(state.clone()).await;
    let gid = create(&client(), &url, &alice).await.unwrap();
    let w = World {
        tmp,
        alice,
        url,
        state,
        gid,
    };
    for i in 0..n {
        add_member(&w, i).await.unwrap();
        w.state.lock().unwrap().group_epoch = u64::from(i) + 1;
    }
    w
}

async fn add_member(w: &World, i: u8) -> Result<u64, GroupError> {
    let s = session(&w.tmp, &format!("m{i}"), 10 + i);
    let (link, _) = invite::create(&client(), &w.url, &s).await.unwrap();
    add(
        &client(),
        &w.url,
        &w.alice,
        w.gid,
        &parse_link(&link).unwrap(),
    )
    .await
}

/// The signature key hex of the member at `leaf`, as `group members` prints it.
fn key_of(w: &World, leaf: u32) -> String {
    members(&w.alice, w.gid)
        .unwrap()
        .into_iter()
        .find(|m| m.leaf == leaf)
        .unwrap()
        .key_hex
}

fn epoch_and_count(w: &World) -> (u64, usize) {
    let local = LocalIdentity::load(&w.alice.store).unwrap();
    let g = mls_group::load_group(w.gid.as_bytes(), &local.provider)
        .unwrap()
        .unwrap();
    (g.epoch().as_u64(), g.members().count())
}

#[tokio::test]
async fn removing_a_member_advances_the_epoch_and_shrinks_the_roster() {
    let w = world(2).await;
    assert_eq!(epoch_and_count(&w), (2, 3));
    let epoch = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1))
        .await
        .unwrap();
    assert_eq!(epoch, 3);
    assert_eq!(epoch_and_count(&w), (3, 2));
    assert_eq!(w.state.lock().unwrap().commits, vec![0, 1, 2]);
    assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
    let roster = members(&w.alice, w.gid).unwrap();
    assert_eq!(
        roster.iter().map(|m| m.leaf).collect::<Vec<_>>(),
        vec![0, 2]
    );
    assert_eq!(roster.iter().filter(|m| m.is_self).count(), 1);
}

#[tokio::test]
async fn unknown_key_and_own_key_are_refused_before_anything_is_posted() {
    let w = world(1).await;
    let before = w.state.lock().unwrap().commits.len();
    let e = remove(&client(), &w.url, &w.alice, w.gid, &"ab".repeat(32))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::NoSuchMember));
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 0))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::RemoveSelf));
    assert_eq!(w.state.lock().unwrap().commits.len(), before);
    assert_eq!(epoch_and_count(&w), (1, 2));
}

#[tokio::test]
async fn a_rejected_remove_aborts_and_can_be_retried() {
    let w = world(1).await;
    w.state.lock().unwrap().commit_status = 409;
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::Rejected));
    assert_eq!(epoch_and_count(&w), (1, 2));
    assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
    w.state.lock().unwrap().commit_status = 0;
    assert_eq!(
        remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1))
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn an_unknown_answer_keeps_the_record_and_blocks_adds_and_removes() {
    let w = world(2).await;
    w.state.lock().unwrap().commit_status = 500;
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::Unknown));
    assert_eq!(epoch_and_count(&w), (2, 3));
    assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
    w.state.lock().unwrap().commit_status = 0;
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 2))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::Unresolved));
    let e = add_member(&w, 9).await.unwrap_err();
    assert!(matches!(e, GroupError::Unresolved));
}

#[tokio::test]
async fn an_epoch_mismatch_and_an_unknown_group_are_refused() {
    let w = world(1).await;
    w.state.lock().unwrap().group_epoch = 9;
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1))
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::EpochMismatch));
    let e = remove(&client(), &w.url, &w.alice, Uuid::new_v4(), "ab")
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::NoSuchGroup));
}

#[tokio::test]
async fn a_key_that_left_the_roster_is_refused_even_if_its_leaf_is_reused() {
    let w = world(2).await;
    let bob = key_of(&w, 1);
    remove(&client(), &w.url, &w.alice, w.gid, &bob)
        .await
        .unwrap();
    w.state.lock().unwrap().group_epoch = 3;
    // A new member fills the freed leaf 1; the old key must not name them.
    add_member(&w, 5).await.unwrap();
    w.state.lock().unwrap().group_epoch = 4;
    assert_ne!(key_of(&w, 1), bob);
    let e = remove(&client(), &w.url, &w.alice, w.gid, &bob)
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::NoSuchMember));
    assert_eq!(epoch_and_count(&w), (4, 3));
}

#[tokio::test]
async fn the_pending_record_is_epoch_then_the_posted_commit() {
    let w = world(1).await;
    w.state.lock().unwrap().commit_status = 500;
    let _ = remove(&client(), &w.url, &w.alice, w.gid, &key_of(&w, 1)).await;
    let raw = w.alice.store.get(&pending_name(w.gid)).unwrap().unwrap();
    assert_eq!(raw[..8], 1u64.to_be_bytes());
    assert!(raw.len() > 8);
}

#[tokio::test]
async fn a_pending_add_blocks_remove_and_a_pair_is_refused() {
    let w = world(1).await;
    let key = key_of(&w, 1);
    w.alice.store.put("gadd-x", b"x").unwrap();
    // A malformed or mismatching gadd record for another group does not block this one.
    w.alice.store.remove("gadd-x").unwrap();
    w.alice
        .store
        .put(&format!("gadd-{}", w.gid.hyphenated()), b"junk")
        .unwrap();
    let e = remove(&client(), &w.url, &w.alice, w.gid, &key)
        .await
        .unwrap_err();
    assert!(matches!(e, GroupError::Unresolved));
    let pair = Uuid::new_v4();
    let c = crate::conversation::Conversation::new(
        pair,
        Uuid::new_v4(),
        crate::conversation::Role::Creator,
        None,
    );
    crate::conversation::save(&w.alice.store, &c).unwrap();
    assert!(matches!(
        remove(&client(), &w.url, &w.alice, pair, &key).await,
        Err(GroupError::NotAGroup)
    ));
    assert!(matches!(
        members(&w.alice, pair),
        Err(GroupError::NotAGroup)
    ));
}

#[tokio::test]
async fn an_uppercase_key_resolves_and_empty_or_oversized_keys_are_refused() {
    let w = world(1).await;
    let before = w.state.lock().unwrap().commits.len();
    for bad in [String::new(), "a".repeat(MAX_KEY_HEX + 1)] {
        let e = remove(&client(), &w.url, &w.alice, w.gid, &bad)
            .await
            .unwrap_err();
        assert!(matches!(e, GroupError::NoSuchMember));
    }
    assert_eq!(w.state.lock().unwrap().commits.len(), before);
    let upper = key_of(&w, 1).to_ascii_uppercase();
    let epoch = remove(&client(), &w.url, &w.alice, w.gid, &upper)
        .await
        .unwrap();
    assert_eq!(epoch, 2);
    assert_eq!(epoch_and_count(&w), (2, 1));
}

#[test]
fn members_and_removed_render_text_and_json() {
    let list = vec![
        Member {
            leaf: 0,
            key_hex: "aa".into(),
            is_self: true,
        },
        Member {
            leaf: 2,
            key_hex: "bb".into(),
            is_self: false,
        },
    ];
    let mut out = Vec::new();
    write_members(&list, false, &mut out).unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "0\taa (you)\n2\tbb\n");
    let mut out = Vec::new();
    write_members(&list, true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v[0]["self"], true);
    assert_eq!(v[1]["leaf"], 2);
    assert_eq!(v[1]["key"], "bb");
    let gid = Uuid::from_bytes([7; 16]);
    let mut out = Vec::new();
    write_removed(gid, "bb", 3, true, &mut out).unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(v["removed"], "bb");
    assert_eq!(v["epoch"], 3);
    assert_eq!(v["server_notified"], false);
    let mut out = Vec::new();
    write_removed(gid, "bb", 3, false, &mut out).unwrap();
    assert!(String::from_utf8(out).unwrap().contains("not told yet"));
}

#[test]
fn bounded_roster_fails_closed_past_the_cap() {
    assert_eq!(bounded(0..3, 3).unwrap(), vec![0, 1, 2]);
    assert!(matches!(bounded(0..4, 3), Err(GroupError::TooMany)));
    assert!(bounded(0..0, 3).unwrap().is_empty());
}
