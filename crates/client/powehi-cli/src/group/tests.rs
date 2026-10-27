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
        Err(crate::message::MessageError::GroupSendUnsupported)
    ));
}

mod add_tests {
    use super::*;
    use crate::invite::{parse_link, InviteLink};

    struct World {
        _tmp: tempfile::TempDir,
        alice: Session,
        bob: Session,
        url: Url,
        state: Arc<Mutex<Backend>>,
        gid: Uuid,
    }

    fn client() -> Client {
        crate::status::http_client().unwrap()
    }

    async fn world() -> World {
        let tmp = tempfile::tempdir().unwrap();
        let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
        let state = Arc::new(Mutex::new(Backend::default()));
        let url = serve(state.clone()).await;
        let gid = create(&client(), &url, &alice).await.unwrap();
        World {
            _tmp: tmp,
            alice,
            bob,
            url,
            state,
            gid,
        }
    }

    async fn link_of(w: &World, s: &Session) -> InviteLink {
        let (link, _) = invite::create(&client(), &w.url, s).await.unwrap();
        parse_link(&link).unwrap()
    }

    fn epoch(s: &Session, gid: Uuid) -> (u64, usize) {
        let local = LocalIdentity::load(&s.store).unwrap();
        let g = mls_group::load_group(gid.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        (g.epoch().as_u64(), g.members().count())
    }

    async fn add_one(w: &World, name: &str, seed: u8) -> Result<u64, GroupError> {
        let s = session(&w._tmp, name, seed);
        let link = link_of(w, &s).await;
        add(&client(), &w.url, &w.alice, w.gid, &link).await
    }

    #[tokio::test]
    async fn adding_two_members_advances_epoch_on_server_and_locally() {
        let w = world().await;
        let link = link_of(&w, &w.bob).await;
        let epoch1 = add(&client(), &w.url, &w.alice, w.gid, &link)
            .await
            .unwrap();
        assert_eq!(epoch1, 1);
        assert_eq!(epoch(&w.alice, w.gid), (1, 2));
        {
            let st = w.state.lock().unwrap();
            assert_eq!(st.commits, vec![0]);
            assert_eq!(st.welcome_count(), 1);
            assert!(st.members.contains(&(w.gid, w.bob.device_id, 1)));
        }
        w.state.lock().unwrap().group_epoch = 1;
        assert_eq!(add_one(&w, "carol", 3).await.unwrap(), 2);
        assert_eq!(epoch(&w.alice, w.gid), (2, 3));
        assert_eq!(w.state.lock().unwrap().commits, vec![0, 1]);
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
    }

    #[tokio::test]
    async fn an_epoch_mismatch_is_refused_and_changes_nothing() {
        let w = world().await;
        w.state.lock().unwrap().group_epoch = 5;
        let err = add_one(&w, "bob2", 4).await.unwrap_err();
        assert!(matches!(err, GroupError::EpochMismatch));
        assert_eq!(epoch(&w.alice, w.gid), (0, 1));
        let st = w.state.lock().unwrap();
        assert!(st.commits.is_empty() && st.welcome_count() == 0);
        // The invite was not spent: local checks precede the redeem.
        assert_eq!(st.invites.len(), 1);
    }

    #[tokio::test]
    async fn a_rejected_commit_aborts_and_keeps_two_members_state() {
        let w = world().await;
        let ok = link_of(&w, &w.bob).await;
        add(&client(), &w.url, &w.alice, w.gid, &ok).await.unwrap();
        {
            let mut st = w.state.lock().unwrap();
            st.group_epoch = 1;
            st.commit_status = 409;
        }
        let err = add_one(&w, "carol", 3).await.unwrap_err();
        assert!(matches!(err, GroupError::Rejected));
        assert_eq!(epoch(&w.alice, w.gid), (1, 2));
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
        assert_eq!(w.state.lock().unwrap().welcome_count(), 1);
        // A retry can stage again.
        w.state.lock().unwrap().commit_status = 0;
        assert_eq!(add_one(&w, "dave", 4).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn an_unknown_answer_leaves_the_commit_staged_and_blocks_further_adds() {
        let w = world().await;
        w.state.lock().unwrap().commit_status = 500;
        let err = add_one(&w, "bob2", 4).await.unwrap_err();
        assert!(matches!(err, GroupError::Unknown));
        assert_eq!(epoch(&w.alice, w.gid), (0, 1));
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
        assert_eq!(w.state.lock().unwrap().welcome_count(), 0);
        w.state.lock().unwrap().commit_status = 0;
        let err = add_one(&w, "carol", 3).await.unwrap_err();
        assert!(matches!(err, GroupError::Unresolved));
    }

    #[tokio::test]
    async fn a_tampered_key_package_is_refused_before_staging() {
        let w = world().await;
        w.state.lock().unwrap().tamper_redeem = true;
        let err = add_one(&w, "bob2", 4).await.unwrap_err();
        assert!(matches!(err, GroupError::Invite(InviteError::HashMismatch)));
        assert_eq!(epoch(&w.alice, w.gid), (0, 1));
        assert!(w.state.lock().unwrap().commits.is_empty());
    }

    #[tokio::test]
    async fn a_pair_unknown_group_and_own_invite_are_refused() {
        let w = world().await;
        let link = link_of(&w, &w.bob).await;
        let (pair, _) = {
            let (l, _) = invite::create(&client(), &w.url, &w.bob).await.unwrap();
            invite::redeem(&client(), &w.url, &w.alice, &parse_link(&l).unwrap())
                .await
                .map(|(g, _)| (g, ()))
                .unwrap()
        };
        let err = add(&client(), &w.url, &w.alice, pair, &link)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::NotAGroup));
        let err = add(&client(), &w.url, &w.alice, Uuid::new_v4(), &link)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::NoSuchGroup));
        let own = link_of(&w, &w.alice).await;
        let err = add(&client(), &w.url, &w.alice, w.gid, &own)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::SelfInvite));
        assert_eq!(epoch(&w.alice, w.gid), (0, 1));
        assert!(w.state.lock().unwrap().commits.is_empty());
    }

    #[tokio::test]
    async fn resume_refuses_an_unknown_group_and_a_pair_conversation() {
        let w = world().await;
        let err = resume(&client(), &w.url, &w.alice, Uuid::new_v4())
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::NoSuchGroup));
        let (l, _) = invite::create(&client(), &w.url, &w.bob).await.unwrap();
        let (pair, _) = invite::redeem(&client(), &w.url, &w.alice, &parse_link(&l).unwrap())
            .await
            .unwrap();
        let before = w.state.lock().unwrap().welcome_count();
        let err = resume(&client(), &w.url, &w.alice, pair).await.unwrap_err();
        assert!(matches!(err, GroupError::NotAGroup));
        assert_eq!(w.state.lock().unwrap().welcome_count(), before);
    }

    /// A two-member kind-Group whose stored record lies and says Pair.
    async fn pair_record_over_two_member_group() -> World {
        let w = world().await;
        let link = link_of(&w, &w.bob).await;
        add(&client(), &w.url, &w.alice, w.gid, &link)
            .await
            .unwrap();
        let lie = crate::conversation::Conversation::new(
            w.gid,
            w.bob.device_id,
            crate::conversation::Role::Creator,
            None,
        );
        crate::conversation::save(&w.alice.store, &lie).unwrap();
        w
    }

    #[tokio::test]
    async fn a_pair_record_over_a_kind_group_state_fails_closed_everywhere() {
        let w = pair_record_over_two_member_group().await;
        assert!(matches!(
            crate::verify::number(&w.alice.store, w.gid),
            Err(crate::verify::VerifyError::GroupUnusable)
        ));
        let sent = crate::message::send(&client(), &w.url, &w.alice, w.gid, b"hi").await;
        assert!(matches!(
            sent,
            Err(crate::message::MessageError::GroupUnusable)
        ));
        let rotated = crate::pcs::rotate(&client(), &w.url, &w.alice, w.gid, 1).await;
        assert!(matches!(
            rotated,
            Err(crate::pcs::RotateError::GroupUnusable)
        ));
        assert!(w
            .alice
            .store
            .get(&crate::pcs::pending_name(w.gid))
            .unwrap()
            .is_none());
        let conv = crate::conversation::load(&w.alice.store, &w.gid)
            .unwrap()
            .unwrap();
        assert_eq!(conv.sent_since_update(), 0);
    }

    #[tokio::test]
    async fn a_two_member_group_still_refuses_send() {
        let w = world().await;
        let link = link_of(&w, &w.bob).await;
        add(&client(), &w.url, &w.alice, w.gid, &link)
            .await
            .unwrap();
        // Two members now: still not a pair for send.
        let err = crate::message::send(&client(), &w.url, &w.alice, w.gid, b"hi").await;
        assert!(matches!(
            err,
            Err(crate::message::MessageError::GroupSendUnsupported)
        ));
    }

    #[tokio::test]
    async fn the_record_holds_epoch_commit_and_welcome_before_the_answer_is_known() {
        let w = world().await;
        w.state.lock().unwrap().commit_status = 500;
        add_one(&w, "bob2", 4).await.unwrap_err();
        let raw = w.alice.store.get(&pending_name(w.gid)).unwrap().unwrap();
        let rec = PendingAdd::decode(&raw).unwrap();
        assert_eq!((rec.server_epoch, rec.state, rec.member_epoch), (0, 0, 1));
        assert!(!rec.commit.is_empty() && !rec.welcome.is_empty());
        assert_eq!(raw[..8], 0u64.to_be_bytes());
        assert_eq!(
            PendingAdd::decode(&raw[..raw.len() - 1])
                .unwrap()
                .welcome
                .len()
                + 1,
            rec.welcome.len()
        );
        assert!(PendingAdd::decode(&raw[..10]).is_none());
    }

    #[tokio::test]
    async fn a_failed_welcome_keeps_the_record_and_resume_delivers_it() {
        let w = world().await;
        w.state.lock().unwrap().fail_welcome = true;
        let err = add_one(&w, "bob2", 4).await.unwrap_err();
        assert!(matches!(err, GroupError::WelcomeNotDelivered));
        assert!(err.to_string().contains("--resume"));
        assert_eq!(epoch(&w.alice, w.gid), (1, 2), "the merge happened");
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
        // A plain add is refused while the Welcome is owed.
        let err = add_one(&w, "carol", 3).await.unwrap_err();
        assert!(matches!(err, GroupError::WelcomePending));
        let err = resume(&client(), &w.url, &w.alice, w.gid)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::WelcomeNotDelivered));
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
        w.state.lock().unwrap().fail_welcome = false;
        assert_eq!(resume(&client(), &w.url, &w.alice, w.gid).await.unwrap(), 1);
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
        assert_eq!(w.state.lock().unwrap().welcome_count(), 1);
        let err = resume(&client(), &w.url, &w.alice, w.gid)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::NothingToResume));
    }

    #[tokio::test]
    async fn resume_is_refused_while_the_commit_is_unresolved() {
        let w = world().await;
        w.state.lock().unwrap().commit_status = 500;
        add_one(&w, "bob2", 4).await.unwrap_err();
        let err = resume(&client(), &w.url, &w.alice, w.gid)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::Unresolved));
        assert_eq!(w.state.lock().unwrap().welcome_count(), 0);
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
    }

    #[tokio::test]
    async fn an_invalid_add_is_not_reported_as_non_membership_and_output_says_not_joinable() {
        let e: GroupError = MlsError::Membership.into();
        assert!(matches!(e, GroupError::AddRefused));
        let id = Uuid::new_v4();
        let (mut t, mut j) = (Vec::new(), Vec::new());
        write_added(id, 3, false, &mut t).unwrap();
        write_added(id, 3, true, &mut j).unwrap();
        assert!(String::from_utf8(t).unwrap().contains("cannot join"));
        let v: serde_json::Value = serde_json::from_slice(&j).unwrap();
        assert_eq!(v["joinable"], false);
        assert_eq!(v["epoch"], 3);
    }

    #[tokio::test]
    async fn resume_after_a_crash_before_the_merge_merges_then_delivers() {
        let w = world().await;
        w.state.lock().unwrap().fail_welcome = true;
        w.state.lock().unwrap().commit_status = 0;
        // Simulate the crash: Commit accepted by the server, record at state 1, group still staged.
        let s = session(&w._tmp, "bob2", 4);
        let link = link_of(&w, &s).await;
        let pinned = invite::fetch_pinned(&client(), &w.url, &w.alice, &link)
            .await
            .unwrap();
        let mut local = LocalIdentity::load(&w.alice.store).unwrap();
        let mut g = mls_group::load_group(w.gid.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        let st = mls_group::stage_group_add(
            &mut g,
            &local.identity.signer,
            &pinned.key_package,
            &local.provider,
        )
        .unwrap();
        local.save(&w.alice.store).unwrap();
        let rec = PendingAdd {
            server_epoch: 0,
            commit: st.commit,
            state: STATE_ACCEPTED,
            peer: pinned.device_id,
            member_epoch: 1,
            welcome: st.welcome,
        };
        w.alice
            .store
            .put(&pending_name(w.gid), &rec.encode())
            .unwrap();
        assert_eq!(epoch(&w.alice, w.gid), (0, 1));
        w.state.lock().unwrap().fail_welcome = false;
        assert_eq!(resume(&client(), &w.url, &w.alice, w.gid).await.unwrap(), 1);
        assert_eq!(epoch(&w.alice, w.gid), (1, 2));
        assert_eq!(w.state.lock().unwrap().welcome_count(), 1);
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_none());
    }

    #[tokio::test]
    async fn resume_over_a_pair_state_with_a_group_record_is_refused() {
        let w = world().await;
        let (l, _) = invite::create(&client(), &w.url, &w.bob).await.unwrap();
        let (pair, _) = invite::redeem(&client(), &w.url, &w.alice, &parse_link(&l).unwrap())
            .await
            .unwrap();
        let lie = crate::conversation::Conversation::new(
            pair,
            w.bob.device_id,
            crate::conversation::Role::Creator,
            None,
        )
        .into_group();
        crate::conversation::save(&w.alice.store, &lie).unwrap();
        // A pair rotation whose outcome was Unknown leaves a staged commit; without the kind
        // gate the merge branch would apply it (RFC 9420 §14: never before the DS sequenced it).
        let mut local = LocalIdentity::load(&w.alice.store).unwrap();
        let mut g = mls_group::load_group(pair.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        let own_key = local.identity.signer.to_public_vec();
        mls_group::stage_pair_self_update(
            &mut g,
            &local.identity.signer,
            &own_key,
            &local.provider,
        )
        .unwrap();
        local.save(&w.alice.store).unwrap();
        let at = g.epoch().as_u64();
        let rec = PendingAdd {
            server_epoch: at,
            commit: vec![1],
            state: STATE_ACCEPTED,
            peer: Uuid::new_v4(),
            member_epoch: at + 1,
            welcome: vec![2],
        };
        w.alice
            .store
            .put(&pending_name(pair), &rec.encode())
            .unwrap();
        let before = w.state.lock().unwrap().welcome_count();
        let err = resume(&client(), &w.url, &w.alice, pair).await.unwrap_err();
        assert!(matches!(err, GroupError::NotAGroup));
        assert_eq!(w.state.lock().unwrap().welcome_count(), before);
        let local = LocalIdentity::load(&w.alice.store).unwrap();
        let g = mls_group::load_group(pair.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        assert_eq!(g.epoch().as_u64(), at, "nothing merged");
        assert!(g.pending_commit().is_some(), "nothing aborted");
    }

    #[tokio::test]
    async fn resume_with_an_unexpected_local_epoch_fails_closed() {
        let w = world().await;
        let rec = PendingAdd {
            server_epoch: 4,
            commit: vec![1],
            state: STATE_ACCEPTED,
            peer: Uuid::new_v4(),
            member_epoch: 5,
            welcome: vec![2],
        };
        w.alice
            .store
            .put(&pending_name(w.gid), &rec.encode())
            .unwrap();
        let err = resume(&client(), &w.url, &w.alice, w.gid)
            .await
            .unwrap_err();
        assert!(matches!(err, GroupError::ResumeEpoch));
        assert_eq!(w.state.lock().unwrap().welcome_count(), 0);
        assert!(w.alice.store.get(&pending_name(w.gid)).unwrap().is_some());
    }

    #[test]
    fn decode_rejects_malformed_records_and_welcome_size_is_capped() {
        let ok = PendingAdd {
            server_epoch: 0,
            commit: vec![1, 2],
            state: STATE_POSTED,
            peer: Uuid::new_v4(),
            member_epoch: 1,
            welcome: vec![3],
        };
        let raw = ok.encode();
        assert!(PendingAdd::decode(&raw).is_some());
        assert!(
            PendingAdd::decode(&raw[..raw.len() - 1]).is_none(),
            "empty welcome"
        );
        assert!(
            PendingAdd::decode(&raw[..raw.len() - 9]).is_none(),
            "truncated tail"
        );
        let mut bad = raw.clone();
        bad[14] = 2;
        assert!(PendingAdd::decode(&bad).is_none(), "state 2");
        let mut bad = raw.clone();
        bad[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(
            PendingAdd::decode(&bad).is_none(),
            "commit_len beyond record"
        );
        for (c, w, m) in [
            (vec![], vec![3], 1),
            (vec![1], vec![3], 2),
            (vec![1], vec![3], 0),
        ] {
            let r = PendingAdd {
                commit: c,
                welcome: w,
                member_epoch: m,
                ..ok_clone(&ok)
            };
            assert!(PendingAdd::decode(&r.encode()).is_none());
        }
        assert!(check_welcome_size(MAX_WELCOME_BYTES).is_ok());
        assert!(check_welcome_size(MAX_WELCOME_BYTES + 1).is_err());
        assert!(check_welcome_size(0).is_err());
    }

    fn ok_clone(p: &PendingAdd) -> PendingAdd {
        PendingAdd {
            server_epoch: p.server_epoch,
            commit: p.commit.clone(),
            state: p.state,
            peer: p.peer,
            member_epoch: p.member_epoch,
            welcome: p.welcome.clone(),
        }
    }
}

mod commit_tests {
    use super::commit::{apply, Outcome};
    use super::*;
    use crate::invite::parse_link;

    fn client() -> Client {
        crate::status::http_client().unwrap()
    }

    fn members_of(s: &Session, gid: Uuid) -> Option<usize> {
        let local = LocalIdentity::load(&s.store).unwrap();
        mls_group::load_group(gid.as_bytes(), &local.provider)
            .unwrap()
            .map(|g| g.members().count())
    }

    /// Alice's group with Bob joined (epoch 1). Returns the world and Bob's signature key hex.
    async fn alice_and_bob() -> (
        tempfile::TempDir,
        Session,
        Session,
        Url,
        Arc<Mutex<Backend>>,
        Uuid,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
        let state = Arc::new(Mutex::new(Backend::default()));
        let url = serve(state.clone()).await;
        let gid = create(&client(), &url, &alice).await.unwrap();
        let (link, _) = invite::create(&client(), &url, &bob).await.unwrap();
        add(&client(), &url, &alice, gid, &parse_link(&link).unwrap())
            .await
            .unwrap();
        crate::welcome::join_invited(&client(), &url, &bob)
            .await
            .unwrap();
        crate::requests::accept(&client(), &url, &bob, gid)
            .await
            .unwrap();
        state.lock().unwrap().group_epoch = 1;
        (tmp, alice, bob, url, state, gid)
    }

    #[tokio::test]
    async fn a_members_add_commit_is_applied_and_a_replay_is_refused() {
        let (tmp, alice, bob, url, state, gid) = alice_and_bob().await;
        let carol = session(&tmp, "carol", 3);
        let (link, _) = invite::create(&client(), &url, &carol).await.unwrap();
        add(&client(), &url, &alice, gid, &parse_link(&link).unwrap())
            .await
            .unwrap();
        let commit = state.lock().unwrap().commit_bytes.last().unwrap().clone();
        assert_eq!(
            apply(&bob, gid, &commit).unwrap(),
            Outcome::Applied {
                added: 1,
                removed: 0
            }
        );
        assert_eq!(members_of(&bob, gid), Some(3));
        // Replay: the epoch is past.
        assert_eq!(apply(&bob, gid, &commit).unwrap(), Outcome::Refused);
        assert_eq!(members_of(&bob, gid), Some(3));
        // Garbage and unknown group.
        assert_eq!(apply(&bob, gid, b"junk").unwrap(), Outcome::Refused);
        assert_eq!(
            apply(&bob, Uuid::new_v4(), &commit).unwrap(),
            Outcome::Unknown
        );
    }

    #[tokio::test]
    async fn the_inbox_applies_a_members_commit_and_acks_it_but_holds_a_foreign_one() {
        let (tmp, alice, bob, url, state, gid) = alice_and_bob().await;
        let carol = session(&tmp, "carol", 3);
        let (link, _) = invite::create(&client(), &url, &carol).await.unwrap();
        add(&client(), &url, &alice, gid, &parse_link(&link).unwrap())
            .await
            .unwrap();
        let commit = state.lock().unwrap().commit_bytes.last().unwrap().clone();
        let push = |kind: &str, ct: &[u8]| {
            state.lock().unwrap().inbox.push(serde_json::json!({
                "id": Uuid::new_v4(), "group_id": gid, "sender": alice.device_id,
                "recipient": bob.device_id.to_string(),
                "message_type": kind, "ciphertext": ct,
            }));
        };
        // Garbage is not acked at once (junk grace), and does not touch the group.
        push("Commit", b"junk");
        let before = state.lock().unwrap().inbox.len();
        crate::inbox::receive(&client(), &url, &bob).await.unwrap();
        assert_eq!(members_of(&bob, gid), Some(2));
        assert!(state.lock().unwrap().inbox.len() <= before);
        push("Commit", &commit);
        let r = crate::inbox::receive(&client(), &url, &bob).await.unwrap();
        assert_eq!(r.commits, 1);
        assert_eq!(members_of(&bob, gid), Some(3));
        let held = (state.lock().unwrap().inbox.iter())
            .filter(|e| e["message_type"] == "Commit")
            .count();
        assert_eq!(held, 1, "the applied Commit is acked, the junk one is held");
    }

    #[tokio::test]
    async fn a_remove_commit_for_this_device_deletes_its_group_state() {
        let (tmp, alice, bob, url, state, gid) = alice_and_bob().await;
        let carol = session(&tmp, "carol", 3);
        let (link, _) = invite::create(&client(), &url, &carol).await.unwrap();
        add(&client(), &url, &alice, gid, &parse_link(&link).unwrap())
            .await
            .unwrap();
        let add_commit = state.lock().unwrap().commit_bytes.last().unwrap().clone();
        assert!(matches!(
            apply(&bob, gid, &add_commit).unwrap(),
            Outcome::Applied { .. }
        ));
        state.lock().unwrap().group_epoch = 2;
        let bob_key = LocalIdentity::load(&bob.store)
            .unwrap()
            .identity
            .signer
            .to_public_vec();
        let hex: String = bob_key.iter().map(|b| format!("{b:02x}")).collect();
        remove::remove(&client(), &url, &alice, gid, &hex)
            .await
            .unwrap();
        let rm = state.lock().unwrap().commit_bytes.last().unwrap().clone();
        let leaked = |s: &Session| {
            let local = LocalIdentity::load(&s.store).unwrap();
            let dump = mls_group::export_provider_state(&local.provider, 0).unwrap();
            // The export writes keys as JSON byte arrays, so search for the label's decimal bytes.
            let label = b"69,112,111,99,104,75,101,121,80,97,105,114,115";
            dump.windows(label.len()).any(|w| w == label)
        };
        // Control: the marker is visible while Bob is a member.
        assert!(leaked(&bob));
        assert_eq!(apply(&bob, gid, &rm).unwrap(), Outcome::Evicted);
        // Reloaded from the saved store: no leaf private keys of the left epochs remain.
        assert!(!leaked(&bob));
        assert_eq!(members_of(&bob, gid), None);
        assert_eq!(members_of(&alice, gid), Some(2));
    }

    #[tokio::test]
    async fn garbage_is_refused_without_touching_state() {
        let (_tmp, _alice, bob, _url, _state, gid) = alice_and_bob().await;
        assert_eq!(apply(&bob, gid, b"x").unwrap(), Outcome::Refused);
    }
}
