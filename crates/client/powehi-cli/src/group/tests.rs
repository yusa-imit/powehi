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
