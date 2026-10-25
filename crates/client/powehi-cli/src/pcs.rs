//! Post-compromise-security rotation policy (prd.md §5, Phase 8 item 8.15): when `send`/`chat`
//! must first rotate this device's leaf key with a self-Update Commit.
//!
//! Pure decisions only; the staging, the server call and the merge live elsewhere. An idle
//! conversation never rotates (there is nothing new to protect), so age counts only once the
//! device has sent under the current epoch secrets.

use powehi_crypto_core::mls_group;
use reqwest::Client;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Conversation, ConversationError};
use crate::identity::{IdentityError, LocalIdentity};
use crate::invite::{self, CommitOutcome, InviteError};
use crate::store::StoreError;

/// Rotate after this many Application messages sent under one leaf key.
pub const MAX_MESSAGES_PER_UPDATE: u32 = 50;
/// Rotate when the leaf key is this old (7 days) and at least one message is about to go out.
pub const MAX_UPDATE_AGE_SECS: u64 = 7 * 24 * 60 * 60;

/// True when a self-Update Commit should precede the next Application message at `now`.
///
/// `last_update_at` unknown (`None`) means no message was sent yet: not due. A clock that went
/// backwards (`now` before the recorded time) is not due either; the counter still applies.
pub fn update_due(conv: &Conversation, now: u64) -> bool {
    let count = conv.sent_since_update();
    if count >= MAX_MESSAGES_PER_UPDATE {
        return true;
    }
    match conv.last_update_at() {
        Some(at) if count > 0 => now.saturating_sub(at) >= MAX_UPDATE_AGE_SECS,
        _ => false,
    }
}

#[derive(Debug, Error)]
pub enum RotateError {
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("{0}")]
    Conversation(#[from] ConversationError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("no such conversation")]
    NoSuchConversation,
    #[error("the conversation's group state is unusable; it cannot rotate")]
    GroupUnusable,
    #[error("MLS operation failed")]
    Mls,
}

impl From<mls_group::MlsError> for RotateError {
    fn from(_: mls_group::MlsError) -> Self {
        RotateError::Mls
    }
}

/// How a rotation attempt ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Rotation {
    /// The server accepted the Commit; it is merged and the policy counters are reset.
    Rotated,
    /// The server definitely refused it; the staged Commit was aborted and nothing changed.
    Rejected,
    /// Not attempted: this device has not applied every Commit the server accepted (local epoch
    /// is not the server's accepted-Commit count plus one, the pair invariant). Staging now
    /// would fork the pair, so nothing was staged; drain the inbox and retry.
    OutOfSync,
    /// The outcome is unknown, or a step after the post failed. A [`PENDING_PREFIX`] record holds
    /// the staged Commit's bytes and the epoch it was posted at; neither merged nor aborted. No
    /// Application message may be sent in this epoch until it is resolved (next slice).
    Unresolved,
}

/// Profile-store record `pcs-<group id>`: `server_epoch` (8 bytes, big endian) then the Commit
/// wire bytes (no version byte; check `len >= 8` before parsing). Written BEFORE the staged
/// state is saved and the bytes leave the device; removed once merged or aborted.
///
/// A record with no staged Commit is STALE (a crash before the staged save, a crash after the
/// merged save, or a peer Commit that displaced ours): discard it and NEVER post its bytes, or
/// the peer moves an epoch and this device forks.
pub const PENDING_PREFIX: &str = "pcs-";

fn pending_name(group_id: Uuid) -> String {
    format!("{PENDING_PREFIX}{}", group_id.hyphenated())
}

/// Rotates this device's leaf key with a self-Update Commit (prd §5.3A). Order matters
/// (crypto-reviewer, 8.15a/c): the server epoch is read and checked against the local epoch
/// BEFORE staging; the Commit bytes and the staged state are saved BEFORE the bytes leave the
/// device; merge or abort follows only a definite answer, and the new state is saved before the
/// counters are reset. Every failure after the post is [`Rotation::Unresolved`], never an `Err`;
/// an `Err` before it does not prove nothing was persisted (the record is kept, fail closed).
///
/// The caller must hold exclusive access to the profile for the whole call (it reads and later
/// rewrites the provider state around two network calls): wiring slice requirement.
pub async fn rotate(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    now: u64,
) -> Result<Rotation, RotateError> {
    let store = &session.store;
    let name = pending_name(group_id);
    if store.get(&name)?.is_some() {
        return Ok(Rotation::Unresolved);
    }
    conversation::load(store, &group_id)?.ok_or(RotateError::NoSuchConversation)?;
    let mut local = LocalIdentity::load(store)?;
    let mut group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .ok_or(RotateError::GroupUnusable)?;
    let own_key = local.identity.signer.to_public_vec();
    if !mls_group::is_pair_with(&group, &own_key) {
        return Err(RotateError::GroupUnusable);
    }
    let server_epoch = invite::group_epoch(client, server, session, group_id).await?;
    if group.epoch().as_u64() != server_epoch.saturating_add(1) {
        return Ok(Rotation::OutOfSync);
    }
    let signer = &local.identity.signer;
    let (commit, _) =
        mls_group::stage_pair_self_update(&mut group, signer, &own_key, &local.provider)?;
    let mut record = server_epoch.to_be_bytes().to_vec();
    record.extend_from_slice(&commit);
    store.put(&name, &record)?;
    local.save(store)?;
    let outcome = invite::send_commit(
        client,
        server,
        session,
        group_id,
        &commit,
        server_epoch,
        false,
    )
    .await;
    let finished = match outcome {
        CommitOutcome::Accepted => finish_accepted(session, group_id, &mut group, &mut local, now),
        CommitOutcome::Rejected => finish_rejected(session, &name, &mut group, &mut local),
        CommitOutcome::Unknown => Err(()),
    };
    Ok(match (outcome, finished) {
        (CommitOutcome::Accepted, Ok(())) => Rotation::Rotated,
        (CommitOutcome::Rejected, Ok(())) => Rotation::Rejected,
        _ => Rotation::Unresolved,
    })
}

fn finish_accepted(
    session: &Session,
    group_id: Uuid,
    group: &mut mls_group::Group,
    local: &mut LocalIdentity,
    now: u64,
) -> Result<(), ()> {
    let store = &session.store;
    mls_group::confirm_pair_self_update(group, &local.provider).map_err(|_| ())?;
    local.save(store).map_err(|_| ())?;
    store.remove(&pending_name(group_id)).map_err(|_| ())?;
    // The counters are policy only; a failure here costs one extra rotation, not safety.
    if let Ok(Some(mut conv)) = conversation::load(store, &group_id) {
        conv.note_self_update(now);
        let _ = conversation::save(store, &conv);
    }
    Ok(())
}

fn finish_rejected(
    session: &Session,
    name: &str,
    group: &mut mls_group::Group,
    local: &mut LocalIdentity,
) -> Result<(), ()> {
    mls_group::abort_pair_self_update(group, &local.provider).map_err(|_| ())?;
    local.save(&session.store).map_err(|_| ())?;
    session.store.remove(name).map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::Role;
    use uuid::Uuid;

    use crate::inbox;
    use crate::testsrv::{serve, session, Backend};
    use std::sync::{Arc, Mutex};

    fn client() -> Client {
        crate::status::http_client().unwrap()
    }

    async fn pair() -> (
        tempfile::TempDir,
        Session,
        Session,
        Url,
        Uuid,
        Arc<Mutex<Backend>>,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
        let state = Arc::new(Mutex::new(Backend::default()));
        let url = serve(state.clone()).await;
        let (link, _) = invite::create(&client(), &url, &alice).await.unwrap();
        let link = invite::parse_link(&link).unwrap();
        let (gid, _) = invite::redeem(&client(), &url, &bob, &link).await.unwrap();
        inbox::receive(&client(), &url, &alice).await.unwrap();
        (tmp, alice, bob, url, gid, state)
    }

    fn epoch_of(s: &Session, gid: Uuid) -> u64 {
        let local = LocalIdentity::load(&s.store).unwrap();
        mls_group::load_group(gid.as_bytes(), &local.provider)
            .unwrap()
            .unwrap()
            .epoch()
            .as_u64()
    }

    #[tokio::test]
    async fn an_accepted_rotation_merges_resets_counters_and_posts_the_server_epoch() {
        let (_t, alice, _bob, url, gid, state) = pair().await;
        let mut c = conversation::load(&alice.store, &gid).unwrap().unwrap();
        c.note_sent(10);
        conversation::save(&alice.store, &c).unwrap();
        let before = epoch_of(&alice, gid);
        let r = rotate(&client(), &url, &alice, gid, 99).await.unwrap();
        assert_eq!(r, Rotation::Rotated);
        assert_eq!(epoch_of(&alice, gid), before + 1);
        assert_eq!(state.lock().unwrap().commits, vec![0]);
        assert!(alice.store.get(&pending_name(gid)).unwrap().is_none());
        let c = conversation::load(&alice.store, &gid).unwrap().unwrap();
        assert_eq!((c.sent_since_update(), c.last_update_at()), (0, Some(99)));
    }

    #[tokio::test]
    async fn a_rejected_rotation_aborts_and_leaves_the_state_usable() {
        let (_t, alice, bob, url, gid, state) = pair().await;
        state.lock().unwrap().commit_status = 409;
        let before = epoch_of(&alice, gid);
        let r = rotate(&client(), &url, &alice, gid, 99).await.unwrap();
        assert_eq!(r, Rotation::Rejected);
        assert_eq!(epoch_of(&alice, gid), before);
        let c = conversation::load(&alice.store, &gid).unwrap().unwrap();
        assert_eq!(c.last_update_at(), None);
        assert!(alice.store.get(&pending_name(gid)).unwrap().is_none());
        // Nothing is staged any more: the pair still talks and a retry can stage again.
        crate::message::send(&client(), &url, &alice, gid, b"still works")
            .await
            .unwrap();
        inbox::receive(&client(), &url, &bob).await.unwrap();
        state.lock().unwrap().commit_status = 0;
        let r = rotate(&client(), &url, &alice, gid, 100).await.unwrap();
        assert_eq!(r, Rotation::Rotated);
    }

    #[tokio::test]
    async fn an_unknown_answer_neither_merges_nor_aborts() {
        let (_t, alice, _bob, url, gid, state) = pair().await;
        state.lock().unwrap().commit_status = 503;
        let before = epoch_of(&alice, gid);
        let r = rotate(&client(), &url, &alice, gid, 99).await.unwrap();
        assert_eq!(r, Rotation::Unresolved);
        assert_eq!(epoch_of(&alice, gid), before);
        let rec = alice.store.get(&pending_name(gid)).unwrap().unwrap();
        assert_eq!(rec[..8], 0u64.to_be_bytes());
        assert!(rec.len() > 8);
        // A second attempt stops at the record: no request, nothing staged over it.
        let n = state.lock().unwrap().calls.len();
        let again = rotate(&client(), &url, &alice, gid, 100).await.unwrap();
        assert_eq!(again, Rotation::Unresolved);
        assert_eq!(state.lock().unwrap().calls.len(), n);
        assert_eq!(state.lock().unwrap().commits.len(), 1);
    }

    #[tokio::test]
    async fn a_local_epoch_behind_the_server_stages_nothing() {
        let (_t, alice, _bob, url, gid, state) = pair().await;
        state.lock().unwrap().group_epoch = 7;
        let before = epoch_of(&alice, gid);
        let r = rotate(&client(), &url, &alice, gid, 99).await.unwrap();
        assert_eq!(r, Rotation::OutOfSync);
        assert_eq!(epoch_of(&alice, gid), before);
        assert!(state.lock().unwrap().commits.is_empty());
        assert!(alice.store.get(&pending_name(gid)).unwrap().is_none());
        // Nothing was staged: once the counts agree again the rotation goes through.
        state.lock().unwrap().group_epoch = 0;
        assert_eq!(
            rotate(&client(), &url, &alice, gid, 100).await.unwrap(),
            Rotation::Rotated
        );
    }

    #[tokio::test]
    async fn an_unknown_conversation_fails_before_any_request() {
        let (_t, alice, _bob, url, _gid, state) = pair().await;
        let n = state.lock().unwrap().calls.len();
        let r = rotate(&client(), &url, &alice, Uuid::new_v4(), 1).await;
        assert!(matches!(r, Err(RotateError::NoSuchConversation)));
        assert_eq!(state.lock().unwrap().calls.len(), n);
    }

    fn conv() -> Conversation {
        Conversation::new(Uuid::new_v4(), Uuid::new_v4(), Role::Creator, None)
    }

    #[test]
    fn a_fresh_conversation_is_not_due() {
        assert!(!update_due(&conv(), 1_000_000));
    }

    #[test]
    fn the_message_count_triggers_exactly_at_the_limit() {
        let mut c = conv();
        for _ in 0..MAX_MESSAGES_PER_UPDATE - 1 {
            c.note_sent(100);
        }
        assert!(!update_due(&c, 100));
        c.note_sent(100);
        assert!(update_due(&c, 100));
    }

    #[test]
    fn age_triggers_only_after_a_send_and_exactly_at_the_limit() {
        let mut c = conv();
        c.note_sent(1_000);
        assert!(!update_due(&c, 1_000 + MAX_UPDATE_AGE_SECS - 1));
        assert!(update_due(&c, 1_000 + MAX_UPDATE_AGE_SECS));
    }

    #[test]
    fn a_confirmed_update_resets_both_triggers() {
        let mut c = conv();
        for _ in 0..MAX_MESSAGES_PER_UPDATE {
            c.note_sent(10);
        }
        assert!(update_due(&c, 10));
        c.note_self_update(20);
        assert_eq!(c.sent_since_update(), 0);
        assert!(!update_due(&c, 20 + MAX_UPDATE_AGE_SECS));
        c.note_sent(30);
        assert!(!update_due(&c, 30));
    }

    #[test]
    fn a_clock_before_the_record_is_not_due_by_age() {
        let mut c = conv();
        c.note_sent(5_000);
        assert!(!update_due(&c, 1));
    }

    #[test]
    fn the_counter_saturates_instead_of_wrapping() {
        let mut c = conv();
        c.set_sent_for_test(u32::MAX);
        c.note_sent(1);
        assert_eq!(c.sent_since_update(), u32::MAX);
        assert!(update_due(&c, 1));
    }
}
