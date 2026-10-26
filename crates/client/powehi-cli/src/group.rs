//! `powehi group create` (prd.md §7A, §5.3B; Phase 8.17).
//!
//! Creates an MLS group whose authenticated GroupContext declares kind `Group` and registers it
//! with the Delivery Service. The creator is the only member until `group add` lands, so the
//! record's `peer_device_id` is the creator's own device id (there is no peer yet) and the
//! pair-only paths (`send`, PCS, Commit handling) refuse it by `Kind` (explicit guards).
//!
//! `powehi group add <group-id>` adds the owner of an `invite create` link to a group: the new
//! member's pinned KeyPackage is staged as an Add Commit, posted with the server epoch as the
//! CAS token, and only after the server accepted it merged, registered and Welcomed. An
//! unresolved Commit (`Unknown` answer) is NOT auto-resolved in this slice: a `gadd-<group id>`
//! record blocks further adds until a later slice resolves it by finding the stored Commit.

use powehi_crypto_core::mls_group::{self, GroupKind, MlsError};
use powehi_crypto_core::safety::GROUP_MAX_MEMBERS;
use reqwest::Client;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Conversation, ConversationError, Kind, Role};
use crate::identity::{IdentityError, LocalIdentity};
use crate::invite::{self, CommitOutcome, InviteError, InviteLink};
use crate::store::StoreError;

pub mod remove;

/// Why `group add` did not (fully) succeed. Messages carry no secrets.
#[derive(Debug, Error)]
pub enum GroupError {
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("{0}")]
    Conversation(#[from] ConversationError),
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("no such group conversation")]
    NoSuchGroup,
    #[error("that conversation is a pair, not a group")]
    NotAGroup,
    #[error("you are not a member of this group (its MLS state is missing or inactive)")]
    NotMember,
    #[error("the group already has the maximum of {GROUP_MAX_MEMBERS} members")]
    TooMany,
    #[error(
        "your copy of the group is at a different epoch than the server's; nothing was changed"
    )]
    EpochMismatch,
    #[error("this invite belongs to this device; give the link of the person to add")]
    SelfInvite,
    #[error("an earlier add or remove in this group is unresolved; no further change until it is resolved")]
    Unresolved,
    #[error("the server refused the change; nothing was changed (check the epoch and retry)")]
    Rejected,
    #[error("the server's answer is unknown; the change (add or remove) may have taken effect")]
    Unknown,
    #[error(
        "the member was added but the Welcome was not delivered; it is saved, retry with \
         `group add <GROUP_ID> --resume`"
    )]
    WelcomeNotDelivered,
    #[error("a Welcome from an earlier add is saved; run `group add <GROUP_ID> --resume`")]
    WelcomePending,
    #[error(
        "the Welcome would exceed the server's {MAX_WELCOME_BYTES}-byte limit; nothing was added"
    )]
    WelcomeTooLarge,
    #[error("the group is at an unexpected epoch for the saved add; nothing was delivered")]
    ResumeEpoch,
    #[error("no add is waiting for its Welcome in this group")]
    NothingToResume,
    #[error("no single member with that signature key in this group (see `group members`)")]
    NoSuchMember,
    #[error("you cannot remove yourself from a group this way")]
    RemoveSelf,
    #[error("the add was refused by MLS (the key package is invalid or already a member)")]
    AddRefused,
    #[error("MLS operation failed")]
    Mls,
}

impl From<MlsError> for GroupError {
    fn from(e: MlsError) -> Self {
        match e {
            MlsError::Membership => GroupError::AddRefused,
            _ => GroupError::Mls,
        }
    }
}

/// Profile-store record `gadd-<group id>` (encrypted profile store), written BEFORE the Commit
/// leaves the device: `server_epoch` (8 bytes BE) || `commit_len` (4 bytes BE) || Commit wire
/// bytes || `state` (1: 0 = posted, answer unknown; 1 = Commit accepted, Welcome undelivered)
/// || peer device id (16) || member epoch (8 BE) || Welcome bytes. The first two fields let a
/// later resolver byte-compare the stored epoch + 1 envelope with the Commit. Removed only after
/// the Welcome was delivered or the Commit was definitely rejected.
const PENDING_PREFIX: &str = "gadd-";
/// Largest Welcome the Delivery Service accepts (`MAX_WELCOME_BYTES`, powehi-grpc server.rs).
const MAX_WELCOME_BYTES: usize = 256 * 1024;
const STATE_POSTED: u8 = 0;
const STATE_ACCEPTED: u8 = 1;

fn pending_name(group_id: Uuid) -> String {
    format!("{PENDING_PREFIX}{}", group_id.hyphenated())
}

struct PendingAdd {
    server_epoch: u64,
    commit: Vec<u8>,
    state: u8,
    peer: Uuid,
    member_epoch: u64,
    welcome: Vec<u8>,
}

impl PendingAdd {
    fn posted(staged: &mls_group::StagedGroupAdd, server_epoch: u64, peer: Uuid) -> Self {
        Self {
            server_epoch,
            commit: staged.commit.clone(),
            state: STATE_POSTED,
            peer,
            member_epoch: staged.prior_epoch + 1,
            welcome: staged.welcome.clone(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = self.server_epoch.to_be_bytes().to_vec();
        out.extend_from_slice(&(self.commit.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.commit);
        out.push(self.state);
        out.extend_from_slice(self.peer.as_bytes());
        out.extend_from_slice(&self.member_epoch.to_be_bytes());
        out.extend_from_slice(&self.welcome);
        out
    }

    /// `None` for anything malformed; callers treat that as unresolved (fail closed).
    fn decode(raw: &[u8]) -> Option<Self> {
        let server_epoch = u64::from_be_bytes(raw.get(..8)?.try_into().ok()?);
        let n = u32::from_be_bytes(raw.get(8..12)?.try_into().ok()?) as usize;
        let commit_end = 12usize.checked_add(n)?;
        let commit = raw.get(12..commit_end)?.to_vec();
        let state = *raw.get(commit_end)?;
        let peer_end = commit_end.checked_add(17)?;
        let peer = Uuid::from_slice(raw.get(commit_end + 1..peer_end)?).ok()?;
        let epoch_end = peer_end.checked_add(8)?;
        let member_epoch = u64::from_be_bytes(raw.get(peer_end..epoch_end)?.try_into().ok()?);
        let welcome = raw.get(epoch_end..)?.to_vec();
        let valid = state <= STATE_ACCEPTED
            && !commit.is_empty()
            && !welcome.is_empty()
            && server_epoch.checked_add(1) == Some(member_epoch);
        valid.then_some(Self {
            server_epoch,
            commit,
            state,
            peer,
            member_epoch,
            welcome,
        })
    }
}

fn load_pending(
    store: &crate::store::ProfileStore,
    gid: Uuid,
) -> Result<Option<PendingAdd>, GroupError> {
    match store.get(&pending_name(gid))? {
        None => Ok(None),
        Some(raw) => PendingAdd::decode(&raw)
            .map(Some)
            .ok_or(GroupError::Unresolved),
    }
}

/// Creates a group of kind `Group` and returns its conversation id.
///
/// Order mirrors `invite::redeem`: MLS state is saved before the server hears of the group, and
/// the conversation record only after registration succeeded, so a failed call leaves at most an
/// unreferenced local group and never a record for a group the server does not know.
pub async fn create(client: &Client, server: &Url, session: &Session) -> Result<Uuid, InviteError> {
    // Check the cap first: a retry at the limit must not strand an orphan group each time.
    if conversation::list(&session.store)?.len() >= conversation::MAX_CONVERSATIONS {
        return Err(ConversationError::TooMany.into());
    }
    let mut local = LocalIdentity::load(&session.store)?;
    let group =
        mls_group::create_group_of_kind(&local.identity, &local.provider, GroupKind::Group)?;
    let group_id = Uuid::from_slice(group.group_id().as_slice()).map_err(|_| InviteError::Mls)?;
    assert_eq!(group.epoch().as_u64(), 0, "a fresh group starts at epoch 0");
    assert_eq!(mls_group::group_kind(&group)?, GroupKind::Group);
    local.save(&session.store)?;
    invite::register_group(client, server, session, group_id).await?;
    let conv = Conversation::new(group_id, session.device_id, Role::Creator, None).into_group();
    conversation::save(&session.store, &conv)?;
    Ok(group_id)
}

/// Checked local state for an add: the group, our identity and the server epoch.
pub(crate) struct AddPrep {
    pub(crate) local: LocalIdentity,
    pub(crate) group: mls_group::Group,
    pub(crate) server_epoch: u64,
}

pub(crate) async fn prepare_add(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    check_cap: bool,
) -> Result<AddPrep, GroupError> {
    let store = &session.store;
    let conv = conversation::load(store, &group_id)?.ok_or(GroupError::NoSuchGroup)?;
    if conv.kind() != Kind::Group {
        return Err(GroupError::NotAGroup);
    }
    match load_pending(store, group_id)? {
        None => {}
        Some(p) if p.state == STATE_ACCEPTED => return Err(GroupError::WelcomePending),
        Some(_) => return Err(GroupError::Unresolved),
    }
    if store.get(&remove::pending_name(group_id))?.is_some() {
        return Err(GroupError::Unresolved);
    }
    let local = LocalIdentity::load(store)?;
    let group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .filter(|g| g.is_active())
        .ok_or(GroupError::NotMember)?;
    // Authenticated kind, not the local record's label, decides (crypto-reviewer 8.17c).
    if mls_group::group_kind(&group)? != GroupKind::Group {
        return Err(GroupError::NotAGroup);
    }
    if check_cap && group.members().take(GROUP_MAX_MEMBERS).count() >= GROUP_MAX_MEMBERS {
        return Err(GroupError::TooMany);
    }
    let server_epoch = invite::group_epoch(client, server, session, group_id).await?;
    // Groups: MLS epoch 0 is server epoch 0 (pairs are offset by one). Fail closed otherwise.
    if group.epoch().as_u64() != server_epoch {
        return Err(GroupError::EpochMismatch);
    }
    Ok(AddPrep {
        local,
        group,
        server_epoch,
    })
}

/// Adds the owner of `link` to the group `group_id` and returns the new MLS epoch.
///
/// Order (crypto-reviewer): local checks and the epoch check before the invite code is spent;
/// the pinned KeyPackage is hash-checked before staging; the staged state and the pending record
/// are saved BEFORE the Commit leaves; on `Accepted` the merge is saved first (the server's answer
/// is definite, so the local epoch must follow even if delivery then fails), then the member is
/// registered and the Welcome sent; on `Rejected` the stage is aborted and saved; on `Unknown`
/// nothing is merged or aborted and the pending record stays.
pub async fn add(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    link: &InviteLink,
) -> Result<u64, GroupError> {
    let AddPrep {
        mut local,
        mut group,
        server_epoch,
    } = prepare_add(client, server, session, group_id, true).await?;
    let pinned = invite::fetch_pinned(client, server, session, link).await?;
    if pinned.device_id == session.device_id {
        return Err(GroupError::SelfInvite);
    }
    let staged = mls_group::stage_group_add(
        &mut group,
        &local.identity.signer,
        &pinned.key_package,
        &local.provider,
    )?;
    if check_welcome_size(staged.welcome.len()).is_err() {
        mls_group::abort_group_add(&mut group, &local.provider)?;
        return Err(GroupError::WelcomeTooLarge);
    }
    debug_assert_eq!(staged.prior_epoch, server_epoch);
    let pending = pending_name(group_id);
    let mut record = PendingAdd::posted(&staged, server_epoch, pinned.device_id);
    session.store.put(&pending, &record.encode())?;
    local.save(&session.store)?;
    let outcome = invite::send_commit(
        client,
        server,
        session,
        group_id,
        &staged.commit,
        server_epoch,
        false,
    )
    .await;
    match outcome {
        CommitOutcome::Accepted => {}
        CommitOutcome::Rejected => {
            mls_group::abort_group_add(&mut group, &local.provider)?;
            local.save(&session.store)?;
            session.store.remove(&pending)?;
            return Err(GroupError::Rejected);
        }
        CommitOutcome::Unknown => return Err(GroupError::Unknown),
    }
    // Definite answer: mark the record as Welcome-owed, then merge. The record keeps the Welcome
    // until it is delivered.
    record.state = STATE_ACCEPTED;
    session.store.put(&pending, &record.encode())?;
    mls_group::confirm_group_add(&mut group, &local.provider)?;
    local.save(&session.store)?;
    let epoch = group.epoch().as_u64();
    assert_eq!(
        epoch,
        staged.prior_epoch + 1,
        "an accepted add moves one epoch"
    );
    deliver_welcome(client, server, session, group_id, &record).await?;
    Ok(epoch)
}

/// Registers the new member and sends the saved Welcome; removes the record on success only.
async fn deliver_welcome(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    rec: &PendingAdd,
) -> Result<(), GroupError> {
    debug_assert_eq!(rec.state, STATE_ACCEPTED);
    let sent = async {
        let (peer, ep) = (rec.peer, rec.member_epoch);
        invite::post_member(client, server, session, group_id, peer, ep).await?;
        invite::send_welcome(client, server, session, group_id, peer, &rec.welcome).await
    };
    sent.await.map_err(|_| GroupError::WelcomeNotDelivered)?;
    session.store.remove(&pending_name(group_id))?;
    Ok(())
}

fn check_welcome_size(len: usize) -> Result<(), GroupError> {
    if len == 0 || len > MAX_WELCOME_BYTES {
        return Err(GroupError::WelcomeTooLarge);
    }
    Ok(())
}

/// Brings the local group to the accepted add's epoch before the Welcome goes out (a crash may
/// have left the Commit staged): staged at `member_epoch - 1` merges and saves; already at
/// `member_epoch` needs nothing; anything else fails closed, never delivering.
fn settle_local_epoch(
    session: &Session,
    group_id: Uuid,
    rec: &PendingAdd,
) -> Result<(), GroupError> {
    let mut local = LocalIdentity::load(&session.store)?;
    let mut group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .filter(|g| g.is_active())
        .ok_or(GroupError::NotMember)?;
    let epoch = group.epoch().as_u64();
    if group.pending_commit().is_some() && epoch.checked_add(1) == Some(rec.member_epoch) {
        mls_group::confirm_group_add(&mut group, &local.provider)?;
        local.save(&session.store)?;
        return Ok(());
    }
    if group.pending_commit().is_none() && epoch == rec.member_epoch {
        return Ok(());
    }
    Err(GroupError::ResumeEpoch)
}

/// Retries the Welcome of an accepted add (`group add --resume`) and returns the member epoch.
/// Refused with [`GroupError::Unresolved`] while the Commit's fate is unknown.
pub async fn resume(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
) -> Result<u64, GroupError> {
    let conv = conversation::load(&session.store, &group_id)?.ok_or(GroupError::NoSuchGroup)?;
    if conv.kind() != Kind::Group {
        return Err(GroupError::NotAGroup);
    }
    let rec = load_pending(&session.store, group_id)?.ok_or(GroupError::NothingToResume)?;
    if rec.state != STATE_ACCEPTED {
        return Err(GroupError::Unresolved);
    }
    settle_local_epoch(session, group_id, &rec)?;
    deliver_welcome(client, server, session, group_id, &rec).await?;
    Ok(rec.member_epoch)
}

/// Writes the add outcome. The new member cannot join yet (no group-join slice): say so.
pub fn write_added(
    group_id: Uuid,
    epoch: u64,
    json: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    assert!(!group_id.is_nil());
    if json {
        let v = serde_json::json!({ "conversation": group_id, "epoch": epoch, "joinable": false });
        return writeln!(out, "{v}");
    }
    writeln!(
        out,
        "added to conversation {group_id} (epoch {epoch}); the new member cannot join until \
         group join is implemented"
    )
}

#[cfg(test)]
mod tests;
