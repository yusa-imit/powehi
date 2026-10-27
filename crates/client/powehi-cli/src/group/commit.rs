//! Applying another member's Commit to a kind-Group conversation (Phase 8.17 slice l).
//!
//! The policy lives in `mls_group::apply_group_commit` (member committer, inline Add/Remove
//! only, update-path leaf keeps key and credential, kind unchanged). Unlike the pair path the
//! sender is not "the peer": it must be a member, which the allowlist checks by MLS leaf, never
//! by the Delivery Service's sender label. A fresh provider per envelope, so a refused Commit
//! leaves no half-advanced state; a Commit that removes this device deletes the group state.
//! Not yet called from the inbox (group receive wiring is a later slice).

use powehi_crypto_core::mls_group::{self, MlsError};
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Kind};
use crate::identity::LocalIdentity;
use crate::invite::InviteError;

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Merged and persisted; the group moved to the next epoch.
    Applied { added: usize, removed: usize },
    /// Merged, and it removed this device: the MLS state is gone and cannot read more.
    Evicted,
    /// A later epoch than ours: an earlier Commit is missing.
    Ahead,
    /// Replay, garbage or a past epoch.
    Refused,
    /// Outside the group allowlist (kind flip, key swap, PSK, ...): later traffic won't decrypt.
    Forked,
    /// This device has its own unresolved Commit (staged or recorded): merging a peer's Commit
    /// would drop it silently, so nothing is applied until it resolves.
    Unresolved,
    /// No such group conversation, or the record is not a group.
    Unknown,
}

pub fn apply(session: &Session, group_id: Uuid, commit: &[u8]) -> Result<Outcome, InviteError> {
    let store = &session.store;
    let Some(conv) = conversation::load(store, &group_id)? else {
        return Ok(Outcome::Unknown);
    };
    if conv.kind() != Kind::Group {
        return Ok(Outcome::Unknown);
    }
    if store.get(&super::pending_name(group_id))?.is_some()
        || store.get(&super::remove::pending_name(group_id))?.is_some()
    {
        return Ok(Outcome::Unresolved);
    }
    let mut local = LocalIdentity::load(store)?;
    let Some(mut group) = mls_group::load_group(group_id.as_bytes(), &local.provider)? else {
        return Ok(Outcome::Refused);
    };
    if !conv.agrees_with(&group) {
        return Ok(Outcome::Unknown);
    }
    if group.pending_commit().is_some() {
        return Ok(Outcome::Unresolved);
    }
    if !group.is_active() {
        return Ok(Outcome::Refused);
    }
    let applied = match mls_group::apply_group_commit(&mut group, commit, &local.provider) {
        Ok(a) => a,
        Err(MlsError::EpochAhead) => return Ok(Outcome::Ahead),
        Err(MlsError::GroupCommitRefused) => return Ok(Outcome::Forked),
        Err(MlsError::Persistence) => return Err(MlsError::Persistence.into()),
        Err(_) => return Ok(Outcome::Refused),
    };
    if !group.is_active() {
        // Evicted: drop the state so no secret of the epochs we left is kept. The record stays
        // so the conversation is visible; sends and receives refuse a missing group.
        mls_group::delete_inactive_group(&mut group, &local.provider)?;
        local.save(store)?;
        return Ok(Outcome::Evicted);
    }
    local.save(store)?;
    Ok(Outcome::Applied {
        added: applied.added,
        removed: applied.removed,
    })
}
