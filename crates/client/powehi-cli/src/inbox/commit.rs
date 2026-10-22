//! Applying a peer's Commit to a 1:1 conversation (8.14, ADR-0005 one-shot merge).
//!
//! The policy lives in `mls_group::apply_pair_commit`: only a Commit from the peer that keeps
//! the group a pair and leaves the peer's signature key and credential unchanged is merged.
//! The peer signature key is pinned on the conversation record at the first applied Commit, so
//! the §5.6 safety number (from the two signature keys) cannot change through the Commit path.
//! Order: conversation record, then MLS state; a crash between re-applies the same Commit.

use powehi_crypto_core::mls_group;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation;
use crate::identity::LocalIdentity;
use crate::invite::InviteError;

pub(super) enum Outcome {
    /// Merged and persisted: the conversation moved to the next epoch.
    Applied,
    /// A later epoch than ours: an earlier Commit is missing. Not a failure.
    Ahead,
    /// Replay, garbage or a past epoch (benign after a crash before the ack).
    Refused,
    /// An authenticated-looking Commit the pair policy refuses (adds/removes someone, changes
    /// keys, or anything but a self-Update). Later peer traffic will not decrypt: reported.
    Forked,
    /// No such conversation, or not from its peer.
    Unknown,
}

pub(super) fn apply(
    session: &Session,
    group_id: Uuid,
    sender: Uuid,
    commit: &[u8],
) -> Result<Outcome, InviteError> {
    let store = &session.store;
    let Some(mut conv) = conversation::load(store, &group_id)? else {
        return Ok(Outcome::Unknown);
    };
    if conv.peer_device_id != sender {
        return Ok(Outcome::Unknown);
    }
    // A fresh provider per envelope: a refused Commit must leave no half-advanced state.
    let mut local = LocalIdentity::load(store)?;
    let Some(mut group) = mls_group::load_group(group_id.as_bytes(), &local.provider)? else {
        return Ok(Outcome::Refused);
    };
    let own_key = local.identity.signer.to_public_vec();
    let applied = match mls_group::apply_pair_commit(
        &mut group,
        commit,
        &local.provider,
        &own_key,
        conv.peer_signature_key(),
        conv.peer_credential(),
    ) {
        Ok(a) => a,
        Err(mls_group::MlsError::EpochAhead) => return Ok(Outcome::Ahead),
        Err(mls_group::MlsError::PairCommitRefused) => return Ok(Outcome::Forked),
        Err(_) => return Ok(Outcome::Refused),
    };
    if conv.peer_signature_key().is_none() {
        conv.pin_peer_signature_key(applied.peer_signature_key)?;
        conversation::save(store, &conv)?;
    }
    local.save(store)?;
    Ok(Outcome::Applied)
}
