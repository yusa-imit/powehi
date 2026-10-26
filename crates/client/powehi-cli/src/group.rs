//! `powehi group create` (prd.md §7A, §5.3B; Phase 8.17).
//!
//! Creates an MLS group whose authenticated GroupContext declares kind `Group` and registers it
//! with the Delivery Service. The creator is the only member until `group add` lands, so the
//! record's `peer_device_id` is the creator's own device id (there is no peer yet) and the
//! pair-only paths (`send`, PCS, Commit handling) refuse it via `is_pair_with`.

use powehi_crypto_core::mls_group::{self, GroupKind};
use reqwest::Client;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Conversation, ConversationError, Role};
use crate::identity::LocalIdentity;
use crate::invite::{self, InviteError};

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

#[cfg(test)]
mod tests;
