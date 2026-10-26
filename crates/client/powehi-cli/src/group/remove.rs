//! `powehi group remove` and `group members` (prd.md §5.4, §7A; Phase 8.17 slice g2).
//!
//! A real MLS Remove Commit: staged on the own leaf, posted with the server epoch as the CAS
//! token and merged only after the server accepted it. A `grem-<group id>` record (server epoch
//! || Commit) is written BEFORE the Commit leaves and removed on a definite answer; an `Unknown`
//! answer leaves it, which blocks further adds and removes until a later slice resolves it.
//! The target is the member's full signature key (hex, as `group members` and the web show it),
//! resolved to a leaf of THIS group's roster at stage time: a leaf index alone is never trusted
//! because an Add fills the leftmost blank leaf, so an index can name another person later
//! (RFC 9420 §7.7, §12.1.1). The server DELETE of the member is not called yet (no authenticated
//! device-to-leaf mapping), so the removed device still receives fan-out until a later slice.

use powehi_crypto_core::mls_group;
use reqwest::Client;
use url::Url;
use uuid::Uuid;

use super::{prepare_add, GroupError};
use crate::auth::Session;
use crate::invite::{self, CommitOutcome};

const PENDING_PREFIX: &str = "grem-";

pub(super) fn pending_name(group_id: Uuid) -> String {
    format!("{PENDING_PREFIX}{}", group_id.hyphenated())
}

/// One roster line: MLS leaf index (informational) and the full signature key in hex.
#[derive(Debug, PartialEq, Eq)]
pub struct Member {
    pub leaf: u32,
    pub key_hex: String,
    pub is_self: bool,
}

fn to_hex(key: &[u8]) -> String {
    key.iter().map(|b| format!("{b:02x}")).collect()
}

/// Longest signature key hex accepted (Ed25519/P-256 keys are far shorter).
const MAX_KEY_HEX: usize = 256;

/// The roster of `group_id` from the local MLS state (no network).
pub fn members(session: &Session, group_id: Uuid) -> Result<Vec<Member>, GroupError> {
    use crate::conversation::{self, Kind};
    use crate::identity::LocalIdentity;
    let conv = conversation::load(&session.store, &group_id)?.ok_or(GroupError::NoSuchGroup)?;
    if conv.kind() != Kind::Group {
        return Err(GroupError::NotAGroup);
    }
    let local = LocalIdentity::load(&session.store)?;
    let group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .filter(|g| g.is_active())
        .ok_or(GroupError::NotMember)?;
    // Authenticated kind, not the local label, decides (crypto-reviewer 8.17c).
    if mls_group::group_kind(&group)? != mls_group::GroupKind::Group {
        return Err(GroupError::NotAGroup);
    }
    let own = local.identity.signer.to_public_vec();
    let out: Vec<Member> = group
        .members()
        .take(powehi_crypto_core::safety::GROUP_MAX_MEMBERS)
        .map(|m| Member {
            leaf: m.index.u32(),
            key_hex: to_hex(&m.signature_key),
            is_self: m.signature_key == own,
        })
        .collect();
    assert!(out.iter().filter(|m| m.is_self).count() <= 1);
    Ok(out)
}

/// Removes the member whose signature key is `key_hex` and returns the new MLS epoch.
///
/// Order mirrors `group add`: local and epoch checks, then the staged state and the `grem-`
/// record are saved BEFORE the Commit leaves; `Accepted` merges and saves; `Rejected` aborts
/// and saves; `Unknown` changes nothing and keeps the record.
pub async fn remove(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    key_hex: &str,
) -> Result<u64, GroupError> {
    let key_hex = key_hex.to_ascii_lowercase();
    if key_hex.is_empty() || key_hex.len() > MAX_KEY_HEX {
        return Err(GroupError::NoSuchMember);
    }
    let super::AddPrep {
        mut local,
        mut group,
        server_epoch,
    } = prepare_add(client, server, session, group_id, false).await?;
    let own = local.identity.signer.to_public_vec();
    // Resolve the key to a leaf of THIS epoch's roster; exactly one match or refuse.
    let hits: Vec<_> = group
        .members()
        .filter(|m| to_hex(&m.signature_key) == key_hex)
        .take(2)
        .collect();
    let [target] = hits.as_slice() else {
        return Err(GroupError::NoSuchMember);
    };
    if target.signature_key == own {
        return Err(GroupError::RemoveSelf);
    }
    let (leaf, target_key) = (target.index.u32(), target.signature_key.clone());
    let count_before = group.members().count();
    let (commit, prior) =
        mls_group::stage_group_remove(&mut group, &local.identity.signer, leaf, &local.provider)
            .map_err(|_| GroupError::Mls)?;
    assert_eq!(prior, server_epoch, "checked against the server epoch");
    let name = pending_name(group_id);
    let mut record = server_epoch.to_be_bytes().to_vec();
    record.extend_from_slice(&commit);
    session.store.put(&name, &record)?;
    local.save(&session.store)?;
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
    match outcome {
        CommitOutcome::Accepted => {}
        CommitOutcome::Rejected => {
            mls_group::abort_group_remove(&mut group, &local.provider)
                .map_err(|_| GroupError::Mls)?;
            local.save(&session.store)?;
            session.store.remove(&name)?;
            return Err(GroupError::Rejected);
        }
        CommitOutcome::Unknown => return Err(GroupError::Unknown),
    }
    mls_group::confirm_group_remove(&mut group, &local.provider).map_err(|_| GroupError::Mls)?;
    local.save(&session.store)?;
    session.store.remove(&name)?;
    let epoch = group.epoch().as_u64();
    assert_eq!(epoch, prior + 1, "an accepted remove moves one epoch");
    assert_eq!(group.members().count() + 1, count_before);
    assert!(group.members().all(|m| m.signature_key != target_key));
    Ok(epoch)
}

pub fn write_removed(
    group_id: Uuid,
    key_hex: &str,
    epoch: u64,
    json: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    assert!(!group_id.is_nil());
    if json {
        let v = serde_json::json!({
            "conversation": group_id, "epoch": epoch, "removed": key_hex, "server_notified": false
        });
        return writeln!(out, "{v}");
    }
    writeln!(
        out,
        "removed member {key_hex} from conversation {group_id} (epoch {epoch}); the server is \
         not told yet, so that device may still receive encrypted traffic it cannot read"
    )
}

pub fn write_members(
    list: &[Member],
    json: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    if json {
        let v: Vec<_> = list
            .iter()
            .map(|m| serde_json::json!({"leaf": m.leaf, "key": m.key_hex, "self": m.is_self}))
            .collect();
        return writeln!(out, "{}", serde_json::Value::Array(v));
    }
    for m in list {
        let tag = if m.is_self { " (you)" } else { "" };
        writeln!(out, "{}\t{}{tag}", m.leaf, m.key_hex)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
