//! `powehi verify <conversation>`: the Safety Number of a 1:1 conversation (prd.md §5.6).
//!
//! The number is derived from the two MLS signature public keys in the local group state, so
//! the server cannot influence it (the command still logs in to open the profile store).
//! Comparing it with the peer over another channel is what detects a man in the middle. A
//! confirmation must quote the number the user compared (`--confirm <number>`); it is stored
//! as `verified-<group>`. If the number later differs (the peer's identity key changed) or the
//! record fails authentication, the state is reported as changed, never as verified, and only
//! a new `--confirm` quoting the current number replaces it.

use powehi_crypto_core::{mls_group, safety};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::conversation::{self, ConversationError};
use crate::identity::{IdentityError, LocalIdentity};
use crate::store::{ProfileStore, StoreError};

const PREFIX: &str = "verified-";
const VERSION: u8 = 1;
const KEY_LEN: usize = 32;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("{0}")]
    Conversation(#[from] ConversationError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("no such conversation")]
    NoSuchConversation,
    #[error("the conversation's group state is unusable; there is nothing to verify")]
    GroupUnusable,
    #[error("the number you gave does not match this conversation's current safety number")]
    NumberMismatch,
    #[error("MLS operation failed")]
    Mls,
}

impl From<mls_group::MlsError> for VerifyError {
    fn from(_: mls_group::MlsError) -> Self {
        VerifyError::Mls
    }
}

/// Where a conversation stands against its stored comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Never confirmed.
    Unverified,
    /// The current number equals the confirmed one.
    Verified,
    /// A number was confirmed before and the identity keys no longer produce it.
    Changed,
}

#[derive(Serialize, Deserialize)]
struct Record {
    version: u8,
    number: String,
}

fn record_name(group_id: &Uuid) -> String {
    format!("{PREFIX}{}", group_id.hyphenated())
}

/// The Safety Number of the pair in `group`, from its two signature keys. `own_key` must be
/// one of them and the group must still include this device.
pub fn number_of(group: &mls_group::Group, own_key: &[u8]) -> Result<String, VerifyError> {
    if !mls_group::group_is_active(group) {
        return Err(VerifyError::GroupUnusable);
    }
    let keys: Vec<Vec<u8>> = group.members().take(3).map(|m| m.signature_key).collect();
    if keys.len() != 2
        || keys.iter().any(|k| k.len() != KEY_LEN)
        || !keys.iter().any(|k| k == own_key)
    {
        return Err(VerifyError::GroupUnusable);
    }
    safety::pairwise(&keys[0], &keys[1]).map_err(|_| VerifyError::GroupUnusable)
}

/// Computes the number for a stored conversation.
pub fn number(store: &ProfileStore, group_id: Uuid) -> Result<String, VerifyError> {
    conversation::load(store, &group_id)?.ok_or(VerifyError::NoSuchConversation)?;
    let local = LocalIdentity::load(store)?;
    let group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .ok_or(VerifyError::GroupUnusable)?;
    number_of(&group, &local.identity.signer.to_public_vec())
}

/// Compares `current` with the stored confirmation. A record that fails authentication or
/// parsing counts as changed (other store errors are returned; `changed_since_verified` alerts on them): it must never be shown as verified.
pub fn state(store: &ProfileStore, group_id: Uuid, current: &str) -> Result<State, VerifyError> {
    let raw = match store.get(&record_name(&group_id)) {
        Ok(Some(raw)) => raw,
        Ok(None) => return Ok(State::Unverified),
        Err(StoreError::Authentication) => return Ok(State::Changed),
        Err(e) => return Err(e.into()),
    };
    Ok(match serde_json::from_slice::<Record>(&raw) {
        Ok(r) if r.version == VERSION && r.number == current => State::Verified,
        _ => State::Changed,
    })
}

/// Stores `current` as confirmed, but only if `typed` (what the user compared, whitespace
/// ignored) is exactly that number.
pub fn confirm(
    store: &ProfileStore,
    group_id: Uuid,
    current: &str,
    typed: &str,
) -> Result<(), VerifyError> {
    let squash = |s: &str| s.split_whitespace().collect::<String>();
    if squash(typed) != squash(current) {
        return Err(VerifyError::NumberMismatch);
    }
    store_record(store, group_id, current)
}

fn store_record(store: &ProfileStore, group_id: Uuid, number: &str) -> Result<(), VerifyError> {
    debug_assert_eq!(number.len(), 83);
    let rec = Record {
        version: VERSION,
        number: number.to_owned(),
    };
    let bytes = serde_json::to_vec(&rec).map_err(|_| VerifyError::Mls)?;
    store.put(&record_name(&group_id), &bytes)?;
    Ok(())
}

/// The §5.6 alert for commands that touch a conversation (`read`, `send`, `chat`): `true` when
/// a confirmation record exists (or cannot be read) and the current number cannot be shown to
/// match it. It warns, it never blocks. Only an absent record, or a record matching the
/// recomputed number, is silent: any store error or unrecomputable number alerts.
pub fn changed_since_verified(store: &ProfileStore, group_id: Uuid) -> bool {
    match store.get(&record_name(&group_id)) {
        Ok(None) => false,
        Err(_) => true,
        Ok(Some(_)) => match number(store, group_id) {
            Ok(current) => !matches!(state(store, group_id, &current), Ok(State::Verified)),
            Err(_) => true,
        },
    }
}

/// The one-line warning shown when [`changed_since_verified`] is true.
pub const CHANGED_WARNING: &str = "warning: the safety number CHANGED since you verified this \
conversation; run `powehi verify <conversation>` and compare it with your peer before trusting it";

/// Writes the report for `verify` in the given state.
pub fn report(
    out: &mut impl std::io::Write,
    group_id: Uuid,
    number: &str,
    state: State,
) -> std::io::Result<()> {
    writeln!(out, "conversation {group_id}")?;
    writeln!(out, "safety number:")?;
    for row in number.split(' ').collect::<Vec<_>>().chunks(4) {
        writeln!(out, "  {}", row.join(" "))?;
    }
    match state {
        State::Verified => writeln!(out, "status: verified"),
        State::Unverified => writeln!(
            out,
            "status: not verified. Compare this number with your peer over another channel, \
             then run `powehi verify <conversation> --confirm \"<number>\"` to record it."
        ),
        State::Changed => writeln!(
            out,
            "status: CHANGED since you verified. The peer's identity key is different: do not \
             trust this conversation until you compare the number again."
        ),
    }?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::auth::Session;
    use crate::invite;
    use crate::testsrv::{serve, session, Backend};

    async fn pair() -> (tempfile::TempDir, Session, Session, Uuid) {
        let tmp = tempfile::tempdir().unwrap();
        let (alice, bob) = (session(&tmp, "alice", 1), session(&tmp, "bob", 2));
        let url = serve(Arc::new(Mutex::new(Backend::default()))).await;
        let client = crate::status::http_client().unwrap();
        let (link, _) = invite::create(&client, &url, &alice).await.unwrap();
        let link = invite::parse_link(&link).unwrap();
        let (gid, _) = invite::redeem(&client, &url, &bob, &link).await.unwrap();
        crate::inbox::receive(&client, &url, &alice).await.unwrap();
        (tmp, alice, bob, gid)
    }

    #[tokio::test]
    async fn both_sides_compute_the_same_number() {
        let (_tmp, alice, bob, gid) = pair().await;
        let a = number(&alice.store, gid).unwrap();
        let b = number(&bob.store, gid).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 83);
    }

    #[tokio::test]
    async fn confirm_then_verified_and_changed_on_mismatch() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Unverified);
        confirm(&alice.store, gid, &n, &n).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Verified);
        let other = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        assert_eq!(state(&alice.store, gid, &other).unwrap(), State::Changed);
    }

    #[tokio::test]
    async fn confirm_must_quote_the_current_number() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        let other = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        assert!(matches!(
            confirm(&alice.store, gid, &n, &other),
            Err(VerifyError::NumberMismatch)
        ));
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Unverified);
        let compact = n.replace(' ', "");
        confirm(&alice.store, gid, &n, &compact).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Verified);
    }

    #[tokio::test]
    async fn tampered_record_is_changed_and_confirm_repairs_it() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        confirm(&alice.store, gid, &n, &n).unwrap();
        // Overwriting through the store with garbage JSON is the authenticated-but-bad case;
        // the unauthenticated case maps to Changed in `state` via StoreError::Authentication.
        alice.store.put(&record_name(&gid), b"x").unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Changed);
        confirm(&alice.store, gid, &n, &n).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Verified);
    }

    #[tokio::test]
    async fn corrupt_record_is_never_verified() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        alice.store.put(&record_name(&gid), b"{not json").unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Changed);
    }

    #[tokio::test]
    async fn record_with_unknown_version_is_never_verified() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        let future = Record {
            version: VERSION + 1,
            number: n.clone(),
        };
        let bytes = serde_json::to_vec(&future).unwrap();
        alice.store.put(&record_name(&gid), &bytes).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Changed);
        confirm(&alice.store, gid, &n, &n).unwrap();
        assert_eq!(state(&alice.store, gid, &n).unwrap(), State::Verified);
    }

    fn record_file(tmp: &tempfile::TempDir, gid: Uuid) -> std::path::PathBuf {
        let name = format!("{}.{}", record_name(&gid), "rec");
        let mut stack = vec![tmp.path().to_path_buf()];
        while let Some(d) = stack.pop() {
            for entry in std::fs::read_dir(d).unwrap().flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.file_name().is_some_and(|n| *n == *name) {
                    return p;
                }
            }
        }
        panic!("record file not found");
    }

    #[tokio::test]
    async fn changed_alert_silent_for_none_or_matching_record() {
        let (_tmp, alice, _bob, gid) = pair().await;
        assert!(!changed_since_verified(&alice.store, gid));
        let n = number(&alice.store, gid).unwrap();
        confirm(&alice.store, gid, &n, &n).unwrap();
        assert!(!changed_since_verified(&alice.store, gid));
        // No record and an unusable (unknown) conversation: nothing to compare, silent.
        assert!(!changed_since_verified(&alice.store, Uuid::new_v4()));
    }

    #[tokio::test]
    async fn changed_alert_fires_for_stale_or_tampered_records() {
        use std::os::unix::fs::PermissionsExt;
        let (tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        let other = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        store_record(&alice.store, gid, &other).unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        alice.store.put(&record_name(&gid), b"x").unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        confirm(&alice.store, gid, &n, &n).unwrap();
        let path = record_file(&tmp, gid);
        let good = std::fs::read(&path).unwrap();
        // Byte flip: authentication failure.
        let mut flipped = good.clone();
        *flipped.last_mut().unwrap() ^= 1;
        std::fs::write(&path, &flipped).unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        // Truncation: corrupt, still mode 0600.
        std::fs::write(&path, &good[..4]).unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        // Loosened mode.
        std::fs::write(&path, &good).unwrap();
        assert!(!changed_since_verified(&alice.store, gid));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(changed_since_verified(&alice.store, gid));
    }

    #[tokio::test]
    async fn changed_alert_fires_when_record_exists_but_number_cannot_be_computed() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        confirm(&alice.store, gid, &n, &n).unwrap();
        alice
            .store
            .remove(&format!("conv-{}", gid.hyphenated()))
            .unwrap();
        assert!(number(&alice.store, gid).is_err());
        assert!(changed_since_verified(&alice.store, gid));
    }

    #[tokio::test]
    async fn unknown_conversation_is_an_error() {
        let (_tmp, alice, _bob, _gid) = pair().await;
        assert!(matches!(
            number(&alice.store, Uuid::new_v4()),
            Err(VerifyError::NoSuchConversation)
        ));
    }

    #[test]
    fn report_groups_digits_and_flags_changes() {
        let n = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        let g = Uuid::new_v4();
        for (st, word) in [
            (State::Verified, "status: verified"),
            (State::Unverified, "not verified"),
            (State::Changed, "CHANGED"),
        ] {
            let mut out = Vec::new();
            report(&mut out, g, &n, st).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert!(text.contains(word));
            assert_eq!(text.lines().filter(|l| l.starts_with("  ")).count(), 3);
        }
    }
}
