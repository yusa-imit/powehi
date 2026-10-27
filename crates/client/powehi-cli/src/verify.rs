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

use crate::conversation::{self, ConversationError, Kind};
use crate::identity::{IdentityError, LocalIdentity};
use crate::store::{ProfileStore, StoreError};

pub(crate) const PREFIX: &str = "verified-";
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
    #[error("the group has too many members for a safety number")]
    TooMany,
    #[error("two members share a signature key; this conversation is inconsistent")]
    DuplicateKey,
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

/// The Safety Number of `group` from its members' signature keys, by conversation `kind`
/// (never by member count: a 2-member group must show the group number the web shows). `own_key`
/// must be a member and the group must still include this device.
pub fn number_of(
    group: &mls_group::Group,
    own_key: &[u8],
    kind: Kind,
) -> Result<String, VerifyError> {
    if !mls_group::group_is_active(group) {
        return Err(VerifyError::GroupUnusable);
    }
    let keys: Vec<Vec<u8>> = group
        .members()
        .take(safety::GROUP_MAX_MEMBERS + 1)
        .map(|m| m.signature_key)
        .collect();
    number_from_keys(&keys, own_key, kind)
}

/// The pure part of [`number_of`]: `keys` is the roster (at most `GROUP_MAX_MEMBERS + 1` read).
fn number_from_keys(keys: &[Vec<u8>], own_key: &[u8], kind: Kind) -> Result<String, VerifyError> {
    // The cap is judged before anything else so it never depends on where our leaf sits.
    if kind == Kind::Group && keys.len() > safety::GROUP_MAX_MEMBERS {
        return Err(VerifyError::TooMany);
    }
    if keys.iter().any(|k| k.len() != KEY_LEN) || !keys.iter().any(|k| k == own_key) {
        return Err(VerifyError::GroupUnusable);
    }
    match kind {
        // A pair that grew past two members is no longer comparable: fail closed (8.16).
        Kind::Pair if keys.len() != 2 => Err(VerifyError::GroupUnusable),
        Kind::Pair if keys[0] == keys[1] => Err(VerifyError::DuplicateKey),
        Kind::Pair => safety::pairwise(&keys[0], &keys[1]).map_err(|_| VerifyError::GroupUnusable),
        Kind::Group => {
            let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
            safety::group(&refs).map_err(group_error)
        }
    }
}

fn group_error(e: safety::GroupSafetyError) -> VerifyError {
    match e {
        safety::GroupSafetyError::TooMany => VerifyError::TooMany,
        safety::GroupSafetyError::DuplicateKey => VerifyError::DuplicateKey,
        safety::GroupSafetyError::TooFew | safety::GroupSafetyError::BadKeyLength => {
            VerifyError::GroupUnusable
        }
    }
}

/// Computes the number for a stored conversation.
pub fn number(store: &ProfileStore, group_id: Uuid) -> Result<String, VerifyError> {
    let conv = conversation::load(store, &group_id)?.ok_or(VerifyError::NoSuchConversation)?;
    let local = LocalIdentity::load(store)?;
    let group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .ok_or(VerifyError::GroupUnusable)?;
    if !conv.agrees_with(&group) {
        return Err(VerifyError::GroupUnusable);
    }
    number_of(&group, &local.identity.signer.to_public_vec(), conv.kind())
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
/// match it. It is the predicate of the `send`/`chat` gate (8.16): it MUST stay fail-closed, never
/// relax an error arm to `false`. Only an absent record, or a record matching the
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

/// `true` when a confirmation record exists for the conversation. A store error counts as no
/// record, so `conversations --unverified` over-reports rather than hides a conversation.
pub fn has_confirmation(store: &ProfileStore, group_id: Uuid) -> bool {
    matches!(store.get(&record_name(&group_id)), Ok(Some(_)))
}

/// The one-line notice shown by `send` and `chat` while the conversation has no confirmation
/// record (prd.md §5.6, 8.10). A CHANGED conversation has a record, so it gets only the
/// [`CHANGED_WARNING`].
pub const UNVERIFIED_WARNING: &str = "warning: this conversation is unverified; run `powehi \
verify <conversation>` and compare the safety number with your peer over another channel";

/// The one-line warning shown when [`changed_since_verified`] is true.
pub const CHANGED_WARNING: &str = "warning: the safety number CHANGED since you verified this \
conversation; run `powehi verify <conversation>` and compare it with your peer before trusting it";

/// Writes the `verify` report as one JSON object (for scripts):
/// `{"conversation":..,"safety_number":"dddd ..","status":"verified"|"unverified"|"changed"}`.
/// The safety number is public by design; no key material or message text is printed.
pub fn report_json(
    out: &mut impl std::io::Write,
    group_id: Uuid,
    number: &str,
    state: State,
) -> std::io::Result<()> {
    let status = match state {
        State::Verified => "verified",
        State::Unverified => "unverified",
        State::Changed => "changed",
    };
    let obj = serde_json::json!({
        "conversation": group_id.to_string(),
        "safety_number": number,
        "status": status,
    });
    writeln!(out, "{obj}")?;
    out.flush()
}

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

    #[test]
    fn roster_rules_by_kind() {
        let k = |i: u8| vec![i; 32];
        let own = k(1);
        // A pair grown to three members fails closed; the same roster is a valid group.
        let three = vec![k(1), k(2), k(3)];
        assert!(matches!(
            number_from_keys(&three, &own, Kind::Pair),
            Err(VerifyError::GroupUnusable)
        ));
        let refs: Vec<&[u8]> = three.iter().map(Vec::as_slice).collect();
        assert_eq!(
            number_from_keys(&three, &own, Kind::Group).unwrap(),
            safety::group(&refs).unwrap()
        );
        // Duplicates keep their own type on both paths' group side.
        assert!(matches!(
            number_from_keys(&[k(1), k(2), k(2)], &own, Kind::Group),
            Err(VerifyError::DuplicateKey)
        ));
        assert!(matches!(
            number_from_keys(&[k(1), k(1)], &own, Kind::Pair),
            Err(VerifyError::DuplicateKey)
        ));
        // 512 members verify, 513 are TooMany even when our key is not in the list.
        let roster = |n: usize| -> Vec<Vec<u8>> {
            (0..n)
                .map(|i| {
                    let mut v = vec![0u8; 32];
                    v[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                    v
                })
                .collect()
        };
        let own = roster(1).remove(0);
        assert!(number_from_keys(&roster(512), &own, Kind::Group).is_ok());
        assert!(matches!(
            number_from_keys(&roster(513), &own, Kind::Group),
            Err(VerifyError::TooMany)
        ));
        assert!(matches!(
            number_from_keys(&roster(513)[1..], &own, Kind::Group),
            Err(VerifyError::GroupUnusable)
        ));
    }

    #[tokio::test]
    async fn kind_decides_the_construction_not_member_count() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let local = LocalIdentity::load(&alice.store).unwrap();
        let own = local.identity.signer.to_public_vec();
        let group = mls_group::load_group(gid.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        let pair_n = number_of(&group, &own, Kind::Pair).unwrap();
        let group_n = number_of(&group, &own, Kind::Group).unwrap();
        assert_ne!(pair_n, group_n);
        let keys: Vec<Vec<u8>> = group.members().map(|m| m.signature_key).collect();
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        assert_eq!(group_n, safety::group(&refs).unwrap());
    }

    #[tokio::test]
    async fn record_kind_must_match_the_authenticated_group_kind() {
        let (_tmp, _alice, bob, gid) = pair().await;
        let conv = conversation::load(&bob.store, &gid).unwrap().unwrap();
        let group_record = conversation::Conversation::new(
            gid,
            conv.peer_device_id,
            conversation::Role::Creator,
            None,
        )
        .into_group();
        assert!(number(&bob.store, gid).is_ok());
        // A pair group whose record claims to be a group: no number.
        conversation::save(&bob.store, &group_record).unwrap();
        assert!(matches!(
            number(&bob.store, gid),
            Err(VerifyError::GroupUnusable)
        ));
    }

    #[tokio::test]
    async fn non_member_key_has_no_number() {
        let (_tmp, alice, _bob, gid) = pair().await;
        let local = LocalIdentity::load(&alice.store).unwrap();
        let own = local.identity.signer.to_public_vec();
        let group = mls_group::load_group(gid.as_bytes(), &local.provider)
            .unwrap()
            .unwrap();
        assert!(number_of(&group, &own, Kind::Pair).is_ok());
        // A key that is not in the pair is refused, never a number over foreign keys.
        assert!(matches!(
            number_of(&group, &[7u8; 32], Kind::Pair),
            Err(VerifyError::GroupUnusable)
        ));
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

    fn record_file(store: &ProfileStore, gid: Uuid) -> std::path::PathBuf {
        store.record_path(&record_name(&gid))
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
        let (_tmp, alice, _bob, gid) = pair().await;
        let n = number(&alice.store, gid).unwrap();
        let other = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        store_record(&alice.store, gid, &other).unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        alice.store.put(&record_name(&gid), b"x").unwrap();
        assert!(changed_since_verified(&alice.store, gid));
        confirm(&alice.store, gid, &n, &n).unwrap();
        let path = record_file(&alice.store, gid);
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

    #[test]
    fn report_json_is_one_object_with_status_per_state() {
        let n = safety::pairwise(&[1u8; 32], &[2u8; 32]).unwrap();
        let g = Uuid::new_v4();
        for (st, word) in [
            (State::Verified, "verified"),
            (State::Unverified, "unverified"),
            (State::Changed, "changed"),
        ] {
            let mut out = Vec::new();
            report_json(&mut out, g, &n, st).unwrap();
            let text = String::from_utf8(out).unwrap();
            assert_eq!(text.lines().count(), 1);
            let v: serde_json::Value = serde_json::from_str(&text).unwrap();
            assert_eq!(v["status"], word);
            assert_eq!(v["conversation"], g.to_string());
            assert_eq!(v["safety_number"], n);
        }
    }
}
