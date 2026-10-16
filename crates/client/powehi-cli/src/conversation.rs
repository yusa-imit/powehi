//! Per-conversation records in the encrypted profile store (prd.md §7A.3).
//!
//! One record `conv-<group uuid>` per 1:1 conversation holds the server-visible ids and, for the
//! side that joined by Welcome, the ML-KEM decapsulation key moved out of `pq-keys` once its
//! KeyPackage was consumed. The MLS group state itself lives in the `mls-provider` record.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use powehi_crypto_core::kem;

use crate::store::{ProfileStore, StoreError};

/// Hard cap on stored conversations (`store::MAX_RECORDS` is 4096 and key packages need room).
pub const MAX_CONVERSATIONS: usize = 256;
const PREFIX: &str = "conv-";
const VERSION: u8 = 1;

#[derive(Debug, Error)]
pub enum ConversationError {
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("stored conversation is malformed")]
    Malformed,
    #[error("too many conversations in this profile")]
    TooMany,
    #[error("could not write the conversation list")]
    Output,
}

/// Which side of the invite this device was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Redeemed the invite, created the MLS group and sent the Welcome.
    Creator,
    /// Created the invite and joined from the Welcome.
    Joiner,
}

#[derive(Serialize, Deserialize)]
pub struct Conversation {
    version: u8,
    pub group_id: Uuid,
    pub peer_device_id: Uuid,
    pub role: Role,
    pq_decap_key: Option<Vec<u8>>,
    /// The published ek the key above must match; public, re-checked on every load.
    pq_encap_key: Option<Vec<u8>>,
    /// 16-hex PQ binding (prd.md §5.3 Phase B) once the ML-KEM exchange completed on this side.
    #[serde(default)]
    pq_binding: Option<String>,
}

impl Conversation {
    pub fn new(
        group_id: Uuid,
        peer_device_id: Uuid,
        role: Role,
        pq: Option<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    ) -> Self {
        let (pq_decap_key, pq_encap_key) = match pq {
            Some((dk, ek)) => (Some(dk.to_vec()), Some(ek)),
            None => (None, None),
        };
        Self {
            version: VERSION,
            group_id,
            peer_device_id,
            role,
            pq_decap_key,
            pq_encap_key,
            pq_binding: None,
        }
    }

    /// The PQ binding recorded after a successful `pq_init` exchange, if any.
    pub fn pq_binding(&self) -> Option<&str> {
        self.pq_binding.as_deref()
    }

    /// Records the binding derived from the ML-KEM shared secret.
    pub fn set_pq_binding(&mut self, binding: String) {
        debug_assert_eq!(binding.len(), 16);
        self.pq_binding = Some(binding);
    }

    /// Finishes the joiner's ML-KEM exchange: records the binding and discards the
    /// decapsulation key, which is single-use and must not outlive the message it served.
    pub fn complete_pq(&mut self, binding: String) {
        debug_assert!(self.role == Role::Joiner && self.pq_binding.is_none());
        self.set_pq_binding(binding);
        if let Some(k) = self.pq_decap_key.as_mut() {
            k.zeroize();
        }
        self.pq_decap_key = None;
        self.pq_encap_key = None;
    }

    /// The decapsulation key kept for the peer's `pq_init` message, if this side joined.
    pub fn pq_decap_key(&self) -> Option<&[u8]> {
        self.pq_decap_key.as_deref()
    }

    fn check(&self) -> Result<(), ConversationError> {
        // FIPS 203 §7.3 on every save and load, before any decapsulation can use the key.
        let key_ok = match (&self.pq_decap_key, &self.pq_encap_key) {
            (None, None) => true,
            (Some(dk), Some(ek)) => kem::validate_decap_key(dk, ek).is_ok(),
            _ => false,
        };
        // A joiner holds its key until `pq_init` arrives, then only the binding remains.
        let role_ok = match self.role {
            Role::Creator => self.pq_decap_key.is_none(),
            Role::Joiner => self.pq_decap_key.is_some() || self.pq_binding.is_some(),
        };
        let binding_ok = self
            .pq_binding
            .as_ref()
            .is_none_or(|b| b.len() == 16 && b.bytes().all(|c| c.is_ascii_hexdigit()));
        if self.version == VERSION && key_ok && role_ok && binding_ok {
            Ok(())
        } else {
            Err(ConversationError::Malformed)
        }
    }
}

impl Drop for Conversation {
    fn drop(&mut self) {
        if let Some(k) = self.pq_decap_key.as_mut() {
            k.zeroize();
        }
    }
}

impl std::fmt::Debug for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conversation")
            .field("group_id", &self.group_id)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

fn record_name(group_id: &Uuid) -> String {
    format!("{PREFIX}{}", group_id.hyphenated())
}

/// Group ids of all stored conversations.
pub fn list(store: &ProfileStore) -> Result<Vec<Uuid>, ConversationError> {
    let mut out = Vec::new();
    for name in store.names()? {
        if let Some(id) = name
            .strip_prefix(PREFIX)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            out.push(id);
        }
    }
    debug_assert!(out.len() <= crate::store::MAX_RECORDS);
    Ok(out)
}

/// Writes one line per stored conversation (`<id> <role>`, plus ` <n> unread` when `n > 0` and
/// ` CHANGED` when a verified Safety Number no longer matches (§5.6), sorted by id), then a
/// count. Ids and roles are server-visible metadata and `n` is a local count; with
/// `only_unread`, conversations without unread messages are omitted, and with `only_changed`,
/// those whose Safety Number did not change are. No message text or key
/// material is printed.
pub fn report(
    store: &ProfileStore,
    unread: &BTreeMap<Uuid, usize>,
    only_unread: bool,
    only_changed: bool,
    out: &mut impl std::io::Write,
) -> Result<(), ConversationError> {
    let mut ids = list(store)?;
    ids.sort();
    assert!(ids.len() <= crate::store::MAX_RECORDS);
    if only_unread {
        ids.retain(|id| unread.get(id).copied().unwrap_or(0) > 0);
    }
    if only_changed {
        ids.retain(|id| crate::verify::changed_since_verified(store, *id));
    }
    for id in &ids {
        let role = match load(store, id)? {
            Some(c) => c.role,
            None => return Err(ConversationError::Malformed),
        };
        let name = match role {
            Role::Creator => "creator",
            Role::Joiner => "joiner",
        };
        let changed = if crate::verify::changed_since_verified(store, *id) {
            " CHANGED"
        } else {
            ""
        };
        match unread.get(id).copied().unwrap_or(0) {
            0 => writeln!(out, "{id} {name}{changed}"),
            n => writeln!(out, "{id} {name} {n} unread{changed}"),
        }
        .map_err(|_| ConversationError::Output)?;
    }
    writeln!(out, "{} conversation(s)", ids.len()).map_err(|_| ConversationError::Output)
}

/// Writes (or replaces) the record for `conv.group_id`.
pub fn save(store: &ProfileStore, conv: &Conversation) -> Result<(), ConversationError> {
    conv.check()?;
    let existing = list(store)?;
    if !existing.contains(&conv.group_id) && existing.len() >= MAX_CONVERSATIONS {
        return Err(ConversationError::TooMany);
    }
    let bytes = Zeroizing::new(serde_json::to_vec(conv).map_err(|_| ConversationError::Malformed)?);
    store.put(&record_name(&conv.group_id), &bytes)?;
    Ok(())
}

pub fn load(
    store: &ProfileStore,
    group_id: &Uuid,
) -> Result<Option<Conversation>, ConversationError> {
    let Some(raw) = store.get(&record_name(group_id))? else {
        return Ok(None);
    };
    let conv: Conversation =
        serde_json::from_slice(&raw).map_err(|_| ConversationError::Malformed)?;
    conv.check()?;
    if conv.group_id != *group_id {
        return Err(ConversationError::Malformed);
    }
    Ok(Some(conv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfilePaths;

    fn open(tmp: &tempfile::TempDir) -> ProfileStore {
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        ProfileStore::open(&paths, &[7u8; 32]).unwrap()
    }

    fn joiner(group: Uuid) -> Conversation {
        let pair = kem::generate();
        Conversation::new(
            group,
            Uuid::new_v4(),
            Role::Joiner,
            Some((pair.decap_key, pair.encap_key)),
        )
    }

    #[test]
    fn round_trip_and_list() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(a)).unwrap();
        save(
            &store,
            &Conversation::new(b, Uuid::new_v4(), Role::Creator, None),
        )
        .unwrap();
        let got = load(&store, &a).unwrap().unwrap();
        assert_eq!(got.role, Role::Joiner);
        assert_eq!(got.pq_decap_key().unwrap().len(), kem::DK_SIZE);
        assert!(load(&store, &b).unwrap().unwrap().pq_decap_key().is_none());
        assert!(load(&store, &Uuid::new_v4()).unwrap().is_none());
        let mut ids = list(&store).unwrap();
        ids.sort();
        let mut want = vec![a, b];
        want.sort();
        assert_eq!(ids, want);
        store.put("account", b"x").unwrap();
        assert_eq!(
            list(&store).unwrap().len(),
            2,
            "non-conversation records are ignored"
        );
    }

    #[test]
    fn report_lists_sorted_ids_and_roles_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let mut out = Vec::new();
        report(&store, &BTreeMap::new(), false, false, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "0 conversation(s)\n");
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(a)).unwrap();
        save(
            &store,
            &Conversation::new(b, Uuid::new_v4(), Role::Creator, None),
        )
        .unwrap();
        let mut out = Vec::new();
        report(&store, &BTreeMap::new(), false, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        let mut want = [format!("{a} joiner"), format!("{b} creator")];
        want.sort();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[..2], want[..]);
        assert_eq!(lines[2], "2 conversation(s)");
        let mut out = Vec::new();
        report(
            &store,
            &BTreeMap::from([(a, 3), (b, 0)]),
            false,
            false,
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("{a} joiner 3 unread\n")));
        assert!(text.contains(&format!("{b} creator\n")));
    }

    struct FailingWriter;

    impl std::io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("closed"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn report_ignores_unknown_unread_ids_and_types_write_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (known, stranger) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(known)).unwrap();
        let unread = BTreeMap::from([(stranger, 9)]);
        let mut out = Vec::new();
        report(&store, &unread, false, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains(&stranger.to_string()));
        assert!(!text.contains("unread"));
        let err = report(&store, &unread, false, false, &mut FailingWriter).unwrap_err();
        assert!(matches!(err, ConversationError::Output));
    }

    #[test]
    fn report_unread_filter_keeps_only_conversations_with_unread() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (quiet, busy) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(quiet)).unwrap();
        save(&store, &joiner(busy)).unwrap();
        let unread = BTreeMap::from([(busy, 2), (quiet, 0)]);
        let mut out = Vec::new();
        report(&store, &unread, true, false, &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, format!("{busy} joiner 2 unread\n1 conversation(s)\n"));
        let mut out = Vec::new();
        report(&store, &BTreeMap::new(), true, false, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "0 conversation(s)\n");
    }

    #[test]
    fn report_flags_changed_safety_number() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (plain, flagged) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(plain)).unwrap();
        save(&store, &joiner(flagged)).unwrap();
        // A confirmation record whose number cannot be recomputed must alert, not stay silent.
        let rec = format!("{}{}", crate::verify::PREFIX, flagged.hyphenated());
        store
            .put(&rec, br#"{"version":1,"number":"1 2 3"}"#)
            .unwrap();
        let mut out = Vec::new();
        report(
            &store,
            &BTreeMap::from([(flagged, 2)]),
            false,
            false,
            &mut out,
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains(&format!("{flagged} joiner 2 unread CHANGED\n")));
        assert!(text.contains(&format!("{plain} joiner\n")));
    }

    #[test]
    fn unread_filter_still_flags_changed_safety_number() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (quiet_changed, busy_changed) = (Uuid::new_v4(), Uuid::new_v4());
        for id in [quiet_changed, busy_changed] {
            save(&store, &joiner(id)).unwrap();
            let rec = format!("{}{}", crate::verify::PREFIX, id.hyphenated());
            store
                .put(&rec, br#"{"version":1,"number":"1 2 3"}"#)
                .unwrap();
        }
        let unread = BTreeMap::from([(busy_changed, 1)]);
        let mut out = Vec::new();
        report(&store, &unread, true, false, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{busy_changed} joiner 1 unread CHANGED\n1 conversation(s)\n")
        );
    }

    #[test]
    fn changed_filter_lists_only_changed_conversations() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let (plain, flagged) = (Uuid::new_v4(), Uuid::new_v4());
        save(&store, &joiner(plain)).unwrap();
        save(&store, &joiner(flagged)).unwrap();
        let rec = format!("{}{}", crate::verify::PREFIX, flagged.hyphenated());
        store
            .put(&rec, br#"{"version":1,"number":"1 2 3"}"#)
            .unwrap();
        let mut out = Vec::new();
        report(&store, &BTreeMap::new(), false, true, &mut out).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("{flagged} joiner CHANGED\n1 conversation(s)\n")
        );
        // Combined with --unread, a changed but fully read conversation is omitted.
        let mut out = Vec::new();
        report(&store, &BTreeMap::new(), true, true, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "0 conversation(s)\n");
    }

    #[test]
    fn rejects_inconsistent_records() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let g = Uuid::new_v4();
        // Joiner without a key, creator with a key, wrong key length.
        let no_key = Conversation::new(g, Uuid::new_v4(), Role::Joiner, None);
        let pair = kem::generate();
        let other = kem::generate();
        let creator_key = Conversation::new(
            g,
            Uuid::new_v4(),
            Role::Creator,
            Some((pair.decap_key.clone(), pair.encap_key.clone())),
        );
        let short = Conversation::new(
            g,
            Uuid::new_v4(),
            Role::Joiner,
            Some((Zeroizing::new(vec![1u8; 10]), pair.encap_key.clone())),
        );
        // A dk paired with some other key's ek fails the §7.3 binding.
        let mismatched = Conversation::new(
            g,
            Uuid::new_v4(),
            Role::Joiner,
            Some((pair.decap_key.clone(), other.encap_key.clone())),
        );
        for (i, c) in [no_key, creator_key, short, mismatched].iter().enumerate() {
            let r = save(&store, c);
            assert!(
                matches!(r, Err(ConversationError::Malformed)),
                "case {i}: {r:?}"
            );
        }
        // A record whose content names another group is rejected on load.
        let other = joiner(Uuid::new_v4());
        let bytes = serde_json::to_vec(&other).unwrap();
        store.put(&record_name(&g), &bytes).unwrap();
        assert!(matches!(
            load(&store, &g),
            Err(ConversationError::Malformed)
        ));
        store.put(&record_name(&g), b"not json").unwrap();
        assert!(matches!(
            load(&store, &g),
            Err(ConversationError::Malformed)
        ));
    }

    #[test]
    fn conversation_cap_is_enforced_but_replacing_is_allowed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let first = Uuid::new_v4();
        let creator = |g| Conversation::new(g, Uuid::new_v4(), Role::Creator, None);
        save(&store, &creator(first)).unwrap();
        for _ in 1..MAX_CONVERSATIONS {
            save(&store, &creator(Uuid::new_v4())).unwrap();
        }
        assert!(matches!(
            save(&store, &creator(Uuid::new_v4())),
            Err(ConversationError::TooMany)
        ));
        save(&store, &creator(first)).unwrap();
    }

    #[test]
    fn completing_pq_drops_the_key_and_keeps_the_binding() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let g = Uuid::new_v4();
        let mut c = joiner(g);
        c.complete_pq("0123456789abcdef".into());
        assert!(c.pq_decap_key().is_none());
        save(&store, &c).unwrap();
        let got = load(&store, &g).unwrap().unwrap();
        assert_eq!(got.pq_binding(), Some("0123456789abcdef"));
        assert!(got.pq_decap_key().is_none());
        // A creator never holds a key, binding or not.
        let mut bad = Conversation::new(g, Uuid::new_v4(), Role::Creator, None);
        bad.pq_decap_key = Some(vec![0; 4]);
        assert!(matches!(
            save(&store, &bad),
            Err(ConversationError::Malformed)
        ));
    }

    #[test]
    fn rejects_malformed_binding_and_unknown_version() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let g = Uuid::new_v4();
        // Bindings must be exactly 16 hex digits.
        for bad in ["", "0123", "0123456789abcdeg", "0123456789abcdef00"] {
            let mut c = joiner(g);
            c.pq_binding = Some(bad.into());
            assert!(
                matches!(save(&store, &c), Err(ConversationError::Malformed)),
                "binding {bad:?}"
            );
        }
        let mut ok = joiner(g);
        ok.set_pq_binding("0123456789ABCDEF".into());
        save(&store, &ok).unwrap();
        // A record from a future format version is refused on save and on load.
        let mut future = joiner(g);
        future.version = VERSION + 1;
        assert!(matches!(
            save(&store, &future),
            Err(ConversationError::Malformed)
        ));
        let bytes = serde_json::to_vec(&future).unwrap();
        store.put(&record_name(&g), &bytes).unwrap();
        assert!(matches!(
            load(&store, &g),
            Err(ConversationError::Malformed)
        ));
    }

    #[test]
    fn debug_never_prints_the_key() {
        let c = joiner(Uuid::new_v4());
        let s = format!("{c:?}");
        assert!(!s.contains("pq_decap_key") && !s.contains("pq_encap_key"));
    }
}
