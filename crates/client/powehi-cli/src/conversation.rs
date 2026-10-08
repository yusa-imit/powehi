//! Per-conversation records in the encrypted profile store (prd.md §7A.3).
//!
//! One record `conv-<group uuid>` per 1:1 conversation holds the server-visible ids and, for the
//! side that joined by Welcome, the ML-KEM decapsulation key moved out of `pq-keys` once its
//! KeyPackage was consumed. The MLS group state itself lives in the `mls-provider` record.

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
        }
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
        let role_ok = (self.role == Role::Joiner) == self.pq_decap_key.is_some();
        if self.version == VERSION && key_ok && role_ok {
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
    fn debug_never_prints_the_key() {
        let c = joiner(Uuid::new_v4());
        let s = format!("{c:?}");
        assert!(!s.contains("pq_decap_key") && !s.contains("pq_encap_key"));
    }
}
