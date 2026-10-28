//! Conversation list rows from the profile store (8.20 slice b).

use uuid::Uuid;

use super::{Mark, Row};
use crate::conversation::{self, ConversationError};
use crate::store::ProfileStore;
use crate::{message, verify};

/// One row per stored conversation (at most [`super::MAX_ROWS`]), ordered by id. A record
/// that cannot be read is skipped. The mark is fail-closed: a confirmation that cannot be
/// shown to match is `Changed`, never `Verified`.
pub fn load(store: &ProfileStore) -> Result<Vec<Row>, ConversationError> {
    let unread = message::unread_counts(store).unwrap_or_default();
    let mut ids: Vec<Uuid> = conversation::list(store)?;
    ids.sort();
    ids.truncate(super::MAX_ROWS);
    let mut rows = Vec::with_capacity(ids.len());
    for id in ids {
        let Ok(Some(conv)) = conversation::load(store, &id) else {
            continue;
        };
        // Fail-closed order as in the send gate: an unreadable record is Changed.
        let mark = if verify::changed_since_verified(store, id) {
            Mark::Changed
        } else if verify::has_confirmation(store, id) {
            Mark::Verified
        } else {
            Mark::Unverified
        };
        rows.push(Row {
            id,
            kind: conv.kind(),
            unread: unread.get(&id).copied().unwrap_or(0),
            mark,
        });
    }
    assert!(rows.len() <= super::MAX_ROWS);
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::{Conversation, Role};
    use crate::profile::ProfilePaths;

    fn open(tmp: &tempfile::TempDir) -> ProfileStore {
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        ProfileStore::open(&paths, &[7u8; 32]).unwrap()
    }

    #[test]
    fn empty_store_has_no_rows() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load(&open(&tmp)).unwrap().is_empty());
    }

    #[test]
    fn stored_conversation_is_listed_unverified_without_confirmation() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let gid = Uuid::new_v4();
        let conv = Conversation::new(gid, Uuid::new_v4(), Role::Creator, None);
        conversation::save(&store, &conv).unwrap();
        let rows = load(&store).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].id, rows[0].mark, rows[0].unread),
            (gid, Mark::Unverified, 0)
        );
    }

    #[test]
    fn confirmation_that_cannot_be_recomputed_is_changed_not_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let gid = Uuid::new_v4();
        let conv = Conversation::new(gid, Uuid::new_v4(), Role::Creator, None);
        conversation::save(&store, &conv).unwrap();
        // A confirmation record exists but there is no MLS group to recompute from.
        store
            .put(&format!("verified-{}", gid.hyphenated()), b"{}")
            .unwrap();
        assert!(verify::has_confirmation(&store, gid));
        assert_eq!(load(&store).unwrap()[0].mark, Mark::Changed);
    }

    #[test]
    fn deleted_or_corrupt_confirmation_is_never_unverified_or_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let store = open(&tmp);
        let gid = Uuid::new_v4();
        conversation::save(
            &store,
            &Conversation::new(gid, Uuid::new_v4(), Role::Creator, None),
        )
        .unwrap();
        store
            .put(&format!("verified-{}", gid.hyphenated()), b"garbage")
            .unwrap();
        assert_eq!(load(&store).unwrap()[0].mark, Mark::Changed);
    }
}
