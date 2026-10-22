//! Persistent fetch cursor (issue #30, Phase 8 item 8.13).
//!
//! One fetch covers `MAX_PAGES` pages from the head of the server's queue. Un-acked envelopes
//! waiting out their grace sit at the head forever, so a backlog longer than the window would
//! hide everything behind it. After a run that exhausted the window and deferred nothing, the
//! next run resumes after the last envelope seen; a run that reaches the end of the queue
//! clears the cursor, so the head (and its grace-expired junk) is revisited on the next run.
//! The record is a local cache of a position: the server's ids and a timestamp, no content.

use serde::{Deserialize, Serialize};

use crate::store::ProfileStore;
use crate::welcome::Cursor;

pub(super) const RECORD: &str = "inbox-cursor";
/// Far above any real record (sane timestamp, UUID, counter); bounds a garbage record.
const MAX_RECORD_BYTES: usize = 256;
/// Consecutive resumed runs before the next run starts at the head again, so a message hidden
/// behind the cursor (late-visible, store-full skip) waits a bounded number of runs.
pub(super) const MAX_HOPS: u32 = 4;

#[derive(Serialize, Deserialize)]
struct Record {
    cursor: Cursor,
    hops: u32,
}

/// The saved cursor and how many runs have resumed from it in a row; missing, oversize,
/// unreadable or out of hops means "start at the head".
pub(super) fn load(store: &ProfileStore) -> Option<(Cursor, u32)> {
    let raw = store.get(RECORD).ok().flatten()?;
    if raw.len() > MAX_RECORD_BYTES {
        return None;
    }
    let r = serde_json::from_slice::<Record>(&raw).ok()?;
    (r.cursor.is_sane() && r.hops < MAX_HOPS).then_some((r.cursor, r.hops))
}

/// Saves `cursor` with its hop count, or clears the record for `None`. A failure only costs a
/// rescan. A cursor too large for the record (cannot happen for a sane one) is dropped.
pub(super) fn save(store: &ProfileStore, cursor: Option<(&Cursor, u32)>) {
    let raw = cursor
        .filter(|(c, _)| c.is_sane())
        .and_then(|(c, hops)| {
            serde_json::to_vec(&Record {
                cursor: c.clone(),
                hops,
            })
            .ok()
        })
        .filter(|raw| raw.len() <= MAX_RECORD_BYTES);
    match raw {
        Some(raw) => {
            let _ = store.put(RECORD, &raw);
        }
        None => {
            let _ = store.remove(RECORD);
        }
    }
}
