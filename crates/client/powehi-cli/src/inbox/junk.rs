//! Bookkeeping for envelopes `inbox` cannot use (issue #30, Phase 8 item 8.13).
//!
//! The server keeps an envelope until it is acked, so anyone who can address this device can
//! fill the fetch window with junk. Two kinds are tracked in one bounded store record:
//! envelopes for a group we neither hold nor have a pending request for (acked once
//! [`UNKNOWN_GRACE_SECS`] have passed since we first saw them, so a Welcome that is merely late
//! is not lost), and envelopes of a known conversation that fail to decrypt (acked after
//! [`MAX_DECRYPT_FAILURES`] attempts *and* the same grace: a message from an epoch we cannot
//! apply yet, before 8.14's Commit path, must not be dropped within seconds). Entries hold
//! only the server-chosen envelope id and counters: no content, no ciphertext.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::store::{ProfileStore, StoreError};

pub(super) const RECORD: &str = "inbox-junk";
/// How long an envelope for an unknown group is kept before it is acked and dropped.
pub(super) const UNKNOWN_GRACE_SECS: u64 = 24 * 60 * 60;
/// How long one held "epoch ahead" envelope may keep the fetch cursor at the head. Past it the
/// cursor moves on (the envelope is seen again at the next head rescan), so a single envelope
/// from a peer cannot hide the rest of a long queue for the whole grace.
pub(super) const AHEAD_PIN_SECS: u64 = 60 * 60;
const _: () = assert!(AHEAD_PIN_SECS < UNKNOWN_GRACE_SECS);
/// Decrypt attempts on a known conversation before the envelope is acked and dropped.
pub(super) const MAX_DECRYPT_FAILURES: u32 = 5;
/// Tracked envelopes: at least one full fetch window (`MAX_PAGES` x `MAX_PAGE_ENVELOPES`).
/// When full, new ids are not tracked (they are tracked once older entries expire), so the
/// oldest entries keep progressing toward their ack instead of being evicted in a cycle.
/// Entries older than this are forgotten: the server's longest envelope TTL is 7 days, so the
/// envelope is gone by then and a stale entry would only fill the tracker.
pub(super) const ENTRY_MAX_AGE_SECS: u64 = 8 * 24 * 60 * 60;
pub(super) const MAX_TRACKED: usize = 512;
const _: () = assert!(MAX_TRACKED >= 4 * 128);

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
struct Entry {
    id: Uuid,
    first_seen: u64,
    fails: u32,
}

#[derive(Default, Debug)]
pub(super) struct Tracker {
    entries: Vec<Entry>,
    dirty: bool,
}

impl Tracker {
    /// A missing or unreadable record starts empty: it is a cache of local timers, and losing
    /// it only restarts the grace clocks.
    pub(super) fn load(store: &ProfileStore) -> Result<Self, StoreError> {
        let entries = store
            .get(RECORD)?
            .and_then(|raw| serde_json::from_slice::<Vec<Entry>>(&raw).ok())
            .map(|mut v| {
                v.truncate(MAX_TRACKED);
                v
            })
            .unwrap_or_default();
        Ok(Tracker {
            entries,
            dirty: false,
        })
    }

    pub(super) fn save(&mut self, store: &ProfileStore) -> Result<(), StoreError> {
        if !self.dirty {
            return Ok(());
        }
        assert!(self.entries.len() <= MAX_TRACKED);
        if self.entries.is_empty() {
            store.remove(RECORD)?;
        } else {
            let raw = serde_json::to_vec(&self.entries).map_err(|_| StoreError::Corrupt)?;
            store.put(RECORD, &raw)?;
        }
        self.dirty = false;
        Ok(())
    }

    /// Forgets entries whose envelope the server has certainly expired.
    pub(super) fn prune(&mut self, now: u64) {
        let before = self.entries.len();
        self.entries
            .retain(|e| now.saturating_sub(e.first_seen) < ENTRY_MAX_AGE_SECS);
        self.dirty |= self.entries.len() != before;
    }

    /// The entry for `id`, created on first sight; `None` when the tracker is full.
    fn slot(&mut self, id: Uuid, now: u64) -> Option<&mut Entry> {
        let i = match self.entries.iter().position(|e| e.id == id) {
            Some(i) => i,
            None if self.entries.len() >= MAX_TRACKED => return None,
            None => {
                self.entries.push(Entry {
                    id,
                    first_seen: now,
                    fails: 0,
                });
                self.dirty = true;
                self.entries.len() - 1
            }
        };
        self.entries.get_mut(i)
    }

    /// Records a sighting of an envelope for an unknown group. True once the grace has run out;
    /// the caller acks it and then calls [`Tracker::forget`].
    pub(super) fn unknown_expired(&mut self, id: Uuid, now: u64) -> bool {
        self.slot(id, now)
            .is_some_and(|e| now.saturating_sub(e.first_seen) >= UNKNOWN_GRACE_SECS)
    }

    /// Records a sighting of an envelope held for a missing Commit. True while it is younger
    /// than [`AHEAD_PIN_SECS`] (the fetch cursor stays put); an untracked id (tracker full)
    /// never pins, so a full tracker cannot freeze the cursor.
    pub(super) fn ahead_pins(&mut self, id: Uuid, now: u64) -> bool {
        self.slot(id, now)
            .is_some_and(|e| now.saturating_sub(e.first_seen) < AHEAD_PIN_SECS)
    }

    /// Records one failed decrypt. True once [`MAX_DECRYPT_FAILURES`] failed and the grace ran
    /// out (ack, then forget). An untracked id (tracker full) never reaches it.
    pub(super) fn failed(&mut self, id: Uuid, now: u64) -> bool {
        let Some(e) = self.slot(id, now) else {
            return false;
        };
        e.fails = e.fails.saturating_add(1);
        let give_up = e.fails >= MAX_DECRYPT_FAILURES
            && now.saturating_sub(e.first_seen) >= UNKNOWN_GRACE_SECS;
        self.dirty = true;
        give_up
    }

    /// Drops an envelope's entry (it was processed or acked).
    pub(super) fn forget(&mut self, id: Uuid) {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        self.dirty |= self.entries.len() != before;
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum Op {
        Unknown(u8, u64),
        Ahead(u8, u64),
        Failed(u8, u64),
        Forget(u8),
        Prune(u64),
    }

    fn id(n: u8) -> Uuid {
        Uuid::from_u128(u128::from(n) + 1)
    }

    fn op() -> impl Strategy<Value = Op> {
        // few ids so ops collide; times span past the grace and the max age
        let t = 0u64..(3 * ENTRY_MAX_AGE_SECS);
        prop_oneof![
            (0u8..6, t.clone()).prop_map(|(i, t)| Op::Unknown(i, t)),
            (0u8..6, t.clone()).prop_map(|(i, t)| Op::Ahead(i, t)),
            (0u8..6, t.clone()).prop_map(|(i, t)| Op::Failed(i, t)),
            (0u8..6).prop_map(Op::Forget),
            t.prop_map(Op::Prune),
        ]
    }

    proptest! {
        /// Model: id -> (first_seen, fails). Time is fed non-decreasing, as a clock is.
        #[test]
        fn tracker_matches_model(mut ops in proptest::collection::vec(op(), 0..80)) {
            let mut clock = 0u64;
            for o in &mut ops {
                match o {
                    Op::Unknown(_, t) | Op::Ahead(_, t) | Op::Failed(_, t) | Op::Prune(t) => {
                        clock = clock.max(*t);
                        *t = clock;
                    }
                    Op::Forget(_) => {}
                }
            }
            let mut tr = Tracker::default();
            let mut model: std::collections::HashMap<u8, (u64, u32)> = Default::default();
            for o in ops {
                match o {
                    Op::Unknown(i, now) => {
                        let first = model.entry(i).or_insert((now, 0)).0;
                        let want = now - first >= UNKNOWN_GRACE_SECS;
                        prop_assert_eq!(tr.unknown_expired(id(i), now), want);
                    }
                    Op::Ahead(i, now) => {
                        let first = model.entry(i).or_insert((now, 0)).0;
                        let want = now - first < AHEAD_PIN_SECS;
                        prop_assert_eq!(tr.ahead_pins(id(i), now), want);
                    }
                    Op::Failed(i, now) => {
                        let e = model.entry(i).or_insert((now, 0));
                        e.1 += 1;
                        let want = e.1 >= MAX_DECRYPT_FAILURES
                            && now - e.0 >= UNKNOWN_GRACE_SECS;
                        prop_assert_eq!(tr.failed(id(i), now), want);
                    }
                    Op::Forget(i) => {
                        model.remove(&i);
                        tr.forget(id(i));
                    }
                    Op::Prune(now) => {
                        model.retain(|_, (f, _)| now - *f < ENTRY_MAX_AGE_SECS);
                        tr.prune(now);
                    }
                }
                prop_assert_eq!(tr.len(), model.len());
                prop_assert!(tr.len() <= MAX_TRACKED);
            }
        }

        /// A full tracker never tracks, pins, or gives up on a new id.
        #[test]
        fn full_tracker_ignores_new_ids(now in 0u64..(2 * UNKNOWN_GRACE_SECS)) {
            let mut tr = Tracker::default();
            for n in 0..MAX_TRACKED {
                tr.entries.push(Entry { id: Uuid::from_u128(n as u128 + 1000), first_seen: 0, fails: 0 });
            }
            let fresh = Uuid::from_u128(1);
            prop_assert!(!tr.unknown_expired(fresh, now));
            prop_assert!(!tr.ahead_pins(fresh, now));
            prop_assert!(!tr.failed(fresh, now));
            prop_assert_eq!(tr.len(), MAX_TRACKED);
        }
    }
}
