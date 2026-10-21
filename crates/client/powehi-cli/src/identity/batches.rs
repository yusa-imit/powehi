//! Upload state of pool KeyPackage batches and orphan pruning (8.9, issue #22).
//!
//! A batch is the set of KeyPackages one top-up sends in one request. Its private halves are
//! persisted before the upload (`identity.rs`), so a failed or lost upload leaves orphans: local
//! keys for packages the server may never hand out. Each batch walks `Prepared` (persisted, no
//! request made) → `Sent` (request about to leave; stays here if the response is lost) →
//! `Confirmed` (server acknowledged). The state is a local record only, so the server learns
//! nothing new.
//!
//! * A `Prepared` batch never reached the server (the process holds the exclusive profile lock,
//!   so none can be in flight): its keys are deleted at the next pruning pass.
//! * A `Sent` batch may be live on the server, and a `Confirmed` one is, until it expires or is
//!   consumed. Both are deleted only [`RETENTION_SECS`] after their last state change: the
//!   84-day KeyPackage lifetime plus 14 days of slack for clock skew.
//!
//! Deleting a batch removes each package's openmls bundle and its ML-KEM decapsulation key. Refs
//! whose decapsulation key is already gone were consumed by a Welcome (or lost their key to a
//! crash) and are forgotten after their bundle, if any, is deleted.

use super::{IdentityError, LocalIdentity, PqKeys, MAX_PQ_KEYS, REF_LEN, UPLOAD_BATCH};
use crate::store::ProfileStore;
use powehi_crypto_core::mls_group;

/// Store record holding the batch list.
pub const BATCHES_RECORD: &str = "kp-batches";
/// KeyPackage lifetime on the server (84 days) plus 14 days of slack.
pub const RETENTION_SECS: u64 = (84 + 14) * 24 * 60 * 60;
const VERSION: u8 = 1;
const HEADER_LEN: usize = 3;
const FIXED_BATCH_LEN: usize = 1 + 8 + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BatchState {
    Prepared,
    Sent,
    Confirmed,
}

impl BatchState {
    fn to_byte(self) -> u8 {
        match self {
            BatchState::Prepared => 0,
            BatchState::Sent => 1,
            BatchState::Confirmed => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(BatchState::Prepared),
            1 => Some(BatchState::Sent),
            2 => Some(BatchState::Confirmed),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Batch {
    pub(super) state: BatchState,
    /// Unix seconds of the last state change (ignored while `Prepared`).
    pub(super) since: u64,
    pub(super) refs: Vec<[u8; REF_LEN]>,
}

impl Batch {
    /// A batch is due for deletion when it never left, or its retention has run out.
    fn is_due(&self, now: u64) -> bool {
        match self.state {
            BatchState::Prepared => true,
            BatchState::Sent | BatchState::Confirmed => {
                now >= self.since.saturating_add(RETENTION_SECS)
            }
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Batches {
    pub(super) list: Vec<Batch>,
}

impl Batches {
    /// Wire format: `version(1) || count(u16 BE) || (state(1) || since(u64 BE) || n(1) ||
    /// ref(32)*n)*`.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.list.len() * FIXED_BATCH_LEN);
        out.push(VERSION);
        let n = u16::try_from(self.list.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&n.to_be_bytes());
        for b in &self.list {
            out.push(b.state.to_byte());
            out.extend_from_slice(&b.since.to_be_bytes());
            out.push(u8::try_from(b.refs.len()).unwrap_or(u8::MAX));
            for r in &b.refs {
                out.extend_from_slice(r);
            }
        }
        out
    }

    pub(super) fn decode(raw: &[u8]) -> Result<Self, IdentityError> {
        let bad = || IdentityError::BadKeyRecord;
        if raw.len() < HEADER_LEN || raw[0] != VERSION {
            return Err(bad());
        }
        let count = usize::from(u16::from_be_bytes([raw[1], raw[2]]));
        if count > MAX_PQ_KEYS {
            return Err(bad());
        }
        let (mut rest, mut total_refs) = (&raw[HEADER_LEN..], 0usize);
        let mut list = Vec::with_capacity(count);
        for _ in 0..count {
            if rest.len() < FIXED_BATCH_LEN {
                return Err(bad());
            }
            let state = BatchState::from_byte(rest[0]).ok_or_else(bad)?;
            let since = u64::from_be_bytes(rest[1..9].try_into().map_err(|_| bad())?);
            let n = usize::from(rest[9]);
            total_refs += n;
            if n == 0 || n > UPLOAD_BATCH || total_refs > MAX_PQ_KEYS {
                return Err(bad());
            }
            let body = &rest[FIXED_BATCH_LEN..];
            if body.len() < n * REF_LEN {
                return Err(bad());
            }
            let refs: Vec<[u8; REF_LEN]> = body[..n * REF_LEN].as_chunks::<REF_LEN>().0.to_vec();
            list.push(Batch { state, since, refs });
            rest = &body[n * REF_LEN..];
        }
        if !rest.is_empty() {
            return Err(bad());
        }
        Ok(Self { list })
    }

    pub(super) fn load(store: &ProfileStore) -> Result<Self, IdentityError> {
        match store.get(BATCHES_RECORD)? {
            Some(raw) => Self::decode(&raw),
            None => Ok(Self::default()),
        }
    }

    pub(super) fn save(&self, store: &ProfileStore) -> Result<(), IdentityError> {
        let total: usize = self.list.iter().map(|b| b.refs.len()).sum();
        if total > MAX_PQ_KEYS {
            return Err(IdentityError::TooManyLocalKeys);
        }
        if self.list.is_empty() {
            store.remove(BATCHES_RECORD)?;
        } else {
            store.put(BATCHES_RECORD, &self.encode())?;
        }
        Ok(())
    }
}

/// Records `refs` as `Prepared` batches of at most [`UPLOAD_BATCH`]. Call before the matching
/// private halves are persisted, so a crash in between leaves refs with no keys (harmless)
/// rather than keys with no batch. A crash after the provider save but before the key save leaves
/// bundles with a batch but no decapsulation key; [`prune`] deletes those bundles too.
pub(super) fn record_prepared(
    store: &ProfileStore,
    refs: &[[u8; REF_LEN]],
) -> Result<(), IdentityError> {
    let mut batches = Batches::load(store)?;
    for chunk in refs.chunks(UPLOAD_BATCH) {
        batches.list.push(Batch {
            state: BatchState::Prepared,
            since: 0,
            refs: chunk.to_vec(),
        });
    }
    batches.save(store)
}

/// Moves the batch identified by its first ref to `state`, stamping `now`.
pub(super) fn set_state(
    store: &ProfileStore,
    first_ref: &[u8; REF_LEN],
    state: BatchState,
    now: u64,
) -> Result<(), IdentityError> {
    let mut batches = Batches::load(store)?;
    let batch = batches
        .list
        .iter_mut()
        .find(|b| b.refs.first() == Some(first_ref))
        .ok_or(IdentityError::BadKeyRecord)?;
    debug_assert!(
        state.to_byte() > batch.state.to_byte(),
        "states only advance"
    );
    batch.state = state;
    batch.since = now;
    batches.save(store)
}

/// Deletes every due batch's local keys and forgets consumed refs. Returns how many
/// KeyPackages' keys were deleted. Local only: it never touches the server, so it also runs
/// offline. Provider and decapsulation keys are saved before the batch list, so a crash leaves
/// the list naming refs that are already gone, which the next pass drops.
pub(super) fn prune(store: &ProfileStore, now: u64) -> Result<usize, IdentityError> {
    let mut batches = Batches::load(store)?;
    if batches.list.is_empty() {
        return Ok(0);
    }
    let mut keys = PqKeys::load(store)?;
    let held = |r: &[u8; REF_LEN]| keys.entries.iter().any(|(k, _)| k == r);
    let before = batches.list.clone();
    // No decapsulation key means either a Welcome consumed the package (openmls already deleted
    // its bundle, so deleting again is a no-op) or a crash hit between the provider save and the
    // key save, which leaves a bundle nothing else would ever delete. Delete both cases.
    let mut doomed: Vec<[u8; REF_LEN]> = Vec::new();
    for b in &mut batches.list {
        b.refs.retain(|r| {
            let keep = held(r);
            if !keep {
                doomed.push(*r);
            }
            keep
        });
    }
    batches.list.retain(|b| !b.refs.is_empty());
    let orphaned = doomed.len();
    doomed.extend(
        batches
            .list
            .iter()
            .filter(|b| b.is_due(now))
            .flat_map(|b| b.refs.iter().copied()),
    );
    if !doomed.is_empty() {
        let mut local = LocalIdentity::load(store)?;
        for r in &doomed {
            mls_group::delete_key_package(&local.provider, r)?;
        }
        local.save(store)?;
        keys.entries.retain(|(k, _)| !doomed.contains(k));
        keys.save(store)?;
        batches.list.retain(|b| !b.is_due(now));
    }
    let deleted = doomed.len() - orphaned;
    if batches.list != before {
        batches.save(store)?;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(state: BatchState, since: u64, n: u8) -> Batch {
        Batch {
            state,
            since,
            refs: (0..n).map(|i| [i; REF_LEN]).collect(),
        }
    }

    #[test]
    fn codec_round_trips() {
        let b = Batches {
            list: vec![
                batch(BatchState::Prepared, 0, 10),
                batch(BatchState::Sent, 1_700_000_000, 3),
                batch(BatchState::Confirmed, u64::MAX, 1),
            ],
        };
        assert_eq!(Batches::decode(&b.encode()).unwrap(), b);
        assert_eq!(
            Batches::decode(&Batches::default().encode()).unwrap(),
            Batches::default()
        );
    }

    #[test]
    fn decode_rejects_malformed() {
        let good = Batches {
            list: vec![batch(BatchState::Sent, 5, 2)],
        }
        .encode();
        let mut bad_version = good.clone();
        bad_version[0] = 2;
        let mut bad_state = good.clone();
        bad_state[3] = 3;
        let mut zero_refs = good.clone();
        zero_refs[HEADER_LEN + 9] = 0;
        let mut too_many_refs = good.clone();
        too_many_refs[HEADER_LEN + 9] = (UPLOAD_BATCH + 1) as u8;
        let mut trailing = good.clone();
        trailing.push(0);
        let mut count_over = good.clone();
        count_over[1..3].copy_from_slice(&u16::MAX.to_be_bytes());
        let mut count_short = good.clone();
        count_short[1..3].copy_from_slice(&2u16.to_be_bytes());
        for raw in [
            &bad_version,
            &bad_state,
            &zero_refs,
            &too_many_refs,
            &trailing,
            &count_over,
            &count_short,
            &good[..good.len() - 1].to_vec(),
            &Vec::new(),
        ] {
            assert!(
                matches!(Batches::decode(raw), Err(IdentityError::BadKeyRecord)),
                "{raw:?}"
            );
        }
    }

    #[test]
    fn due_rules() {
        let sent = batch(BatchState::Sent, 1_000, 1);
        assert!(!sent.is_due(1_000 + RETENTION_SECS - 1));
        assert!(sent.is_due(1_000 + RETENTION_SECS));
        assert!(batch(BatchState::Prepared, 0, 1).is_due(0));
        let confirmed = batch(BatchState::Confirmed, u64::MAX, 1);
        assert!(
            !confirmed.is_due(u64::MAX - 1),
            "saturating add must not wrap"
        );
        assert_eq!(RETENTION_SECS, 98 * 86_400);
    }
}
