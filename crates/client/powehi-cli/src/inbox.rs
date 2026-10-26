//! `powehi inbox`: fetch, decrypt, store and acknowledge pending messages (prd.md §7A.2).
//!
//! Welcomes are joined first (`welcome::join_invited`: invite KeyPackages only; Welcomes for pool
//! KeyPackages become pending requests, issue #24). Application envelopes are accepted
//! only for a stored 1:1 conversation and only from its peer device. The joiner's first peer
//! message may be the `pq_init` ML-KEM ciphertext (prd.md §5.3 Phase B): it is decapsulated
//! with the single-use key from the `conv-*` record, which is then discarded; the result is a
//! display-only binding (ADR-0003). Every other message is stored as an `rx-<envelope id>`
//! record in the encrypted profile store. Order per envelope: store records, then MLS state,
//! then ack, so a crash re-processes rather than loses. Nothing here logs message content.

use powehi_crypto_core::{kem, mls_group};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::auth::Session;
use crate::conversation::{self, Kind, Role};
use crate::identity::LocalIdentity;
use crate::invite::InviteError;
use crate::requests;
use crate::store::ProfileStore;
use crate::welcome;

/// Application envelopes processed per call; the rest are picked up on the next call.
pub const MAX_MESSAGES_PER_RUN: usize = 64;
/// Payload `type`s the web client sends that are not messages: presence and typing every
/// 30 s would otherwise fill the store cap, and a `pq_init` is never displayed content.
const EPHEMERAL_TYPES: [&str; 5] = [
    "pq_init",
    "typing_indicator",
    "presence",
    "read_receipt",
    "delivery_receipt",
];
/// Cap on stored, not yet displayed messages. `store::MAX_RECORDS` is 4096; conversations
/// (256), key packages and misc records need the remainder.
pub const MAX_STORED_MESSAGES: usize = 2048;
/// Decrypt attempts per conversation in one run, so one peer cannot starve the others.
pub const MAX_PER_CONVERSATION: usize = 16;
pub(crate) const RX_PREFIX: &str = "rx-";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct InboxReport {
    /// Conversations joined from Welcomes, by group id.
    pub joined: Vec<Uuid>,
    /// New pending requests kept from Welcomes for pool KeyPackages (`powehi requests`).
    pub requests: usize,
    /// Messages decrypted and stored.
    pub stored: usize,
    /// Conversations whose `pq_init` completed (the 16-hex binding is on the conv record).
    pub pq_bound: Vec<Uuid>,
    /// Peer Commits applied (the conversation's epoch advanced).
    pub commits: usize,
    /// Peer Commits refused by the pair policy; the peer's later messages will not decrypt.
    pub forked: usize,
    /// Envelopes left alone: unknown group, wrong sender, undecryptable, or store full.
    pub skipped: usize,
}

/// Writes the [`InboxReport`] as one JSON object (for scripts):
/// `{"joined":[id..],"pq_bindings":{id:"16-hex"},"requests":n,"commits":n,"forked":n,"stored":n,"skipped":n}`.
/// Only ids, the public PQ binding and counts are printed, never message text.
pub fn report_json(
    out: &mut impl std::io::Write,
    report: &InboxReport,
    bindings: &[(Uuid, String)],
) -> std::io::Result<()> {
    let pq: serde_json::Map<String, serde_json::Value> = bindings
        .iter()
        .map(|(id, b)| (id.to_string(), serde_json::Value::from(b.as_str())))
        .collect();
    let obj = serde_json::json!({
        "joined": report.joined.iter().map(Uuid::to_string).collect::<Vec<_>>(),
        "pq_bindings": pq,
        "requests": report.requests,
        "commits": report.commits,
        "forked": report.forked,
        "stored": report.stored,
        "skipped": report.skipped,
    });
    writeln!(out, "{obj}")?;
    out.flush()
}

#[derive(Deserialize)]
struct PqInit {
    #[serde(rename = "type")]
    kind: String,
    ct: Vec<u8>,
}

/// Wire shape of [`Received`] for reading. The body sits in [`WipedBody`] while the other
/// fields parse, so a failure on a later field drops (and wipes) it instead of leaving the
/// decoded bytes in serde's intermediate `Option<Vec<u8>>`.
#[derive(Deserialize)]
struct RawReceived {
    group_id: Uuid,
    sender: Uuid,
    body: WipedBody,
    #[serde(default)]
    received_at: u64,
}

struct WipedBody(Vec<u8>);

impl<'de> Deserialize<'de> for WipedBody {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        body_hex::deserialize(d).map(WipedBody)
    }
}

impl Drop for WipedBody {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<RawReceived> for Received {
    fn from(mut raw: RawReceived) -> Self {
        Received {
            group_id: raw.group_id,
            sender: raw.sender,
            body: std::mem::take(&mut raw.body.0),
            received_at: raw.received_at,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(from = "RawReceived")]
pub(crate) struct Received {
    pub(crate) group_id: Uuid,
    pub(crate) sender: Uuid,
    #[serde(with = "body_hex")]
    pub(crate) body: Vec<u8>,
    /// Local receive time, nanoseconds since the Unix epoch; orders display (0 = unknown).
    #[serde(default)]
    pub(crate) received_at: u64,
}

impl Received {
    /// Fixed JSON overhead: two hyphenated UUIDs, `received_at`, keys and punctuation.
    const JSON_OVERHEAD: usize = 192;

    /// The stored JSON, written into a buffer sized up front so it never reallocates: a
    /// growing `Vec` would leave unwiped copies of the body behind (hex doubles it, and
    /// needs no escaping, so `2 * len + overhead` always fits).
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, serde_json::Error> {
        if self.body.len() > body_hex::MAX_BODY_BYTES {
            return Err(serde::ser::Error::custom("body too long"));
        }
        let cap = self.body.len() * 2 + Self::JSON_OVERHEAD;
        let mut out = Zeroizing::new(Vec::with_capacity(cap));
        let allocated = out.capacity();
        serde_json::to_writer(&mut *out, self)?;
        debug_assert_eq!(out.capacity(), allocated, "encode reallocated");
        Ok(out)
    }
}

impl Drop for Received {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

enum Outcome {
    Stored,
    PqBound,
    Skip,
    /// Consumed protocol or ephemeral traffic that is not a message (acked, not stored).
    Dropped,
    /// A pending request's group: nothing to do yet; costs no budget.
    Ignored,
    /// Not ours (unknown group, or not from the conversation's peer): acked after a grace.
    Unknown,
    /// A known peer's envelope that did not decrypt: acked after repeated failures.
    Undecryptable,
    /// A known peer's envelope from an epoch we have not reached (a Commit is missing): held,
    /// never counted as a failure, acked only after the grace.
    Ahead,
}

/// Joins pending Welcomes, then processes pending Application messages.
pub async fn receive(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<InboxReport, InviteError> {
    receive_at(client, server, session, requests::now_secs()).await
}

/// [`receive`] with the clock injected (seconds since the Unix epoch).
async fn receive_at(
    client: &Client,
    server: &Url,
    session: &Session,
    now: u64,
) -> Result<InboxReport, InviteError> {
    // Expired requests go first so their slots are free for newly arrived Welcomes.
    if let Ok(dropped) = requests::prune_expired(&session.store, now) {
        for envelope in dropped {
            let _ = welcome::ack(client, server, session, envelope).await;
        }
    }
    let joined = welcome::join_invited(client, server, session).await?;
    let mut report = InboxReport {
        joined: joined.joined,
        requests: joined.requested,
        ..InboxReport::default()
    };
    let saved = cursor::load(&session.store);
    let resumed = saved.is_some();
    let hops = saved.as_ref().map_or(0, |(_, h)| *h);
    let window = match welcome::fetch_from(client, server, session, saved.map(|(c, _)| c)).await {
        Ok(w) => w,
        Err(e) => {
            // A cursor the server rejects must not wedge the inbox: retry from the head.
            if resumed {
                cursor::save(&session.store, None);
            }
            return Err(e);
        }
    };
    let (items, next, more) = (window.items, window.next, window.more);
    // True once an envelope was held back (run caps): the cursor must not move past it.
    let mut deferred = false;
    // True while a held Ahead envelope is young enough to keep the cursor at the head.
    let mut ahead_pinned = false;
    // A local cache of timers: unreadable or unwritable must never fail the run.
    let mut tracker = junk::Tracker::load(&session.store).unwrap_or_default();
    tracker.prune(now);
    // Welcomes that cannot be joined (no such KeyPackage, bad key, group already held) would
    // sit in the fetch window until the server expires them: ack them after the grace.
    for id in joined.unusable {
        if tracker.unknown_expired(id, now)
            && welcome::ack(client, server, session, id).await.is_ok()
        {
            tracker.forget(id);
        }
    }
    // Only real work (a decrypt attempt on a known conversation) spends the per-run budget;
    // envelopes for unknown groups or other senders are free local lookups, so a stranger's
    // junk broadcasts cannot crowd real messages out of the run.
    let mut attempts = 0;
    let mut per_conv: std::collections::HashMap<Uuid, usize> = std::collections::HashMap::new();
    // Application envelopes from an epoch we have not reached yet, kept for a retry right after
    // the Commit that makes them readable (groups keep no past epochs, so order matters).
    let mut held: Vec<welcome::Envelope> = Vec::new();
    let mut blocked: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<welcome::Envelope> = items.into();
    while let Some(env) = queue.pop_front() {
        if env.message_type == "Welcome" {
            continue;
        }
        if env.message_type == "Commit" {
            // Head-of-line: an envelope of this group already waits for the next run (cap or
            // full store), and the Commit would advance the epoch past it (no past epochs).
            if attempts >= MAX_MESSAGES_PER_RUN {
                deferred = true;
                break;
            }
            attempts += 1;
            if env.group_id.is_some_and(|g| blocked.contains(&g)) {
                deferred = true;
                report.skipped += 1;
                continue;
            }
            let applied =
                match handle_commit(client, server, session, &env, &mut tracker, now).await {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = tracker.save(&session.store);
                        return Err(e);
                    }
                };
            if applied == Applied::Forked {
                report.forked += 1;
            }
            if let Applied::Yes(group_id) = applied {
                report.commits += 1;
                let (retry, keep): (Vec<_>, Vec<_>) =
                    held.into_iter().partition(|h| h.group_id == Some(group_id));
                held = keep;
                for h in retry.into_iter().rev() {
                    queue.push_front(h);
                }
            } else {
                report.skipped += 1;
            }
            continue;
        }
        if env.message_type != "Application" {
            // A pair conversation never applies Proposals (the pair policy takes only a peer's
            // self-Update Commit), so a peer Proposal is dead weight: acked after the same
            // grace as any other junk. Anything else from our peer waits; the rest is acked
            // after the grace.
            if let Some(id) = env.id {
                if !is_group_conversation(session, env.group_id)
                    && (env.message_type == "Proposal"
                        || !is_peer_traffic(session, env.group_id, env.sender))
                    && tracker.unknown_expired(id, now)
                    && welcome::ack(client, server, session, id).await.is_ok()
                {
                    tracker.forget(id);
                }
            }
            report.skipped += 1;
            continue;
        }
        if attempts >= MAX_MESSAGES_PER_RUN {
            deferred = true;
            break;
        }
        let (Some(id), Some(group_id), Some(sender), Some(ct)) =
            (env.id, env.group_id, env.sender, env.ciphertext.as_deref())
        else {
            report.skipped += 1;
            continue;
        };
        if sender == session.device_id {
            // Our own broadcast echoed back: never decryptable here, never needed again.
            attempts += 1;
            let _ = welcome::ack(client, server, session, id).await;
            tracker.forget(id);
            continue;
        }
        // One peer cannot use the whole run: the rest of its envelopes wait for the next one.
        let used = per_conv.entry(group_id).or_insert(0);
        if *used >= MAX_PER_CONVERSATION {
            blocked.insert(group_id);
            deferred = true;
            report.skipped += 1;
            continue;
        }
        let outcome = match process_one(session, id, group_id, sender, ct) {
            Ok(o) => o,
            Err(e) => {
                let _ = tracker.save(&session.store);
                return Err(e);
            }
        };
        if !matches!(outcome, Outcome::Ignored | Outcome::Unknown) {
            *used += 1;
        }
        match outcome {
            Outcome::Ignored => report.skipped += 1,
            Outcome::Unknown => {
                report.skipped += 1;
                if tracker.unknown_expired(id, now)
                    && welcome::ack(client, server, session, id).await.is_ok()
                {
                    tracker.forget(id);
                }
            }
            Outcome::Undecryptable => {
                attempts += 1;
                report.skipped += 1;
                if tracker.failed(id, now)
                    && welcome::ack(client, server, session, id).await.is_ok()
                {
                    tracker.forget(id);
                }
            }
            Outcome::Ahead => {
                attempts += 1;
                report.skipped += 1;
                if held.len() < MAX_MESSAGES_PER_RUN {
                    held.push(env.clone());
                }
                ahead_pinned |= tracker.ahead_pins(id, now);
                // Not a failure: the Commit that makes it readable may still arrive. While our
                // own Commit is unresolved (`pcs-` record) the gap may be that Commit: never ack.
                if !pcs_unresolved(session, group_id)
                    && tracker.unknown_expired(id, now)
                    && welcome::ack(client, server, session, id).await.is_ok()
                {
                    tracker.forget(id);
                }
            }
            Outcome::Skip => {
                blocked.insert(group_id);
                deferred = true;
                attempts += 1;
                report.skipped += 1;
            }
            Outcome::Dropped => {
                attempts += 1;
                tracker.forget(id);
                let _ = welcome::ack(client, server, session, id).await;
            }
            done => {
                attempts += 1;
                tracker.forget(id);
                match done {
                    Outcome::PqBound => report.pq_bound.push(group_id),
                    _ => report.stored += 1,
                }
                // Already persisted; a failed ack only leaves a duplicate that fails to
                // decrypt (and is dropped by the junk tracker) later.
                let _ = welcome::ack(client, server, session, id).await;
            }
        }
    }
    // A young held envelope still waits for its Commit: keep the cursor so it is seen again.
    // Past the bound it is revisited at the next head rescan instead (#30).
    deferred |= ahead_pinned;
    let _ = tracker.save(&session.store);
    // Window exhausted and nothing deferred: resume behind it. End of queue: back to the head.
    // Deferred work keeps the old cursor so it is seen again.
    if more && !deferred {
        cursor::save(&session.store, next.as_ref().map(|c| (c, hops + 1)));
    } else if !more {
        cursor::save(&session.store, None);
    }
    Ok(report)
}

/// A Commit envelope. [`Applied::Yes`] when it was applied (the epoch advanced). Own echoes are
/// acked at once (the sender is not in the server's required-ack set); a peer Commit that cannot apply yet (later epoch) is held and acked only
/// after the grace; one that is refused or invalid counts as a failure (acked after repeated
/// failures and the grace); anything not from a held conversation's peer is acked after the
/// grace as junk.
async fn handle_commit(
    client: &Client,
    server: &Url,
    session: &Session,
    env: &welcome::Envelope,
    tracker: &mut junk::Tracker,
    now: u64,
) -> Result<Applied, InviteError> {
    let (Some(id), Some(group_id), Some(sender), Some(ct)) =
        (env.id, env.group_id, env.sender, env.ciphertext.as_deref())
    else {
        return Ok(Applied::No);
    };
    if sender == session.device_id {
        let _ = welcome::ack(client, server, session, id).await;
        tracker.forget(id);
        return Ok(Applied::No);
    }
    if is_group_conversation(session, Some(group_id)) {
        return Ok(Applied::No);
    }
    let outcome = if is_peer_traffic(session, Some(group_id), Some(sender)) {
        commit::apply(session, group_id, sender, ct)?
    } else {
        commit::Outcome::Unknown
    };
    let mut forked = false;
    let ahead = matches!(outcome, commit::Outcome::Ahead);
    let expired = match outcome {
        commit::Outcome::Applied => {
            tracker.forget(id);
            let _ = welcome::ack(client, server, session, id).await;
            return Ok(Applied::Yes(group_id));
        }
        commit::Outcome::Refused => tracker.failed(id, now),
        commit::Outcome::Forked => {
            forked = true;
            tracker.failed(id, now)
        }
        commit::Outcome::Ahead | commit::Outcome::Unknown => tracker.unknown_expired(id, now),
    };
    // A Commit from a later epoch may only be readable after our own unresolved Commit merges
    // (one Commit per epoch, RFC 9420 §14): hold it. Refused/Forked/Unknown never become
    // applicable by that, so they keep the normal grace.
    let hold = ahead && pcs_unresolved(session, group_id);
    if expired && !hold && welcome::ack(client, server, session, id).await.is_ok() {
        tracker.forget(id);
    }
    Ok(if forked { Applied::Forked } else { Applied::No })
}

#[derive(PartialEq, Eq)]
enum Applied {
    Yes(Uuid),
    No,
    Forked,
}

/// True while a self-Update Commit of `group_id` is unresolved. Fail closed: an unreadable store
/// counts as unresolved, so nothing is acked on a guess.
fn pcs_unresolved(session: &Session, group_id: Uuid) -> bool {
    crate::pcs::has_pending(&session.store, group_id).unwrap_or(true)
}

/// True when `group_id` is a stored group-kind conversation. Fail closed: an unreadable record
/// counts as a group, so nothing of it is acked on a guess. Group traffic is not applied or
/// acked until group receive lands (8.17), because another member's Commit or message is not
/// "the peer's" and must not be dropped as junk.
fn is_group_conversation(session: &Session, group_id: Option<Uuid>) -> bool {
    let Some(group_id) = group_id else {
        return false;
    };
    match conversation::load(&session.store, &group_id) {
        Ok(Some(c)) => c.kind() == Kind::Group,
        // Not joined yet: a pending request (up to 5 days) keeps its group's traffic unacked,
        // or a late `accept` would join a Welcome epoch the other members have left.
        Ok(None) => requests::load(&session.store, &group_id)
            .map(|r| r.is_some())
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// True when `group_id` is a stored pair conversation and `sender` is its peer device.
fn is_peer_traffic(session: &Session, group_id: Option<Uuid>, sender: Option<Uuid>) -> bool {
    let (Some(group_id), Some(sender)) = (group_id, sender) else {
        return false;
    };
    // Fail closed: an unreadable record counts as peer traffic, which is never acked here.
    match conversation::load(&session.store, &group_id) {
        Ok(conv) => conv.is_some_and(|c| c.kind() == Kind::Pair && c.peer_device_id == sender),
        Err(_) => true,
    }
}

fn process_one(
    session: &Session,
    id: Uuid,
    group_id: Uuid,
    sender: Uuid,
    ciphertext: &[u8],
) -> Result<Outcome, InviteError> {
    let store = &session.store;
    let Some(mut conv) = conversation::load(store, &group_id)? else {
        return Ok(
            if requests::load(store, &group_id).ok().flatten().is_some() {
                Outcome::Ignored
            } else {
                Outcome::Unknown
            },
        );
    };
    if conv.kind() != Kind::Pair {
        // Not the peer's: never decrypted as a pair message and never acked (see
        // `is_group_conversation`).
        return Ok(Outcome::Ignored);
    }
    if conv.peer_device_id != sender {
        return Ok(Outcome::Unknown);
    }
    if stored_count(store)? >= MAX_STORED_MESSAGES {
        return Ok(Outcome::Skip);
    }
    // A fresh provider per envelope: a failed decrypt must not leave half-advanced state in
    // memory for a later successful `save` to persist.
    let mut local = LocalIdentity::load(store)?;
    let Some(mut group) = mls_group::load_group(group_id.as_bytes(), &local.provider)? else {
        return Ok(Outcome::Skip);
    };
    // Sender authentication rests on the group being exactly this pair (only Commits that
    // keep it a pair are applied, `mls_group::apply_pair_commit`), so every application
    // message is from the peer; `decrypt_message` does not expose the sender leaf.
    if !mls_group::is_pair_with(&group, &local.identity.signer.to_public_vec()) {
        return Ok(Outcome::Skip);
    }
    let plain: Zeroizing<Vec<u8>> =
        match mls_group::decrypt_message(&mut group, ciphertext, &local.provider) {
            Ok(p) => p,
            Err(mls_group::MlsError::EpochAhead) => return Ok(Outcome::Ahead),
            Err(_) => return Ok(Outcome::Undecryptable),
        };
    let awaiting_pq = conv.role == Role::Joiner && conv.pq_decap_key().is_some();
    if awaiting_pq {
        if let Some(binding) = pq_binding(&conv, &plain, group_id) {
            conv.complete_pq(binding);
            conversation::save(store, &conv)?;
            local.save(store)?;
            return Ok(Outcome::PqBound);
        }
    }
    if is_ephemeral(&plain) {
        local.save(store)?;
        return Ok(Outcome::Dropped);
    }
    let name = format!("{RX_PREFIX}{}", id.hyphenated());
    let rec = Received {
        group_id,
        sender,
        body: plain.to_vec(),
        received_at: now_nanos(),
    }
    .encode()
    .map_err(|_| InviteError::BadResponse)?;
    // The envelope id is server-chosen: never overwrite a stored message with different bytes.
    match store.get(&name)? {
        // A re-run after a crash between `put` and the MLS save: same content (the receive
        // time legitimately differs), so fall through to save the ratchet and ack.
        Some(old) if !same_message(&old, &plain, group_id, sender) => return Ok(Outcome::Skip),
        Some(_) => {}
        None => store.put(&name, &rec)?,
    }
    local.save(store)?;
    Ok(Outcome::Stored)
}

/// The binding when `plain` is a well-formed `pq_init` that decapsulates with the stored key.
/// The shared secret is zeroized on return; anything else is an ordinary message.
fn pq_binding(conv: &conversation::Conversation, plain: &[u8], group_id: Uuid) -> Option<String> {
    let init: PqInit = serde_json::from_slice(plain).ok()?;
    if init.kind != "pq_init" {
        return None;
    }
    let ss = kem::decapsulate(conv.pq_decap_key()?, &init.ct).ok()?;
    kem::derive_pq_binding(&ss, &group_id.hyphenated().to_string()).ok()
}

/// True when the stored record `old` holds exactly this group, sender and plaintext.
fn same_message(old: &[u8], plain: &[u8], group_id: Uuid, sender: Uuid) -> bool {
    serde_json::from_slice::<Received>(old)
        .is_ok_and(|r| r.group_id == group_id && r.sender == sender && r.body == plain)
}

/// True for a JSON object whose `type` is one of [`EPHEMERAL_TYPES`].
fn is_ephemeral(plain: &[u8]) -> bool {
    #[derive(Deserialize)]
    struct Typed {
        #[serde(rename = "type")]
        kind: String,
    }
    serde_json::from_slice::<Typed>(plain).is_ok_and(|t| EPHEMERAL_TYPES.contains(&t.kind.as_str()))
}

fn now_nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_nanos()).ok())
        .unwrap_or(0)
}

fn stored_count(store: &ProfileStore) -> Result<usize, InviteError> {
    Ok(store
        .names()?
        .iter()
        .filter(|n| n.starts_with(RX_PREFIX))
        .count())
}

mod body_hex;
mod commit;
mod cursor;
mod junk;

#[cfg(test)]
mod tests;
