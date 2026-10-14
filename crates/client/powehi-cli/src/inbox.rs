//! `powehi inbox`: fetch, decrypt, store and acknowledge pending messages (prd.md §7A.2).
//!
//! Welcomes are joined first (`welcome::join_invited`: invite KeyPackages only, issue #24). Application envelopes are accepted
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
use crate::conversation::{self, Role};
use crate::identity::LocalIdentity;
use crate::invite::InviteError;
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
pub(crate) const RX_PREFIX: &str = "rx-";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct InboxReport {
    /// Conversations joined from Welcomes, by group id.
    pub joined: Vec<Uuid>,
    /// Messages decrypted and stored.
    pub stored: usize,
    /// Conversations whose `pq_init` completed (the 16-hex binding is on the conv record).
    pub pq_bound: Vec<Uuid>,
    /// Envelopes left alone: unknown group, wrong sender, undecryptable, or store full.
    pub skipped: usize,
}

#[derive(Deserialize)]
struct PqInit {
    #[serde(rename = "type")]
    kind: String,
    ct: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Received {
    pub(crate) group_id: Uuid,
    pub(crate) sender: Uuid,
    #[serde(with = "body_hex")]
    pub(crate) body: Vec<u8>,
    /// Local receive time, nanoseconds since the Unix epoch; orders display (0 = unknown).
    #[serde(default)]
    pub(crate) received_at: u64,
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
    /// Not ours to process (unknown conversation or not from its peer); costs no budget.
    Ignored,
}

/// Joins pending Welcomes, then processes pending Application messages.
pub async fn receive(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<InboxReport, InviteError> {
    let joined = welcome::join_invited(client, server, session).await?;
    let mut report = InboxReport {
        joined: joined.joined,
        ..InboxReport::default()
    };
    let items = welcome::fetch_pending(client, server, session).await?;
    // Only real work (a decrypt attempt on a known conversation) spends the per-run budget;
    // envelopes for unknown groups or other senders are free local lookups, so a stranger's
    // junk broadcasts cannot crowd real messages out of the run.
    let mut attempts = 0;
    for env in items
        .into_iter()
        .filter(|e| e.message_type == "Application")
    {
        if attempts >= MAX_MESSAGES_PER_RUN {
            break;
        }
        let (Some(id), Some(group_id), Some(sender), Some(ct)) =
            (env.id, env.group_id, env.sender, env.ciphertext)
        else {
            report.skipped += 1;
            continue;
        };
        if sender == session.device_id {
            // Our own broadcast echoed back: never decryptable here, never needed again.
            attempts += 1;
            let _ = welcome::ack(client, server, session, id).await;
            continue;
        }
        match process_one(session, id, group_id, sender, &ct)? {
            Outcome::Ignored => report.skipped += 1,
            Outcome::Skip => {
                attempts += 1;
                report.skipped += 1;
            }
            Outcome::Dropped => {
                attempts += 1;
                let _ = welcome::ack(client, server, session, id).await;
            }
            done => {
                attempts += 1;
                match done {
                    Outcome::PqBound => report.pq_bound.push(group_id),
                    _ => report.stored += 1,
                }
                // Already persisted; a failed ack only leaves a duplicate that fails to
                // decrypt (and is skipped) until server-side expiry.
                let _ = welcome::ack(client, server, session, id).await;
            }
        }
    }
    Ok(report)
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
        return Ok(Outcome::Ignored);
    };
    if conv.peer_device_id != sender {
        return Ok(Outcome::Ignored);
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
    // Sender authentication rests on the group being exactly the original pair at epoch 1
    // (RFC 9420 §6.3.2: no Commit is ever applied here), so every application message is
    // from the peer; `decrypt_message` does not expose the sender leaf.
    if !mls_group::is_fresh_pair(&group) {
        return Ok(Outcome::Skip);
    }
    let Ok(plain) = mls_group::decrypt_message(&mut group, ciphertext, &local.provider) else {
        return Ok(Outcome::Skip);
    };
    let plain = Zeroizing::new(plain);
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
    let rec = Zeroizing::new(
        serde_json::to_vec(&Received {
            group_id,
            sender,
            body: plain.to_vec(),
            received_at: now_nanos(),
        })
        .map_err(|_| InviteError::BadResponse)?,
    );
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

#[cfg(test)]
mod tests;
