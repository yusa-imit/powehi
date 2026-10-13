//! Joining conversations from pending Welcome envelopes (prd.md §4.2).
//!
//! For each Welcome the device (1) finds the KeyPackage it consumes and the ML-KEM key that
//! package published, (2) looks up the matching decapsulation key by KeyPackageRef and checks
//! it (FIPS 203 §7.3 hash plus equality with the published key) BEFORE any decapsulation can
//! use it, (3) joins, (4) moves the key into the conversation record and prunes it from
//! `pq-keys`, and only then (5) acks the envelope. Welcome bytes are never logged.

use powehi_crypto_core::{kem, mls_group};
use reqwest::Client;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Conversation, Role};
use crate::identity::{self, IdentityError, LocalIdentity};
use crate::invite::InviteError;

/// Largest `GET /v1/messages` page accepted. Welcomes are a few KB each as JSON integer arrays.
pub const MAX_POLL_BYTES: usize = 16 * 1024 * 1024;
/// Welcomes processed per call; the rest are picked up on the next call.
pub const MAX_WELCOMES_PER_RUN: usize = 16;
const ACK_BODY: usize = 4 * 1024;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct JoinReport {
    /// Conversations joined, by group id.
    pub joined: Vec<Uuid>,
    /// Welcomes left unacked: no matching local KeyPackage, bad key, or a mismatched group.
    pub skipped: usize,
}

/// Pages fetched per call. The server returns at most 64 envelopes per page in ascending
/// `(created_at, id)` order and never skips acked ones, so un-acked skipped envelopes at the
/// head (own broadcasts, junk groups) must be paged past or they would starve newer ones.
pub(crate) const MAX_PAGES: usize = 4;
/// The server's page size is 64; a page beyond twice that is a misbehaving server.
const MAX_PAGE_ENVELOPES: usize = 128;
/// Longest cursor timestamp accepted back from the server (RFC 3339 with nanoseconds fits).
const MAX_CURSOR_LEN: usize = 64;

/// Typed (not `Value`) so a hostile page cannot blow up memory: ~1 byte per ciphertext byte.
#[derive(Deserialize)]
pub(crate) struct Envelope {
    pub message_type: String,
    pub id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub sender: Option<Uuid>,
    pub ciphertext: Option<Vec<u8>>,
    created_at: Option<String>,
}

/// Fetches up to [`MAX_PAGES`] pages of pending envelopes, following the server's
/// `(since, since_id)` keyset cursor taken from the last envelope of each page.
pub(crate) async fn fetch_pending(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<Vec<Envelope>, InviteError> {
    let mut all: Vec<Envelope> = Vec::new();
    let mut cursor: Option<(String, Uuid)> = None;
    for _ in 0..MAX_PAGES {
        let mut url = server
            .join("/v1/messages")
            .map_err(|_| InviteError::BadResponse)?;
        if let Some((since, since_id)) = &cursor {
            url.query_pairs_mut()
                .append_pair("since", since)
                .append_pair("since_id", &since_id.to_string());
        }
        let raw = identity::send_raw(client.get(url), session, MAX_POLL_BYTES).await?;
        let page: Vec<Envelope> =
            serde_json::from_slice(&raw).map_err(|_| InviteError::BadResponse)?;
        if page.len() > MAX_PAGE_ENVELOPES {
            return Err(InviteError::BadResponse);
        }
        let next = page
            .last()
            .and_then(|e| Some((e.created_at.clone()?, e.id?)))
            .filter(|(since, _)| since.len() <= MAX_CURSOR_LEN);
        all.extend(page);
        match next {
            // No progress (server ignored the cursor, or no timestamp): stop, don't spin.
            Some(n) if cursor.as_ref() != Some(&n) => cursor = Some(n),
            _ => break,
        }
    }
    Ok(all)
}

/// Fetches pending envelopes and joins every Welcome addressed to one of our KeyPackages, or,
/// with `only_ref`, only the Welcome that consumes that exact KeyPackage (an invite's package,
/// so a pool package handed to a stranger cannot masquerade as the invite being waited on).
pub async fn join_pending(
    client: &Client,
    server: &Url,
    session: &Session,
    only_ref: Option<&[u8]>,
) -> Result<JoinReport, InviteError> {
    let items = fetch_pending(client, server, session).await?;
    let mut report = JoinReport::default();
    for env in items.into_iter().filter(|e| e.message_type == "Welcome") {
        // Only joins count toward the cap; skipped ones cost one cheap local check each and
        // the page itself is bounded by the server's page size and MAX_POLL_BYTES.
        if report.joined.len() >= MAX_WELCOMES_PER_RUN {
            break;
        }
        let (Some(id), Some(group_id), Some(sender), Some(ciphertext)) =
            (env.id, env.group_id, env.sender, env.ciphertext)
        else {
            report.skipped += 1;
            continue;
        };
        let env = Joinable {
            group_id,
            sender,
            ciphertext,
        };
        match join_one(session, &env, only_ref) {
            Ok(group_id) => {
                report.joined.push(group_id);
                // The join is already persisted; a failed ack only leaves a stale envelope
                // that is skipped (its KeyPackage is consumed) until server-side expiry.
                let _ = ack(client, server, session, id).await;
            }
            Err(JoinOutcome::Skip) => report.skipped += 1,
            Err(JoinOutcome::Fatal(e)) => return Err(e),
        }
    }
    Ok(report)
}

struct Joinable {
    group_id: Uuid,
    sender: Uuid,
    ciphertext: Vec<u8>,
}

enum JoinOutcome {
    /// This Welcome cannot be joined; leave it for server-side expiry and carry on.
    Skip,
    /// Local storage failed; stop rather than risk acking over lost state.
    Fatal(InviteError),
}

impl From<IdentityError> for JoinOutcome {
    fn from(e: IdentityError) -> Self {
        JoinOutcome::Fatal(e.into())
    }
}

fn join_one(
    session: &Session,
    env: &Joinable,
    only_ref: Option<&[u8]>,
) -> Result<Uuid, JoinOutcome> {
    // A fresh provider per Welcome: a rejected join must not leave state in memory that a
    // later successful `save` would persist.
    let mut local = LocalIdentity::load(&session.store)?;
    let binding = mls_group::welcome_pq_binding(&env.ciphertext, &local.provider)
        .map_err(|_| JoinOutcome::Skip)?;
    if only_ref.is_some_and(|r| r != binding.key_package_ref.as_slice()) {
        return Err(JoinOutcome::Skip);
    }
    let dk =
        identity::pq_key_for(&session.store, &binding.key_package_ref)?.ok_or(JoinOutcome::Skip)?;
    kem::validate_decap_key(&dk, &binding.encap_key).map_err(|_| JoinOutcome::Skip)?;
    let group =
        mls_group::join_group(&env.ciphertext, &local.provider).map_err(|_| JoinOutcome::Skip)?;
    let group_id = Uuid::from_slice(group.group_id().as_slice()).map_err(|_| JoinOutcome::Skip)?;
    // 1:1 only: a Welcome that seats extra members (a ghost) is not our conversation.
    if !mls_group::is_fresh_pair(&group) {
        return Err(JoinOutcome::Skip);
    }
    // The server labels envelopes; the MLS group id inside the Welcome is authoritative.
    if group_id != env.group_id {
        return Err(JoinOutcome::Skip);
    }
    let conv = Conversation::new(
        group_id,
        env.sender,
        Role::Joiner,
        Some((dk, binding.encap_key.clone())),
    );
    let fatal = |e: InviteError| JoinOutcome::Fatal(e);
    // Conversation record first, then MLS state, then prune: a crash in between leaves the
    // KeyPackage and its key intact so the same Welcome can be joined again.
    conversation::save(&session.store, &conv).map_err(|e| fatal(e.into()))?;
    local.save(&session.store)?;
    identity::prune_pq_key(&session.store, &binding.key_package_ref)?;
    Ok(group_id)
}

pub(crate) async fn ack(
    client: &Client,
    server: &Url,
    session: &Session,
    id: Uuid,
) -> Result<(), InviteError> {
    let url = server
        .join(&format!("/v1/messages/{id}"))
        .map_err(|_| InviteError::BadResponse)?;
    identity::send_raw(client.delete(url), session, ACK_BODY).await?;
    Ok(())
}

#[cfg(test)]
mod tests;
