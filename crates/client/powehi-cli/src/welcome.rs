//! Joining conversations from pending Welcome envelopes (prd.md §4.2).
//!
//! For each Welcome the device (1) finds the KeyPackage it consumes and the ML-KEM key that
//! package published, (2) looks up the matching decapsulation key by KeyPackageRef and checks
//! it (FIPS 203 §7.3 hash plus equality with the published key) BEFORE any decapsulation can
//! use it, (3) joins, (4) moves the key into the conversation record and prunes it from
//! `pq-keys`, and only then (5) acks the envelope. Welcome bytes are never logged.

use powehi_crypto_core::safety::GROUP_MAX_MEMBERS;
use powehi_crypto_core::{kem, mls_group};
use reqwest::Client;
use serde::Deserialize;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, Conversation, ConversationError, Role};
use crate::identity::{self, IdentityError, LocalIdentity};
use crate::invite::InviteError;
use crate::requests;

/// Largest `GET /v1/messages` page accepted. Welcomes are a few KB each as JSON integer arrays.
pub const MAX_POLL_BYTES: usize = 16 * 1024 * 1024;
/// Welcomes processed per call; the rest are picked up on the next call.
pub const MAX_WELCOMES_PER_RUN: usize = 16;
const ACK_BODY: usize = 4 * 1024;
/// Attempts at the idempotent accept call before the join is reported as unconfirmed.
const ACCEPT_ATTEMPTS: usize = 3;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct JoinReport {
    /// Conversations joined, by group id.
    pub joined: Vec<Uuid>,
    /// Welcomes left unacked: no matching local KeyPackage, bad key, or a mismatched group.
    pub skipped: usize,
    /// Welcomes for our pool KeyPackages newly kept as pending requests (8.12).
    pub requested: usize,
    /// Ids of the skipped Welcomes (at most [`MAX_UNUSABLE`]): `inbox` acks them after a grace.
    pub unusable: Vec<Uuid>,
}

/// Cap on [`JoinReport::unusable`]; a fetch window holds at most `MAX_PAGES * 128` envelopes.
pub(crate) const MAX_UNUSABLE: usize = 512;

/// Pages fetched per call. The server returns at most 64 envelopes per page in ascending
/// `(created_at, id)` order and never skips acked ones, so un-acked skipped envelopes at the
/// head (own broadcasts, junk groups) must be paged past or they would starve newer ones.
pub(crate) const MAX_PAGES: usize = 4;
/// The server's page size is 64; a page beyond twice that is a misbehaving server.
const MAX_PAGE_ENVELOPES: usize = 128;
/// Longest cursor timestamp accepted back from the server (RFC 3339 with nanoseconds fits).
const MAX_CURSOR_LEN: usize = 64;

/// Typed (not `Value`) so a hostile page cannot blow up memory: ~1 byte per ciphertext byte.
#[derive(Deserialize, Clone)]
pub(crate) struct Envelope {
    pub message_type: String,
    pub id: Option<Uuid>,
    pub group_id: Option<Uuid>,
    pub sender: Option<Uuid>,
    pub ciphertext: Option<Vec<u8>>,
    created_at: Option<String>,
}

/// A position in the server's `(created_at, id)` keyset order: fetch resumes after it.
#[derive(serde::Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub(crate) struct Cursor {
    pub since: String,
    pub since_id: Uuid,
}

impl Cursor {
    /// True for a cursor the server could have issued (bounded RFC 3339 characters only).
    pub(crate) fn is_sane(&self) -> bool {
        !self.since.is_empty()
            && self.since.len() <= MAX_CURSOR_LEN
            && self
                .since
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'-' | b':' | b'T' | b'Z' | b'.' | b'+'))
    }
}

/// What one fetch saw: the envelopes, the cursor after the last one, and whether the page
/// budget ran out before the server's queue did (more may wait beyond `next`).
pub(crate) struct Window {
    pub items: Vec<Envelope>,
    pub next: Option<Cursor>,
    pub more: bool,
}

/// Fetches up to [`MAX_PAGES`] pages of pending envelopes from the head of the queue.
pub(crate) async fn fetch_pending(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<Vec<Envelope>, InviteError> {
    Ok(fetch_from(client, server, session, None).await?.items)
}

/// [`fetch_pending`] resuming after `start`, following the server's `(since, since_id)` keyset
/// cursor taken from the last envelope of each page.
pub(crate) async fn fetch_from(
    client: &Client,
    server: &Url,
    session: &Session,
    start: Option<Cursor>,
) -> Result<Window, InviteError> {
    let mut all: Vec<Envelope> = Vec::new();
    let mut cursor = start.filter(Cursor::is_sane);
    let mut more = false;
    for page_no in 0..MAX_PAGES {
        let mut url = server
            .join("/v1/messages")
            .map_err(|_| InviteError::BadResponse)?;
        if let Some(c) = &cursor {
            url.query_pairs_mut()
                .append_pair("since", &c.since)
                .append_pair("since_id", &c.since_id.to_string());
        }
        let raw = identity::send_raw(client.get(url), session, MAX_POLL_BYTES).await?;
        let page: Vec<Envelope> =
            serde_json::from_slice(&raw).map_err(|_| InviteError::BadResponse)?;
        if page.len() > MAX_PAGE_ENVELOPES {
            return Err(InviteError::BadResponse);
        }
        let next = page
            .last()
            .and_then(|e| {
                Some(Cursor {
                    since: e.created_at.clone()?,
                    since_id: e.id?,
                })
            })
            .filter(Cursor::is_sane);
        all.extend(page);
        match next {
            // No progress (server ignored the cursor, or no timestamp): stop, don't spin.
            Some(n) if cursor.as_ref() != Some(&n) => {
                cursor = Some(n);
                more = page_no + 1 == MAX_PAGES;
            }
            _ => break,
        }
    }
    Ok(Window {
        items: all,
        next: cursor,
        more,
    })
}

/// Permissive: no invite-marker check (inbox must use [`join_invited`]). Fetches pending envelopes and joins every Welcome addressed to one of our KeyPackages, or,
/// with `only_ref`, only the Welcome that consumes that exact KeyPackage (an invite's package,
/// so a pool package handed to a stranger cannot masquerade as the invite being waited on).
pub async fn join_pending(
    client: &Client,
    server: &Url,
    session: &Session,
    only_ref: Option<&[u8]>,
) -> Result<JoinReport, InviteError> {
    join_filtered(client, server, session, only_ref, false).await
}

/// Like [`join_pending`] but joins only Welcomes that consume a KeyPackage minted by
/// `invite create` (issue #24): a pool KeyPackage is handed to any authenticated device, so a
/// Welcome for one stays unjoined and unacked and is kept as a pending request (8.12).
pub async fn join_invited(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<JoinReport, InviteError> {
    join_filtered(client, server, session, None, true).await
}

async fn join_filtered(
    client: &Client,
    server: &Url,
    session: &Session,
    only_ref: Option<&[u8]>,
    invites_only: bool,
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
        match join_one(session, &env, only_ref, invites_only, false) {
            Err(JoinOutcome::Request(binding_ref)) => {
                let req = requests::Request::new(
                    group_id,
                    sender,
                    id,
                    requests::now_secs(),
                    binding_ref,
                    env.ciphertext,
                );
                match requests::save_new(&session.store, &req) {
                    Ok(true) => report.requested += 1,
                    Err(requests::RequestError::Store(e)) => return Err(e.into()),
                    // Duplicate, over the cap or oversized: not kept, so `inbox` acks it after
                    // the grace, unless it is the envelope of the request already kept.
                    Ok(false) | Err(_) => {
                        report.skipped += 1;
                        let kept = requests::load(&session.store, &group_id)
                            .ok()
                            .flatten()
                            .is_some_and(|r| r.envelope_id == id);
                        if !kept && report.unusable.len() < MAX_UNUSABLE {
                            report.unusable.push(id);
                        }
                    }
                }
            }
            Ok(group_id) => {
                report.joined.push(group_id);
                // The join is already persisted; a failed ack only leaves a stale envelope
                // that is skipped (its KeyPackage is consumed) until server-side expiry.
                let _ = ack(client, server, session, id).await;
                // Consent (prd 3.3, 8.11): joining is our consent to the server-side
                // membership, which stays pending until we say so.
                if accept_membership(client, server, session, group_id)
                    .await
                    .is_err()
                {
                    eprintln!("warning: could not confirm membership with the server; group traffic may not arrive");
                }
            }
            Err(JoinOutcome::Skip) => {
                report.skipped += 1;
                if report.unusable.len() < MAX_UNUSABLE {
                    report.unusable.push(id);
                }
            }
            Err(JoinOutcome::Fatal(e)) => return Err(e),
        }
    }
    Ok(report)
}

pub(crate) struct Joinable {
    pub(crate) group_id: Uuid,
    pub(crate) sender: Uuid,
    pub(crate) ciphertext: Vec<u8>,
}

pub(crate) enum JoinOutcome {
    /// This Welcome cannot be joined; leave it for server-side expiry and carry on.
    Skip,
    /// A valid Welcome for one of our pool KeyPackages: not joined without the user's say-so.
    Request(Vec<u8>),
    /// Local storage failed; stop rather than risk acking over lost state.
    Fatal(InviteError),
}

impl From<IdentityError> for JoinOutcome {
    fn from(e: IdentityError) -> Self {
        JoinOutcome::Fatal(e.into())
    }
}

/// Group keys are immutable per group_id: a Welcome for a group we already hold is never
/// joined, whether or not its conversation record exists. A record WITHOUT the MLS group is an
/// interrupted join (crash between the two saves in `join_one`) and is finished by re-joining.
fn check_group_not_held(
    store: &crate::store::ProfileStore,
    local: &LocalIdentity,
    group_id: Uuid,
) -> Result<(), JoinOutcome> {
    match conversation::load(store, &group_id) {
        Ok(_) => {}
        Err(ConversationError::Store(e)) => return Err(JoinOutcome::Fatal(e.into())),
        Err(_) => return Err(JoinOutcome::Skip),
    }
    match mls_group::load_group(group_id.as_bytes(), &local.provider) {
        Ok(None) => Ok(()),
        Ok(Some(_)) | Err(_) => Err(JoinOutcome::Skip),
    }
}

/// The kind comes from the authenticated GroupContext, never from the member count (8.17): a
/// group Welcome that happens to seat two members is not a pair, and an unreadable kind is
/// refused.
fn welcome_kind(group: &mls_group::Group) -> Result<mls_group::GroupKind, JoinOutcome> {
    mls_group::group_kind(group).map_err(|_| JoinOutcome::Skip)
}

/// A group Welcome seats us among 2..=512 active members at epoch 1 or later (the Add that
/// seated us advanced it); anything else is not a group we can hold.
fn ensure_group_shape(group: &mls_group::Group, own_key: &[u8]) -> Result<(), JoinOutcome> {
    let cap = GROUP_MAX_MEMBERS;
    let members: Vec<_> = group.members().take(cap + 1).collect();
    let ok = group.is_active()
        && group.epoch().as_u64() >= 1
        && (2..=cap).contains(&members.len())
        && members.iter().any(|m| m.signature_key == own_key);
    if ok {
        Ok(())
    } else {
        Err(JoinOutcome::Skip)
    }
}

/// A leftover record (crash between the two saves) may only be finished by a Welcome of the
/// same kind, as a joiner: a Welcome can never turn a pair record into a group or back.
fn ensure_resumable(
    store: &crate::store::ProfileStore,
    group_id: Uuid,
    kind: mls_group::GroupKind,
) -> Result<(), JoinOutcome> {
    let want = match kind {
        mls_group::GroupKind::Pair => conversation::Kind::Pair,
        mls_group::GroupKind::Group => conversation::Kind::Group,
    };
    match conversation::load(store, &group_id) {
        Ok(None) => Ok(()),
        Ok(Some(c)) if c.kind() == want && c.role == Role::Joiner => Ok(()),
        Ok(Some(_)) => Err(JoinOutcome::Skip),
        Err(ConversationError::Store(e)) => Err(JoinOutcome::Fatal(e.into())),
        Err(_) => Err(JoinOutcome::Skip),
    }
}

pub(crate) fn join_one(
    session: &Session,
    env: &Joinable,
    only_ref: Option<&[u8]>,
    invites_only: bool,
    allow_group: bool,
) -> Result<Uuid, JoinOutcome> {
    // A fresh provider per Welcome: a rejected join must not leave state in memory that a
    // later successful `save` would persist.
    let mut local = LocalIdentity::load(&session.store)?;
    check_group_not_held(&session.store, &local, env.group_id)?;
    let binding = mls_group::welcome_pq_binding(&env.ciphertext, &local.provider)
        .map_err(|_| JoinOutcome::Skip)?;
    if only_ref.is_some_and(|r| r != binding.key_package_ref.as_slice()) {
        return Err(JoinOutcome::Skip);
    }
    let dk =
        identity::pq_key_for(&session.store, &binding.key_package_ref)?.ok_or(JoinOutcome::Skip)?;
    if invites_only && !invite_marker_exists(&session.store, &binding.key_package_ref)? {
        return Err(JoinOutcome::Request(binding.key_package_ref.clone()));
    }
    kem::validate_decap_key(&dk, &binding.encap_key).map_err(|_| JoinOutcome::Skip)?;
    let group =
        mls_group::join_group(&env.ciphertext, &local.provider).map_err(|_| JoinOutcome::Skip)?;
    let group_id = Uuid::from_slice(group.group_id().as_slice()).map_err(|_| JoinOutcome::Skip)?;
    let kind = welcome_kind(&group)?;
    let own_key = local.identity.signer.to_public_vec();
    // The server labels envelopes; the MLS group id inside the Welcome is authoritative.
    if group_id != env.group_id {
        return Err(JoinOutcome::Skip);
    }
    match kind {
        // 1:1 only: a Welcome that seats extra members (a ghost) is not our conversation.
        mls_group::GroupKind::Pair if !mls_group::is_fresh_pair(&group) => {
            return Err(JoinOutcome::Skip)
        }
        mls_group::GroupKind::Pair => {}
        mls_group::GroupKind::Group => {
            ensure_group_shape(&group, &own_key)?;
            // Being added to a group is never automatic, whatever KeyPackage it consumed: only
            // `accept` (the user's say-so) joins one.
            if !allow_group {
                return Err(JoinOutcome::Request(binding.key_package_ref.clone()));
            }
        }
    }
    ensure_resumable(&session.store, group_id, kind)?;
    // The peer is whoever the Welcome's tree seats next to us; the server's `sender` label is
    // kept for routing only and cannot be tied to a credential (prd.md §3.3, cycle 456).
    let conv = match kind {
        mls_group::GroupKind::Pair => {
            let peer_credential =
                mls_group::peer_credential_identity(&group, &own_key).ok_or(JoinOutcome::Skip)?;
            Conversation::new(
                group_id,
                env.sender,
                Role::Joiner,
                Some((dk, binding.encap_key.clone())),
            )
            .with_peer_credential(peer_credential)
        }
        // No pair ML-KEM state and no single peer: the group PQ story is a later slice.
        mls_group::GroupKind::Group => {
            Conversation::new(group_id, env.sender, Role::Joiner, None).into_group()
        }
    };
    let fatal = |e: InviteError| JoinOutcome::Fatal(e);
    // Conversation record first, then MLS state, then prune: a crash in between leaves the
    // KeyPackage and its key intact so the same Welcome can be joined again.
    conversation::save(&session.store, &conv).map_err(|e| fatal(e.into()))?;
    local.save(&session.store)?;
    identity::prune_pq_key(&session.store, &binding.key_package_ref)?;
    let _ = session
        .store
        .remove(&invite_marker(&binding.key_package_ref));
    Ok(group_id)
}

/// Profile-store record naming a KeyPackage minted for an invite (value is a constant).
pub(crate) fn invite_marker(key_ref: &[u8]) -> String {
    // Hashed so the plaintext record name does not expose the KeyPackageRef; a 24-byte digest
    // prefix keeps the name under the 64-char record-name cap.
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest([b"powehi-cli/invite-kp/v1".as_slice(), key_ref].concat());
    format!("invite-kp-{}", crate::invite::hex(&digest[..24]))
}

fn invite_marker_exists(
    store: &crate::store::ProfileStore,
    key_ref: &[u8],
) -> Result<bool, JoinOutcome> {
    store
        .get(&invite_marker(key_ref))
        .map(|v| v.is_some())
        .map_err(|e| JoinOutcome::Fatal(IdentityError::from(e).into()))
}

/// Tell the server this device consents to its pending membership in `group_id`. Idempotent
/// server-side (204 for an existing member); retried because a lost response is the only way
/// the join and the consent can end up out of step.
pub(crate) async fn accept_membership(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
) -> Result<(), InviteError> {
    let url = server
        .join(&format!("/v1/groups/{group_id}/accept"))
        .map_err(|_| InviteError::BadResponse)?;
    let mut last = None;
    for _ in 0..ACCEPT_ATTEMPTS {
        match identity::send_raw(client.post(url.clone()), session, ACK_BODY).await {
            Ok(_) => return Ok(()),
            Err(e) => last = Some(e),
        }
    }
    Err(last.map_or(InviteError::BadResponse, InviteError::from))
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
