//! Pending conversation requests (issue #24, 8.12, prd.md §3.3).
//!
//! A Welcome that consumes one of our pool KeyPackages (not an `invite create` package) is not
//! joined automatically: any authenticated device can be handed one of those. The inbox keeps it
//! here as a `req-<group id>` record instead. `powehi accept` joins it and confirms the
//! server-side membership; `powehi decline` drops it and declines. The Welcome is not acked
//! while it is pending, so the server keeps it too (30-day retention; the server's pending
//! membership lasts 7 days). A request expires locally after 5 days: its Welcome is acked and
//! its KeyPackage keys deleted. Welcome bytes
//! are public ciphertext; nothing here logs them.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation;
use crate::identity;
use crate::invite::InviteError;
use crate::store::{ProfileStore, StoreError};
use crate::welcome::{self, Joinable};

/// Requests kept at once; later ones stay on the server (unacked) until a slot frees up.
pub const MAX_REQUESTS: usize = 32;
/// Longest Welcome kept: the Delivery Service's own limit, so a large group's Welcome (8.17,
/// up to 512 members) is never accepted by the server and then dropped here.
pub const MAX_WELCOME_LEN: usize = 256 * 1024;
// One request is one record, and serde_json writes each byte as up to 4 characters.
const _: () = assert!(4 * MAX_WELCOME_LEN + 1024 <= crate::store::MAX_RECORD_LEN);
/// Shorter than the server's 7-day pending-membership TTL, which counts from the add rather
/// than from our receipt: the margin covers a device that was offline for a while.
pub const REQUEST_TTL_SECS: u64 = 5 * 24 * 60 * 60;
const PREFIX: &str = "req-";
const MIN_PREFIX_LEN: usize = 4;
const DECLINE_BODY: usize = 4 * 1024;

#[derive(Debug, Error)]
pub enum RequestError {
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("a stored request is malformed")]
    Malformed,
    #[error("no such request (see `powehi requests`; give the id or a unique prefix of it)")]
    NoSuchRequest,
    #[error("that request id prefix matches more than one request")]
    Ambiguous,
    #[error("this request can no longer be joined; decline it")]
    Unjoinable,
    #[error("this request is older than 5 days and the server no longer accepts it; decline it")]
    Expired,
    #[error("you already joined this conversation; a decline would not remove you from it")]
    AlreadyJoined,
    #[error("could not write the request list")]
    Output,
}

/// One pending request. `received_at` is Unix seconds.
#[derive(Serialize, Deserialize)]
pub struct Request {
    pub group_id: Uuid,
    pub sender: Uuid,
    pub envelope_id: Uuid,
    pub received_at: u64,
    /// The consumed KeyPackage: a KeyPackage is single-use, so one request per reference.
    pub key_package_ref: Vec<u8>,
    welcome: Vec<u8>,
}

impl Request {
    pub fn new(
        group_id: Uuid,
        sender: Uuid,
        envelope_id: Uuid,
        received_at: u64,
        key_package_ref: Vec<u8>,
        welcome: Vec<u8>,
    ) -> Self {
        Request {
            group_id,
            sender,
            envelope_id,
            received_at,
            key_package_ref,
            welcome,
        }
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("group_id", &self.group_id)
            .finish_non_exhaustive()
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn record_name(group_id: &Uuid) -> String {
    format!("{PREFIX}{}", group_id.hyphenated())
}

fn group_ids(store: &ProfileStore) -> Result<Vec<Uuid>, RequestError> {
    let ids: Vec<Uuid> = store
        .names()?
        .iter()
        .filter_map(|n| n.strip_prefix(PREFIX).and_then(|s| Uuid::parse_str(s).ok()))
        .collect();
    debug_assert!(ids.len() <= crate::store::MAX_RECORDS);
    Ok(ids)
}

pub fn load(store: &ProfileStore, group_id: &Uuid) -> Result<Option<Request>, RequestError> {
    let Some(raw) = store.get(&record_name(group_id))? else {
        return Ok(None);
    };
    let req: Request = serde_json::from_slice(&raw).map_err(|_| RequestError::Malformed)?;
    if req.group_id != *group_id || req.welcome.is_empty() || req.welcome.len() > MAX_WELCOME_LEN {
        return Err(RequestError::Malformed);
    }
    Ok(Some(req))
}

/// Stores a new request. Returns `false` (nothing stored) when one for this group or this
/// KeyPackage already exists (the first Welcome wins; the Welcome's contents are not validated
/// before `accept`, so a flood of junk for one KeyPackage must cost one slot), when
/// [`MAX_REQUESTS`] are held, or when the Welcome is oversized.
pub fn save_new(store: &ProfileStore, req: &Request) -> Result<bool, RequestError> {
    if req.welcome.is_empty() || req.welcome.len() > MAX_WELCOME_LEN {
        return Ok(false);
    }
    let held = group_ids(store)?;
    if held.contains(&req.group_id) || held.len() >= MAX_REQUESTS {
        return Ok(false);
    }
    if list(store)?
        .iter()
        .any(|r| r.key_package_ref == req.key_package_ref)
    {
        return Ok(false);
    }
    let bytes = serde_json::to_vec(req).map_err(|_| RequestError::Malformed)?;
    store.put(&record_name(&req.group_id), &bytes)?;
    Ok(true)
}

pub fn remove(store: &ProfileStore, group_id: &Uuid) -> Result<(), RequestError> {
    store.remove(&record_name(group_id))?;
    Ok(())
}

/// Deletes the KeyPackage bundle and ML-KEM key the request's Welcome consumes. A KeyPackage is
/// single-use (RFC 9420 §10): once the request is settled without a join, the secrets must not
/// linger, and the same Welcome must not be classifiable as a request again.
fn retire_keys(store: &ProfileStore, req: &Request) -> Result<(), RequestError> {
    let mut local = identity::LocalIdentity::load(store).map_err(InviteError::from)?;
    powehi_crypto_core::mls_group::delete_key_package(&local.provider, &req.key_package_ref)
        .map_err(InviteError::from)?;
    local.save(store).map_err(InviteError::from)?;
    identity::prune_pq_key(store, &req.key_package_ref).map_err(InviteError::from)?;
    Ok(())
}

/// True when the server no longer accepts this request (its pending membership expired).
pub fn is_expired(req: &Request, now: u64) -> bool {
    now.saturating_sub(req.received_at) > REQUEST_TTL_SECS
}

/// Drops requests older than [`REQUEST_TTL_SECS`] and those that are unreadable. Returns the
/// envelope ids of the dropped Welcomes: the server keeps an unacked Welcome for 30 days, so
/// the caller acks them or they would come straight back as fresh requests.
pub fn prune_expired(store: &ProfileStore, now: u64) -> Result<Vec<Uuid>, RequestError> {
    let mut envelopes = Vec::new();
    for id in group_ids(store)? {
        match load(store, &id) {
            Ok(Some(r)) if is_expired(&r, now) => {
                // Keep going on failure: one bad request must not pin the others' slots.
                if retire_keys(store, &r).is_err() {
                    eprintln!("warning: could not retire the keys of an expired request");
                    continue;
                }
                envelopes.push(r.envelope_id);
            }
            Ok(Some(_) | None) => continue,
            Err(RequestError::Malformed) => {}
            Err(e) => return Err(e),
        }
        remove(store, &id)?;
    }
    Ok(envelopes)
}

/// Requests, oldest first (ties by id). Unreadable records are skipped.
pub fn list(store: &ProfileStore) -> Result<Vec<Request>, RequestError> {
    let mut out = Vec::new();
    for id in group_ids(store)? {
        match load(store, &id) {
            Ok(Some(r)) => out.push(r),
            Ok(None) | Err(RequestError::Malformed) => {}
            Err(e) => return Err(e),
        }
    }
    out.sort_by_key(|r| (r.received_at, r.group_id));
    Ok(out)
}

/// Resolves a typed request id: a full group id or a unique prefix of at least 4 characters.
pub fn resolve(store: &ProfileStore, reference: &str) -> Result<Uuid, RequestError> {
    let wanted = reference.trim().to_ascii_lowercase();
    if wanted.len() < MIN_PREFIX_LEN || !wanted.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(RequestError::NoSuchRequest);
    }
    let mut hits = group_ids(store)?
        .into_iter()
        .filter(|id| id.hyphenated().to_string().starts_with(&wanted));
    let first = hits.next().ok_or(RequestError::NoSuchRequest)?;
    if hits.next().is_some() {
        return Err(RequestError::Ambiguous);
    }
    Ok(first)
}

/// Prints the requests (`id  sender  age`), or a JSON line each. Ids and ages only.
pub fn report(
    out: &mut impl std::io::Write,
    reqs: &[Request],
    now: u64,
    json: bool,
) -> std::io::Result<()> {
    for r in reqs {
        let age = now.saturating_sub(r.received_at);
        if json {
            let obj = serde_json::json!({
                "id": r.group_id,
                "from": r.sender,
                "received_at": r.received_at,
            });
            writeln!(out, "{obj}")?;
        } else {
            writeln!(
                out,
                "{}  from device {} (as reported by the server)  {age}s ago",
                r.group_id, r.sender
            )?;
        }
    }
    out.flush()
}

/// Joins the request's Welcome, then confirms the membership with the server and drops the
/// request. A re-run after a failed confirm skips the join (already held) and retries it.
pub async fn accept(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
) -> Result<(), RequestError> {
    let req = load(&session.store, &group_id)?.ok_or(RequestError::NoSuchRequest)?;
    if is_expired(&req, now_secs()) && !held(session, group_id)? {
        return Err(RequestError::Expired);
    }
    let env = Joinable {
        group_id,
        sender: req.sender,
        ciphertext: req.welcome.clone(),
    };
    match welcome::join_one(session, &env, None, false, true) {
        Ok(_) => {}
        Err(welcome::JoinOutcome::Fatal(e)) => return Err(e.into()),
        Err(_) if held(session, group_id)? => {}
        Err(_) => return Err(RequestError::Unjoinable),
    }
    // The join is persisted; the ack only frees the server copy.
    let _ = welcome::ack(client, server, session, req.envelope_id).await;
    welcome::accept_membership(client, server, session, group_id).await?;
    remove(&session.store, &group_id)
}

/// True when the conversation is stored with its MLS group (a completed join).
fn held(session: &Session, group_id: Uuid) -> Result<bool, RequestError> {
    if conversation::load(&session.store, &group_id)
        .map_err(InviteError::from)?
        .is_none()
    {
        return Ok(false);
    }
    let local = identity::LocalIdentity::load(&session.store).map_err(InviteError::from)?;
    Ok(matches!(
        powehi_crypto_core::mls_group::load_group(group_id.as_bytes(), &local.provider),
        Ok(Some(_))
    ))
}

/// Declines on the server, acks the Welcome and drops the request. The server call comes first
/// so a failure leaves the request in place to retry.
pub async fn decline(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
) -> Result<(), RequestError> {
    let req = load(&session.store, &group_id)?.ok_or(RequestError::NoSuchRequest)?;
    // A decline only drops a *pending* server membership; after a join it would leave us a
    // member while saying "declined".
    if held(session, group_id)? {
        return Err(RequestError::AlreadyJoined);
    }
    let url = server
        .join(&format!("/v1/groups/{group_id}/decline"))
        .map_err(|_| InviteError::BadResponse)?;
    identity::send_raw(client.post(url), session, DECLINE_BODY)
        .await
        .map_err(InviteError::from)?;
    // An interrupted join can leave a conversation record (holding the ML-KEM key) without MLS
    // state; it is not a conversation, so it goes with the request.
    conversation::remove(&session.store, &group_id).map_err(InviteError::from)?;
    retire_keys(&session.store, &req)?;
    let _ = welcome::ack(client, server, session, req.envelope_id).await;
    remove(&session.store, &group_id)
}

#[cfg(test)]
mod tests;
