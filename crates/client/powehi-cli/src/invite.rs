//! `powehi invite create` / `powehi invite redeem` (prd.md §8.3, §4.2).
//!
//! The inviter generates a KeyPackage itself, pins it to a one-time code on the server and
//! shares `<server>/i/connect#<code>.<sha256(KeyPackage)>`. The redeemer fetches the pinned
//! bytes, checks them against the hash from the link (which the server never sees), creates the
//! MLS group, adds the inviter and sends the Welcome. The inviter joins in [`crate::welcome`].
//! The code, hash and KeyPackage bytes are never logged.

use powehi_crypto_core::{kem, mls_group};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::Session;
use crate::conversation::{self, Conversation, ConversationError, Role};
use crate::identity::{self, IdentityError, LocalIdentity};
use crate::store::StoreError;

/// Longest accepted invite link; the real ones are ~110 bytes plus the server origin.
pub const MAX_LINK_LEN: usize = 512;
const CODE_LEN: usize = 32;
const HASH_HEX_LEN: usize = 64;
/// Cap on the JSON bodies of the small control calls.
const SMALL_BODY: usize = 64 * 1024;
/// A pinned KeyPackage comes back as a JSON integer array (~4 bytes per byte).
const REDEEM_BODY: usize = 256 * 1024;

#[derive(Debug, Error)]
pub enum InviteError {
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("{0}")]
    Conversation(#[from] ConversationError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("not a valid invite link")]
    BadLink,
    #[error("this invite does not exist, was already used, or has expired")]
    NotFound,
    #[error("the invite's key package does not match the link; do not trust this invite")]
    HashMismatch,
    #[error("this invite link belongs to a different server than --server")]
    WrongServer,
    #[error("you cannot redeem your own invite")]
    SelfInvite,
    #[error("unexpected response from the server")]
    BadResponse,
    #[error("MLS operation failed")]
    Mls,
}

impl From<mls_group::MlsError> for InviteError {
    fn from(_: mls_group::MlsError) -> Self {
        InviteError::Mls
    }
}

/// A parsed invite link: the one-time code and the pinned KeyPackage's SHA-256 (lowercase hex).
#[derive(PartialEq, Eq)]
pub struct InviteLink {
    /// Origin of a full URL link, if one was given (checked against `--server` on redeem).
    origin: Option<String>,
    code: String,
    kp_hash: String,
}

impl std::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteLink").finish_non_exhaustive()
    }
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Formats the shareable link.
pub fn build_link(server: &Url, code: &str, kp_hash: &str) -> Result<String, InviteError> {
    if !is_lower_hex(code, CODE_LEN) || !is_lower_hex(kp_hash, HASH_HEX_LEN) {
        return Err(InviteError::BadResponse);
    }
    let mut url = server
        .join("/i/connect")
        .map_err(|_| InviteError::BadResponse)?;
    url.set_fragment(Some(&format!("{code}.{kp_hash}")));
    Ok(url.into())
}

/// Parses a full invite URL or the bare `<code>.<hash>` fragment.
pub fn parse_link(input: &str) -> Result<InviteLink, InviteError> {
    let input = input.trim();
    if input.is_empty() || input.len() > MAX_LINK_LEN {
        return Err(InviteError::BadLink);
    }
    let (origin, fragment) = match input.rsplit_once('#') {
        Some((base, f)) => {
            let url = Url::parse(base).map_err(|_| InviteError::BadLink)?;
            (Some(url.origin().ascii_serialization()), f)
        }
        None => (None, input),
    };
    let (code, kp_hash) = fragment.split_once('.').ok_or(InviteError::BadLink)?;
    if !is_lower_hex(code, CODE_LEN) || !is_lower_hex(kp_hash, HASH_HEX_LEN) {
        return Err(InviteError::BadLink);
    }
    Ok(InviteLink {
        origin,
        code: code.to_owned(),
        kp_hash: kp_hash.to_owned(),
    })
}

fn api(server: &Url, path: &str) -> Result<Url, InviteError> {
    server.join(path).map_err(|_| InviteError::BadResponse)
}

fn json_post<T: Serialize>(
    client: &Client,
    url: Url,
    body: &T,
) -> Result<reqwest::RequestBuilder, InviteError> {
    let body = serde_json::to_vec(body).map_err(|_| InviteError::BadResponse)?;
    Ok(client
        .post(url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .body(body))
}

#[derive(Serialize)]
struct CreateReq<'a> {
    key_package: &'a [u8],
}
#[derive(Deserialize)]
struct CreateResp {
    code: String,
}
#[derive(Serialize)]
struct RedeemReq<'a> {
    code: &'a str,
}
#[derive(Deserialize)]
struct RedeemResp {
    device_id: Uuid,
    key_package: Vec<u8>,
}

/// Creates an invite and returns the shareable link and the pinned KeyPackage's ref.
///
/// The KeyPackage's private half is persisted before the server sees the public half. If the
/// upload fails the package is an unused local orphan. Invite KeyPackages are not tracked as
/// upload batches (8.9 covers the pool only); pruning them is a follow-up to issue #22.
pub async fn create(
    client: &Client,
    server: &Url,
    session: &Session,
) -> Result<(String, Vec<u8>), InviteError> {
    let mut local = LocalIdentity::load(&session.store)?;
    let mut packages = identity::generate_and_persist(&session.store, &mut local, 1)?;
    drop(local);
    let key_package = packages.pop().ok_or(InviteError::Mls)?;
    let key_ref = identity::last_pq_ref(&session.store)?.ok_or(InviteError::Mls)?;
    let kp_hash = hex(&Sha256::digest(&key_package));
    // Marker first: `inbox` joins only invite KeyPackages (issue #24 interim policy).
    session
        .store
        .put(&crate::welcome::invite_marker(&key_ref), b"1")
        .map_err(IdentityError::from)?;
    let req = json_post(
        client,
        api(server, "/v1/invites")?,
        &CreateReq {
            key_package: &key_package,
        },
    )?;
    let raw = identity::send_raw(req, session, SMALL_BODY).await?;
    let resp: CreateResp = serde_json::from_slice(&raw).map_err(|_| InviteError::BadResponse)?;
    Ok((build_link(server, &resp.code, &kp_hash)?, key_ref))
}

/// Redeems an invite: verifies the pinned KeyPackage, creates the group, adds the inviter,
/// registers both with the server and sends the Welcome, then (when the inviter's KeyPackage
/// carries a verified ML-KEM key) the `pq_init` message. Returns the new conversation id and
/// how the PQ exchange went.
///
/// Order matters for crash safety: MLS state is saved before any server call that depends on
/// it, and the conversation record before the Welcome leaves, so a lost response never leaves
/// the peer in a group this device cannot find.
pub async fn redeem(
    client: &Client,
    server: &Url,
    session: &Session,
    link: &InviteLink,
) -> Result<(Uuid, PqStatus), InviteError> {
    if link
        .origin
        .as_ref()
        .is_some_and(|o| *o != server.origin().ascii_serialization())
    {
        return Err(InviteError::WrongServer);
    }
    let req = json_post(
        client,
        api(server, "/v1/invites/redeem")?,
        &RedeemReq { code: &link.code },
    )?;
    let raw = match identity::send_raw(req, session, REDEEM_BODY).await {
        Ok(raw) => raw,
        Err(IdentityError::HttpStatus(404)) => return Err(InviteError::NotFound),
        Err(e) => return Err(e.into()),
    };
    let pinned: RedeemResp = serde_json::from_slice(&raw).map_err(|_| InviteError::BadResponse)?;
    if hex(&Sha256::digest(&pinned.key_package)) != link.kp_hash {
        return Err(InviteError::HashMismatch);
    }
    if pinned.device_id == session.device_id {
        return Err(InviteError::SelfInvite);
    }
    let BuiltGroup {
        group_id,
        welcome,
        pq_init,
        pq_state,
        peer_credential,
    } = build_group(session, &pinned.key_package)?;
    post_registration(client, server, session, group_id, pinned.device_id).await?;
    let mut conv = Conversation::new(group_id, pinned.device_id, Role::Creator, None)
        .with_peer_credential(peer_credential);
    conversation::save(&session.store, &conv)?;
    send_welcome(
        client,
        server,
        session,
        group_id,
        pinned.device_id,
        &welcome,
    )
    .await?;
    // Best effort, like the web client: a failed send leaves a working classical conversation
    // and no binding recorded, so a stored binding always means the message left.
    if let Some(pq) = pq_init {
        if send_application(client, server, session, group_id, &pq.message)
            .await
            .is_ok()
        {
            conv.set_pq_binding(pq.binding);
            conversation::save(&session.store, &conv)?;
        }
    }
    let status = match (conv.pq_binding(), pq_state) {
        (Some(b), _) => PqStatus::Bound(b.to_owned()),
        (None, PqState::Classical) => PqStatus::PeerClassical,
        (None, PqState::Rejected) => PqStatus::KeyRejected,
        (None, PqState::Ready) => PqStatus::NotSent,
    };
    Ok((group_id, status))
}

/// Outcome of the `pq_init` step for the user (prd.md §5.3 Phase B). The ML-KEM secret only
/// yields a comparison binding today; message keys stay classical (ADR-0003).
#[derive(Debug, PartialEq, Eq)]
pub enum PqStatus {
    /// `pq_init` was sent; both sides derive this 16-hex binding.
    Bound(String),
    /// The inviter's KeyPackage has no PQ key: a classical-only peer.
    PeerClassical,
    /// The inviter's PQ key failed verification (bad signature, unreduced key, bad length).
    KeyRejected,
    /// A valid PQ key was found but the message could not be built or sent.
    NotSent,
}

enum PqState {
    Ready,
    Classical,
    Rejected,
}

/// The encrypted `pq_init` application message and the binding derived alongside it.
struct PqInit {
    message: Vec<u8>,
    binding: String,
}

/// Encapsulates to the inviter's verified ML-KEM key and encrypts the `pq_init` envelope into
/// the group (prd.md §5.3 Phase B). A classical-only peer and a rejected key are reported
/// separately; the shared secret is zeroized and the conversation stays classical either way.
fn make_pq_init(
    group: &mut mls_group::Group,
    local: &LocalIdentity,
    key_package: &[u8],
    group_id: Uuid,
) -> (Option<PqInit>, PqState) {
    let ek = match mls_group::peer_pq_encap_key(group, key_package, &local.provider) {
        Ok(Some(ek)) => ek,
        Ok(None) => return (None, PqState::Classical),
        Err(_) => return (None, PqState::Rejected),
    };
    let built = (|| {
        let (ct, ss) = kem::encapsulate(&ek).ok()?;
        let ss: Zeroizing<Vec<u8>> = ss;
        let binding = kem::derive_pq_binding(&ss, &group_id.hyphenated().to_string()).ok()?;
        let payload = Zeroizing::new(
            serde_json::to_vec(&serde_json::json!({ "type": "pq_init", "ct": ct })).ok()?,
        );
        let message =
            mls_group::encrypt_message(group, &local.identity.signer, &payload, &local.provider)
                .ok()?;
        Some(PqInit { message, binding })
    })();
    (built, PqState::Ready)
}

pub(crate) async fn send_application(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    ciphertext: &[u8],
) -> Result<(), InviteError> {
    #[derive(Serialize)]
    struct MessageReq<'a> {
        group_id: Uuid,
        ciphertext: &'a [u8],
    }
    let req = json_post(
        client,
        api(server, "/v1/messages")?,
        &MessageReq {
            group_id,
            ciphertext,
        },
    )?;
    identity::send_raw(req, session, SMALL_BODY).await?;
    Ok(())
}

/// What the Delivery Service did with a posted self-Update Commit (8.15). Only a definite
/// answer lets the caller merge or abort; anything else leaves the staged Commit alone.
#[derive(Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    /// 2xx with the epoch the Commit created (`expected_epoch + 1`): merge it.
    Accepted,
    /// The server refused the FIRST post of these bytes with a status it only issues before
    /// storing anything (see [`commit_status_outcome`]): abort it.
    Rejected,
    /// Timeout, transport error, 5xx, 408, other status or a malformed 2xx: the Commit may have
    /// landed (or may land late). Neither merge nor abort; aborting an accepted Commit strands
    /// the device. Resolve only by finding the stored Commit envelope at epoch + 1 (its bytes
    /// equal the staged ones: confirm; another member's: abort); never by an epoch probe alone.
    Unknown,
}

/// Maps a failed response status to a [`CommitOutcome`]. The server's CAS is not idempotent: a
/// re-post of bytes it already stored answers 409, which then proves nothing, so a `resend`
/// never yields `Rejected`. On a first post only the statuses the server issues before the
/// ledger transaction count (400/415/422 body, 401 auth/membership, 404 group, 409 CAS lost,
/// 413 size, 429 rate limit); anything else, including other 4xx, is `Unknown`.
fn commit_status_outcome(status: u16, resend: bool) -> CommitOutcome {
    match status {
        400 | 401 | 404 | 409 | 413 | 415 | 422 | 429 if !resend => CommitOutcome::Rejected,
        _ => CommitOutcome::Unknown,
    }
}

/// Posts a staged self-Update Commit. `expected_epoch` is the SERVER's group epoch (the CAS
/// precondition of prd.md §4A.5), not the local MLS epoch: the server counts only accepted
/// Commits, so a freshly joined pair is at 0 while MLS is at 1. `resend` is true for any post
/// after the first of the same bytes. The body never leaves this function.
pub async fn send_commit(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    commit: &[u8],
    expected_epoch: u64,
    resend: bool,
) -> CommitOutcome {
    #[derive(Serialize)]
    struct CommitReq<'a> {
        group_id: Uuid,
        commit: &'a [u8],
        expected_epoch: u64,
    }
    #[derive(Deserialize)]
    struct CommitResp {
        epoch: u64,
    }
    let Ok(url) = api(server, "/v1/messages/commit") else {
        return CommitOutcome::Unknown;
    };
    let body = CommitReq {
        group_id,
        commit,
        expected_epoch,
    };
    let Ok(req) = json_post(client, url, &body) else {
        return CommitOutcome::Unknown;
    };
    match identity::send_raw(req, session, SMALL_BODY).await {
        Ok(raw) => match serde_json::from_slice::<CommitResp>(&raw) {
            Ok(r) if r.epoch == expected_epoch.saturating_add(1) => CommitOutcome::Accepted,
            _ => CommitOutcome::Unknown,
        },
        Err(IdentityError::HttpStatus(code)) => commit_status_outcome(code, resend),
        Err(_) => CommitOutcome::Unknown,
    }
}

struct BuiltGroup {
    group_id: Uuid,
    welcome: Vec<u8>,
    pq_init: Option<PqInit>,
    pq_state: PqState,
    peer_credential: Vec<u8>,
}

/// Creates the MLS group with the inviter added; persists the provider. Returns the group's
/// UUID (its 16-byte MLS id), the serialized Welcome, the `pq_init` message when PQ applies and
/// the inviter's credential identity.
fn build_group(session: &Session, key_package: &[u8]) -> Result<BuiltGroup, InviteError> {
    let mut local = LocalIdentity::load(&session.store)?;
    let mut group = mls_group::create_group(&local.identity, &local.provider)?;
    let welcome = mls_group::add_member_from_bytes(
        &mut group,
        &local.identity.signer,
        key_package,
        &local.provider,
    )?;
    debug_assert_eq!(group.epoch().as_u64(), 1);
    let group_id = Uuid::from_slice(group.group_id().as_slice()).map_err(|_| InviteError::Mls)?;
    // The inviter's leaf comes from the hash-pinned KeyPackage, so this is the identity the
    // link vouched for (prd.md §7A.3).
    let own_key = local.identity.signer.to_public_vec();
    let peer_credential =
        mls_group::peer_credential_identity(&group, &own_key).ok_or(InviteError::Mls)?;
    let (pq_init, pq_state) = make_pq_init(&mut group, &local, key_package, group_id);
    local.save(&session.store)?;
    Ok(BuiltGroup {
        group_id,
        welcome,
        pq_init,
        pq_state,
        peer_credential,
    })
}

/// Registers the group and the inviter as a member (epoch 1) with the Delivery Service.
async fn post_registration(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    peer: Uuid,
) -> Result<(), InviteError> {
    #[derive(Serialize)]
    struct GroupReq {
        group_id: Uuid,
    }
    #[derive(Serialize)]
    struct MemberReq {
        epoch: u64,
    }
    let req = json_post(client, api(server, "/v1/groups")?, &GroupReq { group_id })?;
    identity::send_raw(req, session, SMALL_BODY).await?;
    let path = format!("/v1/groups/{group_id}/members/{peer}");
    let req = json_post(client, api(server, &path)?, &MemberReq { epoch: 1 })?;
    identity::send_raw(req, session, SMALL_BODY).await?;
    Ok(())
}

async fn send_welcome(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    peer: Uuid,
    welcome: &[u8],
) -> Result<(), InviteError> {
    #[derive(Serialize)]
    struct WelcomeReq<'a> {
        group_id: Uuid,
        welcome: &'a [u8],
        target_device_id: Uuid,
    }
    let req = json_post(
        client,
        api(server, "/v1/messages/welcome")?,
        &WelcomeReq {
            group_id,
            welcome,
            target_device_id: peer,
        },
    )?;
    identity::send_raw(req, session, SMALL_BODY).await?;
    Ok(())
}

/// Writes the freshly created invite link: bare, or as `{"invite":...}` when `json` is set.
pub fn write_created(link: &str, json: bool, out: &mut impl std::io::Write) -> std::io::Result<()> {
    assert!(!link.is_empty());
    if json {
        return writeln!(out, "{}", serde_json::json!({ "invite": link }));
    }
    writeln!(out, "{link}")
}

/// Writes the outcome of `--wait`: the joined conversation id, or (None) that nobody
/// redeemed yet; JSON mode prints `{"conversation": id | null}`.
pub fn write_joined(
    id: Option<Uuid>,
    json: bool,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    assert!(id.is_none_or(|i| !i.is_nil()));
    match (id, json) {
        (Some(id), false) => writeln!(out, "conversation {id}"),
        (None, false) => writeln!(
            out,
            "no one has redeemed the invite yet; it stays valid for 24 hours"
        ),
        (id, true) => writeln!(
            out,
            "{}",
            serde_json::json!({ "conversation": id.map(|i| i.to_string()) })
        ),
    }
}

/// Writes the redeem outcome as one JSON object: the conversation id, the `pq_init` result
/// (`bound`, `peer_classical`, `key_rejected`, `not_sent`) and the public binding or null.
pub fn write_redeemed(
    id: Uuid,
    pq: &PqStatus,
    out: &mut impl std::io::Write,
) -> std::io::Result<()> {
    assert!(!id.is_nil());
    let (state, binding) = match pq {
        PqStatus::Bound(b) => ("bound", Some(b.as_str())),
        PqStatus::PeerClassical => ("peer_classical", None),
        PqStatus::KeyRejected => ("key_rejected", None),
        PqStatus::NotSent => ("not_sent", None),
    };
    writeln!(
        out,
        "{}",
        serde_json::json!({ "conversation": id.to_string(), "pq": state, "pq_binding": binding })
    )
}

#[cfg(test)]
mod tests;
