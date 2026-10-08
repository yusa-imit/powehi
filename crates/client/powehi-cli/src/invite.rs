//! `powehi invite create` / `powehi invite redeem` (prd.md §8.3, §4.2).
//!
//! The inviter generates a KeyPackage itself, pins it to a one-time code on the server and
//! shares `<server>/i/connect#<code>.<sha256(KeyPackage)>`. The redeemer fetches the pinned
//! bytes, checks them against the hash from the link (which the server never sees), creates the
//! MLS group, adds the inviter and sends the Welcome. The inviter joins in [`crate::welcome`].
//! The code, hash and KeyPackage bytes are never logged.

use powehi_crypto_core::mls_group;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;
use uuid::Uuid;

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
/// upload fails the package is an unused local orphan (see issue #22 for the pruning policy).
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
/// registers both with the server and sends the Welcome. Returns the new conversation id.
///
/// Order matters for crash safety: MLS state is saved before any server call that depends on
/// it, and the conversation record before the Welcome leaves, so a lost response never leaves
/// the peer in a group this device cannot find.
pub async fn redeem(
    client: &Client,
    server: &Url,
    session: &Session,
    link: &InviteLink,
) -> Result<Uuid, InviteError> {
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
    let (group_id, welcome) = build_group(session, &pinned.key_package)?;
    post_registration(client, server, session, group_id, pinned.device_id).await?;
    conversation::save(
        &session.store,
        &Conversation::new(group_id, pinned.device_id, Role::Creator, None),
    )?;
    send_welcome(
        client,
        server,
        session,
        group_id,
        pinned.device_id,
        &welcome,
    )
    .await?;
    Ok(group_id)
}

/// Creates the MLS group with the inviter added; persists the provider. Returns the group's
/// UUID (its 16-byte MLS id) and the serialized Welcome.
fn build_group(session: &Session, key_package: &[u8]) -> Result<(Uuid, Vec<u8>), InviteError> {
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
    local.save(&session.store)?;
    Ok((group_id, welcome))
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

#[cfg(test)]
mod tests;
