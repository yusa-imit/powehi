//! `powehi send` / `powehi read`: text messages for a stored 1:1 conversation (prd.md §7A.2).
//!
//! A text message is the raw UTF-8 body encrypted as one MLS application message, the same
//! wire form the web client sends and accepts as legacy plain text. The sender ratchet is
//! persisted BEFORE the POST so a key is never reused after a crash; a failed POST loses that
//! one message but never weakens the state. Received messages are the `rx-*` records written by
//! [`crate::inbox`]; `read` renders them with terminal control characters neutralised and then
//! removes them from the store. Bodies are never logged.

use powehi_crypto_core::mls_group;
use reqwest::Client;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

use crate::auth::Session;
use crate::conversation::{self, ConversationError};
use crate::identity::{IdentityError, LocalIdentity};
use crate::inbox::{Received, RX_PREFIX};
use crate::invite::{self, InviteError};
use crate::store::{ProfileStore, StoreError};

/// Longest message body `send` accepts (bytes of UTF-8), well under the server envelope cap.
pub const MAX_BODY_LEN: usize = 16 * 1024;
/// Shortest accepted conversation id prefix (hex digits and hyphens).
const MIN_PREFIX_LEN: usize = 4;

#[derive(Debug, Error)]
pub enum MessageError {
    #[error("{0}")]
    Invite(#[from] InviteError),
    #[error("{0}")]
    Identity(#[from] IdentityError),
    #[error("{0}")]
    Conversation(#[from] ConversationError),
    #[error("profile store error: {0}")]
    Store(#[from] StoreError),
    #[error("no such conversation (give the id printed by `invite`, or a unique prefix of it)")]
    NoSuchConversation,
    #[error("that conversation id prefix matches more than one conversation")]
    Ambiguous,
    #[error("the message is empty")]
    EmptyBody,
    #[error("the message is not valid UTF-8 text")]
    NotText,
    #[error("the message is longer than {MAX_BODY_LEN} bytes")]
    TooLong,
    #[error("the conversation's group state is unusable; it cannot send")]
    GroupUnusable,
    #[error("MLS operation failed")]
    Mls,
}

impl From<mls_group::MlsError> for MessageError {
    fn from(_: mls_group::MlsError) -> Self {
        MessageError::Mls
    }
}

/// A stored, not yet displayed message.
#[derive(PartialEq, Eq)]
pub struct Pending {
    name: String,
    pub sender: Uuid,
    pub text: String,
    received_at: u64,
}

impl std::fmt::Debug for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pending").finish_non_exhaustive()
    }
}

/// Resolves a user-typed conversation reference: a full group id or a unique prefix of at
/// least [`MIN_PREFIX_LEN`] characters.
pub fn resolve(store: &ProfileStore, reference: &str) -> Result<Uuid, MessageError> {
    let wanted = reference.trim().to_ascii_lowercase();
    if wanted.len() < MIN_PREFIX_LEN || !wanted.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(MessageError::NoSuchConversation);
    }
    let mut hits = conversation::list(store)?
        .into_iter()
        .filter(|id| id.hyphenated().to_string().starts_with(&wanted));
    let first = hits.next().ok_or(MessageError::NoSuchConversation)?;
    if hits.next().is_some() {
        return Err(MessageError::Ambiguous);
    }
    Ok(first)
}

/// Validates a body read from stdin: one trailing newline is dropped; the rest must be
/// non-empty UTF-8 within [`MAX_BODY_LEN`].
pub fn check_body(raw: &[u8]) -> Result<&[u8], MessageError> {
    let body = raw
        .strip_suffix(b"\r\n")
        .or_else(|| raw.strip_suffix(b"\n"))
        .unwrap_or(raw);
    if body.len() > MAX_BODY_LEN {
        return Err(MessageError::TooLong);
    }
    if body.iter().all(u8::is_ascii_whitespace) {
        return Err(MessageError::EmptyBody);
    }
    std::str::from_utf8(body).map_err(|_| MessageError::NotText)?;
    Ok(body)
}

/// Encrypts `body` into the conversation and posts it. The caller has run [`check_body`].
pub async fn send(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    body: &[u8],
) -> Result<(), MessageError> {
    debug_assert!(body.len() <= MAX_BODY_LEN && std::str::from_utf8(body).is_ok());
    let store = &session.store;
    conversation::load(store, &group_id)?.ok_or(MessageError::NoSuchConversation)?;
    let mut local = LocalIdentity::load(store)?;
    let mut group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .ok_or(MessageError::GroupUnusable)?;
    // Same 1:1 invariant the receive path relies on (no Commit is ever applied here).
    if !mls_group::is_fresh_pair(&group) {
        return Err(MessageError::GroupUnusable);
    }
    let ct = mls_group::encrypt_message(&mut group, &local.identity.signer, body, &local.provider)?;
    local.save(store)?;
    invite::send_application(client, server, session, group_id, &ct).await?;
    Ok(())
}

/// Stored messages of one conversation, oldest first. Records that fail to parse are ignored.
pub fn pending(store: &ProfileStore, group_id: Uuid) -> Result<Vec<Pending>, MessageError> {
    let mut out = Vec::new();
    for name in store
        .names()?
        .into_iter()
        .filter(|n| n.starts_with(RX_PREFIX))
    {
        let Some(raw) = store.get(&name)? else {
            continue;
        };
        let Ok(rec) = serde_json::from_slice::<Received>(&raw) else {
            continue;
        };
        if rec.group_id == group_id {
            out.push(Pending {
                text: render(&rec.body),
                sender: rec.sender,
                received_at: rec.received_at,
                name,
            });
        }
    }
    out.sort_by(|a, b| (a.received_at, &a.name).cmp(&(b.received_at, &b.name)));
    Ok(out)
}

/// Writes one message as `[sender] first line`, with continuation lines indented so a body
/// cannot forge a `[id] ...` header line, and flushes so only what reached the terminal is
/// ever discarded afterwards.
pub fn display(out: &mut impl std::io::Write, msg: &Pending) -> std::io::Result<()> {
    let mut lines = msg.text.split('\n');
    writeln!(
        out,
        "[{}] {}",
        short_id(&msg.sender),
        lines.next().unwrap_or("")
    )?;
    for l in lines {
        writeln!(out, "    | {l}")?;
    }
    out.flush()
}

/// Removes a message from the store once it has been shown.
pub fn discard(store: &ProfileStore, msg: &Pending) -> Result<(), MessageError> {
    debug_assert!(msg.name.starts_with(RX_PREFIX));
    store.remove(&msg.name)?;
    Ok(())
}

/// Display form of a message body. Text is shown with every control character except `\n` and
/// `\t` replaced (a peer must not be able to inject terminal escape sequences); structured
/// payloads from the web client become a short placeholder instead of raw JSON.
pub fn render(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_str::<serde_json::Value>(&text) {
        if let Some(serde_json::Value::String(kind)) = obj.get("type") {
            return match kind.as_str() {
                // The web client's structured text (reply / disappearing); the ttl is not
                // enforced here beyond `read` deleting the record once shown.
                "text" => match obj.get("text") {
                    Some(serde_json::Value::String(t)) => sanitize(t),
                    _ => "[unsupported message]".into(),
                },
                "image" => "[image]".into(),
                "video" => "[video]".into(),
                _ => "[unsupported message]".into(),
            };
        }
    }
    sanitize(&text)
}

fn sanitize(text: &str) -> String {
    text.chars()
        .map(|c| if is_unsafe_char(c) { '\u{fffd}' } else { c })
        .collect()
}

/// Controls (except `\n`, `\t`) and invisible format characters (bidi overrides and isolates,
/// zero-width, BOM, soft hyphen, line separators, tag characters, variation selectors, fillers) that can spoof or hide text on a terminal.
fn is_unsafe_char(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c,
            '\u{ad}' | '\u{61c}' | '\u{180e}' | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}' | '\u{2028}' | '\u{2029}' | '\u{34f}' | '\u{115f}'
            | '\u{1160}' | '\u{3164}' | '\u{ffa0}' | '\u{fe00}'..='\u{fe0f}'
            | '\u{e0000}'..='\u{e007f}' | '\u{e0100}'..='\u{e01ef}')
}

/// Sender label for display: the first 8 characters of the device id.
pub fn short_id(id: &Uuid) -> String {
    id.hyphenated().to_string().chars().take(8).collect()
}

#[cfg(test)]
mod tests;
