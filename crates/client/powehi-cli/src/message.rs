//! `powehi send` / `powehi read`: text messages for a stored 1:1 conversation (prd.md §7A.2).
//!
//! A text message is the raw UTF-8 body encrypted as one MLS application message, the same
//! wire form the web client sends and accepts as legacy plain text. The sender ratchet is
//! persisted BEFORE the POST so a key is never reused after a crash; a failed POST loses that
//! one message but never weakens the state. Received messages are the `rx-*` records written by
//! [`crate::inbox`]; `read` renders them with terminal control characters neutralised and then
//! removes them from the store. Bodies are never logged.

use std::collections::BTreeMap;

use powehi_crypto_core::mls_group;
use reqwest::Client;
use serde::Deserialize;
use thiserror::Error;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::Session;
use crate::conversation::{self, ConversationError};
use crate::identity::{IdentityError, LocalIdentity};
use crate::inbox::{Received, RX_PREFIX};
use crate::invite::{self, InviteError};
use crate::pcs;
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
    #[error("a key rotation for this conversation is unresolved; nothing was sent")]
    RotationPending,
    #[error(
        "the safety number CHANGED since you verified this conversation; nothing was sent. Run \
         `powehi verify <conversation>` and compare it with your peer, or pass --allow-changed"
    )]
    Changed,
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
    pub text: Zeroizing<String>,
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

/// [`send_with`] that refuses a CHANGED conversation (the default, prd §5.6, 8.16).
pub async fn send(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    body: &[u8],
) -> Result<(), MessageError> {
    send_with(client, server, session, group_id, body, false).await
}

/// Encrypts `body` into the conversation and posts it. The caller has run [`check_body`].
/// A conversation whose verified safety number CHANGED (or whose record cannot be read) is
/// refused before any key is spent unless `allow_changed` is set (`--allow-changed`).
pub async fn send_with(
    client: &Client,
    server: &Url,
    session: &Session,
    group_id: Uuid,
    body: &[u8],
    allow_changed: bool,
) -> Result<(), MessageError> {
    debug_assert!(body.len() <= MAX_BODY_LEN && std::str::from_utf8(body).is_ok());
    let store = &session.store;
    conversation::load(store, &group_id)?.ok_or(MessageError::NoSuchConversation)?;
    if !allow_changed && crate::verify::changed_since_verified(store, group_id) {
        return Err(MessageError::Changed);
    }
    let now = unix_secs();
    // A staged self-Update Commit not yet resolved: no Application message may go out in this
    // epoch until it is (prd §5.3A).
    if pcs::has_pending(store, group_id)? {
        return Err(MessageError::RotationPending);
    }
    let mut local = LocalIdentity::load(store)?;
    let mut group = mls_group::load_group(group_id.as_bytes(), &local.provider)?
        .ok_or(MessageError::GroupUnusable)?;
    // Same 1:1 invariant the receive path relies on (only pair-preserving Commits are applied).
    if !mls_group::is_pair_with(&group, &local.identity.signer.to_public_vec()) {
        return Err(MessageError::GroupUnusable);
    }
    let ct = mls_group::encrypt_message(&mut group, &local.identity.signer, body, &local.provider)?;
    local.save(store)?;
    // Policy counter, counted once the key is spent (a failed POST still used a ratchet step);
    // a failure here delays the next rotation by one message at most.
    if let Ok(Some(mut conv)) = conversation::load(store, &group_id) {
        conv.note_sent(now);
        let _ = conversation::save(store, &conv);
    }
    invite::send_application(client, server, session, group_id, &ct).await?;
    Ok(())
}

fn unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Number of stored (unread) messages per conversation; groups with none are absent.
/// Unparseable records are ignored, as in [`pending`]. Bodies are dropped (and wiped) at once.
pub fn unread_counts(store: &ProfileStore) -> Result<BTreeMap<Uuid, usize>, MessageError> {
    let mut out = BTreeMap::new();
    for name in store
        .names()?
        .into_iter()
        .filter(|n| n.starts_with(RX_PREFIX))
    {
        let Some(raw) = store.get(&name)? else {
            continue;
        };
        if let Ok(rec) = serde_json::from_slice::<Received>(&raw) {
            *out.entry(rec.group_id).or_insert(0) += 1;
        }
    }
    debug_assert!(out.values().sum::<usize>() <= crate::store::MAX_RECORDS);
    Ok(out)
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

/// Writes the send outcome: the conversation id only (never the body), as text or JSON.
pub fn write_sent(id: Uuid, json: bool, out: &mut impl std::io::Write) -> std::io::Result<()> {
    assert!(!id.is_nil());
    if json {
        writeln!(
            out,
            "{}",
            serde_json::json!({ "conversation": id.to_string() })
        )
    } else {
        writeln!(out, "sent to conversation {id}")
    }
}

/// Writes one message as a JSON line `{"sender","received_at","text"}`. The text is already
/// sanitized (only `\n` and `\t` remain as controls) and is escaped piecewise straight into
/// `out`, so no second plaintext copy is built in memory.
pub fn display_json(out: &mut impl std::io::Write, msg: &Pending) -> std::io::Result<()> {
    write!(
        out,
        "{{\"sender\":\"{}\",\"received_at\":{},\"text\":\"",
        msg.sender, msg.received_at
    )?;
    let mut rest = msg.text.as_str();
    while let Some(i) = rest.find(['"', '\\', '\n', '\t']) {
        out.write_all(&rest.as_bytes()[..i])?;
        out.write_all(match rest.as_bytes()[i] {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\n' => b"\\n",
            _ => b"\\t",
        })?;
        rest = &rest[i + 1..];
    }
    out.write_all(rest.as_bytes())?;
    writeln!(out, "\"}}")?;
    out.flush()
}

/// Why [`show`] stopped: the output closed, or a shown message could not be removed.
#[derive(Debug)]
pub enum ShowError {
    Output,
    Discard(MessageError),
}

/// Displays each message in order and, unless `keep`, removes it right after it was written.
/// Only what reached `out` is removed: a closed pipe leaves the unseen messages stored.
pub fn show(
    store: &ProfileStore,
    msgs: &[Pending],
    keep: bool,
    json: bool,
    out: &mut impl std::io::Write,
) -> Result<(), ShowError> {
    for m in msgs {
        let shown = if json {
            display_json(out, m)
        } else {
            display(out, m)
        };
        shown.map_err(|_| ShowError::Output)?;
        if !keep {
            discard(store, m).map_err(ShowError::Discard)?;
        }
    }
    Ok(())
}

/// The messages received at or after `cutoff` (Unix seconds; `None` = all) of an oldest-first
/// slice. Earlier ones are not returned, so `show` neither displays nor removes them.
pub fn since(msgs: &[Pending], cutoff: Option<u64>) -> &[Pending] {
    let Some(t) = cutoff else {
        return msgs;
    };
    debug_assert!(msgs
        .windows(2)
        .all(|w| w[0].received_at <= w[1].received_at));
    let start = msgs.partition_point(|m| m.received_at < t);
    assert!(start <= msgs.len());
    &msgs[start..]
}

/// The messages received strictly before `cutoff` (Unix seconds; `None` = all) of an
/// oldest-first slice. Later ones are not returned, so `show` neither displays nor removes them.
pub fn until(msgs: &[Pending], cutoff: Option<u64>) -> &[Pending] {
    let Some(t) = cutoff else {
        return msgs;
    };
    debug_assert!(msgs
        .windows(2)
        .all(|w| w[0].received_at <= w[1].received_at));
    let end = msgs.partition_point(|m| m.received_at < t);
    assert!(end <= msgs.len());
    &msgs[..end]
}

/// The newest `last` messages of an oldest-first slice (`None` = all). Older ones are not
/// returned, so `show` neither displays nor removes them.
pub fn newest(msgs: &[Pending], last: Option<usize>) -> &[Pending] {
    let Some(n) = last else {
        return msgs;
    };
    assert!(n > 0, "callers validate --last >= 1");
    &msgs[msgs.len().saturating_sub(n)..]
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
pub fn render(body: &[u8]) -> Zeroizing<String> {
    let text = lossy_utf8(body);
    // Only objects are parsed: serde_json formats a top-level string/number into its error
    // message, which would be an unwiped copy of the body.
    let is_object = text
        .trim_start_matches([' ', '\t', '\n', '\r'])
        .starts_with('{');
    let parsed = if is_object {
        serde_json::from_str::<Structured>(&text).ok()
    } else {
        None
    };
    if let Some(Structured {
        kind: Some(kind),
        text: inner,
    }) = parsed
    {
        return match (kind.as_str(), inner) {
            // The web client's structured text (reply / disappearing); the ttl is not
            // enforced here beyond `read` deleting the record once shown.
            ("text", Some(t)) => sanitize(&t),
            ("image", _) => Zeroizing::new("[image]".into()),
            ("video", _) => Zeroizing::new("[video]".into()),
            _ => Zeroizing::new("[unsupported message]".into()),
        };
    }
    sanitize(&text)
}

/// UTF-8 decode with U+FFFD for invalid bytes, into a buffer sized for the worst case
/// (3 bytes per input byte) so it never reallocates and leaves no unwiped copy behind.
fn lossy_utf8(body: &[u8]) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(body.len().saturating_mul(3)));
    for chunk in body.utf8_chunks() {
        out.push_str(chunk.valid());
        if !chunk.invalid().is_empty() {
            out.push('\u{fffd}');
        }
    }
    out
}

/// Web-client payload view: a JSON *object* (arrays are rejected, like the web client) whose
/// `type` and `text` members are read last-wins (like `JSON.parse`). A non-string member is
/// `None`. `kind` is `Some` only for a string `type`. The text is copied straight into a
/// `Zeroizing` string. Known residual: serde_json's scratch buffer for strings containing
/// escapes (newline, quote, backslash, `\u`) is freed unwiped;
/// `tests/render_residue.rs` pins the other heap copies at zero.
struct Structured {
    kind: Option<Zeroizing<String>>,
    text: Option<Zeroizing<String>>,
}

impl<'de> Deserialize<'de> for Structured {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Structured;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<Structured, A::Error> {
                let mut out = Structured {
                    kind: None,
                    text: None,
                };
                while let Some(key) = m.next_key::<Field>()? {
                    match key {
                        Field::Type => out.kind = m.next_value::<MaybeStr>()?.0,
                        Field::Text => out.text = m.next_value::<MaybeStr>()?.0,
                        Field::Other => {
                            m.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(out)
            }
        }
        d.deserialize_map(V)
    }
}

/// Object key, matched without allocating (a key is peer-controlled plaintext too).
enum Field {
    Type,
    Text,
    Other,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Field;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object key")
            }
            fn visit_str<E>(self, v: &str) -> Result<Field, E> {
                Ok(match v {
                    "type" => Field::Type,
                    "text" => Field::Text,
                    _ => Field::Other,
                })
            }
        }
        d.deserialize_identifier(V)
    }
}

/// A string value kept in a `Zeroizing` buffer; any other JSON value (skipped) is `None`.
struct MaybeStr(Option<Zeroizing<String>>);

impl<'de> Deserialize<'de> for MaybeStr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = MaybeStr;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_str<E>(self, v: &str) -> Result<MaybeStr, E> {
                Ok(MaybeStr(Some(Zeroizing::new(v.to_owned()))))
            }
            fn visit_bool<E>(self, _: bool) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_i64<E>(self, _: i64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_u64<E>(self, _: u64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_f64<E>(self, _: f64) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_unit<E>(self) -> Result<MaybeStr, E> {
                Ok(MaybeStr(None))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut s: A,
            ) -> Result<MaybeStr, A::Error> {
                while s.next_element::<serde::de::IgnoredAny>()?.is_some() {}
                Ok(MaybeStr(None))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut m: A,
            ) -> Result<MaybeStr, A::Error> {
                while m
                    .next_entry::<serde::de::IgnoredAny, serde::de::IgnoredAny>()?
                    .is_some()
                {}
                Ok(MaybeStr(None))
            }
        }
        d.deserialize_any(V)
    }
}

/// Replaces unsafe characters; the output is pre-sized for the worst case (a 1-byte control
/// becomes the 3-byte U+FFFD) so it never reallocates.
fn sanitize(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len().saturating_mul(3)));
    out.extend(
        text.chars()
            .map(|c| if is_unsafe_char(c) { '\u{fffd}' } else { c }),
    );
    out
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
