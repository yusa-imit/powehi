//! Handle and password canonicalisation shared by the CLI and (by test vector) the web client.
//!
//! The server only ever sees `SHA-256(handle)` and OPAQUE messages, so it cannot validate a
//! handle: the clients do (Phase 8 item 8.6, issue #19).
//!
//! - **Handle**: [`trim_handle`] strips Unicode `White_Space` plus U+FEFF from both ends. New
//!   accounts must then match `[a-z0-9-]{1,64}` ([`registrable_handle`]); login accepts any
//!   trimmed handle so accounts created before the rule keep working.
//! - **Password**: [`nfc_password`] applies Unicode NFC and nothing else (no trim, no NFKC).
//!   Accounts registered from the raw bytes keep working through [`password_candidates`],
//!   which lists the NFC form first and the raw form second when they differ.
//!
//! Residual risk: the `unicode-normalization` iterator keeps a small internal buffer that is
//! not zeroized (upstream); the output string is.
//!
//! The vectors in `docs/test-vectors/credential-normalization.json` pin both functions; the
//! web client runs the same file in Vitest.

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Longest handle accepted for a new account.
pub const MAX_HANDLE_LEN: usize = 64;

/// Why a handle cannot be used to register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HandleError {
    #[error("the handle is empty")]
    Empty,
    #[error("the handle is longer than {MAX_HANDLE_LEN} characters")]
    TooLong,
    #[error("the handle may contain only a-z, 0-9 and '-'")]
    BadCharacter,
}

fn is_edge_space(c: char) -> bool {
    c.is_whitespace() || c == '\u{FEFF}'
}

/// Strips `White_Space` and U+FEFF from both ends. The login-side canonical form.
#[must_use]
pub fn trim_handle(raw: &str) -> &str {
    raw.trim_matches(is_edge_space)
}

/// Trims, then requires `[a-z0-9-]{1,64}`. Returns the canonical handle for a new account.
pub fn registrable_handle(raw: &str) -> Result<&str, HandleError> {
    let handle = trim_handle(raw);
    if handle.is_empty() {
        return Err(HandleError::Empty);
    }
    if !handle
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(HandleError::BadCharacter);
    }
    if handle.len() > MAX_HANDLE_LEN {
        return Err(HandleError::TooLong);
    }
    debug_assert!(handle.is_ascii());
    Ok(handle)
}

/// Unicode NFC of the password; every other byte is left as typed.
#[must_use]
pub fn nfc_password(raw: &str) -> Zeroizing<String> {
    // NFC grows UTF-8 by at most 3x (UAX #15). Reserving it up front keeps the buffer from
    // reallocating, which would leave unzeroed password prefixes in freed heap blocks.
    let cap = raw.len().saturating_mul(3);
    let mut out = Zeroizing::new(String::with_capacity(cap));
    out.extend(raw.nfc());
    assert!(out.capacity() >= out.len());
    out
}

/// Passwords to try at login, in order: the NFC form, then the raw input when it differs
/// (accounts registered before NFC normalisation). One or two entries.
#[must_use]
pub fn password_candidates(raw: &str) -> Vec<Zeroizing<String>> {
    let nfc = nfc_password(raw);
    let mut out = vec![nfc];
    if *out[0] != raw {
        out.push(Zeroizing::new(raw.to_owned()));
    }
    assert!(!out.is_empty() && out.len() <= 2);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct HandleCase {
        input: String,
        trimmed: String,
        registrable: bool,
    }
    #[derive(Deserialize)]
    struct PasswordCase {
        input: String,
        nfc: String,
    }
    #[derive(Deserialize)]
    struct Vectors {
        handles: Vec<HandleCase>,
        passwords: Vec<PasswordCase>,
    }

    fn vectors() -> Vectors {
        let raw = include_str!("../../../../docs/test-vectors/credential-normalization.json");
        serde_json::from_str(raw).expect("vector file parses")
    }

    #[test]
    fn handle_vectors() {
        let v = vectors();
        assert!(v.handles.len() >= 10);
        for c in &v.handles {
            assert_eq!(trim_handle(&c.input), c.trimmed, "trim {:?}", c.input);
            assert_eq!(
                registrable_handle(&c.input).is_ok(),
                c.registrable,
                "{:?}",
                c.input
            );
        }
    }

    #[test]
    fn password_vectors() {
        let v = vectors();
        assert!(v.passwords.len() >= 5);
        for c in &v.passwords {
            assert_eq!(*nfc_password(&c.input), c.nfc, "nfc {:?}", c.input);
        }
    }

    #[test]
    fn handle_error_kinds() {
        assert_eq!(registrable_handle("  "), Err(HandleError::Empty));
        assert_eq!(registrable_handle("Ab"), Err(HandleError::BadCharacter));
        let long_hangul = "\u{c624}".repeat(30);
        assert_eq!(
            registrable_handle(&long_hangul),
            Err(HandleError::BadCharacter)
        );
        assert_eq!(
            registrable_handle(&"a".repeat(MAX_HANDLE_LEN)).map(str::len),
            Ok(64)
        );
        assert_eq!(
            registrable_handle(&"a".repeat(MAX_HANDLE_LEN + 1)),
            Err(HandleError::TooLong)
        );
    }

    #[test]
    fn candidates_list_nfc_first_and_raw_only_when_different() {
        let c = password_candidates("cafe\u{301}");
        assert_eq!(c.len(), 2);
        assert_eq!(*c[0], "caf\u{e9}");
        assert_eq!(*c[1], "cafe\u{301}");
        assert_eq!(password_candidates("plain").len(), 1);
    }

    #[test]
    fn nfc_is_idempotent() {
        for c in &vectors().passwords {
            let once = nfc_password(&c.input);
            assert_eq!(*nfc_password(&once), *once);
        }
    }
}
