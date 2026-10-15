//! Serde adapter for `Received.body`: lowercase hex string on write, hex string or legacy
//! JSON number array on read (records written before F9 stay readable). A byte vector as a
//! JSON number array costs ~3-4x the plaintext and leaks nothing extra, but hex is compact.

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::Serializer;
use std::fmt;
use zeroize::Zeroizing;

use crate::store::MAX_RECORD_LEN;

/// Upper bound on a body: its hex form plus 1 KiB of JSON framing fits one store record.
pub(super) const MAX_BODY_BYTES: usize = (MAX_RECORD_LEN - 1024) / 2;
const _: () = assert!(2 * MAX_BODY_BYTES + 1024 <= MAX_RECORD_LEN);

pub(crate) fn serialize<S: Serializer>(body: &[u8], s: S) -> Result<S::Ok, S::Error> {
    if body.len() > MAX_BODY_BYTES {
        return Err(serde::ser::Error::custom("body too long"));
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = Zeroizing::new(String::with_capacity(body.len() * 2));
    for b in body {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    s.serialize_str(out.as_str())
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    d.deserialize_any(BodyVisitor)
}

struct BodyVisitor;

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

impl<'de> Visitor<'de> for BodyVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a lowercase hex string or an array of bytes")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
        let raw = v.as_bytes();
        if raw.len() & 1 != 0 || raw.len() / 2 > MAX_BODY_BYTES {
            return Err(E::custom("bad body length"));
        }
        let mut out = Zeroizing::new(Vec::with_capacity(raw.len() / 2));
        for i in 0..raw.len() / 2 {
            match (nibble(raw[2 * i]), nibble(raw[2 * i + 1])) {
                (Some(h), Some(l)) => out.push(h << 4 | l),
                _ => return Err(E::custom("bad hex digit")),
            }
        }
        Ok(std::mem::take(&mut *out))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        // Never `Vec::push`-realloc: that frees the old buffer unwiped. Grow geometrically into
        // a fresh zeroizing buffer; the old one is wiped on drop. Wiped on error paths too.
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        while let Some(b) = seq.next_element::<u8>()? {
            if out.len() >= MAX_BODY_BYTES {
                return Err(de::Error::custom("body too long"));
            }
            if out.len() == out.capacity() {
                let cap = (out.capacity() * 2).min(MAX_BODY_BYTES);
                let mut bigger = Zeroizing::new(Vec::with_capacity(cap));
                bigger.extend_from_slice(&out);
                out = bigger;
            }
            out.push(b);
        }
        Ok(std::mem::take(&mut *out))
    }
}
