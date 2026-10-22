//! Store manifest (8.8a): encoding, authentication and verification of the file that lists every
//! record's tag and ciphertext hash under a monotonic generation. The manifest is AES-256-GCM
//! under its own key with the profile in the AAD; a record that is missing, extra, stale or
//! swapped is a typed error at `open`.
//!
//! Crash safety: a mutation first writes the manifest with the new state plus a `pending` entry
//! naming the record and its previous hash, then the record, then a manifest without `pending`.
//! A `pending` manifest accepts the record in either state; only a MAC'd manifest can carry it,
//! so the crash window only ever allows the in-flight record's immediately previous version
//! (nothing beyond the snapshot replay of prd §3.2). A handle that finds anything else is poisoned.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Nonce;
use rand::rngs::OsRng;
use rand::RngCore;

use super::{
    Manifest, Pending, StoreError, HASH_LEN, MANIFEST_MAGIC, MAX_MANIFEST_LEN, NONCE_LEN,
    RAW_TAG_LEN,
};

/// Tag (32 lowercase hex) → 16 raw bytes; `None` if it is not a tag.
fn tag_bytes(tag: &str) -> Option<[u8; RAW_TAG_LEN]> {
    // `from_str_radix` accepts a leading `+` and uppercase; a tag is exactly lowercase hex.
    if !super::is_tag(tag) {
        return None;
    }
    let mut out = [0u8; RAW_TAG_LEN];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(tag.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

pub(super) fn tag_hex(raw: &[u8]) -> String {
    debug_assert_eq!(raw.len(), RAW_TAG_LEN);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

/// AAD: `magic || len(profile) || profile`.
pub(super) fn manifest_aad(profile: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(MANIFEST_MAGIC.len() + 1 + profile.len());
    a.extend_from_slice(MANIFEST_MAGIC);
    a.push(u8::try_from(profile.len()).unwrap_or(u8::MAX));
    a.extend_from_slice(profile.as_bytes());
    a
}

impl Manifest {
    /// `generation(8) || n(4) || n × (tag(16) || hash(32)) || pending(1) [|| tag(16) || has_old(1) [|| hash(32)]]`.
    pub(super) fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut out = Vec::with_capacity(16 + self.entries.len() * (RAW_TAG_LEN + HASH_LEN));
        out.extend_from_slice(&self.generation.to_be_bytes());
        let n = u32::try_from(self.entries.len()).map_err(|_| StoreError::ManifestCorrupt)?;
        out.extend_from_slice(&n.to_be_bytes());
        for (tag, hash) in &self.entries {
            out.extend_from_slice(&tag_bytes(tag).ok_or(StoreError::ManifestCorrupt)?);
            out.extend_from_slice(hash);
        }
        match &self.pending {
            None => out.push(0),
            Some(p) => {
                out.push(1);
                out.extend_from_slice(&tag_bytes(&p.tag).ok_or(StoreError::ManifestCorrupt)?);
                match &p.old {
                    None => out.push(0),
                    Some(h) => {
                        out.push(1);
                        out.extend_from_slice(h);
                    }
                }
            }
        }
        debug_assert!(out.len() <= MAX_MANIFEST_LEN);
        Ok(out)
    }

    pub(super) fn decode(mut b: &[u8]) -> Result<Self, StoreError> {
        let bad = || StoreError::ManifestCorrupt;
        let generation = u64::from_be_bytes(
            take(&mut b, 8)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        );
        let n = u32::from_be_bytes(
            take(&mut b, 4)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?,
        );
        if n as usize > super::MAX_RECORDS + 2 {
            return Err(bad());
        }
        let mut entries = BTreeMap::new();
        for _ in 0..n {
            let tag = tag_hex(take(&mut b, RAW_TAG_LEN).ok_or_else(bad)?);
            let hash: [u8; HASH_LEN] = take(&mut b, HASH_LEN)
                .ok_or_else(bad)?
                .try_into()
                .map_err(|_| bad())?;
            if entries.insert(tag, hash).is_some() {
                return Err(bad());
            }
        }
        let pending = match take(&mut b, 1).ok_or_else(bad)?[0] {
            0 => None,
            1 => {
                let tag = tag_hex(take(&mut b, RAW_TAG_LEN).ok_or_else(bad)?);
                let old = match take(&mut b, 1).ok_or_else(bad)?[0] {
                    0 => None,
                    1 => Some(
                        take(&mut b, HASH_LEN)
                            .ok_or_else(bad)?
                            .try_into()
                            .map_err(|_| bad())?,
                    ),
                    _ => return Err(bad()),
                };
                Some(Pending { tag, old })
            }
            _ => return Err(bad()),
        };
        if !b.is_empty() {
            return Err(bad());
        }
        Ok(Self {
            generation,
            entries,
            pending,
        })
    }

    /// `MAGIC || nonce || AES-GCM(encode)`.
    pub(super) fn seal(&self, store: &super::ProfileStore) -> Result<Vec<u8>, StoreError> {
        let pt = zeroize::Zeroizing::new(self.encode()?);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| StoreError::Io(std::io::ErrorKind::Other))?;
        let ct = store
            .manifest_cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &pt,
                    aad: &manifest_aad(&store.profile),
                },
            )
            .map_err(|_| StoreError::ManifestCorrupt)?;
        let mut blob = Vec::with_capacity(MANIFEST_MAGIC.len() + NONCE_LEN + ct.len());
        blob.extend_from_slice(MANIFEST_MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        Ok(blob)
    }

    pub(super) fn open_blob(store: &super::ProfileStore, blob: &[u8]) -> Result<Self, StoreError> {
        let head = MANIFEST_MAGIC.len() + NONCE_LEN;
        if blob.len() < head + super::TAG_LEN || &blob[..MANIFEST_MAGIC.len()] != MANIFEST_MAGIC {
            return Err(StoreError::ManifestCorrupt);
        }
        let pt = store
            .manifest_cipher
            .decrypt(
                Nonce::from_slice(&blob[MANIFEST_MAGIC.len()..head]),
                Payload {
                    msg: &blob[head..],
                    aad: &manifest_aad(&store.profile),
                },
            )
            .map_err(|_| StoreError::Authentication)?;
        Self::decode(&zeroize::Zeroizing::new(pt))
    }

    /// Checks `found` (tag → hash of each `.rc2` file on disk) against the manifest.
    pub(super) fn verify(
        &self,
        found: &BTreeMap<String, [u8; HASH_LEN]>,
    ) -> Result<(), StoreError> {
        let pend = self.pending.as_ref();
        for (tag, hash) in &self.entries {
            match found.get(tag) {
                // Only a pending create may lack its file (the crash hit before the write).
                None => {
                    if !pend.is_some_and(|p| &p.tag == tag && p.old.is_none()) {
                        return Err(StoreError::RecordMissing { tag: tag.clone() });
                    }
                }
                Some(h) if h == hash => {}
                Some(h) => {
                    let old_ok = pend.is_some_and(|p| &p.tag == tag && p.old.as_ref() == Some(h));
                    if !old_ok {
                        return Err(StoreError::RecordStale { tag: tag.clone() });
                    }
                }
            }
        }
        for (tag, h) in found {
            if self.entries.contains_key(tag) {
                continue;
            }
            // Pending delete: the file is still there with its old hash.
            let old_ok = pend.is_some_and(|p| &p.tag == tag && p.old.as_ref() == Some(h));
            if !old_ok {
                return Err(StoreError::RecordUnlisted { tag: tag.clone() });
            }
        }
        Ok(())
    }
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    if b.len() < n {
        return None;
    }
    let (head, rest) = b.split_at(n);
    *b = rest;
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const H1: [u8; HASH_LEN] = [1; HASH_LEN];
    const H2: [u8; HASH_LEN] = [2; HASH_LEN];

    fn manifest(entries: &[(&str, [u8; HASH_LEN])], pending: Option<Pending>) -> Manifest {
        Manifest {
            generation: 1,
            entries: entries.iter().map(|(t, h)| ((*t).to_owned(), *h)).collect(),
            pending,
        }
    }

    fn found(files: &[(&str, [u8; HASH_LEN])]) -> BTreeMap<String, [u8; HASH_LEN]> {
        files.iter().map(|(t, h)| ((*t).to_owned(), *h)).collect()
    }

    fn pend(tag: &str, old: Option<[u8; HASH_LEN]>) -> Option<Pending> {
        Some(Pending {
            tag: tag.to_owned(),
            old,
        })
    }

    #[test]
    fn verify_accepts_an_exact_match() {
        let m = manifest(&[(A, H1)], None);
        assert!(m.verify(&found(&[(A, H1)])).is_ok());
    }

    #[test]
    fn verify_without_pending_refuses_missing_stale_and_unlisted() {
        let m = manifest(&[(A, H1)], None);
        assert!(matches!(
            m.verify(&found(&[])),
            Err(StoreError::RecordMissing { .. })
        ));
        assert!(matches!(
            m.verify(&found(&[(A, H2)])),
            Err(StoreError::RecordStale { .. })
        ));
        assert!(matches!(
            m.verify(&found(&[(A, H1), (B, H1)])),
            Err(StoreError::RecordUnlisted { .. })
        ));
    }

    #[test]
    fn pending_create_excuses_only_its_own_missing_file() {
        let m = manifest(&[(A, H1), (B, H2)], pend(B, None));
        assert!(m.verify(&found(&[(A, H1)])).is_ok(), "crash before write");
        assert!(
            m.verify(&found(&[(A, H1), (B, H2)])).is_ok(),
            "crash after write"
        );
        // The other record going missing is not excused.
        assert!(matches!(
            m.verify(&found(&[(B, H2)])),
            Err(StoreError::RecordMissing { .. })
        ));
    }

    #[test]
    fn pending_update_accepts_exactly_the_previous_hash() {
        let m = manifest(&[(A, H2)], pend(A, Some(H1)));
        assert!(m.verify(&found(&[(A, H1)])).is_ok(), "old version");
        assert!(m.verify(&found(&[(A, H2)])).is_ok(), "new version");
        assert!(matches!(
            m.verify(&found(&[(A, [3; HASH_LEN])])),
            Err(StoreError::RecordStale { .. })
        ));
        // An update (old is Some) does not excuse a missing file.
        assert!(matches!(
            m.verify(&found(&[])),
            Err(StoreError::RecordMissing { .. })
        ));
    }

    #[test]
    fn pending_delete_accepts_the_old_file_only_with_the_old_hash() {
        let m = manifest(&[], pend(A, Some(H1)));
        assert!(m.verify(&found(&[])).is_ok(), "file already gone");
        assert!(m.verify(&found(&[(A, H1)])).is_ok(), "file still there");
        assert!(matches!(
            m.verify(&found(&[(A, H2)])),
            Err(StoreError::RecordUnlisted { .. })
        ));
        assert!(matches!(
            m.verify(&found(&[(B, H1)])),
            Err(StoreError::RecordUnlisted { .. })
        ));
    }
}
