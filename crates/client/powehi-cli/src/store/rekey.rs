//! Rekey (8.8c): moves an upgraded store off its `export_key`-derived keys onto a fresh random
//! bundle, so a later password change really retires the old keys (`rewrap_password` refuses
//! such a store with `RekeyRequired`).
//!
//! Every record is re-encrypted, under a new record key and a new name-tag key, into a staging
//! directory `rekey.new/` that is a complete store of its own (records, manifest, key file).
//! Once it is fsynced, `rekey.go` (sealed under the new bundle; it lists the staged files with
//! their SHA-256 and the old record tags to delete) is the commit point. The
//! switch is a roll-forward that `open` runs first, under the profile lock, and that can be
//! repeated after a crash: staged records move into the profile directory, then the manifest,
//! then the key file (so the old key file keeps pointing at the old keys until the last
//! move), then only the old records the journal lists are deleted (never "everything unlisted"), and the staging directory and the
//! journal go. A crash before `rekey.go` exists leaves the old store untouched (`open` deletes
//! the staging directory). The journal is sealed under the new bundle's manifest key, and the
//! staged `keys.wk3` must open with the caller's KEK before anything
//! moves, and every staged file must match its journaled hash first, so a planted, damaged or
//! foreign staging directory is refused untouched. A journal replayed alone, or with incomplete
//! staging, deletes nothing (it blocks `open` until removed); a genuine journal re-injected with
//! its complete staging rolls the store back to rekey time, the §3.2 ① snapshot replay.
//!
//! The recovery slot is bound to the old bundle, so a store that has one needs the phrase's KEK
//! again to rewrap the new bundle (`RecoveryPhraseRequired`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::keys::{Bundle, KeyFile, PasswordKek, KEYFILE_MAX_LEN};
use super::{
    check_private_dir, is_tag, mkdir_private, read_private_file, Flow, ProfileStore, RecoveryKek,
    StoreError, EXT, HASH_LEN, KEYFILE, LOCK_FILE, MANIFEST_FILE, MARKER, MAX_INNER_LEN,
    MAX_RECORDS, NONCE_LEN, TAG_HEX_LEN, TAG_LEN,
};
use crate::profile::ProfilePaths;

const STAGING: &str = "rekey.new";
const JOURNAL: &str = "rekey.go";
/// One `n <tag> <hash>` line per staged record, `m <hash>`, and one `d <tag>` per old record.
const JOURNAL_BODY_MAX: usize =
    (MAX_RECORDS + 2) * (4 + TAG_HEX_LEN + 2 * HASH_LEN + 4 + TAG_HEX_LEN) + 4 + 2 * HASH_LEN;
/// The journal is `PHJ1 || nonce || AES-256-GCM(new manifest key, AAD PHJ1 || profile, body)`.
const JOURNAL_MAGIC: &[u8; 4] = b"PHJ1";
const JOURNAL_MAX_LEN: usize = 4 + NONCE_LEN + JOURNAL_BODY_MAX + TAG_LEN;

impl ProfileStore {
    /// Whether the store still uses the `export_key`-derived keys of an upgraded store.
    #[must_use]
    pub fn needs_rekey(&self) -> bool {
        self.derived_keys || self.by_recovery
    }

    /// Re-encrypts the whole store under a fresh random key bundle and returns the reopened
    /// store. Only a store that still uses the `export_key`-derived keys is changed; any other is
    /// returned as it is. `export_key` must be the one those keys derive from. If the key file
    /// has a recovery slot, `recovery` (the same phrase's KEK) is required and is rewrapped; a
    /// store without one gains it when `recovery` is given. On error the handle is gone: the
    /// caller reopens, which finishes or discards an interrupted rekey.
    pub fn rekey(
        self,
        paths: &ProfilePaths,
        export_key: &[u8],
        recovery: Option<&RecoveryKek>,
    ) -> Result<Self, StoreError> {
        if self.by_recovery {
            return Err(StoreError::RekeyRequired);
        }
        if !self.derived_keys {
            return Ok(self);
        }
        if paths.dir != self.dir {
            return Err(StoreError::InsecurePath);
        }
        if self.poisoned.load(std::sync::atomic::Ordering::Acquire) {
            return Err(StoreError::Corrupt);
        }
        if !Bundle::derived(export_key)?.same_keys(&self.bundle) {
            return Err(StoreError::Authentication);
        }
        check_private_dir(&self.dir)?;
        let current = Self::read_keyfile(&self.dir)?.ok_or(StoreError::KeyfileMissing)?;
        if current.has_recovery() {
            let rc = recovery.ok_or(StoreError::RecoveryPhraseRequired)?;
            if !current
                .unlock_recovery(&self.profile, rc)?
                .same_keys(&self.bundle)
            {
                return Err(StoreError::Authentication);
            }
        }
        let old = self.tags()?;
        let tags = match self.stage(export_key, recovery) {
            Ok(t) => t,
            Err(e) => {
                let _ = remove_staging(&self.dir);
                return Err(e);
            }
        };
        let committed =
            PasswordKek::new(export_key).and_then(|pw| self.write_journal(&tags, &old, &pw));
        drop(self);
        committed?;
        let reopened = Self::open(paths, export_key)?;
        debug_assert!(!reopened.derived_keys);
        Ok(reopened)
    }

    /// Builds the staging store and returns the tags of its records.
    fn stage(
        &self,
        export_key: &[u8],
        recovery: Option<&RecoveryKek>,
    ) -> Result<Vec<String>, StoreError> {
        let staging = self.dir.join(STAGING);
        remove_staging(&self.dir)?;
        mkdir_private(&staging)?;
        check_private_dir(&staging)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(staging.join(LOCK_FILE))?;
        let fresh = Self::build(
            &ProfilePaths {
                dir: staging.clone(),
            },
            self.profile.clone(),
            lock,
            Bundle::random()?,
        )?;
        let fresh = fresh.start(Flow::Fresh(PasswordKek::new(export_key)?))?;
        if let Some(rc) = recovery {
            fresh.add_recovery_wrap(rc)?;
        }
        if self.index()?.contains(MARKER) {
            fresh.put_record(MARKER, b"", false)?;
        }
        // Write in new-tag order so inode/mtime order matches the visible file-name order and
        // leaks nothing about which record is which (the plain name order would).
        let mut names: Vec<String> = self.names()?.into_iter().collect();
        names.sort_by_cached_key(|n| super::tag_of(&fresh.name_mac, n));
        for name in names {
            let pt = self.get(&name)?.ok_or(StoreError::Corrupt)?;
            fresh.put_record(&name, &pt, true)?;
        }
        let tags = fresh.tags()?;
        drop(fresh);
        File::open(&staging)?.sync_all()?;
        Ok(tags)
    }

    /// The commit point: after this the switch is rolled forward by every `open`. The sealed
    /// journal names the staged files with their hashes and the old records to delete.
    fn write_journal(
        &self,
        tags: &[String],
        old: &[String],
        pw: &PasswordKek,
    ) -> Result<(), StoreError> {
        let staging = self.dir.join(STAGING);
        let mut body = String::new();
        for tag in tags {
            debug_assert!(is_tag(tag));
            let hash = file_hash_hex(&staging.join(format!("{tag}.{EXT}")))?;
            body.push_str(&format!("n {tag} {hash}\n"));
        }
        body.push_str(&format!(
            "m {}\n",
            file_hash_hex(&staging.join(MANIFEST_FILE))?
        ));
        for tag in old {
            debug_assert!(is_tag(tag));
            body.push_str(&format!("d {tag}\n"));
        }
        if body.len() > JOURNAL_BODY_MAX {
            return Err(StoreError::TooManyRecords);
        }
        let staged_keys = read_private_file(
            &staging.join(KEYFILE),
            KEYFILE_MAX_LEN,
            StoreError::KeyfileCorrupt,
        )?;
        let bundle = KeyFile::decode(&staged_keys)?.unlock_password(&self.profile, pw)?;
        let sealed = seal_journal(&bundle, &self.profile, body.as_bytes())?;
        self.atomic_write(JOURNAL, &sealed)?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
}

fn remove_staging(dir: &Path) -> Result<(), StoreError> {
    let staging = dir.join(STAGING);
    match fs::symlink_metadata(&staging) {
        Ok(md) if md.is_dir() => fs::remove_dir_all(&staging)?,
        Ok(_) => fs::remove_file(&staging)?,
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

fn journal_aad(profile: &str) -> Vec<u8> {
    let mut a = JOURNAL_MAGIC.to_vec();
    a.extend_from_slice(profile.as_bytes());
    a
}

fn seal_journal(bundle: &Bundle, profile: &str, body: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| StoreError::Io(ErrorKind::Other))?;
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(bundle.manifest()))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &journal_aad(profile),
            },
        )
        .map_err(|_| StoreError::RekeyJournalCorrupt)?;
    let mut out = JOURNAL_MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Authenticates the journal under the new bundle and returns its tag list.
fn open_journal(bundle: &Bundle, profile: &str, bytes: &[u8]) -> Result<Journal, StoreError> {
    if bytes.len() < 4 + NONCE_LEN + TAG_LEN || &bytes[..4] != JOURNAL_MAGIC {
        return Err(StoreError::RekeyJournalCorrupt);
    }
    let (nonce, ct) = bytes[4..].split_at(NONCE_LEN);
    let body = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(bundle.manifest()))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &journal_aad(profile),
            },
        )
        .map_err(|_| StoreError::RekeyJournalCorrupt)?;
    parse_journal(&body)
}

/// What the sealed journal says: staged record hashes, the manifest hash, old tags to delete.
#[derive(Debug)]
struct Journal {
    new: BTreeMap<String, String>,
    manifest: String,
    old: BTreeSet<String>,
}

fn is_hash_hex(h: &str) -> bool {
    h.len() == 2 * HASH_LEN && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn parse_journal(bytes: &[u8]) -> Result<Journal, StoreError> {
    let bad = || StoreError::RekeyJournalCorrupt;
    let text = std::str::from_utf8(bytes).map_err(|_| bad())?;
    let body = text.strip_suffix('\n').ok_or_else(bad)?;
    let mut j = Journal {
        new: BTreeMap::new(),
        manifest: String::new(),
        old: BTreeSet::new(),
    };
    for line in body.split('\n') {
        let parts: Vec<&str> = line.split(' ').collect();
        match parts.as_slice() {
            ["n", tag, hash] if is_tag(tag) && is_hash_hex(hash) => {
                if j.new
                    .insert((*tag).to_owned(), (*hash).to_owned())
                    .is_some()
                {
                    return Err(bad());
                }
            }
            ["m", hash] if is_hash_hex(hash) && j.manifest.is_empty() => {
                j.manifest = (*hash).to_owned();
            }
            ["d", tag] if is_tag(tag) => {
                if !j.old.insert((*tag).to_owned()) {
                    return Err(bad());
                }
            }
            _ => return Err(bad()),
        }
    }
    let limit = MAX_RECORDS + 2;
    if j.manifest.is_empty()
        || j.new.len() > limit
        || j.old.len() > limit
        || j.new.keys().any(|t| j.old.contains(t))
    {
        return Err(bad());
    }
    Ok(j)
}

/// Lower-case hex SHA-256 of a private regular file of at most one record file's size.
fn file_hash_hex(path: &Path) -> Result<String, StoreError> {
    let max = 4 + NONCE_LEN + TAG_LEN + MAX_INNER_LEN;
    let bytes = read_private_file(path, max, StoreError::RekeyJournalCorrupt)?;
    Ok(Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Moves `from/file` onto `to/file` if it is a regular file; a missing one is skipped (already
/// moved by an earlier pass).
fn move_in(from: &Path, to: &Path, file: &str) -> Result<(), StoreError> {
    let src = from.join(file);
    match fs::symlink_metadata(&src) {
        Ok(md) if md.is_file() => fs::rename(&src, to.join(file))?,
        Ok(_) => return Err(StoreError::InsecurePath),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

/// Finishes or discards an interrupted rekey. Runs in `open` with the profile lock held and no
/// KEK of the caller (`unlock`): it only moves files the authenticated journal names.
///
/// Before any file moves or is deleted, the staged key file must open with the caller's KEK
/// (`unlock`): a planted or foreign staging directory is refused and left alone.
pub(super) fn recover(
    dir: &Path,
    profile: &str,
    unlock: &dyn Fn(&KeyFile, &str) -> Result<Bundle, StoreError>,
) -> Result<(), StoreError> {
    let journal = match read_private_file(
        &dir.join(JOURNAL),
        JOURNAL_MAX_LEN,
        StoreError::RekeyJournalCorrupt,
    ) {
        Ok(b) => b,
        Err(StoreError::Io(ErrorKind::NotFound)) => return remove_staging(dir),
        Err(e) => return Err(e),
    };
    let staging = dir.join(STAGING);
    let staged = match fs::symlink_metadata(&staging) {
        Ok(md) if md.is_dir() => true,
        Ok(_) => return Err(StoreError::InsecurePath),
        Err(e) if e.kind() == ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    // Without a staging directory the switch already finished (a crash before the journal was
    // removed); deleting "old" records then would be deleting the new ones.
    if staged {
        check_private_dir(&staging)?;
        // The key file moves last: once it has, the profile's own copy is the staged one.
        let keys_at = if staging.join(KEYFILE).exists() {
            staging.join(KEYFILE)
        } else {
            dir.join(KEYFILE)
        };
        let staged_keys = read_private_file(&keys_at, KEYFILE_MAX_LEN, StoreError::KeyfileCorrupt)?;
        let bundle = unlock(&KeyFile::decode(&staged_keys)?, profile)?;
        // Authenticated by the new bundle: a planted or damaged journal deletes nothing.
        let journal = open_journal(&bundle, profile, &journal)?;
        // Every staged file, wherever it is now, must be exactly what was sealed before anything
        // is replaced or deleted.
        for (tag, want) in &journal.new {
            verify_file(&staging, dir, &format!("{tag}.{EXT}"), want)?;
        }
        verify_file(&staging, dir, MANIFEST_FILE, &journal.manifest)?;
        for tag in journal.new.keys() {
            move_in(&staging, dir, &format!("{tag}.{EXT}"))?;
        }
        move_in(&staging, dir, MANIFEST_FILE)?;
        move_in(&staging, dir, KEYFILE)?;
        // The deletes below rely on the moves having reached the disk first.
        File::open(dir)?.sync_all()?;
        drop_old_records(dir, &journal.old)?;
        // A missing staging directory means "the switch finished", so the deletes must be
        // durable before it goes.
        File::open(dir)?.sync_all()?;
        fs::remove_dir_all(&staging)?;
    }
    File::open(dir)?.sync_all()?;
    fs::remove_file(dir.join(JOURNAL))?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

/// Deletes the pre-rekey records the sealed journal lists. Anything else, including records
/// created after a rekey, is left alone.
fn drop_old_records(dir: &Path, old: &BTreeSet<String>) -> Result<(), StoreError> {
    for tag in old {
        match fs::remove_file(dir.join(format!("{tag}.{EXT}"))) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// `file` must hash to `want` in the staging directory, or (moved already) in the profile.
fn verify_file(staging: &Path, dir: &Path, file: &str, want: &str) -> Result<(), StoreError> {
    let path = if staging.join(file).exists() {
        staging.join(file)
    } else {
        dir.join(file)
    };
    if file_hash_hex(&path)? != want {
        return Err(StoreError::RekeyJournalCorrupt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::derive_key;

    const EK: [u8; 32] = [7u8; 32];
    const NEW_EK: [u8; 32] = [9u8; 32];
    const SEED: [u8; 64] = [0x33; 64];

    fn paths(tmp: &tempfile::TempDir) -> ProfilePaths {
        ProfilePaths::resolve(tmp.path(), "work").unwrap()
    }

    /// An upgraded store: export-key-derived keys, key file written.
    fn upgraded(tmp: &tempfile::TempDir) -> ProfileStore {
        let p = paths(tmp);
        let s = ProfileStore::open_legacy_fixture(&p, &EK).unwrap();
        s.put("a", b"one").unwrap();
        s.put("b", b"two").unwrap();
        drop(s);
        fs::remove_file(p.dir.join(KEYFILE)).ok();
        ProfileStore::open_upgrading(&p, &EK).unwrap()
    }

    fn record_files(dir: &Path) -> BTreeSet<String> {
        fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.unwrap().file_name().into_string().ok())
            .filter(|f| f.ends_with(".rc2"))
            .collect()
    }

    #[test]
    fn rekey_moves_the_store_onto_fresh_keys_and_keeps_every_record() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = upgraded(&tmp);
        assert!(s.derived_keys);
        let before = record_files(&p.dir);
        let s = s.rekey(&p, &EK, None).unwrap();
        assert!(!s.derived_keys);
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        assert_eq!(&**s.get("b").unwrap().unwrap(), b"two");
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        let after = record_files(&p.dir);
        assert_eq!(after.len(), before.len());
        assert!(after.is_disjoint(&before), "new name-tag key, new tags");
        assert_ne!(s.bundle.record(), &derive_key(&EK).unwrap()[..]);
        assert!(!p.dir.join(STAGING).exists() && !p.dir.join(JOURNAL).exists());
        s.rewrap_password(&NEW_EK).unwrap();
        drop(s);
        assert!(matches!(
            ProfileStore::open(&p, &EK),
            Err(StoreError::Authentication)
        ));
        let s = ProfileStore::open(&p, &NEW_EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        s.put("c", b"three").unwrap();
    }

    #[test]
    fn a_store_with_random_keys_is_returned_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = ProfileStore::open(&p, &EK).unwrap();
        s.put("a", b"one").unwrap();
        let files = record_files(&p.dir);
        let s = s.rekey(&p, &EK, None).unwrap();
        assert_eq!(files, record_files(&p.dir));
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
    }

    #[test]
    fn rekey_needs_the_export_key_the_keys_derive_from() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = upgraded(&tmp);
        let err = s.rekey(&p, &NEW_EK, None).err();
        assert!(matches!(err, Some(StoreError::Authentication)), "{err:?}");
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(s.derived_keys && !p.dir.join(STAGING).exists());
    }

    #[test]
    fn the_recovery_slot_is_rewrapped_and_needs_the_phrase() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = upgraded(&tmp);
        s.add_recovery_wrap(&rc).unwrap();
        let err = s.rekey(&p, &EK, None).err();
        assert!(
            matches!(err, Some(StoreError::RecoveryPhraseRequired)),
            "{err:?}"
        );
        let s = ProfileStore::open(&p, &EK).unwrap();
        let wrong = RecoveryKek::from_seed(&[0x34; 64]).unwrap();
        assert!(s.rekey(&p, &EK, Some(&wrong)).is_err());
        let s = ProfileStore::open(&p, &EK).unwrap();
        let s = s.rekey(&p, &EK, Some(&rc)).unwrap();
        assert!(s.has_recovery_wrap().unwrap());
        drop(s);
        let by_phrase = ProfileStore::open_with_recovery(&p, &rc).unwrap();
        assert_eq!(&**by_phrase.get("b").unwrap().unwrap(), b"two");
    }

    #[test]
    fn a_phrase_given_at_rekey_adds_the_slot() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = upgraded(&tmp);
        assert!(!s.has_recovery_wrap().unwrap());
        let s = s.rekey(&p, &EK, Some(&rc)).unwrap();
        assert!(s.has_recovery_wrap().unwrap());
    }

    /// Runs `stage` and `write_journal` but not the switch: the state a crash right after the
    /// commit point leaves.
    fn commit_without_switching(tmp: &tempfile::TempDir) -> (BTreeSet<String>, Vec<String>) {
        let s = upgraded(tmp);
        let old = record_files(&paths(tmp).dir);
        let old_tags = s.tags().unwrap();
        let tags = s.stage(&EK, None).unwrap();
        s.write_journal(&tags, &old_tags, &PasswordKek::new(&EK).unwrap())
            .unwrap();
        (old, tags)
    }

    #[test]
    fn a_crash_before_the_journal_discards_the_staging_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = upgraded(&tmp);
        s.stage(&EK, None).unwrap();
        drop(s);
        assert!(p.dir.join(STAGING).exists());
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(s.derived_keys, "the old store is untouched");
        assert!(!p.dir.join(STAGING).exists());
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
    }

    #[test]
    fn a_crash_after_the_journal_rolls_forward_at_the_next_open() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let (old, tags) = commit_without_switching(&tmp);
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(!s.derived_keys);
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        let now = record_files(&p.dir);
        assert!(now.is_disjoint(&old));
        assert_eq!(now.len(), tags.len());
        assert!(!p.dir.join(STAGING).exists() && !p.dir.join(JOURNAL).exists());
    }

    #[test]
    fn a_crash_in_the_middle_of_the_switch_rolls_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let (_, tags) = commit_without_switching(&tmp);
        // Some staged records already moved in; the manifest and key file have not.
        let staging = p.dir.join(STAGING);
        fs::rename(
            staging.join(format!("{}.{EXT}", tags[0])),
            p.dir.join(format!("{}.{EXT}", tags[0])),
        )
        .unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(!s.derived_keys);
        assert_eq!(&**s.get("b").unwrap().unwrap(), b"two");
    }

    #[test]
    fn a_crash_after_the_key_file_moved_rolls_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let (_, tags) = commit_without_switching(&tmp);
        let staging = p.dir.join(STAGING);
        for f in tags
            .iter()
            .map(|t| format!("{t}.{EXT}"))
            .chain([MANIFEST_FILE.to_owned(), KEYFILE.to_owned()])
        {
            fs::rename(staging.join(&f), p.dir.join(&f)).unwrap();
        }
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(!s.derived_keys);
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        assert!(!p.dir.join(STAGING).exists() && !p.dir.join(JOURNAL).exists());
    }

    #[test]
    fn a_crash_after_the_manifest_moved_before_the_key_file_rolls_forward() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let (_, tags) = commit_without_switching(&tmp);
        let staging = p.dir.join(STAGING);
        for f in tags
            .iter()
            .map(|t| format!("{t}.{EXT}"))
            .chain([MANIFEST_FILE.to_owned()])
        {
            fs::rename(staging.join(&f), p.dir.join(&f)).unwrap();
        }
        // Some old records are already gone as well.
        let old: Vec<_> = record_files(&p.dir)
            .into_iter()
            .filter(|f| !tags.iter().any(|t| *f == format!("{t}.{EXT}")))
            .collect();
        fs::remove_file(p.dir.join(&old[0])).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(!s.derived_keys);
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        assert!(!p.dir.join(STAGING).exists() && !p.dir.join(JOURNAL).exists());
    }

    #[test]
    fn a_staging_directory_with_the_profiles_own_key_file_still_needs_a_sealed_journal() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        drop(upgraded(&tmp));
        let before = record_files(&p.dir);
        let staging = p.dir.join(STAGING);
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(
            &staging,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        fs::copy(p.dir.join(KEYFILE), staging.join(KEYFILE)).unwrap();
        let mut junk = JOURNAL_MAGIC.to_vec();
        junk.extend_from_slice(&[7u8; NONCE_LEN + 40]);
        fs::write(p.dir.join(JOURNAL), junk).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        assert!(ProfileStore::open(&p, &EK).is_err());
        assert_eq!(before, record_files(&p.dir));
        fs::remove_file(p.dir.join(JOURNAL)).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert_eq!(s.names().unwrap(), ["a", "b"]);
    }

    #[test]
    fn a_crash_after_the_switch_before_the_journal_goes_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        commit_without_switching(&tmp);
        let journal = fs::read(p.dir.join(JOURNAL)).unwrap();
        drop(ProfileStore::open(&p, &EK).unwrap());
        fs::write(p.dir.join(JOURNAL), journal).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        assert!(!p.dir.join(JOURNAL).exists());
    }

    #[test]
    fn a_planted_journal_without_staging_cannot_delete_records() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        drop(ProfileStore::open(&p, &EK).unwrap());
        let s = ProfileStore::open(&p, &EK).unwrap();
        s.put("a", b"one").unwrap();
        drop(s);
        let before = record_files(&p.dir);
        let junk = "00000000000000000000000000000000\n";
        fs::write(p.dir.join(JOURNAL), junk).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert_eq!(before, record_files(&p.dir));
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
    }

    #[test]
    fn a_foreign_staging_directory_cannot_take_over_the_store() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let other = tempfile::tempdir().unwrap();
        let op = paths(&other);
        let o = ProfileStore::open(&op, &[1u8; 32]).unwrap();
        o.put("a", b"evil").unwrap();
        drop(o);
        let s = upgraded(&tmp);
        let tags = record_files(&op.dir);
        drop(s);
        let staging = p.dir.join(STAGING);
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(
            &staging,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let mut body = String::new();
        for f in &tags {
            fs::copy(op.dir.join(f), staging.join(f)).unwrap();
            body.push_str(f.strip_suffix(".rc2").unwrap());
            body.push('\n');
        }
        for f in [KEYFILE, MANIFEST_FILE] {
            fs::copy(op.dir.join(f), staging.join(f)).unwrap();
        }
        fs::write(p.dir.join(JOURNAL), body).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        // The planted key file is sealed under another account's password KEK: refused before
        // anything moves, so the real store survives.
        assert!(matches!(
            ProfileStore::open(&p, &EK),
            Err(StoreError::Authentication)
        ));
        fs::remove_file(p.dir.join(JOURNAL)).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert_eq!(s.names().unwrap(), ["a", "b"]);
        assert!(s.derived_keys);
    }

    fn private_staging(p: &ProfilePaths) -> std::path::PathBuf {
        let staging = p.dir.join(STAGING);
        fs::create_dir(&staging).unwrap();
        fs::set_permissions(
            &staging,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        staging
    }

    #[test]
    fn a_junk_journal_with_an_empty_staging_directory_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = ProfileStore::open(&p, &EK).unwrap();
        s.put("a", b"one").unwrap();
        s.put("b", b"two").unwrap();
        drop(s);
        let before = record_files(&p.dir);
        private_staging(&p);
        let junk = "00000000000000000000000000000000\n";
        fs::write(p.dir.join(JOURNAL), junk).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let err = ProfileStore::open(&p, &EK).err();
        assert!(
            matches!(err, Some(StoreError::RekeyJournalCorrupt)),
            "{err:?}"
        );
        assert_eq!(before, record_files(&p.dir));
        assert!(p.dir.join(JOURNAL).exists() && p.dir.join(STAGING).exists());
    }

    #[test]
    fn a_damaged_journal_in_a_real_commit_window_deletes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let (old, tags) = commit_without_switching(&tmp);
        let journal = fs::read(p.dir.join(JOURNAL)).unwrap();
        for cut in [journal.len() - 1, journal.len() / 2, 5] {
            fs::write(p.dir.join(JOURNAL), &journal[..cut]).unwrap();
            let err = ProfileStore::open(&p, &EK).err();
            assert!(
                matches!(err, Some(StoreError::RekeyJournalCorrupt)),
                "{err:?}"
            );
            assert_eq!(old, record_files(&p.dir));
            assert_eq!(tags.len(), record_files(&p.dir.join(STAGING)).len());
        }
        fs::write(p.dir.join(JOURNAL), &journal).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert!(!s.derived_keys);
    }

    #[test]
    fn journal_parsing_is_strict() {
        let t1 = "0123456789abcdef0123456789abcdef";
        let t2 = "fedcba9876543210fedcba9876543210";
        let h = "ab".repeat(32);
        let good = format!("n {t1} {h}\nm {h}\nd {t2}\n");
        let j = parse_journal(good.as_bytes()).unwrap();
        assert_eq!((j.new.len(), j.old.len()), (1, 1));
        for bad in [
            String::new(),
            "\n".to_owned(),
            good.trim_end().to_owned(),
            format!("n {t1} {h}\n"),
            format!("m {h}\nm {h}\n"),
            format!("n {t1} {h}\nn {t1} {h}\nm {h}\n"),
            format!("n {t1} {h}\nm {h}\nd {t1}\n"),
            format!("n {t1} {h}\nm {h}\nd {t2}\nd {t2}\n"),
            format!("n {t1} {h}\nm {h}\n\n"),
            format!("n {} {h}\nm {h}\n", t1.to_uppercase()),
            format!("n {t1} {}\nm {h}\n", h.to_uppercase()),
            format!("n {t1} {h}x\nm {h}\n"),
            format!("x {t1}\nm {h}\n"),
            format!("d ../{}\nm {h}\n", &t1[3..]),
        ] {
            assert!(
                matches!(
                    parse_journal(bad.as_bytes()),
                    Err(StoreError::RekeyJournalCorrupt)
                ),
                "{bad:?}"
            );
        }
        assert!(parse_journal(&[0xff, b'\n']).is_err());
    }

    #[test]
    fn a_replayed_journal_deletes_nothing_made_after_the_rekey() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        commit_without_switching(&tmp);
        let journal = fs::read(p.dir.join(JOURNAL)).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        s.put("c", b"after").unwrap();
        drop(s);
        let before = record_files(&p.dir);
        private_staging(&p);
        fs::write(p.dir.join(JOURNAL), journal).unwrap();
        fs::set_permissions(
            p.dir.join(JOURNAL),
            std::os::unix::fs::PermissionsExt::from_mode(0o600),
        )
        .unwrap();
        let err = ProfileStore::open(&p, &EK).err();
        assert!(
            matches!(err, Some(StoreError::RekeyJournalCorrupt)),
            "{err:?}"
        );
        assert_eq!(before, record_files(&p.dir), "nothing deleted");
        fs::remove_file(p.dir.join(JOURNAL)).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        assert_eq!(&**s.get("c").unwrap().unwrap(), b"after");
    }

    #[test]
    fn a_damaged_staged_record_or_manifest_stops_the_switch_before_any_delete() {
        for victim in ["record", "manifest"] {
            let tmp = tempfile::tempdir().unwrap();
            let p = paths(&tmp);
            let (old, tags) = commit_without_switching(&tmp);
            let file = if victim == "record" {
                format!("{}.{EXT}", tags[0])
            } else {
                MANIFEST_FILE.to_owned()
            };
            let path = p.dir.join(STAGING).join(file);
            let mut bytes = fs::read(&path).unwrap();
            *bytes.last_mut().unwrap() ^= 1;
            fs::write(&path, bytes).unwrap();
            let err = ProfileStore::open(&p, &EK).err();
            assert!(
                matches!(err, Some(StoreError::RekeyJournalCorrupt)),
                "{err:?}"
            );
            assert_eq!(old, record_files(&p.dir), "{victim}");
            assert!(p.dir.join(JOURNAL).exists());
        }
    }

    #[test]
    fn recovery_opened_handles_do_not_claim_random_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = ProfileStore::open(&p, &EK).unwrap();
        s.add_recovery_wrap(&rc).unwrap();
        drop(s);
        let s = ProfileStore::open_with_recovery(&p, &rc).unwrap();
        assert!(s.needs_rekey());
        assert!(matches!(
            s.rekey(&p, &EK, Some(&rc)).err(),
            Some(StoreError::RekeyRequired)
        ));
    }

    #[test]
    fn rekey_leaves_no_plaintext_and_a_private_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let p = paths(&tmp);
        let s = upgraded(&tmp);
        s.put("c", b"needle-plaintext-needle").unwrap();
        let s = s.rekey(&p, &EK, None).unwrap();
        drop(s);
        for entry in fs::read_dir(&p.dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file() {
                let bytes = fs::read(&path).unwrap();
                assert!(!bytes.windows(6).any(|w| w == b"needle"), "{path:?}");
            }
        }
    }
}
