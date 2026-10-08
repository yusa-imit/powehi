//! Encrypted profile store (prd.md §7A.3). Unix only: relies on POSIX modes.
//!
//! Every record is one file `<name>.rec` holding `MAGIC || nonce(12) || AES-256-GCM(..)`.
//! The record key is `HKDF-SHA256(ikm = OPAQUE export_key, info = KEY_INFO)`; the info label
//! is CLI-specific so it is domain-separated from the web DB key (§7.4). The AEAD AAD binds
//! `MAGIC || name`, so a record file renamed to another record name fails authentication.
//! Record *names* are non-secret labels and appear in file names; contents never do.
//! The AAD also binds the profile directory name, so records cannot be moved between profiles.
//!
//! Known limits (escalated to the owner, see the need-human issue on store rollback): each
//! record is an independent file, so an attacker with write access to the profile directory can
//! roll back, delete or mix records from different points in time; only a wholesale snapshot
//! replay is the risk accepted in §3.2. One process may hold a profile open at a time (an
//! exclusive `flock` on `.lock`), which keeps writers from clobbering each other.
//! The record key is fixed for the account's OPAQUE registration, so the GCM random-nonce
//! budget (NIST SP 800-38D §8.3, 2^32 invocations) is cumulative over the account lifetime.
//! Key hygiene: the AES key schedule is zeroized on drop (`aes/zeroize`); the HKDF/HMAC
//! internals and the GHASH subkey held by the cipher are not zeroized (upstream) and may linger
//! in memory. Further hardening (owner checks, DEK/KEK, key canary) is tracked in issue #16.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::profile::ProfilePaths;

/// File magic and format version.
const MAGIC: &[u8; 4] = b"PHS1";
/// HKDF info label (domain separation from every other use of the export key).
const KEY_INFO: &[u8] = b"powehi-cli/profile-store/v1/record-key";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// The one accepted export-key length: `powehi_crypto_core::opaque::EXPORT_KEY_LEN`. Register and
/// login must both pass exactly this prefix, or the derived key (and every record) would differ.
const EXPORT_KEY_LEN: usize = 32;
const LOCK_FILE: &str = ".lock";
/// Upper bound on one record's plaintext.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;
/// Upper bound on records per profile (bounds `names()` and the directory scan in `put`).
pub const MAX_RECORDS: usize = 4096;
/// Longest record name, in bytes.
pub const MAX_NAME_LEN: usize = 64;
const EXT: &str = "rec";

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("export key has an unsupported length")]
    BadKeyLength,
    #[error("invalid record name")]
    BadName,
    #[error("record exceeds the maximum size")]
    TooLarge,
    #[error("too many records in the profile")]
    TooManyRecords,
    #[error("profile path is not a private directory or file (expected 0700/0600, no symlinks)")]
    InsecurePath,
    #[error("record is malformed")]
    Corrupt,
    #[error("record failed authentication (wrong key or tampered file)")]
    Authentication,
    #[error("profile is already open in another process")]
    Locked,
    #[error("profile store I/O error: {0}")]
    Io(ErrorKind),
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Handle to one profile directory plus its derived record key. The key is zeroized on drop.
pub struct ProfileStore {
    dir: PathBuf,
    profile: String,
    cipher: Aes256Gcm,
    _lock: File,
}

impl std::fmt::Debug for ProfileStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileStore")
            .field("dir", &self.dir)
            .finish_non_exhaustive()
    }
}

fn validate_record_name(name: &str) -> Result<(), StoreError> {
    let ok = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
    if ok {
        Ok(())
    } else {
        Err(StoreError::BadName)
    }
}

fn derive_key(export_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    if export_key.len() != EXPORT_KEY_LEN {
        return Err(StoreError::BadKeyLength);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, export_key)
        .expand(KEY_INFO, key.as_mut())
        .map_err(|_| StoreError::BadKeyLength)?;
    Ok(key)
}

fn aad(profile: &str, name: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(MAGIC.len() + 1 + profile.len() + name.len());
    a.extend_from_slice(MAGIC);
    // `open` re-validates the profile name (<= 64 bytes); the length prefix keeps
    // `profile || name` unambiguous.
    a.push(u8::try_from(profile.len()).unwrap_or(u8::MAX));
    a.extend_from_slice(profile.as_bytes());
    a.extend_from_slice(name.as_bytes());
    a
}

/// Rejects symlinks, non-directories and any group/other permission bits.
fn check_private_dir(dir: &Path) -> Result<(), StoreError> {
    let md = fs::symlink_metadata(dir)?;
    if !md.is_dir() || md.mode() & 0o077 != 0 {
        return Err(StoreError::InsecurePath);
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    check_private_dir(dir)
}

impl ProfileStore {
    /// Opens (creating with mode 0700 if absent) the profile directory and derives the key.
    /// `export_key` is borrowed; the caller zeroizes its own copy.
    pub fn open(paths: &ProfilePaths, export_key: &[u8]) -> Result<Self, StoreError> {
        let key = derive_key(export_key)?;
        create_private_dir(&paths.dir)?;
        let profile = paths
            .dir
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(StoreError::InsecurePath)?
            .to_owned();
        crate::profile::validate_name(&profile).map_err(|_| StoreError::InsecurePath)?;
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(paths.dir.join(LOCK_FILE))?;
        lock.try_lock().map_err(|e| match e {
            std::fs::TryLockError::WouldBlock => StoreError::Locked,
            std::fs::TryLockError::Error(e) => StoreError::from(e),
        })?;
        debug_assert!(key.iter().any(|&b| b != 0));
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
        Ok(Self {
            dir: paths.dir.clone(),
            profile,
            cipher,
            _lock: lock,
        })
    }

    fn record_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.{EXT}"))
    }

    /// Encrypts and atomically writes a record (temp file 0600 → fsync → rename → fsync dir).
    pub fn put(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        validate_record_name(name)?;
        if plaintext.len() > MAX_RECORD_LEN {
            return Err(StoreError::TooLarge);
        }
        check_private_dir(&self.dir)?;
        let is_new = fs::symlink_metadata(self.record_path(name)).is_err();
        if is_new && self.names()?.len() >= MAX_RECORDS {
            return Err(StoreError::TooManyRecords);
        }
        let mut nonce = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| StoreError::Io(ErrorKind::Other))?;
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad(&self.profile, name),
                },
            )
            .map_err(|_| StoreError::Corrupt)?;
        let mut blob = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        self.write_atomic(name, &blob)
    }

    fn write_atomic(&self, name: &str, blob: &[u8]) -> Result<(), StoreError> {
        let tmp = self.dir.join(format!("{name}.{EXT}.tmp"));
        // The profile lock makes this process the only writer; a stale temp holds only ciphertext.
        match fs::remove_file(&tmp) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        let written = f.write_all(blob).and_then(|()| f.sync_all());
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, self.record_path(name))) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Reads and decrypts a record; `Ok(None)` if it does not exist.
    pub fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        validate_record_name(name)?;
        check_private_dir(&self.dir)?;
        let path = self.record_path(name);
        // O_NOFOLLOW: a symlinked record is refused; O_NONBLOCK: a FIFO cannot hang the open.
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(StoreError::InsecurePath)
            }
            Err(e) => return Err(e.into()),
        };
        let md = f.metadata()?;
        if !md.is_file() || md.mode() & 0o077 != 0 {
            return Err(StoreError::InsecurePath);
        }
        let max = (MAGIC.len() + NONCE_LEN + TAG_LEN + MAX_RECORD_LEN) as u64;
        if md.len() > max {
            return Err(StoreError::Corrupt);
        }
        let mut blob = Vec::with_capacity(md.len() as usize);
        Read::by_ref(&mut f).take(max).read_to_end(&mut blob)?;
        if blob.len() < MAGIC.len() + NONCE_LEN + TAG_LEN || &blob[..MAGIC.len()] != MAGIC {
            return Err(StoreError::Corrupt);
        }
        let (nonce, ct) = blob[MAGIC.len()..].split_at(NONCE_LEN);
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(&self.profile, name),
                },
            )
            .map_err(|_| StoreError::Authentication)?;
        Ok(Some(Zeroizing::new(pt)))
    }

    /// Deletes a record; absent records are not an error.
    pub fn remove(&self, name: &str) -> Result<(), StoreError> {
        validate_record_name(name)?;
        check_private_dir(&self.dir)?;
        match fs::remove_file(self.record_path(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Sorted record names currently present; more than `MAX_RECORDS` is an error.
    pub fn names(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let file = entry?.file_name();
            let Some(stem) = file.to_str().and_then(|s| s.strip_suffix(".rec")) else {
                continue;
            };
            if validate_record_name(stem).is_ok() {
                out.push(stem.to_owned());
                if out.len() > MAX_RECORDS {
                    return Err(StoreError::TooManyRecords);
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const EK: [u8; 32] = [7u8; 32];
    const KAT_KEY: &str = "0baafe165147fa018516574f9d58ff546bcfec06647af0cc8e3edb63b64dea32";

    fn open(tmp: &tempfile::TempDir, ek: &[u8]) -> Result<ProfileStore, StoreError> {
        ProfileStore::open(&ProfilePaths::resolve(tmp.path(), "work").unwrap(), ek)
    }

    #[test]
    fn round_trip_and_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        assert!(s.get("identity").unwrap().is_none());
        s.put("identity", b"secret-bytes").unwrap();
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"secret-bytes");
        s.put("identity", b"v2").unwrap();
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"v2");
        s.put("empty", b"").unwrap();
        assert_eq!(s.get("empty").unwrap().unwrap().len(), 0);
        assert_eq!(s.names().unwrap(), vec!["empty", "identity"]);
        s.remove("identity").unwrap();
        s.remove("identity").unwrap();
        assert!(s.get("identity").unwrap().is_none());
    }

    #[test]
    fn persists_across_reopen_with_same_key() {
        let tmp = tempfile::tempdir().unwrap();
        open(&tmp, &EK).unwrap().put("a", b"x").unwrap();
        assert_eq!(&**open(&tmp, &EK).unwrap().get("a").unwrap().unwrap(), b"x");
    }

    #[test]
    fn wrong_key_is_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        open(&tmp, &EK).unwrap().put("a", b"x").unwrap();
        let other = open(&tmp, &[8u8; 32]).unwrap();
        assert!(matches!(other.get("a"), Err(StoreError::Authentication)));
    }

    #[test]
    fn tampered_file_is_typed_error() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"hello world").unwrap();
        let path = s.record_path("a");
        let orig = fs::read(&path).unwrap();
        for i in [0, MAGIC.len(), MAGIC.len() + NONCE_LEN, orig.len() - 1] {
            let mut b = orig.clone();
            b[i] ^= 1;
            fs::write(&path, &b).unwrap();
            let r = s.get("a");
            assert!(
                matches!(r, Err(StoreError::Corrupt | StoreError::Authentication)),
                "{i}"
            );
        }
        fs::write(&path, &orig[..10]).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Corrupt)));
    }

    #[test]
    fn record_swap_between_names_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        fs::copy(s.record_path("a"), s.record_path("b")).unwrap();
        assert!(matches!(s.get("b"), Err(StoreError::Authentication)));
    }

    #[test]
    fn no_plaintext_on_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        let marker = b"PLAINTEXT-MARKER-0123456789-abcdef";
        s.put("msgs", marker).unwrap();
        s.put("msgs", marker).unwrap();
        for e in fs::read_dir(&s.dir).unwrap() {
            let bytes = fs::read(e.unwrap().path()).unwrap();
            assert!(!bytes.windows(marker.len()).any(|w| w == marker));
        }
    }

    #[test]
    fn same_plaintext_gives_distinct_ciphertexts() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"same").unwrap();
        let first = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"same").unwrap();
        assert_ne!(first, fs::read(s.record_path("a")).unwrap());
    }

    #[test]
    fn permissions_are_private_and_no_temp_left() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        assert_eq!(fs::metadata(&s.dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(s.record_path("a")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(!s.dir.join("a.rec.tmp").exists());
    }

    #[test]
    fn open_rejects_loose_dir_and_symlink_and_loose_file() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        fs::set_permissions(s.record_path("a"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::InsecurePath)));
        fs::set_permissions(&s.dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::InsecurePath)));
        fs::set_permissions(&s.dir, fs::Permissions::from_mode(0o700)).unwrap();

        let real = tmp.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        let link_base = tempfile::tempdir().unwrap();
        fs::create_dir_all(link_base.path().join("powehi")).unwrap();
        std::os::unix::fs::symlink(&real, link_base.path().join("powehi/work")).unwrap();
        assert!(matches!(
            open(&link_base, &EK),
            Err(StoreError::InsecurePath)
        ));
    }

    #[test]
    fn rejects_bad_names_keys_and_sizes() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        for n in ["", "../x", "a/b", "A", "a.b", "a\0"] {
            assert!(matches!(s.put(n, b"x"), Err(StoreError::BadName)), "{n:?}");
            assert!(matches!(s.get(n), Err(StoreError::BadName)));
        }
        assert!(matches!(
            open(&tmp, &[1u8; 31]),
            Err(StoreError::BadKeyLength)
        ));
        // Only the 32-byte prefix that register and login both return is accepted.
        assert!(matches!(
            open(&tmp, &[1u8; 64]),
            Err(StoreError::BadKeyLength)
        ));
        let big = vec![0u8; MAX_RECORD_LEN + 1];
        assert!(matches!(s.put("a", &big), Err(StoreError::TooLarge)));
    }

    #[test]
    fn key_derivation_is_domain_separated_and_deterministic() {
        let a = derive_key(&EK).unwrap();
        assert_eq!(*a, *derive_key(&EK).unwrap());
        assert_ne!(*a, *derive_key(&[8u8; 32]).unwrap());
        let mut raw = [0u8; 32];
        Hkdf::<Sha256>::new(None, &EK)
            .expand(b"other-label", &mut raw)
            .unwrap();
        assert_ne!(*a, raw);
        // Distinct from the web DB key derivation (app/src/db/encryption.ts).
        let mut web = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"powehi-indexed-db-v1"), &EK)
            .expand(b"powehi-idb-aes-gcm-256-v1", &mut web)
            .unwrap();
        assert_ne!(*a, web);
    }

    #[test]
    fn key_derivation_known_answer() {
        let k = derive_key(&EK).unwrap();
        assert_eq!(hex(&k[..]), KAT_KEY);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn second_open_is_locked_until_first_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        let first = open(&tmp, &EK).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::Locked)));
        drop(first);
        assert!(open(&tmp, &EK).is_ok());
    }

    #[test]
    fn symlinked_record_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        let target = tmp.path().join("elsewhere");
        fs::copy(s.record_path("a"), &target).unwrap();
        fs::remove_file(s.record_path("a")).unwrap();
        std::os::unix::fs::symlink(&target, s.record_path("a")).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::InsecurePath)));
    }

    #[test]
    fn record_moved_between_profiles_fails() {
        let tmp = tempfile::tempdir().unwrap();
        let a =
            ProfileStore::open(&ProfilePaths::resolve(tmp.path(), "one").unwrap(), &EK).unwrap();
        let b =
            ProfileStore::open(&ProfilePaths::resolve(tmp.path(), "two").unwrap(), &EK).unwrap();
        a.put("id", b"x").unwrap();
        fs::copy(a.record_path("id"), b.record_path("id")).unwrap();
        assert!(matches!(b.get("id"), Err(StoreError::Authentication)));
    }

    #[test]
    fn trailing_byte_is_authentication_error() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"hello").unwrap();
        let mut b = fs::read(s.record_path("a")).unwrap();
        b.push(0);
        fs::write(s.record_path("a"), &b).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Authentication)));
    }

    #[test]
    fn bad_magic_with_valid_length_is_corrupt() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"hello").unwrap();
        let mut b = fs::read(s.record_path("a")).unwrap();
        b[..MAGIC.len()].copy_from_slice(b"PHS2");
        fs::write(s.record_path("a"), &b).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Corrupt)));
    }

    #[test]
    fn oversized_record_file_is_corrupt_without_reading() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        let f = OpenOptions::new()
            .write(true)
            .open(s.record_path("a"))
            .unwrap();
        f.set_len((MAGIC.len() + NONCE_LEN + TAG_LEN + MAX_RECORD_LEN + 1) as u64)
            .unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Corrupt)));
    }

    #[test]
    fn fifo_record_is_refused_not_hung() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        let path = std::ffi::CString::new(s.record_path("a").to_str().unwrap()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated string that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        assert!(matches!(s.get("a"), Err(StoreError::InsecurePath)));
    }

    #[test]
    fn names_ignores_foreign_files_and_stale_temp_is_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("good", b"x").unwrap();
        for junk in ["Bad.rec", "x.txt", "good.rec.tmp", ".rec"] {
            fs::write(s.dir.join(junk), b"junk").unwrap();
        }
        assert_eq!(s.names().unwrap(), vec!["good"]);
        fs::write(s.dir.join("fresh.rec.tmp"), b"stale").unwrap();
        s.put("fresh", b"y").unwrap();
        assert_eq!(&**s.get("fresh").unwrap().unwrap(), b"y");
        assert!(!s.dir.join("fresh.rec.tmp").exists());
    }

    #[test]
    fn record_limit_blocks_new_names_but_not_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("first", b"x").unwrap();
        for i in 1..MAX_RECORDS {
            fs::write(s.dir.join(format!("r{i}.rec")), b"").unwrap();
        }
        assert_eq!(s.names().unwrap().len(), MAX_RECORDS);
        assert!(matches!(
            s.put("extra", b"x"),
            Err(StoreError::TooManyRecords)
        ));
        s.put("first", b"y").unwrap();
        assert_eq!(&**s.get("first").unwrap().unwrap(), b"y");
        fs::write(s.dir.join("overflow.rec"), b"").unwrap();
        assert!(matches!(s.names(), Err(StoreError::TooManyRecords)));
    }

    #[test]
    fn operations_refuse_a_loosened_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        fs::set_permissions(&s.dir, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(s.put("b", b"x"), Err(StoreError::InsecurePath)));
        assert!(matches!(s.get("a"), Err(StoreError::InsecurePath)));
        assert!(matches!(s.remove("a"), Err(StoreError::InsecurePath)));
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]
        #[test]
        fn round_trip_any_bytes(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
            let tmp = tempfile::tempdir().unwrap();
            let s = open(&tmp, &EK).unwrap();
            s.put("p", &data).unwrap();
            proptest::prop_assert_eq!(&**s.get("p").unwrap().unwrap(), &data[..]);
        }
    }
}
