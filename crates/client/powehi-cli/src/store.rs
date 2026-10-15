//! Encrypted profile store (prd.md §7A.3). Unix only: relies on POSIX modes.
//!
//! Every record is one file `<tag>.rc2` holding `MAGIC || nonce(12) || AES-256-GCM(..)`, where
//! `tag` is the hex of `HMAC-SHA256(name_key, name)[..16]` (threat-model F1: record names such
//! as a group or envelope id never reach the directory listing). The real name travels inside
//! the ciphertext (`len || name || payload`). The record key is
//! `HKDF-SHA256(ikm = OPAQUE export_key, info = KEY_INFO)`; the info label is CLI-specific so
//! it is domain-separated from the web DB key (§7.4), and `name_key` uses its own label. The
//! AEAD AAD binds `MAGIC || profile || tag`, so a record file renamed to another tag fails
//! authentication, and so does one moved between profiles. A decrypted name must hash back to
//! its file's tag. `<name>.rec` files (format `PHS1`, plain names) are migrated at `open`.
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

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::profile::ProfilePaths;

/// File magic and format version.
const MAGIC: &[u8; 4] = b"PHS2";
/// Format of the pre-F1 store: plain `<name>.rec` files, AAD `MAGIC || profile || name`.
const LEGACY_MAGIC: &[u8; 4] = b"PHS1";
/// HKDF info label (domain separation from every other use of the export key).
const KEY_INFO: &[u8] = b"powehi-cli/profile-store/v1/record-key";
/// HKDF info label for the key that turns record names into file-name tags.
const NAME_KEY_INFO: &[u8] = b"powehi-cli/profile-store/v2/name-key";
/// Hex characters in a file-name tag (128 bits).
const TAG_HEX_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// The one accepted export-key length: `powehi_crypto_core::opaque::EXPORT_KEY_LEN`. Register and
/// login must both pass exactly this prefix, or the derived key (and every record) would differ.
const EXPORT_KEY_LEN: usize = 32;
const LOCK_FILE: &str = ".lock";
/// Upper bound on one record's plaintext.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;
/// Largest on-disk plaintext: one length byte, the name, then the payload.
const MAX_INNER_LEN: usize = 1 + MAX_NAME_LEN + MAX_RECORD_LEN;
/// Upper bound on user records per profile (the internal marker is extra).
pub const MAX_RECORDS: usize = 4096;
/// Longest record name, in bytes.
pub const MAX_NAME_LEN: usize = 64;
const EXT: &str = "rc2";
const LEGACY_EXT: &str = "rec";
/// Internal record whose presence latches the `PHS1` import window shut (hidden from `names`).
const MARKER: &str = "store-v2";

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
    #[error("profile path is not a private directory or file (expected 0700/0600, current-user owner, no symlinks, parent not group/other-writable)")]
    InsecurePath,
    #[error("record is malformed")]
    Corrupt,
    #[error("record failed authentication (wrong key or tampered file)")]
    Authentication,
    #[error("profile is already open in another process")]
    Locked,
    #[error("profile store I/O error: {0}")]
    Io(ErrorKind),
    /// `open` failed on one record file; `tag` is its opaque file stem (no record name).
    #[error("record file {tag}.{EXT}: {cause}")]
    Record { tag: String, cause: Box<StoreError> },
}

impl StoreError {
    /// The underlying error, with any `Record` file context stripped.
    #[must_use]
    pub fn root(&self) -> &StoreError {
        match self {
            Self::Record { cause, .. } => cause.root(),
            other => other,
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.kind())
    }
}

/// Handle to one profile directory plus its derived record key. The AES key is zeroized on drop (the HMAC state is not).
pub struct ProfileStore {
    dir: PathBuf,
    profile: String,
    cipher: Aes256Gcm,
    /// Keyed once at `open`; cloned per tag (the HMAC internals are not zeroized, see above).
    name_mac: Hmac<Sha256>,
    /// Names of the records present. Built (and every record authenticated) at `open`; this
    /// process holds the profile lock, so it stays in step with `put`/`remove` and keeps
    /// `names()` and the record limit from decrypting the whole store on hot paths.
    index: Mutex<BTreeSet<String>>,
    /// In-memory lower bound for the MLS provider-state generation seen or written by this
    /// process; never persisted, so a swapped-in older record cannot lower it.
    provider_floor: AtomicU64,
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

fn expand(export_key: &[u8], info: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    if export_key.len() != EXPORT_KEY_LEN {
        return Err(StoreError::BadKeyLength);
    }
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Hkdf::<Sha256>::new(None, export_key)
        .expand(info, key.as_mut())
        .map_err(|_| StoreError::BadKeyLength)?;
    Ok(key)
}

fn derive_key(export_key: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, StoreError> {
    expand(export_key, KEY_INFO)
}

/// File-name tag of a record: truncated HMAC of its name under the profile's name key.
fn tag_of(name_mac: &Hmac<Sha256>, name: &str) -> String {
    let mut mac = name_mac.clone();
    mac.update(name.as_bytes());
    let digest = mac.finalize().into_bytes();
    debug_assert!(digest.len() >= TAG_HEX_LEN / 2);
    digest[..TAG_HEX_LEN / 2]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `tag` is 32 lowercase hex characters.
fn is_tag(tag: &str) -> bool {
    tag.len() == TAG_HEX_LEN
        && tag
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// AAD: `magic || len(profile) || profile || label`, where `label` is the file-name tag
/// (`PHS2`) or the plain record name (`PHS1`).
fn aad(magic: &[u8; 4], profile: &str, label: &str) -> Vec<u8> {
    let mut a = Vec::with_capacity(magic.len() + 1 + profile.len() + label.len());
    a.extend_from_slice(magic);
    // `open` re-validates the profile name (<= 64 bytes); the length prefix keeps
    // `profile || label` unambiguous.
    a.push(u8::try_from(profile.len()).unwrap_or(u8::MAX));
    a.extend_from_slice(profile.as_bytes());
    a.extend_from_slice(label.as_bytes());
    a
}

/// Rejects symlinks, non-directories, foreign owners and any group/other permission bits.
fn check_private_dir(dir: &Path) -> Result<(), StoreError> {
    let md = fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if !md.is_dir() || md.mode() & 0o077 != 0 || md.uid() != unsafe { libc::geteuid() } {
        return Err(StoreError::InsecurePath);
    }
    Ok(())
}

/// The `powehi/` parent holds the profile names: it must be ours and not writable by others
/// (a swapped-in parent would let a local attacker race the path-based operations).
fn check_parent_dir(dir: &Path) -> Result<(), StoreError> {
    let md = fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if !md.is_dir() || md.mode() & 0o022 != 0 || md.uid() != unsafe { libc::geteuid() } {
        return Err(StoreError::InsecurePath);
    }
    Ok(())
}

/// Older versions created `powehi/` with the umask default (0755/0775). Tighten a directory we
/// own to 0700; anything else (symlink, foreign owner) is left for `check_parent_dir` to refuse.
fn tighten_legacy_parent(dir: &Path) -> Result<(), StoreError> {
    let md = fs::symlink_metadata(dir)?;
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if md.is_dir() && md.uid() == unsafe { libc::geteuid() } && md.mode() & 0o077 != 0 {
        fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    }
    Ok(())
}

fn mkdir_private(dir: &Path) -> Result<(), StoreError> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn create_private_dir(dir: &Path) -> Result<(), StoreError> {
    let parent = dir.parent().ok_or(StoreError::InsecurePath)?;
    if let Some(base) = parent.parent() {
        fs::create_dir_all(base)?;
    }
    mkdir_private(parent)?;
    tighten_legacy_parent(parent)?;
    check_parent_dir(parent)?;
    mkdir_private(dir)?;
    check_private_dir(dir)
}

impl ProfileStore {
    /// Opens (creating with mode 0700 if absent) the profile directory and derives the key.
    /// `export_key` is borrowed; the caller zeroizes its own copy. Legacy `PHS1` records are
    /// re-encrypted under opaque file names before this returns.
    pub fn open(paths: &ProfilePaths, export_key: &[u8]) -> Result<Self, StoreError> {
        let key = derive_key(export_key)?;
        let name_key = expand(export_key, NAME_KEY_INFO)?;
        let name_mac = <Hmac<Sha256> as Mac>::new_from_slice(name_key.as_ref())
            .map_err(|_| StoreError::BadKeyLength)?;
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
        let store = Self {
            dir: paths.dir.clone(),
            profile,
            cipher,
            name_mac,
            index: Mutex::new(BTreeSet::new()),
            provider_floor: AtomicU64::new(0),
            _lock: lock,
        };
        store.load_index()?;
        store.migrate_legacy()?;
        Ok(store)
    }

    /// Lowest provider-state generation this process will accept on reload.
    pub(crate) fn provider_floor(&self) -> u64 {
        self.provider_floor.load(Ordering::Acquire)
    }

    /// Raises (never lowers) the in-process provider-state generation floor.
    pub(crate) fn raise_provider_floor(&self, generation: u64) {
        self.provider_floor.fetch_max(generation, Ordering::AcqRel);
    }

    pub(crate) fn record_path(&self, name: &str) -> PathBuf {
        self.dir
            .join(format!("{}.{EXT}", tag_of(&self.name_mac, name)))
    }

    fn index(&self) -> Result<std::sync::MutexGuard<'_, BTreeSet<String>>, StoreError> {
        self.index.lock().map_err(|_| StoreError::Corrupt)
    }

    /// Authenticates every `.rc2` record and builds the name index. With a wrong key every name
    /// hashes to a different tag, so a lookup alone would report "absent" instead of failing;
    /// this makes a wrong key or a tampered file an error at `open`.
    fn load_index(&self) -> Result<(), StoreError> {
        check_private_dir(&self.dir)?;
        let mut names = BTreeSet::new();
        for tag in self.tags()? {
            let path = self.dir.join(format!("{tag}.{EXT}"));
            let named = |cause: StoreError| StoreError::Record {
                tag: tag.clone(),
                cause: Box::new(cause),
            };
            let inner = self.read_file(&path, MAGIC, &tag).map_err(named)?;
            names.insert(self.split_inner(inner, &tag).map_err(named)?.0);
        }
        *self.index()? = names;
        Ok(())
    }

    /// Re-encrypts every `<name>.rec` (`PHS1`) record as an opaque-named `PHS2` record, then
    /// deletes it. Each legacy file is removed only after its replacement authenticates (a
    /// crash between write and delete leaves both; the new record wins). Once the store holds
    /// the `MARKER` record the import window is closed: stray `.rec` files (for example planted
    /// from an old backup) are deleted unread. Stale `<name>.rec.tmp` files are always removed.
    fn migrate_legacy(&self) -> Result<(), StoreError> {
        let mut legacy = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let file = entry?.file_name();
            let Some(file) = file.to_str() else { continue };
            if let Some(stem) = file.strip_suffix(".rec.tmp") {
                if validate_record_name(stem).is_ok() {
                    fs::remove_file(self.dir.join(file))?;
                }
            } else if let Some(stem) = file.strip_suffix(".rec") {
                if validate_record_name(stem).is_ok() {
                    legacy.push(stem.to_owned());
                    if legacy.len() > MAX_RECORDS {
                        return Err(StoreError::TooManyRecords);
                    }
                }
            }
        }
        legacy.sort();
        let closed = self.index()?.contains(MARKER);
        let mut imported = false;
        for name in legacy {
            let path = self.dir.join(format!("{name}.{LEGACY_EXT}"));
            if !closed {
                self.import_legacy(&path, &name)?;
            }
            fs::remove_file(&path)?;
            File::open(&self.dir)?.sync_all()?;
            imported = imported || !closed;
        }
        if imported {
            self.put_record(MARKER, b"", false)?;
        }
        Ok(())
    }

    /// Imports one legacy record unless an authenticating new-format record already exists.
    fn import_legacy(&self, path: &Path, name: &str) -> Result<(), StoreError> {
        if self.index()?.contains(name) {
            return Ok(());
        }
        match fs::symlink_metadata(self.record_path(name)) {
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
            // Present but not in the index: it failed to load, which `load_index` already
            // turned into an error; refuse rather than overwrite.
            Ok(_) => return Err(StoreError::Corrupt),
        }
        let pt = self.read_file(path, LEGACY_MAGIC, name)?;
        if pt.len() > MAX_RECORD_LEN {
            return Err(StoreError::Corrupt);
        }
        self.put_record(name, &pt, false)
    }

    /// Encrypts and atomically writes a record (temp file 0600 → fsync → rename → fsync dir).
    pub fn put(&self, name: &str, plaintext: &[u8]) -> Result<(), StoreError> {
        validate_record_name(name)?;
        if name == MARKER {
            return Err(StoreError::BadName);
        }
        self.put_record(name, plaintext, true)
    }

    /// `latch`: write the `MARKER` first when the store has none. Migration passes `false` and
    /// writes the marker itself once every legacy file is dealt with, so a failed migration
    /// never closes the import window.
    fn put_record(&self, name: &str, plaintext: &[u8], latch: bool) -> Result<(), StoreError> {
        if plaintext.len() > MAX_RECORD_LEN {
            return Err(StoreError::TooLarge);
        }
        check_private_dir(&self.dir)?;
        let (is_new, has_marker, user_records) = {
            let index = self.index()?;
            let has_marker = index.contains(MARKER);
            (
                !index.contains(name),
                has_marker,
                index.len() - usize::from(has_marker),
            )
        };
        // The marker is internal and does not count against the user-visible limit.
        if is_new && name != MARKER && user_records >= MAX_RECORDS {
            return Err(StoreError::TooManyRecords);
        }
        if latch && !has_marker {
            self.put_record(MARKER, b"", false)?;
        }
        let tag = tag_of(&self.name_mac, name);
        let mut inner = Zeroizing::new(Vec::with_capacity(1 + name.len() + plaintext.len()));
        inner.push(u8::try_from(name.len()).map_err(|_| StoreError::BadName)?);
        inner.extend_from_slice(name.as_bytes());
        inner.extend_from_slice(plaintext);
        let mut nonce = [0u8; NONCE_LEN];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| StoreError::Io(ErrorKind::Other))?;
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &aad(MAGIC, &self.profile, &tag),
                },
            )
            .map_err(|_| StoreError::Corrupt)?;
        let mut blob = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        blob.extend_from_slice(MAGIC);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        self.write_atomic(&tag, &blob, name)
    }

    /// Once the rename has landed the record exists, so it enters the index before the final
    /// directory fsync (whose failure is still reported).
    fn write_atomic(&self, tag: &str, blob: &[u8], name: &str) -> Result<(), StoreError> {
        let tmp = self.dir.join(format!("{tag}.{EXT}.tmp"));
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
        let target = self.dir.join(format!("{tag}.{EXT}"));
        let written = f.write_all(blob).and_then(|()| f.sync_all());
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, target)) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        self.index()?.insert(name.to_owned());
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Reads and decrypts a record; `Ok(None)` if it does not exist.
    pub fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        validate_record_name(name)?;
        if name == MARKER {
            return Err(StoreError::BadName);
        }
        check_private_dir(&self.dir)?;
        let tag = tag_of(&self.name_mac, name);
        match self.read_file(&self.record_path(name), MAGIC, &tag) {
            Ok(inner) => Ok(Some(self.split_inner(inner, &tag)?.1)),
            Err(StoreError::Io(ErrorKind::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Opens `path` (no symlink, no FIFO hang, private regular file) and decrypts it with
    /// `label` in the AAD. A missing file is `Io(NotFound)`.
    fn read_file(
        &self,
        path: &Path,
        magic: &[u8; 4],
        label: &str,
    ) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        // O_NOFOLLOW: a symlinked record is refused; O_NONBLOCK: a FIFO cannot hang the open.
        let mut f = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
                return Err(StoreError::InsecurePath)
            }
            Err(e) => return Err(e.into()),
        };
        let md = f.metadata()?;
        if !md.is_file() || md.mode() & 0o077 != 0 {
            return Err(StoreError::InsecurePath);
        }
        let max = (MAGIC.len() + NONCE_LEN + TAG_LEN + MAX_INNER_LEN) as u64;
        if md.len() > max {
            return Err(StoreError::Corrupt);
        }
        let mut blob = Vec::with_capacity(md.len() as usize);
        Read::by_ref(&mut f).take(max).read_to_end(&mut blob)?;
        if blob.len() < MAGIC.len() + NONCE_LEN + TAG_LEN || &blob[..MAGIC.len()] != magic {
            return Err(StoreError::Corrupt);
        }
        let (nonce, ct) = blob[MAGIC.len()..].split_at(NONCE_LEN);
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(magic, &self.profile, label),
                },
            )
            .map_err(|_| StoreError::Authentication)?;
        Ok(Zeroizing::new(pt))
    }

    /// Splits `len || name || payload`; the name must be valid and hash back to `tag`.
    fn split_inner(
        &self,
        mut inner: Zeroizing<Vec<u8>>,
        tag: &str,
    ) -> Result<(String, Zeroizing<Vec<u8>>), StoreError> {
        let len = inner.first().map(|&n| 1 + usize::from(n));
        let len = len
            .filter(|&n| n <= inner.len())
            .ok_or(StoreError::Corrupt)?;
        let name = std::str::from_utf8(&inner[1..len]).map_err(|_| StoreError::Corrupt)?;
        if validate_record_name(name).is_err() || tag_of(&self.name_mac, name) != tag {
            return Err(StoreError::Corrupt);
        }
        let name = name.to_owned();
        inner.drain(..len);
        Ok((name, inner))
    }

    /// Deletes a record; absent records are not an error.
    pub fn remove(&self, name: &str) -> Result<(), StoreError> {
        validate_record_name(name)?;
        if name == MARKER {
            return Err(StoreError::BadName);
        }
        check_private_dir(&self.dir)?;
        match fs::remove_file(self.record_path(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                self.index()?.remove(name);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        self.index()?.remove(name);
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// File-name tags of the records present; more than `MAX_RECORDS` plus the marker is an error.
    fn tags(&self) -> Result<Vec<String>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let file = entry?.file_name();
            let Some(stem) = file.to_str().and_then(|s| s.strip_suffix(".rc2")) else {
                continue;
            };
            if is_tag(stem) {
                out.push(stem.to_owned());
                if out.len() > MAX_RECORDS + 1 {
                    return Err(StoreError::TooManyRecords);
                }
            }
        }
        Ok(out)
    }

    /// Sorted record names currently present (from the index built at `open`; the internal
    /// marker is hidden). No decryption happens here.
    pub fn names(&self) -> Result<Vec<String>, StoreError> {
        check_private_dir(&self.dir)?;
        let index = self.index()?;
        Ok(index.iter().filter(|n| *n != MARKER).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    const EK: [u8; 32] = [7u8; 32];
    const KAT_TAG: &str = "467c076c500f1cab67ef8c840817f5a9";
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
        let err = open(&tmp, &[8u8; 32]).unwrap_err();
        assert!(matches!(err.root(), StoreError::Authentication));
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
        assert!(!PathBuf::from(format!("{}.tmp", s.record_path("a").display())).exists());
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
    fn parent_dir_is_private_legacy_tightened_symlink_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        open(&tmp, &EK).unwrap();
        let parent = tmp.path().join("powehi");
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
        // A legacy umask-default parent is tightened, not refused.
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o775)).unwrap();
        open(&tmp, &EK).unwrap();
        assert_eq!(fs::metadata(&parent).unwrap().mode() & 0o777, 0o700);
        // A symlinked parent is refused.
        let other = tempfile::tempdir().unwrap();
        let real = other.path().join("real");
        fs::DirBuilder::new().mode(0o700).create(&real).unwrap();
        std::os::unix::fs::symlink(&real, other.path().join("powehi")).unwrap();
        assert!(matches!(open(&other, &EK), Err(StoreError::InsecurePath)));
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
    fn name_tag_known_answer() {
        let key = expand(&EK, NAME_KEY_INFO).unwrap();
        let mac = <Hmac<Sha256> as Mac>::new_from_slice(key.as_ref()).unwrap();
        assert_eq!(tag_of(&mac, "identity"), KAT_TAG);
        assert_ne!(tag_of(&mac, "identity"), tag_of(&mac, "identitz"));
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
        b[..MAGIC.len()].copy_from_slice(b"PHS9");
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
        f.set_len((MAGIC.len() + NONCE_LEN + TAG_LEN + MAX_INNER_LEN + 1) as u64)
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
        for junk in ["Bad.rec", "x.txt", "good.rc2.tmp", ".rec", "short.rc2"] {
            fs::write(s.dir.join(junk), b"junk").unwrap();
        }
        assert_eq!(s.names().unwrap(), vec!["good"]);
        let tmp_name = format!("{}.tmp", s.record_path("fresh").display());
        fs::write(&tmp_name, b"stale").unwrap();
        s.put("fresh", b"y").unwrap();
        assert_eq!(&**s.get("fresh").unwrap().unwrap(), b"y");
        assert!(!Path::new(&tmp_name).exists());
    }

    #[test]
    fn record_limit_blocks_new_names_but_not_overwrites() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("first", b"x").unwrap();
        for i in 1..MAX_RECORDS {
            s.index().unwrap().insert(format!("fake{i}"));
        }
        assert_eq!(s.names().unwrap().len(), MAX_RECORDS);
        assert!(matches!(
            s.put("extra", b"x"),
            Err(StoreError::TooManyRecords)
        ));
        s.put("first", b"y").unwrap();
        assert_eq!(&**s.get("first").unwrap().unwrap(), b"y");
        drop(s);
        for i in 0..=MAX_RECORDS + 1 {
            fs::write(
                tmp.path().join("powehi/work").join(format!("{i:032x}.rc2")),
                b"",
            )
            .unwrap();
        }
        assert!(matches!(open(&tmp, &EK), Err(StoreError::TooManyRecords)));
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

    fn legacy_record(dir: &Path, key: &[u8], profile: &str, name: &str, pt: &[u8]) {
        let k = derive_key(key).unwrap();
        let c = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(k.as_ref()));
        let nonce = [3u8; NONCE_LEN];
        let ct = c
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: pt,
                    aad: &aad(LEGACY_MAGIC, profile, name),
                },
            )
            .unwrap();
        let mut blob = LEGACY_MAGIC.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        let path = dir.join(format!("{name}.rec"));
        fs::write(&path, blob).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn file_names_do_not_reveal_record_names() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("conv-secretgroupid", b"x").unwrap();
        s.put("conv-secretgroupid", b"y").unwrap();
        let files: Vec<String> = fs::read_dir(&s.dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert!(
            files.iter().all(|f| !f.contains("secretgroupid")),
            "{files:?}"
        );
        assert_eq!(s.names().unwrap(), vec!["conv-secretgroupid"]);
        assert!(s.tags().unwrap().iter().all(|t| is_tag(t)));
    }

    #[test]
    fn legacy_records_are_migrated_at_open() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        drop(ProfileStore::open(&paths, &EK).unwrap());
        legacy_record(&paths.dir, &EK, "work", "identity", b"old-secret");
        legacy_record(&paths.dir, &EK, "work", "conv-abc", b"");
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert!(!paths.dir.join("identity.rec").exists());
        assert!(!paths.dir.join("conv-abc.rec").exists());
        assert_eq!(s.names().unwrap(), vec!["conv-abc", "identity"]);
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"old-secret");
    }

    #[test]
    fn migration_prefers_existing_new_record_and_rejects_wrong_key() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = ProfileStore::open(&paths, &EK).unwrap();
        s.put("a", b"new").unwrap();
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "a", b"stale");
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"new");
        assert!(!paths.dir.join("a.rec").exists());
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "b", b"x");
        let err = ProfileStore::open(&paths, &[9u8; 32]).unwrap_err();
        assert!(matches!(err.root(), StoreError::Authentication));
        assert!(paths.dir.join("b.rec").exists());
    }

    #[test]
    fn record_renamed_to_another_tag_fails_open_and_get() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        let forged = s.dir.join(format!("{:032x}.rc2", 7));
        fs::copy(s.record_path("a"), &forged).unwrap();
        drop(s);
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err.root(), StoreError::Authentication));
        assert!(err.to_string().contains(&format!("{:032x}", 7)), "{err}");
        fs::remove_file(&forged).unwrap();
        let s = open(&tmp, &EK).unwrap();
        fs::copy(s.record_path("a"), s.record_path("b")).unwrap();
        assert!(matches!(s.get("b"), Err(StoreError::Authentication)));
    }

    #[test]
    fn legacy_import_window_closes_once_the_store_has_records() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = ProfileStore::open(&paths, &EK).unwrap();
        s.put("a", b"new").unwrap();
        s.put("gone", b"x").unwrap();
        s.remove("gone").unwrap();
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "gone", b"resurrected");
        legacy_record(&paths.dir, &EK, "work", "a", b"stale");
        fs::write(paths.dir.join("rx-1.rec.tmp"), b"junk").unwrap();
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert!(s.get("gone").unwrap().is_none());
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"new");
        assert_eq!(s.names().unwrap(), vec!["a"]);
        for f in ["gone.rec", "a.rec", "rx-1.rec.tmp"] {
            assert!(!paths.dir.join(f).exists(), "{f}");
        }
    }

    #[test]
    fn failed_migration_never_closes_the_window() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let marker = drop_and_marker_path(&paths);
        for n in ["a", "z"] {
            legacy_record(&paths.dir, &EK, "work", n, n.as_bytes());
        }
        // Sorted import order is a, m, z: the damaged file sits between two good ones.
        let bad = paths.dir.join("m.rec");
        fs::write(&bad, b"damaged").unwrap();
        fs::set_permissions(&bad, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProfileStore::open(&paths, &EK).is_err());
        assert!(!marker.exists(), "failed migration must not latch");
        assert!(paths.dir.join("z.rec").exists());
        fs::remove_file(&bad).unwrap();
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert_eq!(s.names().unwrap(), vec!["a", "z"]);
        assert_eq!(&**s.get("z").unwrap().unwrap(), b"z");
        assert!(marker.exists());
    }

    /// Creates the profile dir and returns where its marker record would live.
    fn drop_and_marker_path(paths: &ProfilePaths) -> PathBuf {
        let s = ProfileStore::open(paths, &EK).unwrap();
        let p = s.record_path(MARKER);
        drop(s);
        p
    }

    #[test]
    fn full_legacy_store_migrates_and_marker_is_reserved() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        drop(ProfileStore::open(&paths, &EK).unwrap());
        for i in 0..40 {
            legacy_record(&paths.dir, &EK, "work", &format!("r{i}"), b"x");
        }
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert_eq!(s.names().unwrap().len(), 40);
        for i in 40..MAX_RECORDS {
            s.index().unwrap().insert(format!("fake{i}"));
        }
        assert!(matches!(
            s.put("extra", b"x"),
            Err(StoreError::TooManyRecords)
        ));
        for r in [
            s.put(MARKER, b"").map(drop),
            s.get(MARKER).map(drop),
            s.remove(MARKER),
        ] {
            assert!(matches!(r, Err(StoreError::BadName)));
        }
        drop(s);
        assert_eq!(open(&tmp, &EK).unwrap().names().unwrap().len(), 40);
    }

    #[test]
    fn legacy_name_swap_and_transplant_fail_to_authenticate() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        drop(ProfileStore::open(&paths, &EK).unwrap());
        legacy_record(&paths.dir, &EK, "work", "a", b"x");
        fs::rename(paths.dir.join("a.rec"), paths.dir.join("b.rec")).unwrap();
        assert!(matches!(
            ProfileStore::open(&paths, &EK),
            Err(StoreError::Authentication)
        ));
        // A PHS1 blob moved to an opaque name is not a PHS2 record.
        let s_tag = format!("{:032x}.rc2", 5);
        fs::rename(paths.dir.join("b.rec"), paths.dir.join(&s_tag)).unwrap();
        let err = ProfileStore::open(&paths, &EK).unwrap_err();
        assert!(matches!(err.root(), StoreError::Corrupt));
    }

    #[test]
    fn unauthenticated_new_record_blocks_legacy_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = ProfileStore::open(&paths, &EK).unwrap();
        let junk = s.record_path("a");
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "a", b"only-copy");
        fs::write(&junk, b"not a record").unwrap();
        fs::set_permissions(&junk, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProfileStore::open(&paths, &EK).is_err());
        assert!(paths.dir.join("a.rec").exists());
    }

    #[test]
    fn name_header_must_match_tag() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        // A record whose inner name hashes to a different tag than its file (validly encrypted).
        let tag = tag_of(&s.name_mac, "a");
        let mut inner = vec![1u8, b'b'];
        inner.extend_from_slice(b"payload");
        let nonce = [1u8; NONCE_LEN];
        let ct = s
            .cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &inner,
                    aad: &aad(MAGIC, &s.profile, &tag),
                },
            )
            .unwrap();
        let mut blob = MAGIC.to_vec();
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);
        s.write_atomic(&tag, &blob, "a").unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Corrupt)));
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
