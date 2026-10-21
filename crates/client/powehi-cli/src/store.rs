//! Encrypted profile store (prd.md §7A.3). Unix only: relies on POSIX modes.
//!
//! Every record is one file `<tag>.rc2` holding `MAGIC || nonce(12) || AES-256-GCM(..)`, where
//! `tag` is the hex of `HMAC-SHA256(name_key, name)[..16]` (threat-model F1: record names such
//! as a group or envelope id never reach the directory listing). The real name travels inside
//! the ciphertext (`len || name || payload`). The record key is
//! `HKDF-SHA256(ikm = OPAQUE export_key, info = KEY_INFO)` for an upgraded store (`keys`: a new
//! store has random keys); the info label is CLI-specific so it is domain-separated from the
//! web DB key (§7.4), and `name_key` uses its own label. The
//! AEAD AAD binds `MAGIC || profile || tag`, so a record file renamed to another tag fails
//! authentication, and so does one moved between profiles. A decrypted name must hash back to
//! its file's tag. `<name>.rec` files (format `PHS1`, plain names) are migrated at `open`.
//!
//! A MAC'd manifest (`manifest.mf3`, see `manifest`) lists every record's tag and file hash under
//! a monotonic generation, so `open` and `get` reject a rolled-back, deleted, extra or swapped
//! record. One process may hold a profile open at a time (an exclusive `flock` on `.lock`),
//! which keeps writers from clobbering each other.
//!
//! Rekey (8.8c, `rekey`): an upgraded store is re-encrypted under a fresh bundle at login, through
//! a staging directory and a roll-forward journal that `open` finishes after a crash.
//!
//! Keys (8.8b, `keys`): the record, name-tag and manifest keys are a per-store bundle sealed in
//! `keys.wk3` under a password KEK (from the `export_key`) and optionally a recovery-phrase KEK.
//! A store without that file but with records is a pre-`PHS3` store: `open` refuses it
//! (`UpgradeRequired`) and only `open_upgrading`, which the CLI calls after the user confirms,
//! converts it. So deleting the manifest and latch of a current store cannot silently make it
//! look pre-manifest; a store whose key file is deleted fails to open. Residual risks (prd §3.2):
//! a wholesale snapshot replay, and a user who confirms the upgrade of a store whose key file,
//! manifest and latch were all deleted (only possible while its keys are the `export_key`-derived
//! ones of an upgraded store).
//! The record key lives as long as the store, so the GCM random-nonce budget (NIST SP 800-38D
//! §8.3, 2^32 invocations) is cumulative over the store's lifetime; the separate manifest key
//! has its own budget, spent faster (two seals per mutation, one more per settle or adoption).
//! Key hygiene: the AES key schedule is zeroized on drop (`aes/zeroize`); the HKDF/HMAC
//! internals and the GHASH subkey held by the cipher are not zeroized (upstream) and may linger
//! in memory.

use std::collections::{BTreeMap, BTreeSet};
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
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::profile::ProfilePaths;

mod keys;
mod manifest;
mod rekey;

pub use keys::RecoveryKek;
use keys::{Bundle, KeyFile, PasswordKek, KEYFILE, KEYFILE_MAX_LEN};

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
/// Manifest file (format `PHM1`): AEAD of the generation and every record's tag and hash.
const MANIFEST_FILE: &str = "manifest.mf3";
const MANIFEST_MAGIC: &[u8; 4] = b"PHM1";
/// HKDF info label for the manifest key (separate from the record key).
const MANIFEST_KEY_INFO: &[u8] = b"powehi-cli/profile-store/v3/manifest-key";
/// Internal record whose presence proves the store has had a manifest: a manifest-less store
/// holding it is a deleted manifest, not a pre-manifest (`PHS2`) store to adopt.
const MANIFEST_LATCH: &str = "store-v3";
const HASH_LEN: usize = 32;
const RAW_TAG_LEN: usize = TAG_HEX_LEN / 2;
/// Largest manifest plaintext: header, every record entry, the pending entry.
const MAX_MANIFEST_LEN: usize = 8 + 4 + (MAX_RECORDS + 2) * (RAW_TAG_LEN + HASH_LEN) + 2 + 48;
const LEGACY_EXT: &str = "rec";
/// Internal record whose presence latches the `PHS1` import window shut (hidden from `names`).
const MARKER: &str = "store-v2";

/// Names reserved for the store itself: hidden from `names`, refused by `put`/`get`/`remove`.
fn is_internal(name: &str) -> bool {
    name == MARKER || name == MANIFEST_LATCH
}

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
    #[error("record failed authentication (wrong key, or a modified or tampered file; do not delete record files to work around this)")]
    Authentication,
    #[error("the store manifest is missing (a deleted manifest cannot be told from a rollback; do not delete files to work around this)")]
    ManifestMissing,
    #[error("the store manifest is malformed or from another profile")]
    ManifestCorrupt,
    #[error("this profile uses the pre-PHS3 store format; it is converted only after you confirm the upgrade")]
    UpgradeRequired,
    #[error("the store key file is missing (do not delete files to work around this)")]
    KeyfileMissing,
    #[error("the store key file is malformed")]
    KeyfileCorrupt,
    #[error("this store's keys still derive from the old export key; a password change cannot retire them until the store is rekeyed")]
    RekeyRequired,
    #[error("the store has a recovery-phrase key slot; enter the phrase to rekey it")]
    RecoveryPhraseRequired,
    #[error(
        "the interrupted-rekey journal is malformed (do not delete files to work around this)"
    )]
    RekeyJournalCorrupt,
    #[error("the store has no recovery-phrase key slot yet")]
    NoRecoveryWrap,
    #[error("record file {tag}.{EXT} is listed in the manifest but missing")]
    RecordMissing { tag: String },
    #[error("record file {tag}.{EXT} is not listed in the manifest")]
    RecordUnlisted { tag: String },
    #[error(
        "record file {tag}.{EXT} is not the version the manifest lists (rolled back or replaced)"
    )]
    RecordStale { tag: String },
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

/// An interrupted mutation: the record at `tag` is either `old` or the manifest's entry.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pending {
    tag: String,
    old: Option<[u8; HASH_LEN]>,
}

/// Decoded manifest: a monotonic generation and the SHA-256 of every record file.
#[derive(Clone, Debug, Default)]
struct Manifest {
    generation: u64,
    entries: BTreeMap<String, [u8; HASH_LEN]>,
    pending: Option<Pending>,
}

/// Handle to one profile directory plus its key bundle. The AES key is zeroized on drop (the HMAC state is not).
pub struct ProfileStore {
    dir: PathBuf,
    profile: String,
    cipher: Aes256Gcm,
    manifest_cipher: Aes256Gcm,
    /// The store's keys, kept to reseal them on a password change.
    bundle: Bundle,
    /// The keys are the `export_key`-derived ones of an upgraded store, so a new password would
    /// not retire them (`rewrap_password` refuses).
    derived_keys: bool,
    /// Opened with the recovery phrase: no `export_key` to tell whether the keys are derived.
    by_recovery: bool,
    manifest: Mutex<Manifest>,
    /// Serializes the pending → record → settled sequence of one mutation.
    write_lock: Mutex<()>,
    /// Set when a mutation found the directory in a state it must not certify; the handle then
    /// refuses further writes.
    poisoned: std::sync::atomic::AtomicBool,
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

/// How `open_as` proves the caller may read the store.
#[derive(Clone, Copy)]
enum Unlock<'a> {
    Password(&'a [u8]),
    Recovery(&'a RecoveryKek),
}

/// What `start` still has to do after the key bundle is known.
enum Flow {
    /// The key file already holds the bundle.
    Keyed,
    /// A new store: write the key file before anything else.
    Fresh(PasswordKek),
    /// A pre-`PHS3` store: adopt, then write the key file once every record has authenticated.
    /// `None` (test fixtures) skips the key file.
    Upgrade(Option<PasswordKek>),
}

/// Reads a private regular file of at most `max` bytes (no symlink, no FIFO hang); a longer one
/// is `too_big`.
fn read_private_file(path: &Path, max: usize, too_big: StoreError) -> Result<Vec<u8>, StoreError> {
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => StoreError::InsecurePath,
            _ => e.into(),
        })?;
    let md = f.metadata()?;
    if !md.is_file() || md.mode() & 0o077 != 0 {
        return Err(StoreError::InsecurePath);
    }
    if md.len() > max as u64 {
        return Err(too_big);
    }
    let mut bytes = Vec::with_capacity(md.len() as usize);
    Read::by_ref(&mut f)
        .take(md.len())
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl ProfileStore {
    /// Opens (creating with mode 0700 if absent) the profile directory and unlocks the key
    /// bundle with the password KEK. `export_key` is borrowed; the caller zeroizes its own copy.
    /// A pre-`PHS3` store is refused with `UpgradeRequired` (see `open_upgrading`).
    pub fn open(paths: &ProfilePaths, export_key: &[u8]) -> Result<Self, StoreError> {
        Self::open_as(paths, Unlock::Password(export_key), false)
    }

    /// Like `open`, but converts a pre-`PHS3` store (`PHS1` files, a manifest-less or key-file-less
    /// `PHS2` store): it keeps its export-key-derived keys, adopts or checks the manifest and
    /// writes the key file last, once every record has authenticated. Call it only after the
    /// user confirmed the upgrade.
    pub fn open_upgrading(paths: &ProfilePaths, export_key: &[u8]) -> Result<Self, StoreError> {
        Self::open_as(paths, Unlock::Password(export_key), true)
    }

    /// Opens with the recovery-phrase KEK, for a store whose password path is lost. Needs the
    /// recovery slot (`add_recovery_wrap`); a store without one is `NoRecoveryWrap`.
    pub fn open_with_recovery(paths: &ProfilePaths, kek: &RecoveryKek) -> Result<Self, StoreError> {
        Self::open_as(paths, Unlock::Recovery(kek), false)
    }

    fn open_as(
        paths: &ProfilePaths,
        unlock: Unlock<'_>,
        upgrade: bool,
    ) -> Result<Self, StoreError> {
        let pw = match unlock {
            Unlock::Password(ek) => Some(PasswordKek::new(ek)?),
            Unlock::Recovery(_) => None,
        };
        let (profile, lock) = Self::prepare(paths)?;
        rekey::recover(&paths.dir, &profile, &|kf, profile| match (unlock, &pw) {
            (Unlock::Password(_), Some(pw)) => kf.unlock_password(profile, pw),
            (Unlock::Recovery(rc), _) => kf.unlock_recovery(profile, rc),
            (Unlock::Password(_), None) => Err(StoreError::Corrupt),
        })?;
        let keyfile = Self::read_keyfile(&paths.dir)?;
        let has_files = Self::has_store_files(&paths.dir)?;
        let mut derived_keys = false;
        let (bundle, flow) = match (keyfile, unlock, pw) {
            (Some(kf), Unlock::Password(ek), Some(pw)) => {
                let bundle = kf.unlock_password(&profile, &pw)?;
                derived_keys = bundle.same_keys(&Bundle::derived(ek)?);
                (bundle, Flow::Keyed)
            }
            (Some(kf), Unlock::Recovery(rc), _) => (kf.unlock_recovery(&profile, rc)?, Flow::Keyed),
            (None, Unlock::Recovery(_), _) => return Err(StoreError::KeyfileMissing),
            (None, Unlock::Password(ek), Some(pw)) if has_files => {
                if !upgrade {
                    return Err(StoreError::UpgradeRequired);
                }
                derived_keys = true;
                (Bundle::derived(ek)?, Flow::Upgrade(Some(pw)))
            }
            (None, Unlock::Password(_), Some(pw)) => (Bundle::random()?, Flow::Fresh(pw)),
            (Some(_), Unlock::Password(_), None) => return Err(StoreError::Corrupt),
            (None, Unlock::Password(_), None) => return Err(StoreError::Corrupt),
        };
        let mut store = Self::build(paths, profile, lock, bundle)?;
        store.derived_keys = derived_keys;
        store.by_recovery = matches!(unlock, Unlock::Recovery(_));
        store.start(flow)
    }

    /// Creates the directory, validates the profile name and takes the profile lock.
    fn prepare(paths: &ProfilePaths) -> Result<(String, File), StoreError> {
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
        Ok((profile, lock))
    }

    fn build(
        paths: &ProfilePaths,
        profile: String,
        lock: File,
        bundle: Bundle,
    ) -> Result<Self, StoreError> {
        let name_mac = <Hmac<Sha256> as Mac>::new_from_slice(bundle.name())
            .map_err(|_| StoreError::BadKeyLength)?;
        debug_assert!(bundle.record().iter().any(|&b| b != 0));
        Ok(Self {
            dir: paths.dir.clone(),
            profile,
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(bundle.record())),
            manifest_cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(bundle.manifest())),
            bundle,
            derived_keys: false,
            by_recovery: false,
            manifest: Mutex::new(Manifest::default()),
            write_lock: Mutex::new(()),
            poisoned: std::sync::atomic::AtomicBool::new(false),
            name_mac,
            index: Mutex::new(BTreeSet::new()),
            provider_floor: AtomicU64::new(0),
            _lock: lock,
        })
    }

    /// Loads and authenticates the store. A fresh store gets its key file before anything else; an
    /// upgraded one gets it last, so a wrong password never leaves a key file behind.
    fn start(self, flow: Flow) -> Result<Self, StoreError> {
        let upgrading = matches!(flow, Flow::Upgrade(_));
        let mut flow = flow;
        if let Flow::Fresh(pw) = &flow {
            self.write_keyfile(&KeyFile::new(&self.profile, &self.bundle, pw, None)?)?;
        }
        let found = self.load_index()?;
        if upgrading && found.is_empty() {
            self.authenticate_first_legacy()?;
        }
        self.load_manifest(&found, upgrading)?;
        self.migrate_legacy(upgrading)?;
        if let Flow::Upgrade(pw) = &mut flow {
            if let Some(pw) = pw.take() {
                self.write_keyfile(&KeyFile::new(&self.profile, &self.bundle, &pw, None)?)?;
            }
        }
        Ok(self)
    }

    /// Test fixture: a keyless store with `export_key`-derived keys, what a pre-`PHS3` version left
    /// behind. `open` refuses it; `open_upgrading` converts it.
    #[cfg(test)]
    pub(crate) fn open_legacy_fixture(
        paths: &ProfilePaths,
        export_key: &[u8],
    ) -> Result<Self, StoreError> {
        let (profile, lock) = Self::prepare(paths)?;
        let mut store = Self::build(paths, profile, lock, Bundle::derived(export_key)?)?;
        store.derived_keys = true;
        store.start(Flow::Upgrade(None))
    }

    /// An upgrade of a store with no `PHS2` record yet (`PHS1` files only) would otherwise write
    /// a manifest and latch before any key was checked, so a wrong key would poison the
    /// directory. Authenticates the first legacy record, if there is no manifest, before that.
    fn authenticate_first_legacy(&self) -> Result<(), StoreError> {
        if fs::symlink_metadata(self.dir.join(MANIFEST_FILE)).is_ok() {
            return Ok(());
        }
        let mut first: Option<String> = None;
        for entry in fs::read_dir(&self.dir)? {
            let file = entry?.file_name();
            let stem = file.to_str().and_then(|f| f.strip_suffix(".rec"));
            if let Some(stem) = stem.filter(|s| validate_record_name(s).is_ok()) {
                if first.as_deref().is_none_or(|f| stem < f) {
                    first = Some(stem.to_owned());
                }
            }
        }
        match first {
            Some(name) => self
                .read_file(
                    &self.dir.join(format!("{name}.{LEGACY_EXT}")),
                    LEGACY_MAGIC,
                    &name,
                )
                .map(drop),
            None => Ok(()),
        }
    }

    /// Whether the directory holds anything a store would: records, a manifest or `PHS1` files.
    fn has_store_files(dir: &Path) -> Result<bool, StoreError> {
        for entry in fs::read_dir(dir)? {
            let file = entry?.file_name();
            let Some(file) = file.to_str() else { continue };
            let record = file.strip_suffix(".rc2").is_some_and(is_tag)
                || file
                    .strip_suffix(".rec")
                    .is_some_and(|stem| validate_record_name(stem).is_ok());
            if record || file == MANIFEST_FILE {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn read_keyfile(dir: &Path) -> Result<Option<KeyFile>, StoreError> {
        match read_private_file(
            &dir.join(KEYFILE),
            KEYFILE_MAX_LEN,
            StoreError::KeyfileCorrupt,
        ) {
            Ok(bytes) => KeyFile::decode(&bytes).map(Some),
            Err(StoreError::Io(ErrorKind::NotFound)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn write_keyfile(&self, kf: &KeyFile) -> Result<(), StoreError> {
        self.atomic_write(KEYFILE, &kf.encode())?;
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Reseals the key bundle under the key of a new password (`new_export_key`), keeping the
    /// recovery slot. No record is rewritten: the old password's KEK stops opening the store
    /// (a copy of the old `keys.wk3` still does, as with any snapshot, prd §3.2 ①). An upgraded
    /// store is refused (`RekeyRequired`): its keys are a function of the old `export_key`, so
    /// resealing them would only look like a rotation.
    pub fn rewrap_password(&self, new_export_key: &[u8]) -> Result<(), StoreError> {
        // A recovery-opened store cannot tell derived keys from random ones: refuse until the
        // restore flow (8.18) can check that.
        if self.derived_keys || self.by_recovery {
            return Err(StoreError::RekeyRequired);
        }
        let pw = PasswordKek::new(new_export_key)?;
        let _one_at_a_time = self.write_lock.lock().map_err(|_| StoreError::Corrupt)?;
        check_private_dir(&self.dir)?;
        let current = Self::read_keyfile(&self.dir)?.ok_or(StoreError::KeyfileMissing)?;
        self.write_keyfile(&current.with_password(&self.profile, &self.bundle, &pw)?)
    }

    /// Adds (or replaces) the recovery-phrase slot, so `open_with_recovery` can unlock the store.
    pub fn add_recovery_wrap(&self, kek: &RecoveryKek) -> Result<(), StoreError> {
        let _one_at_a_time = self.write_lock.lock().map_err(|_| StoreError::Corrupt)?;
        check_private_dir(&self.dir)?;
        let current = Self::read_keyfile(&self.dir)?.ok_or(StoreError::KeyfileMissing)?;
        self.write_keyfile(&current.with_recovery(&self.profile, &self.bundle, kek)?)
    }

    /// Whether the key file carries a recovery slot.
    pub fn has_recovery_wrap(&self) -> Result<bool, StoreError> {
        check_private_dir(&self.dir)?;
        let kf = Self::read_keyfile(&self.dir)?.ok_or(StoreError::KeyfileMissing)?;
        Ok(kf.has_recovery())
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
    fn load_index(&self) -> Result<BTreeMap<String, [u8; HASH_LEN]>, StoreError> {
        check_private_dir(&self.dir)?;
        let mut names = BTreeSet::new();
        let mut found = BTreeMap::new();
        for tag in self.tags()? {
            let path = self.dir.join(format!("{tag}.{EXT}"));
            let named = |cause: StoreError| StoreError::Record {
                tag: tag.clone(),
                cause: Box::new(cause),
            };
            let (inner, hash) = self.read_blob(&path, MAGIC, &tag).map_err(named)?;
            names.insert(self.split_inner(inner, &tag).map_err(named)?.0);
            found.insert(tag, hash);
        }
        *self.index()? = names;
        Ok(found)
    }

    /// Reads and verifies the manifest against the record files found by `load_index`. A
    /// manifest-less store is adopted (a `PHS2` store being upgraded) unless it holds the
    /// `MANIFEST_LATCH` record, which proves a manifest was deleted.
    fn load_manifest(
        &self,
        found: &BTreeMap<String, [u8; HASH_LEN]>,
        may_adopt: bool,
    ) -> Result<(), StoreError> {
        let blob = match self.read_manifest_blob() {
            Ok(b) => Some(b),
            Err(StoreError::Io(ErrorKind::NotFound)) => None,
            Err(e) => return Err(e),
        };
        let Some(blob) = blob else {
            if self.index()?.contains(MANIFEST_LATCH) || (!found.is_empty() && !may_adopt) {
                return Err(StoreError::ManifestMissing);
            }
            if !found.is_empty() {
                eprintln!("note: profile store upgraded to the manifest format (PHS3a)");
            }
            let first = Manifest {
                generation: 1,
                entries: found.clone(),
                pending: None,
            };
            self.commit_manifest(first, true)?;
            return self.put_record(MANIFEST_LATCH, b"", false);
        };
        let loaded = Manifest::open_blob(self, &blob)?;
        loaded.verify(found)?;
        match &loaded.pending {
            Some(p) => self.settle_pending(&loaded, p, found)?,
            None => *self.manifest()? = loaded,
        }
        // A crash during adoption can leave a manifest without its latch; restore it.
        if self.index()?.contains(MANIFEST_LATCH) {
            return Ok(());
        }
        self.put_record(MANIFEST_LATCH, b"", false)
    }

    /// Finishes an interrupted mutation: a pending delete whose file is still there completes
    /// the delete; the manifest is rewritten to match the files, without `pending`.
    fn settle_pending(
        &self,
        loaded: &Manifest,
        p: &Pending,
        found: &BTreeMap<String, [u8; HASH_LEN]>,
    ) -> Result<(), StoreError> {
        let mut entries = found.clone();
        if !loaded.entries.contains_key(&p.tag) && entries.remove(&p.tag).is_some() {
            fs::remove_file(self.dir.join(format!("{}.{EXT}", p.tag)))?;
            self.index()?.retain(|n| tag_of(&self.name_mac, n) != p.tag);
            File::open(&self.dir)?.sync_all()?;
        }
        let next = Manifest {
            generation: loaded.generation.saturating_add(1),
            entries,
            pending: None,
        };
        self.commit_manifest(next, true)
    }

    fn manifest(&self) -> Result<std::sync::MutexGuard<'_, Manifest>, StoreError> {
        self.manifest.lock().map_err(|_| StoreError::Corrupt)
    }

    fn read_manifest_blob(&self) -> Result<Vec<u8>, StoreError> {
        let max = MAX_MANIFEST_LEN + MANIFEST_MAGIC.len() + NONCE_LEN + TAG_LEN;
        read_private_file(
            &self.dir.join(MANIFEST_FILE),
            max,
            StoreError::ManifestCorrupt,
        )
    }

    /// Atomically replaces the manifest file, then adopts `next` in memory.
    /// The file is always fsynced before the rename (no zero-length manifest after a power
    /// cut). `durable` also fsyncs the directory; the settling write that clears `pending`
    /// skips that: if the rename is lost, `open` accepts the `pending` manifest it restores.
    fn commit_manifest(&self, next: Manifest, durable: bool) -> Result<(), StoreError> {
        let blob = next.seal(self)?;
        self.atomic_write(MANIFEST_FILE, &blob)?;
        if durable {
            File::open(&self.dir)?.sync_all()?;
        }
        *self.manifest()? = next;
        Ok(())
    }

    /// Re-encrypts every `<name>.rec` (`PHS1`) record as an opaque-named `PHS2` record, then
    /// deletes it. Each legacy file is removed only after its replacement authenticates (a
    /// crash between write and delete leaves both; the new record wins). Once the store holds
    /// the `MARKER` record the import window is closed: stray `.rec` files (for example planted
    /// from an old backup) are deleted unread. Stale `<name>.rec.tmp` files are always removed.
    fn migrate_legacy(&self, may_import: bool) -> Result<(), StoreError> {
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
        let closed = !may_import || self.index()?.contains(MARKER);
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
        if is_internal(name) {
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
            let internal = index.iter().filter(|n| is_internal(n)).count();
            (!index.contains(name), has_marker, index.len() - internal)
        };
        // Internal records do not count against the user-visible limit.
        if is_new && !is_internal(name) && user_records >= MAX_RECORDS {
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
        self.write_with_manifest(&tag, &blob, name)
    }

    /// Manifest-first mutation (see `manifest`): the new state with a `pending` entry, then the
    /// record, then the manifest without `pending`.
    fn write_with_manifest(&self, tag: &str, blob: &[u8], name: &str) -> Result<(), StoreError> {
        let new = Some(Sha256::digest(blob).into());
        self.mutate(tag, name, new, || self.write_atomic(tag, blob, name))
    }

    /// Runs `apply` (which must leave the record at `tag` as `new`, or fail) between the
    /// `pending` manifest and the settled one. The settled state is only ever one the MAC'd
    /// `pending` entry allows: `new` when `apply` succeeded, `new` or the previous state when it
    /// failed. Anything else (a file swapped in during the window) is never certified: the
    /// handle is poisoned, the `pending` manifest stays on disk and the call fails with
    /// `RecordStale`. One mutation at a time per handle.
    fn mutate(
        &self,
        tag: &str,
        name: &str,
        new: Option<[u8; HASH_LEN]>,
        apply: impl FnOnce() -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        let _one_at_a_time = self.write_lock.lock().map_err(|_| StoreError::Corrupt)?;
        if self.poisoned.load(Ordering::Acquire) {
            return Err(StoreError::Corrupt);
        }
        let before = self.manifest()?.clone();
        let old = before.entries.get(tag).copied();
        let mut next = before;
        next.generation = next.generation.saturating_add(1);
        match new {
            Some(h) => next.entries.insert(tag.to_owned(), h),
            None => next.entries.remove(tag),
        };
        next.pending = Some(Pending {
            tag: tag.to_owned(),
            old,
        });
        self.commit_manifest(next.clone(), true)?;
        let applied = apply();
        let actual = match self.file_hash(tag) {
            Ok(a) => a,
            Err(e) => {
                self.poisoned.store(true, Ordering::Release);
                return Err(applied.err().unwrap_or(e));
            }
        };
        let allowed = actual == new || (applied.is_err() && actual == old);
        if !allowed {
            self.poisoned.store(true, Ordering::Release);
            return Err(StoreError::RecordStale {
                tag: tag.to_owned(),
            });
        }
        let mut settled = next;
        settled.generation = settled.generation.saturating_add(1);
        settled.pending = None;
        match actual {
            Some(h) => {
                settled.entries.insert(tag.to_owned(), h);
                self.index()?.insert(name.to_owned());
            }
            None => {
                settled.entries.remove(tag);
                self.index()?.remove(name);
            }
        }
        // If this write fails the disk keeps the `pending` manifest, which `open` accepts for
        // either state of this record; memory already holds the truth.
        let committed = self.commit_manifest(settled.clone(), false);
        if committed.is_err() {
            *self.manifest()? = settled;
        }
        applied.and(committed)
    }

    /// SHA-256 of the record file at `tag`, `None` if absent. Opened like `read_blob`.
    fn file_hash(&self, tag: &str) -> Result<Option<[u8; HASH_LEN]>, StoreError> {
        let path = self.dir.join(format!("{tag}.{EXT}"));
        let max = (MAGIC.len() + NONCE_LEN + TAG_LEN + MAX_INNER_LEN) as u64;
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
        if !md.is_file() || md.len() > max {
            return Err(StoreError::InsecurePath);
        }
        let mut bytes = Vec::with_capacity(md.len() as usize);
        Read::by_ref(&mut f).take(max).read_to_end(&mut bytes)?;
        Ok(Some(Sha256::digest(&bytes).into()))
    }

    /// Once the rename has landed the record exists, so it enters the index before the final
    /// directory fsync (whose failure is still reported).
    fn write_atomic(&self, tag: &str, blob: &[u8], name: &str) -> Result<(), StoreError> {
        self.atomic_write(&format!("{tag}.{EXT}"), blob)?;
        self.index()?.insert(name.to_owned());
        File::open(&self.dir)?.sync_all()?;
        Ok(())
    }

    /// Temp file 0600 → fsync → rename onto `file`. The caller fsyncs the directory.
    fn atomic_write(&self, file: &str, blob: &[u8]) -> Result<(), StoreError> {
        let tmp = self.dir.join(format!("{file}.tmp"));
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
        let target = self.dir.join(file);
        let written = f.write_all(blob).and_then(|()| f.sync_all());
        if let Err(e) = written.and_then(|()| fs::rename(&tmp, target)) {
            let _ = fs::remove_file(&tmp);
            return Err(e.into());
        }
        Ok(())
    }

    /// Reads and decrypts a record; `Ok(None)` if it does not exist.
    pub fn get(&self, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StoreError> {
        validate_record_name(name)?;
        if is_internal(name) {
            return Err(StoreError::BadName);
        }
        check_private_dir(&self.dir)?;
        let tag = tag_of(&self.name_mac, name);
        let _read_between_writes = self.write_lock.lock().map_err(|_| StoreError::Corrupt)?;
        let listed = self.manifest()?.entries.get(&tag).copied();
        match (self.read_blob(&self.record_path(name), MAGIC, &tag), listed) {
            (Ok((inner, hash)), Some(want)) if hash == want => {
                Ok(Some(self.split_inner(inner, &tag)?.1))
            }
            (Ok(_), Some(_)) => Err(StoreError::RecordStale { tag }),
            (Ok(_), None) => Err(StoreError::RecordUnlisted { tag }),
            (Err(StoreError::Io(ErrorKind::NotFound)), Some(_)) => {
                Err(StoreError::RecordMissing { tag })
            }
            (Err(StoreError::Io(ErrorKind::NotFound)), None) => Ok(None),
            (Err(e), _) => Err(e),
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
        Ok(self.read_blob(path, magic, label)?.0)
    }

    /// `read_file` plus the SHA-256 of the file's bytes (what the manifest lists).
    fn read_blob(
        &self,
        path: &Path,
        magic: &[u8; 4],
        label: &str,
    ) -> Result<(Zeroizing<Vec<u8>>, [u8; HASH_LEN]), StoreError> {
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
        Ok((Zeroizing::new(pt), Sha256::digest(&blob).into()))
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
        if is_internal(name) {
            return Err(StoreError::BadName);
        }
        check_private_dir(&self.dir)?;
        let tag = tag_of(&self.name_mac, name);
        if self.poisoned.load(Ordering::Acquire) {
            return Err(StoreError::Corrupt);
        }
        if !self.manifest()?.entries.contains_key(&tag) {
            return Ok(());
        }
        self.mutate(&tag, name, None, || {
            match fs::remove_file(self.record_path(name)) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            File::open(&self.dir)?.sync_all()?;
            Ok(())
        })
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
                if out.len() > MAX_RECORDS + 2 {
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
        Ok(index.iter().filter(|n| !is_internal(n)).cloned().collect())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use proptest::strategy::Strategy;

    use super::*;
    use manifest::tag_hex;

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
        assert!(
            err.to_string().contains("do not delete") && err.to_string().contains("tampered"),
            "{err}"
        );
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

    fn legacy_open(paths: &ProfilePaths, ek: &[u8]) -> Result<ProfileStore, StoreError> {
        ProfileStore::open_legacy_fixture(paths, ek)
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
        create_private_dir(&paths.dir).unwrap();
        legacy_record(&paths.dir, &EK, "work", "identity", b"old-secret");
        legacy_record(&paths.dir, &EK, "work", "conv-abc", b"");
        assert!(matches!(
            ProfileStore::open(&paths, &EK),
            Err(StoreError::UpgradeRequired)
        ));
        assert!(!paths.dir.join(KEYFILE).exists());
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert!(paths.dir.join(KEYFILE).exists());
        assert!(!paths.dir.join("identity.rec").exists());
        assert!(!paths.dir.join("conv-abc.rec").exists());
        assert_eq!(s.names().unwrap(), vec!["conv-abc", "identity"]);
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"old-secret");
        drop(s);
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"old-secret");
    }

    #[test]
    fn migration_prefers_existing_new_record_and_rejects_wrong_key() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = legacy_open(&paths, &EK).unwrap();
        s.put("a", b"new").unwrap();
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "a", b"stale");
        legacy_record(&paths.dir, &EK, "work", "b", b"x");
        let err = ProfileStore::open_upgrading(&paths, &[9u8; 32]).unwrap_err();
        assert!(matches!(err.root(), StoreError::Authentication));
        assert!(paths.dir.join("b.rec").exists());
        assert!(
            !paths.dir.join(KEYFILE).exists(),
            "a wrong key must not leave a key file"
        );
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"new");
        assert!(!paths.dir.join("a.rec").exists());
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
        let s = legacy_open(&paths, &EK).unwrap();
        s.put("a", b"new").unwrap();
        s.put("gone", b"x").unwrap();
        s.remove("gone").unwrap();
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "gone", b"resurrected");
        legacy_record(&paths.dir, &EK, "work", "a", b"stale");
        fs::write(paths.dir.join("rx-1.rec.tmp"), b"junk").unwrap();
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
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
        assert!(ProfileStore::open_upgrading(&paths, &EK).is_err());
        assert!(!marker.exists(), "failed migration must not latch");
        assert!(!paths.dir.join(KEYFILE).exists());
        assert!(paths.dir.join("z.rec").exists());
        fs::remove_file(&bad).unwrap();
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert_eq!(s.names().unwrap(), vec!["a", "z"]);
        assert_eq!(&**s.get("z").unwrap().unwrap(), b"z");
        assert!(marker.exists());
    }

    /// Creates the profile dir and returns where its marker record would live.
    fn drop_and_marker_path(paths: &ProfilePaths) -> PathBuf {
        let s = legacy_open(paths, &EK).unwrap();
        let p = s.record_path(MARKER);
        drop(s);
        p
    }

    #[test]
    fn full_legacy_store_migrates_and_marker_is_reserved() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        create_private_dir(&paths.dir).unwrap();
        for i in 0..40 {
            legacy_record(&paths.dir, &EK, "work", &format!("r{i}"), b"x");
        }
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
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
        create_private_dir(&paths.dir).unwrap();
        legacy_record(&paths.dir, &EK, "work", "a", b"x");
        fs::rename(paths.dir.join("a.rec"), paths.dir.join("b.rec")).unwrap();
        assert!(matches!(
            ProfileStore::open_upgrading(&paths, &EK),
            Err(StoreError::Authentication)
        ));
        // A PHS1 blob moved to an opaque name is not a PHS2 record.
        let s_tag = format!("{:032x}.rc2", 5);
        fs::rename(paths.dir.join("b.rec"), paths.dir.join(&s_tag)).unwrap();
        let err = ProfileStore::open_upgrading(&paths, &EK).unwrap_err();
        assert!(matches!(err.root(), StoreError::Corrupt));
    }

    #[test]
    fn unauthenticated_new_record_blocks_legacy_deletion() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = legacy_open(&paths, &EK).unwrap();
        let junk = s.record_path("a");
        drop(s);
        legacy_record(&paths.dir, &EK, "work", "a", b"only-copy");
        fs::write(&junk, b"not a record").unwrap();
        fs::set_permissions(&junk, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(ProfileStore::open_upgrading(&paths, &EK).is_err());
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
        s.write_with_manifest(&tag, &blob, "a").unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::Corrupt)));
    }

    fn two_record_store(tmp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
        let s = open(tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        s.put("b", b"two").unwrap();
        (s.record_path("a"), s.record_path("b"))
    }

    fn manifest_path(tmp: &tempfile::TempDir) -> PathBuf {
        tmp.path().join("powehi").join("work").join(MANIFEST_FILE)
    }

    #[test]
    fn rolled_back_record_is_rejected_at_open() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let old = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"v2").unwrap();
        let path = s.record_path("a");
        drop(s);
        fs::write(&path, old).unwrap();
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::RecordStale { .. }), "{err:?}");
    }

    #[test]
    fn deleted_record_is_rejected_at_open() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, _) = two_record_store(&tmp);
        fs::remove_file(a).unwrap();
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::RecordMissing { .. }), "{err:?}");
    }

    #[test]
    fn record_added_outside_the_store_is_rejected_at_open() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        // A validly encrypted record from an earlier life of the store, replayed as new.
        let ghost = fs::read(s.record_path("a")).unwrap();
        s.remove("a").unwrap();
        fs::write(s.record_path("a"), ghost).unwrap();
        fs::set_permissions(s.record_path("a"), fs::Permissions::from_mode(0o600)).unwrap();
        drop(s);
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::RecordUnlisted { .. }), "{err:?}");
    }

    #[test]
    fn mixing_two_snapshots_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"a1").unwrap();
        s.put("b", b"b1").unwrap();
        let (pa, pb) = (s.record_path("a"), s.record_path("b"));
        let (a1, b1) = (fs::read(&pa).unwrap(), fs::read(&pb).unwrap());
        s.put("a", b"a2").unwrap();
        s.put("b", b"b2").unwrap();
        drop(s);
        fs::write(&pa, a1).unwrap();
        assert!(open(&tmp, &EK).is_err());
        fs::write(&pb, b1).unwrap();
        assert!(open(&tmp, &EK).is_err());
    }

    #[test]
    fn swapped_records_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, b) = two_record_store(&tmp);
        let (ba, bb) = (fs::read(&a).unwrap(), fs::read(&b).unwrap());
        fs::write(&a, bb).unwrap();
        fs::write(&b, ba).unwrap();
        assert!(open(&tmp, &EK).is_err());
    }

    #[test]
    fn deleted_manifest_is_not_adopted_once_the_store_has_had_one() {
        let tmp = tempfile::tempdir().unwrap();
        two_record_store(&tmp);
        fs::remove_file(manifest_path(&tmp)).unwrap();
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::ManifestMissing), "{err:?}");
    }

    #[test]
    fn manifest_tamper_and_foreign_profile_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        two_record_store(&tmp);
        let path = manifest_path(&tmp);
        let orig = fs::read(&path).unwrap();
        for i in [0, MANIFEST_MAGIC.len(), orig.len() - 1] {
            let mut b = orig.clone();
            b[i] ^= 1;
            fs::write(&path, &b).unwrap();
            assert!(open(&tmp, &EK).is_err(), "{i}");
        }
        fs::write(&path, &orig[..8]).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::ManifestCorrupt)));
        // A manifest from another profile fails authentication here.
        fs::write(&path, &orig).unwrap();
        let other = ProfilePaths::resolve(tmp.path(), "other").unwrap();
        drop(ProfileStore::open(&other, &EK).unwrap());
        fs::copy(&path, other.dir.join(MANIFEST_FILE)).unwrap();
        let err = ProfileStore::open(&other, &EK).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
    }

    #[test]
    fn pre_manifest_store_is_adopted_only_on_upgrade_then_protected() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let s = legacy_open(&paths, &EK).unwrap();
        s.put("a", b"one").unwrap();
        s.put("b", b"two").unwrap();
        let (a, latch) = (s.record_path("a"), s.record_path(MANIFEST_LATCH));
        drop(s);
        // Make it look like a PHS2 store: no manifest, no latch record, no key file.
        fs::remove_file(latch).unwrap();
        fs::remove_file(manifest_path(&tmp)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::UpgradeRequired)));
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        assert_eq!(s.names().unwrap(), vec!["a", "b"]);
        drop(s);
        fs::remove_file(a).unwrap();
        assert!(open(&tmp, &EK).is_err());
    }

    #[test]
    fn latch_lost_to_a_crash_during_adoption_is_restored() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        // State after a crash between the first manifest commit and the latch write.
        let latch_tag = tag_of(&s.name_mac, MANIFEST_LATCH);
        let mut m = s.manifest().unwrap().clone();
        m.entries.remove(&latch_tag);
        s.commit_manifest(m, true).unwrap();
        fs::remove_file(s.record_path(MANIFEST_LATCH)).unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert!(s.record_path(MANIFEST_LATCH).exists());
        drop(s);
        fs::remove_file(manifest_path(&tmp)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::ManifestMissing)));
    }

    #[test]
    fn failed_put_leaves_memory_and_disk_in_step() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        // A directory where the temp file goes makes the write fail after the pending manifest.
        let tmp_path = s
            .dir
            .join(format!("{}.{EXT}.tmp", tag_of(&s.name_mac, "a")));
        fs::create_dir(&tmp_path).unwrap();
        assert!(s.put("a", b"v2").is_err());
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"v1");
        fs::remove_dir(&tmp_path).unwrap();
        s.put("c", b"other").unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"v1");
        assert_eq!(&**s.get("c").unwrap().unwrap(), b"other");
    }

    #[test]
    fn failed_unlink_leaves_memory_and_disk_in_step() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let tag = tag_of(&s.name_mac, "a");
        let r = s.mutate(&tag, "a", None, || Err(StoreError::Io(ErrorKind::Other)));
        assert!(matches!(r, Err(StoreError::Io(ErrorKind::Other))));
        assert_eq!(s.names().unwrap(), vec!["a"]);
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"v1");
        s.put("y", b"z").unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"v1");
    }

    #[test]
    fn latch_is_restored_on_the_settle_path_too() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"x").unwrap();
        let latch_tag = tag_of(&s.name_mac, MANIFEST_LATCH);
        let mut m = s.manifest().unwrap().clone();
        m.entries.remove(&latch_tag);
        m.pending = Some(Pending {
            tag: latch_tag,
            old: None,
        });
        s.commit_manifest(m, true).unwrap();
        fs::remove_file(s.record_path(MANIFEST_LATCH)).unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert!(s.record_path(MANIFEST_LATCH).exists());
        drop(s);
        fs::remove_file(manifest_path(&tmp)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::ManifestMissing)));
    }

    #[test]
    fn get_notices_changes_made_behind_the_open_handle() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let old = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"v2").unwrap();
        fs::write(s.record_path("a"), old).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::RecordStale { .. })));
        fs::remove_file(s.record_path("a")).unwrap();
        assert!(matches!(s.get("a"), Err(StoreError::RecordMissing { .. })));
    }

    #[test]
    fn replaying_an_older_whole_store_snapshot_is_the_accepted_risk() {
        // Pins prd §3.2 residual ①: flip this test if a generation anchor ever exists.
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let dir = s.dir.clone();
        let snap: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "rc2" || x == "mf3"))
            .map(|p| (p.clone(), fs::read(p).unwrap()))
            .collect();
        s.put("a", b"v2").unwrap();
        drop(s);
        for (p, b) in snap {
            fs::write(p, b).unwrap();
        }
        let s = open(&tmp, &EK).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"v1");
    }

    proptest::proptest! {
        #[test]
        fn manifest_encoding_round_trips(
            generation in proptest::prelude::any::<u64>(),
            entries in proptest::collection::btree_map(
                proptest::prelude::any::<[u8; RAW_TAG_LEN]>().prop_map(|b| tag_hex(&b)),
                proptest::prelude::any::<[u8; HASH_LEN]>(),
                0..16,
            ),
            pend in proptest::option::of((
                proptest::prelude::any::<[u8; RAW_TAG_LEN]>(),
                proptest::option::of(proptest::prelude::any::<[u8; HASH_LEN]>()),
            )),
            junk in proptest::collection::vec(proptest::prelude::any::<u8>(), 1..4),
        ) {
            let m = Manifest {
                generation,
                entries,
                pending: pend.map(|(t, old)| Pending { tag: tag_hex(&t), old }),
            };
            let enc = m.encode().unwrap();
            let dec = Manifest::decode(&enc).unwrap();
            proptest::prop_assert_eq!(dec.encode().unwrap(), enc.clone());
            // Trailing bytes and truncation are refused.
            let mut longer = enc.clone();
            longer.extend_from_slice(&junk);
            proptest::prop_assert!(Manifest::decode(&longer).is_err());
            proptest::prop_assert!(Manifest::decode(&enc[..enc.len() - 1]).is_err());
        }
    }

    fn sample_manifest_bytes(pending: bool) -> Vec<u8> {
        let mut m = Manifest {
            generation: 3,
            ..Manifest::default()
        };
        m.entries
            .insert(tag_hex(&[1u8; RAW_TAG_LEN]), [2u8; HASH_LEN]);
        if pending {
            m.pending = Some(Pending {
                tag: tag_hex(&[1u8; RAW_TAG_LEN]),
                old: None,
            });
        }
        m.encode().unwrap()
    }

    #[test]
    fn manifest_decode_refuses_malformed_encodings() {
        // Duplicate tag: two identical entries.
        let mut dup = Vec::new();
        dup.extend_from_slice(&1u64.to_be_bytes());
        dup.extend_from_slice(&2u32.to_be_bytes());
        for _ in 0..2 {
            dup.extend_from_slice(&[1u8; RAW_TAG_LEN]);
            dup.extend_from_slice(&[2u8; HASH_LEN]);
        }
        dup.push(0);
        assert!(matches!(
            Manifest::decode(&dup),
            Err(StoreError::ManifestCorrupt)
        ));
        // Entry count over the record cap is refused before any allocation per entry.
        let mut huge = Vec::new();
        huge.extend_from_slice(&1u64.to_be_bytes());
        huge.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            Manifest::decode(&huge),
            Err(StoreError::ManifestCorrupt)
        ));
        // Unknown pending / has_old flag bytes.
        let plain = sample_manifest_bytes(false);
        let mut flag = plain.clone();
        *flag.last_mut().unwrap() = 2;
        assert!(matches!(
            Manifest::decode(&flag),
            Err(StoreError::ManifestCorrupt)
        ));
        let mut pend = sample_manifest_bytes(true);
        *pend.last_mut().unwrap() = 2;
        assert!(matches!(
            Manifest::decode(&pend),
            Err(StoreError::ManifestCorrupt)
        ));
        assert!(matches!(
            Manifest::decode(&[]),
            Err(StoreError::ManifestCorrupt)
        ));
    }

    #[test]
    fn manifest_encode_refuses_non_canonical_tags() {
        for bad in [
            "+f".repeat(16),
            "AB".repeat(16),
            "ab".repeat(15),
            "zz".repeat(16),
        ] {
            let mut m = Manifest::default();
            m.entries.insert(bad.clone(), [0u8; HASH_LEN]);
            assert!(m.encode().is_err(), "{bad}");
            let p = Manifest {
                pending: Some(Pending {
                    tag: bad.clone(),
                    old: None,
                }),
                ..Manifest::default()
            };
            assert!(p.encode().is_err(), "pending {bad}");
        }
        let mixed = format!("F{}", "0".repeat(31));
        let mut m = Manifest::default();
        m.entries.insert(mixed, [0u8; HASH_LEN]);
        assert!(m.encode().is_err());
    }

    #[test]
    fn rollback_during_a_failed_put_is_not_certified() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"gen-1").unwrap();
        let old = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"gen-2").unwrap();
        fs::write(s.record_path("a"), old).unwrap();
        let tmp_path = s
            .dir
            .join(format!("{}.{EXT}.tmp", tag_of(&s.name_mac, "a")));
        fs::create_dir(&tmp_path).unwrap();
        assert!(s.put("a", b"gen-3").is_err());
        assert!(s.put("c", b"x").is_err(), "the handle is poisoned");
        drop(s);
        fs::remove_dir(&tmp_path).unwrap();
        // The pending manifest stayed on disk: gen-1 is neither the old nor the new state.
        assert!(matches!(
            open(&tmp, &EK),
            Err(StoreError::RecordStale { .. })
        ));
    }

    #[test]
    fn record_swapped_back_during_remove_is_not_certified() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let old = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"v2").unwrap();
        let tag = tag_of(&s.name_mac, "a");
        let path = s.record_path("a");
        let r = s.mutate(&tag, "a", None, || {
            fs::remove_file(&path)?;
            fs::write(&path, &old)?;
            Ok(())
        });
        assert!(matches!(r, Err(StoreError::RecordStale { .. })), "{r:?}");
        assert!(s.remove("a").is_err());
    }

    #[test]
    fn unreadable_record_after_a_failed_write_poisons_instead_of_diverging() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"v1").unwrap();
        let path = s.record_path("a");
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(s.put("a", b"v2").is_err());
        assert!(s.put("c", b"x").is_err());
    }

    #[test]
    fn generation_increases_on_every_mutation() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        let g0 = s.manifest().unwrap().generation;
        s.put("a", b"x").unwrap();
        let g1 = s.manifest().unwrap().generation;
        s.remove("a").unwrap();
        let g2 = s.manifest().unwrap().generation;
        assert!(g0 < g1 && g1 < g2, "{g0} {g1} {g2}");
        assert!(s.manifest().unwrap().pending.is_none());
    }

    #[test]
    fn interrupted_mutations_are_accepted_and_settled() {
        // Crash after the pending manifest, before the record landed (create, update, delete).
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("keep", b"k").unwrap();
        s.put("upd", b"u1").unwrap();
        s.put("del", b"d").unwrap();
        let mac = s.name_mac.clone();
        let tag = move |n: &str| tag_of(&mac, n);
        let mut m = s.manifest().unwrap().clone();
        let old_upd = m.entries[&tag("upd")];
        // create "new": listed, no file
        m.entries.insert(tag("new"), [9u8; HASH_LEN]);
        m.pending = Some(Pending {
            tag: tag("new"),
            old: None,
        });
        s.commit_manifest(m.clone(), true).unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert!(s.manifest().unwrap().pending.is_none());
        assert!(s.get("new").unwrap().is_none());
        // update: manifest lists a new hash, file still has the old one
        let mut m = s.manifest().unwrap().clone();
        m.entries.insert(tag("upd"), [7u8; HASH_LEN]);
        m.pending = Some(Pending {
            tag: tag("upd"),
            old: Some(old_upd),
        });
        s.commit_manifest(m, true).unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert_eq!(&**s.get("upd").unwrap().unwrap(), b"u1");
        // delete: manifest drops the entry, file still present
        let mut m = s.manifest().unwrap().clone();
        let old_del = m.entries.remove(&tag("del")).unwrap();
        m.pending = Some(Pending {
            tag: tag("del"),
            old: Some(old_del),
        });
        s.commit_manifest(m, true).unwrap();
        drop(s);
        let s = open(&tmp, &EK).unwrap();
        assert_eq!(s.names().unwrap(), vec!["keep", "upd"]);
        assert!(s.manifest().unwrap().pending.is_none());
    }

    #[test]
    fn pending_does_not_excuse_a_rollback_of_another_record() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"a1").unwrap();
        let old = fs::read(s.record_path("a")).unwrap();
        s.put("a", b"a2").unwrap();
        s.put("b", b"b1").unwrap();
        let mut m = s.manifest().unwrap().clone();
        let tb = tag_of(&s.name_mac, "b");
        m.pending = Some(Pending {
            tag: tb,
            old: Some([1u8; HASH_LEN]),
        });
        s.commit_manifest(m, true).unwrap();
        let pa = s.record_path("a");
        drop(s);
        fs::write(&pa, old).unwrap();
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::RecordStale { .. }), "{err:?}");
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

    const SEED: [u8; 64] = [0x5a; 64];

    fn keyfile_path(tmp: &tempfile::TempDir) -> PathBuf {
        tmp.path().join("powehi").join("work").join(KEYFILE)
    }

    #[test]
    fn a_new_store_has_its_own_random_keys_and_a_private_key_file() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        let mode = fs::metadata(keyfile_path(&tmp))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        // The record key is not the export-key-derived one, so the export key alone is no longer
        // enough to decrypt a record.
        assert_ne!(s.bundle.record(), &derive_key(&EK).unwrap()[..]);
        assert_ne!(s.bundle.name(), &expand(&EK, NAME_KEY_INFO).unwrap()[..]);
        assert_ne!(
            s.bundle.manifest(),
            &expand(&EK, MANIFEST_KEY_INFO).unwrap()[..]
        );
        let other = tempfile::tempdir().unwrap();
        let t = open(&other, &EK).unwrap();
        assert_ne!(s.bundle.record(), t.bundle.record());
        assert_ne!(
            s.record_path("a").file_name(),
            t.record_path("a").file_name()
        );
    }

    #[test]
    fn upgraded_stores_keep_the_keys_they_had() {
        let b = Bundle::derived(&EK).unwrap();
        assert_eq!(hex(b.record()), KAT_KEY);
        let mac = <Hmac<Sha256> as Mac>::new_from_slice(b.name()).unwrap();
        assert_eq!(tag_of(&mac, "identity"), KAT_TAG);
        assert_eq!(b.manifest(), &expand(&EK, MANIFEST_KEY_INFO).unwrap()[..]);
    }

    #[test]
    fn password_change_reseals_the_bundle_and_leaves_records_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        let record = fs::read(s.record_path("a")).unwrap();
        let manifest = fs::read(manifest_path(&tmp)).unwrap();
        let before = fs::read(keyfile_path(&tmp)).unwrap();
        let new_ek = [9u8; 32];
        s.rewrap_password(&new_ek).unwrap();
        assert_ne!(before, fs::read(keyfile_path(&tmp)).unwrap());
        assert_eq!(record, fs::read(s.record_path("a")).unwrap());
        assert_eq!(manifest, fs::read(manifest_path(&tmp)).unwrap());
        drop(s);
        let err = open(&tmp, &EK).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
        let s = open(&tmp, &new_ek).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        s.put("b", b"two").unwrap();
    }

    #[test]
    fn the_recovery_phrase_unlocks_the_store_without_the_password() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        assert!(!s.has_recovery_wrap().unwrap());
        drop(s);
        // No recovery slot yet.
        let err = ProfileStore::open_with_recovery(&paths, &rc).unwrap_err();
        assert!(matches!(err, StoreError::NoRecoveryWrap), "{err:?}");
        let s = open(&tmp, &EK).unwrap();
        s.add_recovery_wrap(&rc).unwrap();
        assert!(s.has_recovery_wrap().unwrap());
        drop(s);
        let s = ProfileStore::open_with_recovery(&paths, &rc).unwrap();
        assert_eq!(&**s.get("a").unwrap().unwrap(), b"one");
        // A recovery-opened handle cannot tell derived keys from random ones (no export key), so
        // it refuses to rewrap until 8.18's restore can.
        assert!(matches!(
            s.rewrap_password(&[9u8; 32]),
            Err(StoreError::RekeyRequired)
        ));
        drop(s);
        // A new password later: the recovery slot survives the rewrap.
        open(&tmp, &EK)
            .unwrap()
            .rewrap_password(&[9u8; 32])
            .unwrap();
        assert!(ProfileStore::open_with_recovery(&paths, &rc).is_ok());
        assert!(open(&tmp, &[9u8; 32]).is_ok());
        let wrong = RecoveryKek::from_seed(&[0x5b; 64]).unwrap();
        let err = ProfileStore::open_with_recovery(&paths, &wrong).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
    }

    #[test]
    fn a_deleted_key_file_is_never_silently_replaced() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.put("a", b"one").unwrap();
        drop(s);
        fs::remove_file(keyfile_path(&tmp)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::UpgradeRequired)));
        assert!(matches!(
            ProfileStore::open_with_recovery(&paths, &rc),
            Err(StoreError::KeyfileMissing)
        ));
        // Even a confirmed upgrade cannot read records sealed under the lost random keys, and
        // it leaves no key file behind.
        let err = ProfileStore::open_upgrading(&paths, &EK).unwrap_err();
        assert!(matches!(err.root(), StoreError::Authentication), "{err:?}");
        assert!(!keyfile_path(&tmp).exists());
    }

    #[test]
    fn a_current_store_never_adopts_a_manifest_less_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let (a, _) = two_record_store(&tmp);
        let latch = open(&tmp, &EK).unwrap().record_path(MANIFEST_LATCH);
        fs::remove_file(latch).unwrap();
        fs::remove_file(manifest_path(&tmp)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::ManifestMissing)));
        assert!(a.exists());
    }

    #[test]
    fn key_file_tampering_and_transplants_are_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        let rc = RecoveryKek::from_seed(&SEED).unwrap();
        let s = open(&tmp, &EK).unwrap();
        s.add_recovery_wrap(&rc).unwrap();
        drop(s);
        let path = keyfile_path(&tmp);
        let orig = fs::read(&path).unwrap();
        for i in 0..orig.len() {
            let mut b = orig.clone();
            b[i] ^= 1;
            fs::write(&path, &b).unwrap();
            let r = open(&tmp, &EK).map(drop);
            let q = ProfileStore::open_with_recovery(&paths, &rc).map(drop);
            // Every flipped byte breaks at least one slot; none may open with wrong keys.
            assert!(r.is_err() || q.is_err(), "byte {i}");
        }
        for bad in [
            &orig[..orig.len() - 1],
            &[orig.as_slice(), &[0]].concat()[..],
            b"PHK1",
        ] {
            fs::write(&path, bad).unwrap();
            assert!(matches!(open(&tmp, &EK), Err(StoreError::KeyfileCorrupt)));
        }
        // The password slot presented as the recovery slot (and the reverse) fails.
        let head = MAGIC.len() + keys::BUNDLE_LEN + NONCE_LEN + TAG_LEN;
        let mut swapped = orig.clone();
        swapped.copy_within(MAGIC.len()..head, head + 1);
        fs::write(&path, &swapped).unwrap();
        let err = ProfileStore::open_with_recovery(&paths, &rc).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
        // A key file from another profile.
        fs::write(&path, &orig).unwrap();
        let other = ProfilePaths::resolve(tmp.path(), "other").unwrap();
        drop(ProfileStore::open(&other, &EK).unwrap());
        fs::copy(&path, other.dir.join(KEYFILE)).unwrap();
        let err = ProfileStore::open(&other, &EK).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
    }

    #[test]
    fn a_wrong_key_cannot_poison_a_phs1_only_upgrade() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        create_private_dir(&paths.dir).unwrap();
        legacy_record(&paths.dir, &EK, "work", "identity", b"old");
        let err = ProfileStore::open_upgrading(&paths, &[9u8; 32]).unwrap_err();
        assert!(matches!(err, StoreError::Authentication), "{err:?}");
        for f in [MANIFEST_FILE, KEYFILE] {
            assert!(!paths.dir.join(f).exists(), "{f} written under a wrong key");
        }
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert_eq!(&**s.get("identity").unwrap().unwrap(), b"old");
    }

    #[test]
    fn upgraded_stores_refuse_a_password_rewrap_but_new_ones_allow_it() {
        let tmp = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::resolve(tmp.path(), "work").unwrap();
        drop(legacy_open(&paths, &EK).unwrap());
        let s = ProfileStore::open_upgrading(&paths, &EK).unwrap();
        assert!(matches!(
            s.rewrap_password(&[9u8; 32]),
            Err(StoreError::RekeyRequired)
        ));
        drop(s);
        // Still detected on a later plain open of the upgraded store.
        let s = ProfileStore::open(&paths, &EK).unwrap();
        assert!(matches!(
            s.rewrap_password(&[9u8; 32]),
            Err(StoreError::RekeyRequired)
        ));
        let fresh = tempfile::tempdir().unwrap();
        assert!(open(&fresh, &EK)
            .unwrap()
            .rewrap_password(&[9u8; 32])
            .is_ok());
    }

    #[test]
    fn has_recovery_wrap_reports_a_missing_key_file() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        fs::remove_file(keyfile_path(&tmp)).unwrap();
        assert!(matches!(
            s.has_recovery_wrap(),
            Err(StoreError::KeyfileMissing)
        ));
    }

    #[test]
    fn key_file_must_be_a_private_regular_file() {
        let tmp = tempfile::tempdir().unwrap();
        drop(open(&tmp, &EK).unwrap());
        let path = keyfile_path(&tmp);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::InsecurePath)));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let real = path.with_extension("real");
        fs::rename(&path, &real).unwrap();
        std::os::unix::fs::symlink(&real, &path).unwrap();
        assert!(matches!(open(&tmp, &EK), Err(StoreError::InsecurePath)));
    }

    #[test]
    fn key_file_holds_no_plaintext_key_material() {
        let tmp = tempfile::tempdir().unwrap();
        let s = open(&tmp, &EK).unwrap();
        let bytes = fs::read(keyfile_path(&tmp)).unwrap();
        for key in [s.bundle.record(), s.bundle.name(), s.bundle.manifest()] {
            assert!(!bytes.windows(key.len()).any(|w| w == key));
        }
        assert!(bytes.len() <= KEYFILE_MAX_LEN);
        assert!(!bytes.windows(EK.len()).any(|w| w == EK));
    }
}
