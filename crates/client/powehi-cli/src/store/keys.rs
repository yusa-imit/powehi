//! Key bundle and key file (8.8b). The store's three keys (record, name-tag, manifest) are a
//! random per-store bundle, not a function of the OPAQUE `export_key`. `keys.wk3` (format `PHK1`)
//! holds the bundle sealed twice: under `KEK_pw` (HKDF of the `export_key`) and, once the user
//! has entered the recovery phrase, under `KEK_rc` (HKDF of the phrase's BIP-39 seed). A password
//! change reseals only the bundle (`ProfileStore::rewrap_password`); the records are untouched,
//! and `KEK_rc` reopens the store if the password path is lost (for example the server's OPRF
//! key was regenerated).
//!
//! A store upgraded from `PHS2` keeps the keys it already had: its bundle is the old
//! `export_key`-derived triple, so no record is re-encrypted. Those keys stay tied to the old
//! `export_key` until a rekey exists; only stores created by this version have independent keys.
//!
//! Each slot is `nonce(12) || AES-256-GCM(bundle(96))` with AAD `PHK1 || kind || len(profile) ||
//! profile`, so a slot moved to another profile, or the password slot presented as the recovery
//! slot, fails authentication. The two slots are not bound to each other: they wrap the same
//! bundle, which never changes for the life of the store.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::RngCore;
use zeroize::Zeroizing;

use super::{
    derive_key, expand, StoreError, KEY_INFO, KEY_LEN, MANIFEST_KEY_INFO, NAME_KEY_INFO, NONCE_LEN,
    TAG_LEN,
};

/// Key file name inside the profile directory.
pub(super) const KEYFILE: &str = "keys.wk3";
const MAGIC: &[u8; 4] = b"PHK1";
pub(super) const BUNDLE_LEN: usize = 3 * KEY_LEN;
const SLOT_LEN: usize = NONCE_LEN + BUNDLE_LEN + TAG_LEN;
/// Magic, password slot, recovery-slot flag, recovery slot.
pub(super) const KEYFILE_MAX_LEN: usize = MAGIC.len() + SLOT_LEN + 1 + SLOT_LEN;
const KEK_PW_INFO: &[u8] = b"powehi-cli/profile-store/v3/kek-pw";
const KEK_RC_INFO: &[u8] = b"powehi-cli/profile-store/v3/kek-rc";
/// Length of a BIP-39 seed (`powehi_crypto_core::recovery::mnemonic_to_seed`).
const RECOVERY_SEED_LEN: usize = 64;
const KIND_PASSWORD: u8 = 1;
const KIND_RECOVERY: u8 = 2;

/// The record, name-tag and manifest keys of one store.
pub(super) struct Bundle(Zeroizing<[u8; BUNDLE_LEN]>);

impl Bundle {
    /// Fresh store: three independent random keys.
    pub(super) fn random() -> Result<Self, StoreError> {
        let mut raw = Zeroizing::new([0u8; BUNDLE_LEN]);
        OsRng
            .try_fill_bytes(raw.as_mut())
            .map_err(|_| StoreError::Io(std::io::ErrorKind::Other))?;
        debug_assert!(raw.iter().any(|&b| b != 0));
        Ok(Self(raw))
    }

    /// The keys a `PHS2` store already uses, derived from its `export_key`.
    pub(super) fn derived(export_key: &[u8]) -> Result<Self, StoreError> {
        let mut raw = Zeroizing::new([0u8; BUNDLE_LEN]);
        raw[..KEY_LEN].copy_from_slice(derive_key(export_key)?.as_ref());
        raw[KEY_LEN..2 * KEY_LEN].copy_from_slice(expand(export_key, NAME_KEY_INFO)?.as_ref());
        raw[2 * KEY_LEN..].copy_from_slice(expand(export_key, MANIFEST_KEY_INFO)?.as_ref());
        debug_assert!(KEY_INFO != NAME_KEY_INFO && NAME_KEY_INFO != MANIFEST_KEY_INFO);
        Ok(Self(raw))
    }

    /// Constant-time equality of all three keys.
    pub(super) fn same_keys(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }

    pub(super) fn record(&self) -> &[u8] {
        &self.0[..KEY_LEN]
    }

    pub(super) fn name(&self) -> &[u8] {
        &self.0[KEY_LEN..2 * KEY_LEN]
    }

    pub(super) fn manifest(&self) -> &[u8] {
        &self.0[2 * KEY_LEN..]
    }
}

/// Key-encryption key from the OPAQUE `export_key`.
pub(super) struct PasswordKek(Zeroizing<[u8; KEY_LEN]>);

impl PasswordKek {
    pub(super) fn new(export_key: &[u8]) -> Result<Self, StoreError> {
        Ok(Self(expand(export_key, KEK_PW_INFO)?))
    }
}

/// Key-encryption key from the recovery phrase's BIP-39 seed.
pub struct RecoveryKek(Zeroizing<[u8; KEY_LEN]>);

impl RecoveryKek {
    /// `seed` must be the 64-byte BIP-39 seed of the phrase.
    pub fn from_seed(seed: &[u8]) -> Result<Self, StoreError> {
        if seed.len() != RECOVERY_SEED_LEN {
            return Err(StoreError::BadKeyLength);
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        hkdf::Hkdf::<sha2::Sha256>::new(None, seed)
            .expand(KEK_RC_INFO, key.as_mut())
            .map_err(|_| StoreError::BadKeyLength)?;
        Ok(Self(key))
    }
}

fn slot_aad(profile: &str, kind: u8) -> Vec<u8> {
    let mut a = Vec::with_capacity(MAGIC.len() + 2 + profile.len());
    a.extend_from_slice(MAGIC);
    a.push(kind);
    a.push(u8::try_from(profile.len()).unwrap_or(u8::MAX));
    a.extend_from_slice(profile.as_bytes());
    a
}

fn seal(
    kek: &[u8; KEY_LEN],
    profile: &str,
    kind: u8,
    bundle: &Bundle,
) -> Result<Vec<u8>, StoreError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| StoreError::Io(std::io::ErrorKind::Other))?;
    let ct = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek))
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &bundle.0[..],
                aad: &slot_aad(profile, kind),
            },
        )
        .map_err(|_| StoreError::KeyfileCorrupt)?;
    let mut slot = Vec::with_capacity(SLOT_LEN);
    slot.extend_from_slice(&nonce);
    slot.extend_from_slice(&ct);
    debug_assert_eq!(slot.len(), SLOT_LEN);
    Ok(slot)
}

fn unseal(kek: &[u8; KEY_LEN], profile: &str, kind: u8, slot: &[u8]) -> Result<Bundle, StoreError> {
    if slot.len() != SLOT_LEN {
        return Err(StoreError::KeyfileCorrupt);
    }
    let (nonce, ct) = slot.split_at(NONCE_LEN);
    let pt = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(kek))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct,
                aad: &slot_aad(profile, kind),
            },
        )
        .map_err(|_| StoreError::Authentication)?;
    let pt = Zeroizing::new(pt);
    if pt.len() != BUNDLE_LEN {
        return Err(StoreError::KeyfileCorrupt);
    }
    let mut raw = Zeroizing::new([0u8; BUNDLE_LEN]);
    raw.copy_from_slice(&pt);
    Ok(Bundle(raw))
}

/// Decoded `keys.wk3`: the password slot and the optional recovery slot.
pub(super) struct KeyFile {
    password: Vec<u8>,
    recovery: Option<Vec<u8>>,
}

impl KeyFile {
    pub(super) fn new(
        profile: &str,
        bundle: &Bundle,
        pw: &PasswordKek,
        rc: Option<&RecoveryKek>,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            password: seal(&pw.0, profile, KIND_PASSWORD, bundle)?,
            recovery: rc
                .map(|k| seal(&k.0, profile, KIND_RECOVERY, bundle))
                .transpose()?,
        })
    }

    /// The same bundle under a new password key; the recovery slot is carried over unchanged.
    pub(super) fn with_password(
        self,
        profile: &str,
        bundle: &Bundle,
        pw: &PasswordKek,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            password: seal(&pw.0, profile, KIND_PASSWORD, bundle)?,
            recovery: self.recovery,
        })
    }

    /// The same bundle with a (new or replaced) recovery slot.
    pub(super) fn with_recovery(
        self,
        profile: &str,
        bundle: &Bundle,
        rc: &RecoveryKek,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            password: self.password,
            recovery: Some(seal(&rc.0, profile, KIND_RECOVERY, bundle)?),
        })
    }

    pub(super) fn has_recovery(&self) -> bool {
        self.recovery.is_some()
    }

    pub(super) fn unlock_password(
        &self,
        profile: &str,
        pw: &PasswordKek,
    ) -> Result<Bundle, StoreError> {
        unseal(&pw.0, profile, KIND_PASSWORD, &self.password)
    }

    pub(super) fn unlock_recovery(
        &self,
        profile: &str,
        rc: &RecoveryKek,
    ) -> Result<Bundle, StoreError> {
        let slot = self.recovery.as_deref().ok_or(StoreError::NoRecoveryWrap)?;
        unseal(&rc.0, profile, KIND_RECOVERY, slot)
    }

    /// `PHK1 || password slot || has_recovery(1) [|| recovery slot]`.
    pub(super) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEYFILE_MAX_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.password);
        match &self.recovery {
            Some(slot) => {
                out.push(1);
                out.extend_from_slice(slot);
            }
            None => out.push(0),
        }
        debug_assert!(out.len() <= KEYFILE_MAX_LEN);
        out
    }

    pub(super) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let head = MAGIC.len() + SLOT_LEN;
        if bytes.len() <= head || &bytes[..MAGIC.len()] != MAGIC {
            return Err(StoreError::KeyfileCorrupt);
        }
        let password = bytes[MAGIC.len()..head].to_vec();
        let recovery = match (bytes[head], bytes.len() - head - 1) {
            (0, 0) => None,
            (1, SLOT_LEN) => Some(bytes[head + 1..].to_vec()),
            _ => return Err(StoreError::KeyfileCorrupt),
        };
        Ok(Self { password, recovery })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_kek_needs_a_full_seed_and_is_not_the_password_kek() {
        assert!(matches!(
            RecoveryKek::from_seed(&[1u8; 32]),
            Err(StoreError::BadKeyLength)
        ));
        let a = RecoveryKek::from_seed(&[0x5a; 64]).unwrap();
        assert_eq!(a.0[..], RecoveryKek::from_seed(&[0x5a; 64]).unwrap().0[..]);
        assert_ne!(a.0[..], RecoveryKek::from_seed(&[0x5b; 64]).unwrap().0[..]);
        // The same bytes under the password label give a different key.
        assert_ne!(a.0[..], PasswordKek::new(&[0x5a; 32]).unwrap().0[..]);
        assert!(matches!(
            PasswordKek::new(&[0x5a; 31]),
            Err(StoreError::BadKeyLength)
        ));
    }

    proptest::proptest! {
        #[test]
        fn key_file_round_trips_and_rejects_every_truncation(
            with_rc in proptest::bool::ANY,
            pw in proptest::array::uniform32(proptest::num::u8::ANY),
            cut in 0usize..KEYFILE_MAX_LEN,
        ) {
            let bundle = Bundle::random().unwrap();
            let pwk = PasswordKek::new(&pw).unwrap();
            let rc = RecoveryKek::from_seed(&[3u8; 64]).unwrap();
            let kf = KeyFile::new("p", &bundle, &pwk, with_rc.then_some(&rc)).unwrap();
            let bytes = kf.encode();
            let back = KeyFile::decode(&bytes).unwrap();
            proptest::prop_assert_eq!(back.has_recovery(), with_rc);
            proptest::prop_assert!(back.unlock_password("p", &pwk).unwrap().same_keys(&bundle));
            if cut < bytes.len() {
                proptest::prop_assert!(KeyFile::decode(&bytes[..cut]).is_err());
            }
        }
    }

    #[test]
    fn slot_kinds_and_profiles_are_bound_into_the_aad() {
        let bundle = Bundle::random().unwrap();
        let pw = PasswordKek::new(&[1u8; 32]).unwrap();
        let slot = seal(&pw.0, "work", KIND_PASSWORD, &bundle).unwrap();
        assert_eq!(slot.len(), SLOT_LEN);
        assert!(unseal(&pw.0, "work", KIND_PASSWORD, &slot).is_ok());
        for (profile, kind) in [("other", KIND_PASSWORD), ("work", KIND_RECOVERY)] {
            let err = unseal(&pw.0, profile, kind, &slot).err();
            assert!(matches!(err, Some(StoreError::Authentication)), "{profile}");
        }
        let again = seal(&pw.0, "work", KIND_PASSWORD, &bundle).unwrap();
        assert_ne!(slot, again, "fresh nonce per seal");
    }

    #[test]
    fn key_file_decode_rejects_malformed_layouts() {
        let bundle = Bundle::random().unwrap();
        let pw = PasswordKek::new(&[1u8; 32]).unwrap();
        let rc = RecoveryKek::from_seed(&[2u8; 64]).unwrap();
        let both = KeyFile::new("work", &bundle, &pw, Some(&rc))
            .unwrap()
            .encode();
        let only_pw = KeyFile::new("work", &bundle, &pw, None).unwrap().encode();
        assert!(KeyFile::decode(&both).is_ok() && KeyFile::decode(&only_pw).is_ok());
        let mut flag = only_pw.clone();
        *flag.last_mut().unwrap() = 2;
        let mut trailing = only_pw.clone();
        trailing.push(0);
        let mut no_slot = both.clone();
        no_slot.truncate(both.len() - 1);
        for bad in [&flag, &trailing, &no_slot, &Vec::new(), &both[1..].to_vec()] {
            assert!(
                matches!(KeyFile::decode(bad), Err(StoreError::KeyfileCorrupt)),
                "{}",
                bad.len()
            );
        }
    }
}
