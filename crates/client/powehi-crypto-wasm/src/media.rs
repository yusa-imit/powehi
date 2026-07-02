// AES-256-GCM media encryption primitives for prd.md §9.2.
//
// Security invariants:
// - All key material is wrapped in Zeroizing to zero heap buffers on drop.
// - ONLY aes-gcm (RustCrypto) is used; no homegrown crypto
//   (rule: crypto-libraries-pinned).
// - No key material, IV, or ciphertext appears in any error message
//   (rule: no-plaintext-logging).
// - IV (nonce) is generated from the OS CSPRNG (getrandom / browser
//   crypto.getRandomValues on wasm32) — never reused. Each encrypt call
//   generates a fresh IV and a fresh key.
// - GCM authentication tag (16 bytes) is appended to the ciphertext by the
//   `aes-gcm` crate and verified on decrypt. A tampered ciphertext (including
//   wrong key or wrong IV) returns MediaError::Decrypt.
// - The sender path (wasm_exports.rs): media key is stored in a thread-local
//   handle map and never crosses the WASM-JS boundary — only an opaque string
//   handle is returned to JS (same pattern as KEM keys in ADR-0003 Phase B).
// - The receiver path: the media key bytes arrive inside an MLS-decrypted
//   application message (already protected by MLS AEAD during transit). The JS
//   caller extracts them from the plaintext JSON and passes them to
//   `decrypt_with_raw_key`. This is the minimum necessary exposure; both ends
//   must trust their own WASM worker for key-material hygiene.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::rand::RngCore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

/// AES-256-GCM key size (bytes).
pub const MEDIA_KEY_BYTES: usize = 32;
/// AES-256-GCM nonce (IV) size (bytes). GCM standard is 12 (96-bit).
pub const MEDIA_IV_BYTES: usize = 12;
/// SHA-256 blob hash size (bytes).
pub const BLOB_HASH_BYTES: usize = 32;

/// Result type for `encrypt`: ciphertext, Zeroizing key, IV, SHA-256 blob hash.
pub type EncryptResult = (
    Vec<u8>,
    Zeroizing<[u8; MEDIA_KEY_BYTES]>,
    [u8; MEDIA_IV_BYTES],
    [u8; BLOB_HASH_BYTES],
);

#[derive(Debug, Error)]
pub enum MediaError {
    #[error("media encryption failed")]
    Encrypt,
    #[error("media decryption failed")]
    Decrypt,
    #[error("invalid key length")]
    InvalidKeyLen,
    #[error("invalid iv length")]
    InvalidIvLen,
    // R-2 (crypto-reviewer): receiver-side blob-hash mismatch — indicates a
    // server-side blob swap (adversary replaced the R2 object after upload).
    // Verified before AES-GCM decrypt so no decryption oracle is exposed.
    #[error("blob hash mismatch")]
    BlobHashMismatch,
}

/// Encrypt `plaintext` with a fresh AES-256-GCM key and IV.
///
/// Returns `(ciphertext, key, iv, blob_hash)`:
/// - `ciphertext`: encrypted bytes with 16-byte GCM tag appended.
/// - `key`: fresh 32-byte media key (`Zeroizing` — zeroed on drop).
/// - `iv`: 12-byte nonce (public; must be stored alongside the ciphertext).
/// - `blob_hash`: SHA-256 of the ciphertext (integrity check for R2 upload).
///
/// The key is returned here so the caller (wasm_exports.rs) can store it in the
/// thread-local handle map before returning an opaque handle to JS.
pub fn encrypt(plaintext: &[u8]) -> Result<EncryptResult, MediaError> {
    let mut rng = OsRng;
    let mut raw_key = [0u8; MEDIA_KEY_BYTES];
    rng.fill_bytes(&mut raw_key);
    let key = Zeroizing::new(raw_key);

    let mut iv = [0u8; MEDIA_IV_BYTES];
    rng.fill_bytes(&mut iv);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&iv);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| MediaError::Encrypt)?;

    let blob_hash: [u8; BLOB_HASH_BYTES] = Sha256::digest(&ciphertext).into();

    Ok((ciphertext, key, iv, blob_hash))
}

/// Decrypt `ciphertext` (with appended 16-byte GCM tag) using the given 32-byte key and 12-byte IV.
///
/// Returns `Err(MediaError::Decrypt)` if the GCM tag does not verify (wrong key, wrong IV,
/// or any byte of the ciphertext was tampered).
pub fn decrypt(
    key: &[u8; MEDIA_KEY_BYTES],
    iv: &[u8; MEDIA_IV_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, MediaError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| MediaError::Decrypt)
}

/// Decrypt using raw key/IV byte slices from the JS caller (receiver path).
///
/// The media key arrives inside an MLS-decrypted application message payload.
/// The JS caller extracts it from the JSON and passes it here.
///
/// **R-2 (crypto-reviewer, NIST SP 800-38D §5.2.1.1):** `blob_hash_expected`
/// is the SHA-256 of the ciphertext that the *sender* computed and embedded
/// in the MLS-encrypted message.  We re-compute `SHA-256(ciphertext)` here
/// and reject before AES-GCM decrypt if it mismatches, detecting a server-side
/// R2 blob swap.  This check runs before decryption to avoid any oracle.
///
/// Returns `Err(MediaError::BlobHashMismatch)` if hashes differ.
/// Returns `Err(MediaError::InvalidKeyLen)` if `key_bytes.len() != 32`.
/// Returns `Err(MediaError::InvalidIvLen)` if `iv_bytes.len() != 12`.
/// Returns `Err(MediaError::Decrypt)` if the AES-GCM tag fails.
pub fn decrypt_with_raw_key(
    key_bytes: &[u8],
    iv_bytes: &[u8],
    ciphertext: &[u8],
    blob_hash_expected: &[u8; BLOB_HASH_BYTES],
) -> Result<Vec<u8>, MediaError> {
    // Verify blob hash FIRST — before any decryption — so a blob-swap is caught
    // without exposing an AES-GCM decryption oracle to the adversary.
    let actual_hash: [u8; BLOB_HASH_BYTES] = Sha256::digest(ciphertext).into();
    if &actual_hash != blob_hash_expected {
        return Err(MediaError::BlobHashMismatch);
    }
    let key: &[u8; MEDIA_KEY_BYTES] = key_bytes
        .try_into()
        .map_err(|_| MediaError::InvalidKeyLen)?;
    let iv: &[u8; MEDIA_IV_BYTES] = iv_bytes.try_into().map_err(|_| MediaError::InvalidIvLen)?;
    decrypt(key, iv, ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Property-based tests (proptest) ─────────────────────────────────────
    //
    // These exercise AES-256-GCM security invariants against arbitrary inputs,
    // complementing the fixed-input unit tests below (testing-conventions.md:
    // "Property-based (proptest): crypto round-trips and serialization").

    #[cfg(not(target_arch = "wasm32"))]
    mod property {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            /// For any plaintext up to 64 KB, encrypt→decrypt returns the original bytes.
            #[test]
            fn encrypt_decrypt_roundtrip(plaintext in proptest::collection::vec(any::<u8>(), 0..=65536)) {
                let (ciphertext, key, iv, _hash) = encrypt(&plaintext).unwrap();
                let recovered = decrypt(&key, &iv, &ciphertext).unwrap();
                prop_assert_eq!(recovered, plaintext);
            }

            /// Wrong-length key always returns InvalidKeyLen before any AES-GCM attempt.
            #[test]
            fn wrong_key_len_always_rejected(
                bad_len in (0usize..=64).prop_filter("not exactly 32", |l| *l != MEDIA_KEY_BYTES),
                plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
            ) {
                let (ciphertext, _key, iv, blob_hash) = encrypt(&plaintext).unwrap();
                let bad_key = vec![0u8; bad_len];
                let result = decrypt_with_raw_key(&bad_key, &iv, &ciphertext, &blob_hash);
                prop_assert!(
                    matches!(result, Err(MediaError::InvalidKeyLen)),
                    "expected InvalidKeyLen for key len {bad_len}, got {result:?}"
                );
            }

            /// Wrong-length IV always returns InvalidIvLen before any AES-GCM attempt.
            #[test]
            fn wrong_iv_len_always_rejected(
                bad_len in (0usize..=24).prop_filter("not exactly 12", |l| *l != MEDIA_IV_BYTES),
                plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
            ) {
                let (ciphertext, key, _iv, blob_hash) = encrypt(&plaintext).unwrap();
                let bad_iv = vec![0u8; bad_len];
                let result = decrypt_with_raw_key(key.as_ref(), &bad_iv, &ciphertext, &blob_hash);
                prop_assert!(
                    matches!(result, Err(MediaError::InvalidIvLen)),
                    "expected InvalidIvLen for iv len {bad_len}, got {result:?}"
                );
            }

            /// Any single-byte flip in ciphertext or GCM tag causes decryption to fail.
            /// Verifies GCM integrity protection for random plaintexts.
            #[test]
            fn tampered_ciphertext_never_decrypts(
                plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
                flip_offset in any::<u8>(),
            ) {
                let (mut ciphertext, key, iv, _hash) = encrypt(&plaintext).unwrap();
                // Flip a byte anywhere in ciphertext+tag using modular indexing so
                // we never go out of bounds regardless of ciphertext length.
                let idx = (flip_offset as usize) % ciphertext.len();
                ciphertext[idx] ^= 0xff;
                prop_assert!(
                    decrypt(&key, &iv, &ciphertext).is_err(),
                    "tampered ciphertext at byte {idx} must not decrypt"
                );
            }

            /// Blob-hash mismatch is caught before AES-GCM decryption.
            /// Any 1-bit deviation in the expected hash triggers BlobHashMismatch.
            #[test]
            fn blob_hash_mismatch_rejected_before_decrypt(
                plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
                flip_offset in any::<u8>(),
            ) {
                let (ciphertext, key, iv, mut blob_hash) = encrypt(&plaintext).unwrap();
                let idx = (flip_offset as usize) % BLOB_HASH_BYTES;
                blob_hash[idx] ^= 0xff;
                prop_assert!(
                    matches!(
                        decrypt_with_raw_key(key.as_ref(), &iv, &ciphertext, &blob_hash),
                        Err(MediaError::BlobHashMismatch)
                    ),
                    "tampered blob_hash at byte {idx} must return BlobHashMismatch"
                );
            }

            /// Two encryptions of the same plaintext always produce different ciphertexts
            /// (fresh random key + IV per call → semantic security).
            #[test]
            fn semantic_security_different_ciphertexts(
                plaintext in proptest::collection::vec(any::<u8>(), 1..=256),
            ) {
                let (ct1, _k1, _iv1, _h1) = encrypt(&plaintext).unwrap();
                let (ct2, _k2, _iv2, _h2) = encrypt(&plaintext).unwrap();
                prop_assert_ne!(ct1, ct2, "two encryptions of the same plaintext must differ");
            }
        }
    }

    // ── Deterministic unit tests ─────────────────────────────────────────────

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = b"hello powehi media world";
        let (ciphertext, key, iv, _hash) = encrypt(plaintext).unwrap();
        let decrypted = decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_ciphertext_includes_gcm_tag() {
        let plaintext = b"hello powehi media world";
        let (ciphertext, _key, _iv, _hash) = encrypt(plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let plaintext = [0x42u8; 32];
        let (ciphertext, _key, _iv, _hash) = encrypt(&plaintext).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn test_two_encrypts_produce_different_ciphertexts() {
        let plaintext = b"same plaintext same plaintext 12";
        let (ct1, _k1, _iv1, _h1) = encrypt(plaintext).unwrap();
        let (ct2, _k2, _iv2, _h2) = encrypt(plaintext).unwrap();
        assert_ne!(ct1, ct2);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let plaintext = b"hello powehi media world";
        let (ciphertext, _key, iv, _hash) = encrypt(plaintext).unwrap();
        let wrong_key = [0u8; MEDIA_KEY_BYTES];
        assert!(decrypt(&wrong_key, &iv, &ciphertext).is_err());
    }

    #[test]
    fn test_wrong_iv_fails_decryption() {
        let plaintext = b"hello powehi media world";
        let (ciphertext, key, _iv, _hash) = encrypt(plaintext).unwrap();
        let wrong_iv = [0u8; MEDIA_IV_BYTES];
        assert!(decrypt(&key, &wrong_iv, &ciphertext).is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails_decryption() {
        let plaintext = b"hello powehi media world";
        let (mut ciphertext, key, iv, _hash) = encrypt(plaintext).unwrap();
        ciphertext[0] ^= 0xff;
        assert!(decrypt(&key, &iv, &ciphertext).is_err());
    }

    #[test]
    fn test_blob_hash_is_sha256_of_ciphertext() {
        let plaintext = b"hello powehi media world";
        let (ciphertext, _key, _iv, blob_hash) = encrypt(plaintext).unwrap();
        let expected: [u8; 32] = Sha256::digest(&ciphertext).into();
        assert_eq!(blob_hash, expected);
    }

    #[test]
    fn test_decrypt_with_raw_key_round_trip() {
        let plaintext = b"receiver side decryption path";
        let (ciphertext, key, iv, blob_hash) = encrypt(plaintext).unwrap();
        let decrypted = decrypt_with_raw_key(key.as_ref(), &iv, &ciphertext, &blob_hash).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_raw_key_wrong_len_fails() {
        let plaintext = b"short key test";
        let (ciphertext, _key, iv, blob_hash) = encrypt(plaintext).unwrap();
        let short_key = [0u8; 16];
        assert!(matches!(
            decrypt_with_raw_key(&short_key, &iv, &ciphertext, &blob_hash),
            Err(MediaError::InvalidKeyLen)
        ));
    }

    #[test]
    fn test_decrypt_with_raw_iv_wrong_len_fails() {
        let plaintext = b"short iv test";
        let (ciphertext, key, _iv, blob_hash) = encrypt(plaintext).unwrap();
        let short_iv = [0u8; 8];
        assert!(matches!(
            decrypt_with_raw_key(key.as_ref(), &short_iv, &ciphertext, &blob_hash),
            Err(MediaError::InvalidIvLen)
        ));
    }

    #[test]
    fn test_decrypt_with_wrong_blob_hash_fails_before_decrypt() {
        let plaintext = b"blob hash mismatch test";
        let (ciphertext, key, iv, _blob_hash) = encrypt(plaintext).unwrap();
        let wrong_hash = [0u8; BLOB_HASH_BYTES];
        assert!(matches!(
            decrypt_with_raw_key(key.as_ref(), &iv, &ciphertext, &wrong_hash),
            Err(MediaError::BlobHashMismatch)
        ));
    }

    #[test]
    fn test_empty_plaintext_encrypts_and_decrypts() {
        let plaintext = b"";
        let (ciphertext, key, iv, _hash) = encrypt(plaintext).unwrap();
        assert_eq!(ciphertext.len(), 16); // only the GCM tag
        let decrypted = decrypt(&key, &iv, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
