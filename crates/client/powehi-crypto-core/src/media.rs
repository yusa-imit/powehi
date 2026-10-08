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
//   caller extracts them from the plaintext JSON and immediately passes them to
//   `wasm_exports::media_import_key`, which stores them under an opaque handle and
//   lets the caller zero its own copy right away (cycle 309 — receiver-side
//   opaque-handle pattern). `decrypt_with_raw_key` (below) is the shared decrypt
//   primitive both `wasm_exports::media_decrypt_with_handle` (handle-sourced key)
//   and the chunked equivalent call into; it no longer has a directly-JS-callable
//   wasm-bindgen export of its own.

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
    // §9.4.2 chunked streaming: the concatenated ciphertext length is not an exact
    // multiple of MEDIA_CHUNK_SIZE + 16 (the GCM tag), so it cannot be a valid
    // sequence of fixed-size encrypted chunks — reject before any decrypt.
    #[error("invalid chunk length")]
    InvalidChunkLen,
    // §9.4.2 chunked streaming: the number of ciphertext chunks does not match the
    // count implied by total_plaintext_len. Rejecting this prevents a malicious or
    // corrupted blob from causing an out-of-bounds truncation or silently returning
    // wrong-length plaintext.
    #[error("chunk count mismatch")]
    ChunkCountMismatch,
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
/// **R-2 (crypto-reviewer):** `blob_hash_expected` is the SHA-256 of the
/// ciphertext that the *sender* computed and embedded in the MLS-encrypted
/// message. This is an application-layer integrity check on top of the AEAD,
/// not a NIST SP 800-38D requirement (that spec governs GCM's own IV/tag
/// construction, not this outer blob-swap check). We re-compute
/// `SHA-256(ciphertext)` here and reject before AES-GCM decrypt if it
/// mismatches, detecting a server-side R2 blob swap. This check runs before
/// decryption to avoid any oracle.
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

// ── §9.4.2 Chunked streaming (large video) ─────────────────────────────────────
//
// Streaming media (large video, prd.md §9.4.2) is encrypted per-chunk so that a
// receiver can eventually fetch and progressively play a partial download. AES-256-GCM
// is safe to use per chunk **provided each chunk gets a unique nonce under the same
// key**. We achieve that with the standard "static base IV XOR counter" construction
// (identical in spirit to the TLS 1.3 per-record nonce, RFC 8446 §5.3): every chunk's
// nonce is the random 96-bit base IV with its last 4 bytes XORed against the chunk
// index encoded big-endian as a u32. See `chunk_nonce` for the reasoning.
//
// Size-leak mitigation (prd.md §9.4.2): every chunk's *plaintext* is zero-padded to
// exactly MEDIA_CHUNK_SIZE before encryption, so every chunk ciphertext is exactly
// MEDIA_CHUNK_SIZE + 16 bytes. The total ciphertext length therefore only reveals the
// plaintext size bucketed up to the nearest MEDIA_CHUNK_SIZE multiple, never the exact
// byte count. The exact length is carried separately as `total_plaintext_len` inside
// the MLS-encrypted (confidential) application message, not derivable from the blob.

/// Fixed chunk size for streaming media: 16 MiB (prd.md §9.4.2).
///
/// Every chunk's plaintext is zero-padded up to this size before encryption, so each
/// chunk ciphertext is exactly `MEDIA_CHUNK_SIZE + 16` bytes (the trailing 16 is the
/// GCM tag). This fixed-size bucketing is the size-leak mitigation §9.4.2 requires.
pub const MEDIA_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Result of `encrypt_chunked`.
///
/// - `ciphertext`: all chunk ciphertexts concatenated; length is always an exact
///   multiple of `MEDIA_CHUNK_SIZE + 16`.
/// - `key`: fresh 32-byte media key (`Zeroizing` — zeroed on drop). Stored in the
///   WASM handle map by the caller; never crosses the WASM-JS boundary on the sender path.
/// - `base_iv`: fresh 12-byte base nonce; per-chunk nonces are derived from it. Public.
/// - `blob_hash`: SHA-256 of the concatenated `ciphertext` (integrity check for the R2
///   upload, same role as in `encrypt`).
/// - `total_plaintext_len`: exact original plaintext length in bytes; needed to truncate
///   the final chunk's zero padding on decrypt.
/// - `num_chunks`: number of chunks (>= 1).
pub struct ChunkedEncryptResult {
    pub ciphertext: Vec<u8>,
    pub key: Zeroizing<[u8; MEDIA_KEY_BYTES]>,
    pub base_iv: [u8; MEDIA_IV_BYTES],
    pub blob_hash: [u8; BLOB_HASH_BYTES],
    pub total_plaintext_len: u64,
    pub num_chunks: u32,
}

/// Derive the AES-256-GCM nonce for chunk `chunk_index` from the random `base_iv`.
///
/// Construction: `nonce_i = base_iv`, with the last 4 bytes XORed against
/// `chunk_index.to_be_bytes()` (big-endian `u32`). This is the standard "static IV XOR
/// counter" nonce derivation, the same idea as the TLS 1.3 per-record nonce
/// (RFC 8446 §5.3) and the SRTP/GCM constructions.
///
/// **Why this is nonce-reuse-safe (the GCM must-not-repeat-nonce invariant,
/// NIST SP 800-38D §8.2):**
/// - Each `encrypt_chunked` call generates a *fresh random key AND a fresh random base
///   IV*, so nonces are never reused across two different messages/keys.
/// - Within one message (one key), the XOR of a fixed base IV with the *distinct*
///   values `0, 1, 2, …, num_chunks-1` yields `num_chunks` *distinct* nonces, because
///   `a XOR x == a XOR y  ⇒  x == y`. So no two chunks under the same key share a nonce.
/// - The counter is a `u32`, giving up to 2^32 unique chunks per key — far beyond any
///   realistic media size (2^32 × 16 MiB ≈ 64 EiB), so the counter never wraps in practice.
///
/// Only the low 32 bits of the 96-bit nonce vary; the high 64 bits stay at the random base
/// IV, which is fine — uniqueness (not unpredictability) is all GCM requires of a nonce.
fn chunk_nonce(base_iv: &[u8; MEDIA_IV_BYTES], chunk_index: u32) -> [u8; MEDIA_IV_BYTES] {
    let mut nonce = *base_iv;
    let idx = chunk_index.to_be_bytes();
    nonce[8] ^= idx[0];
    nonce[9] ^= idx[1];
    nonce[10] ^= idx[2];
    nonce[11] ^= idx[3];
    nonce
}

/// Ciphertext length of a single fully-padded chunk: `MEDIA_CHUNK_SIZE` plaintext bytes
/// plus the 16-byte GCM tag appended by `aes-gcm`.
const CHUNK_CIPHERTEXT_LEN: usize = MEDIA_CHUNK_SIZE + 16;

/// Encrypt `plaintext` as a sequence of fixed-size AES-256-GCM chunks (prd.md §9.4.2).
///
/// Generates one fresh key + base IV (exactly like `encrypt`), splits `plaintext` into
/// `MEDIA_CHUNK_SIZE`-byte chunks, **zero-pads the last chunk up to `MEDIA_CHUNK_SIZE`**
/// before encrypting it, encrypts each chunk under the per-chunk nonce from `chunk_nonce`,
/// and concatenates the chunk ciphertexts. `blob_hash = SHA-256(concatenated ciphertext)`.
///
/// Zero-length plaintext still produces exactly **one** chunk (a full `MEDIA_CHUNK_SIZE`
/// of zero padding, so `ciphertext.len() == MEDIA_CHUNK_SIZE + 16`). This intentionally
/// differs from `encrypt`, whose empty-plaintext ciphertext is 16 bytes: the whole point
/// of the chunked path is fixed-size bucketing (§9.4.2 size-leak mitigation), so even an
/// empty/tiny input is padded to a full chunk. `total_plaintext_len == 0` records the truth.
pub fn encrypt_chunked(plaintext: &[u8]) -> Result<ChunkedEncryptResult, MediaError> {
    let mut rng = OsRng;
    let mut raw_key = [0u8; MEDIA_KEY_BYTES];
    rng.fill_bytes(&mut raw_key);
    let key = Zeroizing::new(raw_key);

    let mut base_iv = [0u8; MEDIA_IV_BYTES];
    rng.fill_bytes(&mut base_iv);

    let total_plaintext_len = plaintext.len() as u64;

    // Empty plaintext still yields one (fully padded) chunk — see doc comment.
    let num_chunks_usize = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(MEDIA_CHUNK_SIZE)
    };
    // GCM nonce counter is a u32 → at most 2^32 chunks per key.
    let num_chunks = u32::try_from(num_chunks_usize).map_err(|_| MediaError::Encrypt)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_ref()));

    // Reusable, zeroing scratch buffer for the padded plaintext of each chunk. Holding
    // plaintext, so it is Zeroizing (wiped on drop). Reused across chunks to avoid
    // reallocating 16 MiB per chunk.
    let mut padded = Zeroizing::new(vec![0u8; MEDIA_CHUNK_SIZE]);
    let mut ciphertext = Vec::with_capacity(num_chunks_usize * CHUNK_CIPHERTEXT_LEN);

    for i in 0..num_chunks {
        let start = i as usize * MEDIA_CHUNK_SIZE;
        let end = core::cmp::min(start + MEDIA_CHUNK_SIZE, plaintext.len());
        let chunk = &plaintext[start..end];
        // Copy this chunk's real bytes to the front, zero the remaining tail (padding).
        padded[..chunk.len()].copy_from_slice(chunk);
        for b in padded[chunk.len()..].iter_mut() {
            *b = 0;
        }
        let nonce = chunk_nonce(&base_iv, i);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), padded.as_slice())
            .map_err(|_| MediaError::Encrypt)?;
        ciphertext.extend_from_slice(&ct);
    }

    let blob_hash: [u8; BLOB_HASH_BYTES] = Sha256::digest(&ciphertext).into();

    Ok(ChunkedEncryptResult {
        ciphertext,
        key,
        base_iv,
        blob_hash,
        total_plaintext_len,
        num_chunks,
    })
}

/// Decrypt exactly one chunk. This is the primitive that will back progressive /
/// partial download: a caller can fetch chunk `chunk_index` (bytes
/// `chunk_index * CHUNK_CIPHERTEXT_LEN .. +CHUNK_CIPHERTEXT_LEN` of the blob) and
/// decrypt it independently, deriving the nonce from the same `base_iv`.
///
/// The returned plaintext is still zero-padded up to `MEDIA_CHUNK_SIZE` for a full
/// chunk; the caller truncates the final chunk using the known `total_plaintext_len`.
///
/// Returns `Err(MediaError::Decrypt)` if the GCM tag fails (wrong key/iv/index or a
/// tampered chunk).
pub fn decrypt_chunk(
    key: &[u8; MEDIA_KEY_BYTES],
    base_iv: &[u8; MEDIA_IV_BYTES],
    chunk_index: u32,
    chunk_ciphertext: &[u8],
) -> Result<Vec<u8>, MediaError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = chunk_nonce(base_iv, chunk_index);
    cipher
        .decrypt(Nonce::from_slice(&nonce), chunk_ciphertext)
        .map_err(|_| MediaError::Decrypt)
}

/// Decrypt and reassemble a full chunked ciphertext (receiver path, prd.md §9.4.2).
///
/// **R-2 (crypto-reviewer):** `SHA-256(ciphertext)` is re-computed and compared
/// to `blob_hash_expected` (authenticated inside the MLS envelope) BEFORE any
/// AES-GCM decrypt, so a server-side R2 blob swap is caught without exposing a
/// decryption oracle — identical rule to `decrypt_with_raw_key`. This is an
/// application-layer check, not a NIST SP 800-38D requirement — that spec
/// covers GCM's own IV/tag construction, not this outer blob-swap check.
///
/// Then it validates structure before decrypting:
/// - `ciphertext.len()` must be a non-zero exact multiple of `MEDIA_CHUNK_SIZE + 16`,
///   else `MediaError::InvalidChunkLen`.
/// - the chunk count implied by `ciphertext.len()` must equal the count implied by
///   `total_plaintext_len` (`ceil(len / MEDIA_CHUNK_SIZE)`, or 1 when the length is 0),
///   else `MediaError::ChunkCountMismatch`. This prevents a malicious/corrupted blob
///   from driving an out-of-bounds truncation or returning wrong-length plaintext.
///
/// Finally it decrypts each chunk via `decrypt_chunk`, concatenates, and truncates the
/// final chunk's zero padding down to `total_plaintext_len`.
pub fn decrypt_chunked(
    key: &[u8; MEDIA_KEY_BYTES],
    base_iv: &[u8; MEDIA_IV_BYTES],
    ciphertext: &[u8],
    total_plaintext_len: u64,
    blob_hash_expected: &[u8; BLOB_HASH_BYTES],
) -> Result<Vec<u8>, MediaError> {
    // Blob-hash check FIRST — before any decryption — to avoid a decryption oracle.
    let actual_hash: [u8; BLOB_HASH_BYTES] = Sha256::digest(ciphertext).into();
    if &actual_hash != blob_hash_expected {
        return Err(MediaError::BlobHashMismatch);
    }

    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(CHUNK_CIPHERTEXT_LEN) {
        return Err(MediaError::InvalidChunkLen);
    }
    let num_chunks = ciphertext.len() / CHUNK_CIPHERTEXT_LEN;

    // Compare chunk counts entirely in u64 to avoid any 32-bit truncation ambiguity.
    let num_chunks_u64 = num_chunks as u64;
    let expected_chunks_u64 = if total_plaintext_len == 0 {
        1
    } else {
        total_plaintext_len.div_ceil(MEDIA_CHUNK_SIZE as u64)
    };
    if num_chunks_u64 != expected_chunks_u64 {
        return Err(MediaError::ChunkCountMismatch);
    }

    // Safe: total_plaintext_len <= num_chunks * MEDIA_CHUNK_SIZE (from the count match),
    // which is <= ciphertext-derived usize capacity, so this fits usize.
    let total = usize::try_from(total_plaintext_len).map_err(|_| MediaError::ChunkCountMismatch)?;

    let mut plaintext = Vec::with_capacity(num_chunks * MEDIA_CHUNK_SIZE);
    for i in 0..num_chunks {
        let start = i * CHUNK_CIPHERTEXT_LEN;
        let chunk_ct = &ciphertext[start..start + CHUNK_CIPHERTEXT_LEN];
        let chunk_plain = decrypt_chunk(key, base_iv, i as u32, chunk_ct)?;
        plaintext.extend_from_slice(&chunk_plain);
    }
    // Drop the final chunk's zero padding.
    plaintext.truncate(total);
    Ok(plaintext)
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

        // Chunked streaming round-trip (§9.4.2). We bound the plaintext to a small,
        // fast range (0..=8192): every chunk is still padded to the full 16 MiB, so
        // exercising the true multi-chunk boundary sizes in every proptest case would
        // be far too slow — those exact sizes are covered by the deterministic tests
        // below. NOTE: even a tiny input is zero-padded to a full 16 MiB chunk before
        // encryption, so each case costs a full 16 MiB debug-mode AES-GCM round-trip;
        // the case count is kept very low (4) to bound total runtime.
        proptest! {
            #![proptest_config(ProptestConfig::with_cases(4))]

            /// For any small plaintext, encrypt_chunked → decrypt_chunked round-trips,
            /// and the ciphertext length is always an exact multiple of the padded chunk size.
            #[test]
            fn encrypt_decrypt_chunked_roundtrip(
                plaintext in proptest::collection::vec(any::<u8>(), 0..=8192),
            ) {
                let res = encrypt_chunked(&plaintext).unwrap();
                prop_assert!(res.ciphertext.len().is_multiple_of(MEDIA_CHUNK_SIZE + 16));
                prop_assert_eq!(res.num_chunks, 1); // all lengths here fit one chunk
                let recovered = decrypt_chunked(
                    &res.key,
                    &res.base_iv,
                    &res.ciphertext,
                    res.total_plaintext_len,
                    &res.blob_hash,
                )
                .unwrap();
                prop_assert_eq!(recovered, plaintext);
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

    // ── §9.4.2 Chunked streaming (deterministic) ─────────────────────────────

    /// Round-trip helper that also asserts the fixed-size-bucketing invariant.
    fn chunked_round_trip(len: usize) {
        // Deterministic, non-trivial content so padding vs. real bytes is distinguishable.
        let plaintext: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let res = encrypt_chunked(&plaintext).unwrap();

        // Size bucketing: every chunk ciphertext is exactly MEDIA_CHUNK_SIZE + 16 bytes.
        assert!(
            res.ciphertext.len().is_multiple_of(MEDIA_CHUNK_SIZE + 16),
            "ciphertext length must be an exact multiple of the padded chunk size (len={len})"
        );
        assert_eq!(res.total_plaintext_len, len as u64);
        let expected_chunks = if len == 0 {
            1
        } else {
            len.div_ceil(MEDIA_CHUNK_SIZE)
        };
        assert_eq!(res.num_chunks as usize, expected_chunks);
        assert_eq!(
            res.ciphertext.len(),
            expected_chunks * (MEDIA_CHUNK_SIZE + 16)
        );

        let recovered = decrypt_chunked(
            &res.key,
            &res.base_iv,
            &res.ciphertext,
            res.total_plaintext_len,
            &res.blob_hash,
        )
        .unwrap();
        assert_eq!(recovered.len(), len);
        assert_eq!(recovered, plaintext, "round-trip mismatch for len={len}");
    }

    #[test]
    fn test_chunked_round_trip_empty() {
        chunked_round_trip(0);
    }

    #[test]
    fn test_chunked_round_trip_one_byte() {
        chunked_round_trip(1);
    }

    #[test]
    fn test_chunked_round_trip_chunk_minus_one() {
        chunked_round_trip(MEDIA_CHUNK_SIZE - 1);
    }

    #[test]
    fn test_chunked_round_trip_exact_chunk() {
        chunked_round_trip(MEDIA_CHUNK_SIZE);
    }

    #[test]
    fn test_chunked_round_trip_chunk_plus_one() {
        chunked_round_trip(MEDIA_CHUNK_SIZE + 1);
    }

    #[test]
    fn test_chunked_round_trip_two_chunks_plus_tail() {
        chunked_round_trip(2 * MEDIA_CHUNK_SIZE + 12345);
    }

    #[test]
    fn test_chunked_per_chunk_nonces_differ() {
        // The whole nonce-reuse-safety argument rests on distinct chunk indices giving
        // distinct nonces. Verify chunk 0 and chunk 1 of the same encryption differ,
        // and that chunk 0 equals the base IV unchanged (XOR with 0).
        let base_iv = [0x5au8; MEDIA_IV_BYTES];
        let n0 = chunk_nonce(&base_iv, 0);
        let n1 = chunk_nonce(&base_iv, 1);
        assert_eq!(n0, base_iv, "chunk 0 nonce must equal the base IV (XOR 0)");
        assert_ne!(n0, n1, "chunk 0 and chunk 1 nonces must differ");
        // Only the last 4 bytes may change; the first 8 stay pinned to the base IV.
        assert_eq!(n0[..8], n1[..8]);
    }

    #[test]
    fn test_chunked_tampered_ciphertext_fails() {
        // Flip a byte AND recompute the blob hash so the GCM layer (not the hash gate)
        // is what rejects it — proving per-chunk AES-GCM integrity holds.
        let mut res = encrypt_chunked(&[7u8; 4096]).unwrap();
        res.ciphertext[100] ^= 0xff;
        let rehash: [u8; BLOB_HASH_BYTES] = Sha256::digest(&res.ciphertext).into();
        let out = decrypt_chunked(
            &res.key,
            &res.base_iv,
            &res.ciphertext,
            res.total_plaintext_len,
            &rehash,
        );
        assert!(
            matches!(out, Err(MediaError::Decrypt)),
            "tampered chunk must fail GCM verification, got {out:?}"
        );
    }

    #[test]
    fn test_chunked_wrong_blob_hash_rejected_before_decrypt() {
        let res = encrypt_chunked(&[1u8; 2048]).unwrap();
        let wrong_hash = [0u8; BLOB_HASH_BYTES];
        assert!(matches!(
            decrypt_chunked(
                &res.key,
                &res.base_iv,
                &res.ciphertext,
                res.total_plaintext_len,
                &wrong_hash,
            ),
            Err(MediaError::BlobHashMismatch)
        ));
    }

    #[test]
    fn test_chunked_invalid_ciphertext_length_rejected() {
        // Truncate one byte, then recompute the hash so we pass the hash gate and reach
        // the length-structure check.
        let res = encrypt_chunked(&[9u8; 512]).unwrap();
        let mut truncated = res.ciphertext.clone();
        truncated.pop();
        let rehash: [u8; BLOB_HASH_BYTES] = Sha256::digest(&truncated).into();
        assert!(matches!(
            decrypt_chunked(
                &res.key,
                &res.base_iv,
                &truncated,
                res.total_plaintext_len,
                &rehash
            ),
            Err(MediaError::InvalidChunkLen)
        ));
    }

    #[test]
    fn test_chunked_chunk_count_mismatch_rejected() {
        // Valid single-chunk ciphertext + hash, but claim a total_plaintext_len that
        // implies two chunks → ChunkCountMismatch (guards against OOB truncation).
        let res = encrypt_chunked(&[3u8; 128]).unwrap();
        let lying_total = (MEDIA_CHUNK_SIZE + 1) as u64;
        assert!(matches!(
            decrypt_chunked(
                &res.key,
                &res.base_iv,
                &res.ciphertext,
                lying_total,
                &res.blob_hash
            ),
            Err(MediaError::ChunkCountMismatch)
        ));
    }

    #[test]
    fn test_decrypt_chunk_single_primitive_round_trip() {
        // decrypt_chunk decrypts one chunk to its full padded plaintext; caller truncates.
        let payload = b"partial download primitive test";
        let res = encrypt_chunked(payload).unwrap();
        assert_eq!(res.num_chunks, 1);
        let chunk0 = &res.ciphertext[..MEDIA_CHUNK_SIZE + 16];
        let padded = decrypt_chunk(&res.key, &res.base_iv, 0, chunk0).unwrap();
        assert_eq!(padded.len(), MEDIA_CHUNK_SIZE);
        assert_eq!(&padded[..payload.len()], payload);
        assert!(padded[payload.len()..].iter().all(|&b| b == 0));
    }
}
