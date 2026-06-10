// §8.5 Recovery Mechanism — BIP-39 mnemonic + deterministic MLS identity derivation.
//
// No cryptographic primitives are implemented here.  All work is delegated to
// audited libraries (rule: crypto-libraries-pinned.md):
//   - bip39  → BIP-39 mnemonic generation + PBKDF2-HMAC-SHA512 seed derivation
//   - hkdf   → HKDF-SHA256 expansion of the seed to a 32-byte Ed25519 secret
//   - ed25519-dalek → re-creates the SigningKey from the 32-byte secret
//
// Security invariants enforced by this module:
//   * All secret material lives behind `Zeroizing` so the heap buffer is wiped
//     on drop (rule: no-plaintext-logging applies to runtime memory too).
//   * The domain-separation label `b"powehi-mls-signing-v1"` MUST NOT change
//     without a crypto-reviewer pass — silent rotation would brick recovery
//     for every existing user.
//   * The 32-byte HKDF output is fed straight into `SigningKey::from_bytes`,
//     which interprets it as the Ed25519 secret scalar seed per RFC 8032 §5.1.5.
//   * No plaintext, password, or key material is ever embedded in an error
//     (rule: no-plaintext-logging).

use bip39::Mnemonic;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain-separation label for HKDF-Expand.  Versioned (`v1`) so a future
/// rotation to a different ciphersuite (e.g. PQ-hybrid) can mint a `v2` label
/// without colliding with the current derivation.  Changing this constant
/// breaks recovery for every existing user; gate any change behind crypto-reviewer.
pub const SIGNING_KEY_DOMAIN: &[u8] = b"powehi-mls-signing-v1";

/// Errors surfaced by the recovery module.
///
/// Variants are coarse and content-free: no plaintext, mnemonic words, or key
/// material is ever embedded in an error (rule: no-plaintext-logging).
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// CSPRNG failed to provide entropy.
    #[error("entropy failure")]
    Entropy,
    /// BIP-39 mnemonic construction failed (should be unreachable given 256-bit entropy).
    #[error("mnemonic generation failed")]
    Mnemonic,
    /// The supplied phrase is not a valid BIP-39 mnemonic (wrong length, bad
    /// checksum, or unknown word).
    #[error("invalid recovery phrase")]
    InvalidPhrase,
    /// HKDF expansion failed (only possible if OKM length is malformed; with a
    /// fixed 32-byte output and SHA-256 this is unreachable in practice).
    #[error("key derivation failed")]
    Hkdf,
}

/// Generate a fresh 24-word BIP-39 recovery phrase from 256-bit CSPRNG entropy.
///
/// The 32-byte entropy buffer is wrapped in `Zeroizing` so it is wiped on drop;
/// the resulting `Mnemonic` carries its own internal entropy representation,
/// which the caller is expected to surface to the user exactly once and then drop.
pub fn generate_mnemonic() -> Result<Mnemonic, RecoveryError> {
    let mut entropy = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(entropy.as_mut()).map_err(|_| RecoveryError::Entropy)?;
    Mnemonic::from_entropy(&*entropy).map_err(|_| RecoveryError::Mnemonic)
}

/// Parse and validate a BIP-39 phrase (normalized — handles whitespace + case).
///
/// Returns `RecoveryError::InvalidPhrase` for any malformed input.  The caller
/// is responsible for zeroizing the input `&str` if it came from a user-input
/// buffer.  Per BIP-39, the checksum verification rejects single-word typos
/// with overwhelming probability.
pub fn parse_phrase(phrase: &str) -> Result<Mnemonic, RecoveryError> {
    Mnemonic::parse_normalized(phrase).map_err(|_| RecoveryError::InvalidPhrase)
}

/// BIP-39 PBKDF2-HMAC-SHA512 seed derivation with an empty passphrase
/// (standard BIP-39 mode — no second factor on top of the mnemonic).
///
/// **Threat-model decision (prd.md §8.5):** the 24-word mnemonic is the sole
/// recovery secret.  An empty BIP-39 passphrase is used by design; the 256-bit
/// entropy of a CSPRNG-generated mnemonic makes brute-force infeasible.
///
/// **Stack-residue caveat (WASM linear memory):** `bip39::Mnemonic::to_seed`
/// writes a raw `[u8; 64]` onto the stack before we copy it here.  That
/// intermediate buffer is not automatically zeroed.  This is consistent with
/// the documented WASM linear-memory caveat for `mls_clear_session` (see
/// `wasm_exports.rs`).  The output of this function IS wrapped in `Zeroizing`
/// and wiped on drop.
///
/// Returns a `Zeroizing<[u8; 64]>` so the 64-byte seed is wiped on drop.
pub fn mnemonic_to_seed(mnemonic: &Mnemonic) -> Zeroizing<[u8; 64]> {
    let seed = mnemonic.to_seed("");
    let mut result = Zeroizing::new([0u8; 64]);
    result.copy_from_slice(&seed);
    result
}

/// Derive an Ed25519 signing keypair from the BIP-39 seed using HKDF-SHA256
/// (RFC 5869) with domain label [`SIGNING_KEY_DOMAIN`] and no salt.
///
/// HKDF-Extract is implicit (the seed is high-entropy already; using `None` for
/// the salt is the RFC 5869 recommendation when the IKM is already a
/// cryptographically uniform value).  HKDF-Expand then produces 32 bytes of
/// output keying material; those 32 bytes become the Ed25519 secret scalar seed
/// per RFC 8032 §5.1.5 (the algorithm clamps internally).
///
/// Returns `(private_key_bytes_32, public_key_bytes_32)`.  The private bytes are
/// wrapped in `Zeroizing` so the heap buffer is wiped on drop; the public bytes
/// are not secret.
pub fn derive_signing_keypair(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RecoveryError> {
    let hkdf = Hkdf::<Sha256>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(SIGNING_KEY_DOMAIN, okm.as_mut())
        .map_err(|_| RecoveryError::Hkdf)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&okm);
    let public_bytes = signing_key.verifying_key().to_bytes();
    Ok((okm, public_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP-39 24-word mnemonic length is fixed by the 256-bit entropy choice.
    #[test]
    fn mnemonic_has_24_words() {
        let m = generate_mnemonic().unwrap();
        assert_eq!(m.words().count(), 24);
    }

    /// A freshly generated mnemonic round-trips through `parse_phrase` exactly.
    #[test]
    fn parse_roundtrip() {
        let m = generate_mnemonic().unwrap();
        let phrase = m.to_string();
        let m2 = parse_phrase(&phrase).unwrap();
        assert_eq!(m.to_string(), m2.to_string());
    }

    /// A non-BIP-39 string is rejected.  Construction must be fail-closed —
    /// silent acceptance would let a user enter a bad phrase and quietly derive
    /// a different (wrong) identity.
    #[test]
    fn invalid_phrase_rejected() {
        assert!(parse_phrase("invalid phrase that is not bip39").is_err());
    }

    /// Deterministic derivation: the same seed must always yield the same
    /// (private, public) pair — this is the recovery invariant.
    #[test]
    fn derive_signing_keypair_deterministic() {
        let m = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&m);
        let (priv1, pub1) = derive_signing_keypair(&*seed).unwrap();
        let (priv2, pub2) = derive_signing_keypair(&*seed).unwrap();
        assert_eq!(*priv1, *priv2);
        assert_eq!(pub1, pub2);
    }

    /// Different phrases (overwhelmingly) yield different keys — this is the
    /// non-collision invariant.
    #[test]
    fn different_phrases_give_different_keys() {
        let m1 = generate_mnemonic().unwrap();
        let m2 = generate_mnemonic().unwrap();
        let seed1 = mnemonic_to_seed(&m1);
        let seed2 = mnemonic_to_seed(&m2);
        let (_, pub1) = derive_signing_keypair(&*seed1).unwrap();
        let (_, pub2) = derive_signing_keypair(&*seed2).unwrap();
        assert_ne!(pub1, pub2);
    }

    /// HKDF domain separation: the derived 32-byte secret must differ from a
    /// raw slice of the seed.  This guards against an accidental
    /// "just take the first 32 bytes of the seed" regression.
    #[test]
    fn private_key_not_equal_to_seed_bytes() {
        let seed = [0u8; 64];
        let (priv_key, _) = derive_signing_keypair(&seed).unwrap();
        assert_ne!(
            *priv_key, [0u8; 32],
            "HKDF output must differ from zero seed"
        );
    }

    /// End-to-end chain: mnemonic → seed → signing keypair, and verify the
    /// Ed25519 pair is internally consistent (`verifying_key()` of the derived
    /// `SigningKey` equals the public bytes returned by the helper).
    #[test]
    fn seed_to_keypair_and_back() {
        let m = generate_mnemonic().unwrap();
        let seed = mnemonic_to_seed(&m);
        let (priv_key, pub_key) = derive_signing_keypair(&*seed).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&priv_key);
        assert_eq!(signing_key.verifying_key().to_bytes(), pub_key);
    }

    /// Capture helper — prints byte arrays needed to populate the KAT constants.
    /// Run with: cargo test -p powehi-crypto-wasm --lib recovery::tests::kat_capture -- --ignored --nocapture
    #[test]
    #[ignore = "capture helper: run once to obtain KAT constants, then ignore"]
    fn kat_capture() {
        let seed_zero = [0u8; 64];
        let (priv_zero, pub_zero) = derive_signing_keypair(&seed_zero).unwrap();
        println!("ZERO SEED priv: {:?}", *priv_zero);
        println!("ZERO SEED pub:  {:?}", pub_zero);

        let abandon_phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(abandon_phrase).unwrap();
        let seed_abandon = mnemonic_to_seed(&m);
        let (priv_ab, pub_ab) = derive_signing_keypair(&*seed_abandon).unwrap();
        println!("ABANDON SEED priv: {:?}", *priv_ab);
        println!("ABANDON SEED pub:  {:?}", pub_ab);
    }

    /// Known-answer test: lock the derivation construction so any silent
    /// change to the domain label, HKDF parameters, or seed treatment is
    /// detected immediately.
    ///
    /// Two test vectors:
    /// 1. All-zero 64-byte seed (pure HKDF smoke-test, no BIP-39 involved).
    /// 2. BIP-39 standard `abandon × 11 + about` phrase (exercises the full
    ///    mnemonic → PBKDF2 → HKDF → Ed25519 chain).
    ///
    /// Constants were captured by running `kat_capture` once against the
    /// initial correct implementation (HKDF-SHA256, salt=None,
    /// info=b"powehi-mls-signing-v1", L=32).  Changing them requires a
    /// crypto-reviewer pass (rule: crypto-libraries-pinned.md).
    #[test]
    fn derive_signing_keypair_known_answer() {
        // --- Vector 1: all-zero 64-byte seed ---
        // Captured: HKDF-SHA256(salt=None, ikm=[0u8;64], info=b"powehi-mls-signing-v1", L=32)
        // then Ed25519 public key derived by ed25519-dalek 2.2.0.
        const KAT_ZERO_PRIV: [u8; 32] = [
            105, 31, 108, 190, 159, 70, 198, 179, 155, 56, 16, 112, 61, 14, 115, 113, 171, 178,
            233, 34, 200, 106, 42, 12, 98, 112, 47, 178, 9, 21, 131, 240,
        ];
        const KAT_ZERO_PUB: [u8; 32] = [
            93, 91, 179, 227, 90, 63, 147, 149, 3, 200, 171, 194, 73, 40, 23, 163, 240, 157, 173,
            10, 44, 197, 83, 7, 184, 65, 2, 155, 129, 176, 33, 44,
        ];

        let seed_zero = [0u8; 64];
        let (priv_key, pub_key) = derive_signing_keypair(&seed_zero).unwrap();
        assert_eq!(
            *priv_key, KAT_ZERO_PRIV,
            "HKDF output drifted from KAT (zero seed)"
        );
        assert_eq!(
            pub_key, KAT_ZERO_PUB,
            "Ed25519 public key drifted from KAT (zero seed)"
        );

        // --- Vector 2: BIP-39 `abandon × 11 + about` phrase ---
        // Captured: BIP-39 PBKDF2("mnemonic", abandon×11+about, 2048) → 64-byte seed
        // → HKDF-SHA256(salt=None, info=b"powehi-mls-signing-v1", L=32)
        // → Ed25519 public key via ed25519-dalek 2.2.0.
        const KAT_ABANDON_PUB: [u8; 32] = [
            0, 32, 185, 202, 233, 49, 30, 20, 154, 213, 141, 105, 212, 16, 57, 156, 114, 133, 155,
            185, 177, 121, 141, 129, 43, 12, 161, 36, 24, 99, 15, 135,
        ];
        let abandon_phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(abandon_phrase).unwrap();
        let seed_ab = mnemonic_to_seed(&m);
        let (_, pub_ab) = derive_signing_keypair(&*seed_ab).unwrap();
        assert_eq!(
            pub_ab, KAT_ABANDON_PUB,
            "Ed25519 public key drifted from KAT (abandon phrase)"
        );
    }
}
