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

/// Domain-separation label for HKDF-Expand deriving the RECOVERY-AUTHENTICATION
/// Ed25519 keypair (§8.5).
///
/// DISTINCT from [`SIGNING_KEY_DOMAIN`] (which derives the MLS identity signing
/// key) and from [`RECOVERY_CHALLENGE_DOMAIN`] (which frames the signed MESSAGE,
/// not a key).  This label derives a SEPARATE, independent Ed25519 keypair whose
/// public half is what the client ships to the server as `recovery_pubkey` and
/// stores in `users.recovery_pubkey`.
///
/// SECURITY RATIONALE (threat-model-checker finding, cycle 303): the recovery
/// public key is durably stored server-side keyed to the `user_id`.  It MUST NOT
/// be the MLS identity (LeafNode/credential) signing public key — prd.md §3.3
/// lists the MLS LeafNode 서명 키 among "서버가 알지 못하는 것", and §5.4 documents
/// that the server never learns the MLS signing key.  Deriving `recovery_pubkey`
/// under this distinct domain keeps the server-stored authentication key
/// cryptographically independent of (and unlinkable to) the MLS identity key:
/// HKDF domain separation makes the two 32-byte outputs computationally
/// unrelated even though both descend from the same BIP-39 seed.  Versioned
/// (`v1`) so a future rotation can mint a `v2` label; changing this constant
/// breaks recovery-challenge verification for every existing user, so gate any
/// change behind crypto-reviewer.
pub const RECOVERY_AUTH_KEY_DOMAIN: &[u8] = b"powehi-recovery-auth-v1";

/// Domain-separation label for the recovery login-challenge SIGNATURE (§8.5).
///
/// DISTINCT from [`SIGNING_KEY_DOMAIN`]: that label derives the Ed25519 KEY from
/// the BIP-39 seed; THIS label frames the MESSAGE that key signs when proving
/// possession of the recovery secret to the login server.  They serve different
/// purposes and MUST NOT be merged or collide.
///
/// Domain separation is mandatory here: the login server chooses the nonce
/// content, so signing the bare nonce would let a malicious/compromised server
/// obtain a signature over attacker-chosen bytes under the user's long-term
/// recovery-auth key (cross-protocol confusable-signature risk).  Prefixing a
/// fixed domain label + NUL separator binds every recovery signature to this one
/// purpose.  Versioned (`v1`) so a future rotation can mint a `v2` label.
pub const RECOVERY_CHALLENGE_DOMAIN: &[u8] = b"powehi-recovery-challenge-v1";

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

/// Derive an Ed25519 keypair from the BIP-39 seed using HKDF-SHA256 (RFC 5869)
/// under the caller-supplied `domain` label and no salt.
///
/// HKDF-Extract is implicit (the seed is high-entropy already; using `None` for
/// the salt is the RFC 5869 recommendation when the IKM is already a
/// cryptographically uniform value).  HKDF-Expand with `domain` as the `info`
/// parameter then produces 32 bytes of output keying material; those 32 bytes
/// become the Ed25519 secret scalar seed per RFC 8032 §5.1.5 (the algorithm
/// clamps internally).
///
/// The `domain` (HKDF `info`) is what makes two derivations from the SAME seed
/// cryptographically independent: distinct labels yield computationally
/// unrelated 32-byte outputs.  Callers MUST pass a versioned, purpose-specific,
/// non-prefix-colliding label — see [`SIGNING_KEY_DOMAIN`] (MLS identity signing
/// key) and [`RECOVERY_AUTH_KEY_DOMAIN`] (server-stored recovery-auth key).
///
/// Returns `(private_key_bytes_32, public_key_bytes_32)`.  The private bytes are
/// wrapped in `Zeroizing` so the heap buffer is wiped on drop; the public bytes
/// are not secret.
pub fn derive_keypair(
    seed: &[u8],
    domain: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RecoveryError> {
    let hkdf = Hkdf::<Sha256>::new(None, seed);
    let mut okm = Zeroizing::new([0u8; 32]);
    hkdf.expand(domain, okm.as_mut())
        .map_err(|_| RecoveryError::Hkdf)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&okm);
    let public_bytes = signing_key.verifying_key().to_bytes();
    Ok((okm, public_bytes))
}

/// Derive the MLS identity signing keypair from the BIP-39 seed under
/// [`SIGNING_KEY_DOMAIN`].  Thin wrapper over [`derive_keypair`]; its output is
/// KAT-locked (`derive_signing_keypair_known_answer`) and drives the MLS
/// LeafNode/credential signing key — do NOT reroute it to a different domain.
///
/// Returns `(private_key_bytes_32, public_key_bytes_32)`.
pub fn derive_signing_keypair(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RecoveryError> {
    derive_keypair(seed, SIGNING_KEY_DOMAIN)
}

/// Derive the RECOVERY-AUTHENTICATION keypair from the BIP-39 seed under
/// [`RECOVERY_AUTH_KEY_DOMAIN`].  Thin wrapper over [`derive_keypair`].
///
/// This keypair is COMPLETELY DECOUPLED from the MLS identity signing key
/// ([`derive_signing_keypair`]): its public half is the value shipped to and
/// durably stored by the server as `recovery_pubkey`, and its private half signs
/// the recovery login challenge.  Keeping it under a distinct HKDF domain ensures
/// the server-stored key is cryptographically independent of the MLS identity
/// signing key that §3.3/§5.4 say the server must never learn.
///
/// Returns `(private_key_bytes_32, public_key_bytes_32)`.
pub fn derive_recovery_auth_keypair(
    seed: &[u8],
) -> Result<(Zeroizing<[u8; 32]>, [u8; 32]), RecoveryError> {
    derive_keypair(seed, RECOVERY_AUTH_KEY_DOMAIN)
}

/// Build the message the recovery client signs to prove possession of the
/// phrase-derived recovery-auth key (see [`derive_recovery_auth_keypair`]) to
/// the login server (§8.5).  The signing key is the recovery-auth key, NOT the
/// MLS identity signing key.
///
/// Format: `RECOVERY_CHALLENGE_DOMAIN || 0x00 || login_nonce`
///
/// Mirrors `kem_credential::signing_message`'s exact byte layout: fixed domain
/// label, a single 0x00 NUL separator, then the data.  The NUL separator
/// prevents the domain prefix from extending into the nonce bytes.
///
/// **Wire contract (load-bearing for the INDEPENDENT backend verifier, which
/// reconstructs this layout WITHOUT importing this crate):** the signed message
/// is `b"powehi-recovery-challenge-v1" || 0x00 || login_nonce_utf8_bytes`, where
/// `login_nonce` is passed here already as the UTF-8 bytes of the server's
/// `login_nonce` STRING (a UUID-formatted string) — i.e. the JS caller does
/// `new TextEncoder().encode(login_nonce_string)`.  These are the UTF-8 bytes of
/// the string, NOT raw/hex-decoded UUID bytes.
pub fn recovery_challenge_message(login_nonce: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(RECOVERY_CHALLENGE_DOMAIN.len() + 1 + login_nonce.len());
    msg.extend_from_slice(RECOVERY_CHALLENGE_DOMAIN);
    msg.push(0x00);
    msg.extend_from_slice(login_nonce);
    msg
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

        // Recovery-auth domain (RECOVERY_AUTH_KEY_DOMAIN) KAT capture.
        let (ra_priv_zero, ra_pub_zero) = derive_recovery_auth_keypair(&seed_zero).unwrap();
        println!("RA ZERO SEED priv: {:?}", *ra_priv_zero);
        println!("RA ZERO SEED pub:  {:?}", ra_pub_zero);
        let (_ra_priv_ab, ra_pub_ab) = derive_recovery_auth_keypair(&*seed_abandon).unwrap();
        println!("RA ABANDON SEED pub:  {:?}", ra_pub_ab);
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

    /// Known-answer test for [`derive_recovery_auth_keypair`] — the sibling of
    /// `derive_signing_keypair_known_answer` above, at the same bar.  The
    /// `RECOVERY_AUTH_KEY_DOMAIN` doc explicitly states that "changing this
    /// constant breaks recovery-challenge verification for every existing
    /// user"; without a KAT pinning the derivation, a silent drift in the
    /// domain label or HKDF parameters would brick every enrolled user's
    /// restore path while still passing CI. Changing these constants requires
    /// a crypto-reviewer pass (rule: crypto-libraries-pinned.md).
    ///
    /// Constants captured by running `kat_capture` (see above) against the
    /// initial correct implementation (HKDF-SHA256, salt=None,
    /// info=b"powehi-recovery-auth-v1", L=32).
    #[test]
    fn derive_recovery_auth_keypair_known_answer() {
        // --- Vector 1: all-zero 64-byte seed ---
        const KAT_RA_ZERO_PRIV: [u8; 32] = [
            65, 84, 23, 151, 76, 213, 223, 115, 128, 67, 114, 187, 76, 13, 27, 161, 19, 165, 211,
            188, 102, 143, 34, 19, 138, 36, 153, 197, 66, 50, 229, 206,
        ];
        const KAT_RA_ZERO_PUB: [u8; 32] = [
            16, 212, 49, 229, 217, 173, 10, 171, 226, 58, 201, 64, 227, 211, 248, 254, 16, 70, 245,
            81, 204, 59, 84, 98, 0, 22, 29, 214, 206, 255, 9, 203,
        ];

        let seed_zero = [0u8; 64];
        let (priv_key, pub_key) = derive_recovery_auth_keypair(&seed_zero).unwrap();
        assert_eq!(
            *priv_key, KAT_RA_ZERO_PRIV,
            "recovery-auth HKDF output drifted from KAT (zero seed)"
        );
        assert_eq!(
            pub_key, KAT_RA_ZERO_PUB,
            "recovery-auth Ed25519 public key drifted from KAT (zero seed)"
        );

        // --- Vector 2: BIP-39 `abandon × 11 + about` phrase ---
        const KAT_RA_ABANDON_PUB: [u8; 32] = [
            174, 246, 110, 76, 55, 80, 246, 158, 94, 124, 53, 39, 43, 16, 96, 39, 188, 98, 182,
            189, 1, 150, 177, 189, 53, 53, 36, 209, 210, 102, 242, 118,
        ];
        let abandon_phrase =
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(abandon_phrase).unwrap();
        let seed_ab = mnemonic_to_seed(&m);
        let (_, pub_ab) = derive_recovery_auth_keypair(&*seed_ab).unwrap();
        assert_eq!(
            pub_ab, KAT_RA_ABANDON_PUB,
            "recovery-auth Ed25519 public key drifted from KAT (abandon phrase)"
        );
    }

    // ── §8.5 recovery login-challenge signature ───────────────────────────────

    /// The signed-message construction is deterministic and matches the exact
    /// documented wire layout: DOMAIN || 0x00 || nonce.
    #[test]
    fn recovery_challenge_message_layout() {
        let nonce = b"nonce-mock-0001";
        let msg = recovery_challenge_message(nonce);
        let mut expected = Vec::new();
        expected.extend_from_slice(RECOVERY_CHALLENGE_DOMAIN);
        expected.push(0x00);
        expected.extend_from_slice(nonce);
        assert_eq!(msg, expected);
        assert_eq!(
            &msg[..RECOVERY_CHALLENGE_DOMAIN.len()],
            RECOVERY_CHALLENGE_DOMAIN
        );
        assert_eq!(msg[RECOVERY_CHALLENGE_DOMAIN.len()], 0x00);
        assert_eq!(&msg[RECOVERY_CHALLENGE_DOMAIN.len() + 1..], nonce);
    }

    /// The domain labels must not collide or alias.  `RECOVERY_CHALLENGE_DOMAIN`
    /// frames the signed MESSAGE; `SIGNING_KEY_DOMAIN` frames the KEY derivation.
    /// It must also be non-aliasing with `kem_credential::SIGN_DOMAIN` (the other
    /// message-framing label the SAME Ed25519 key signs under) — neither equal nor
    /// a prefix of the other — so no server-chosen nonce can yield a recovery
    /// message confusable with a signed kem-ek credential message.
    #[test]
    fn recovery_and_signing_domains_are_distinct() {
        use crate::kem_credential::SIGN_DOMAIN;
        assert_ne!(RECOVERY_CHALLENGE_DOMAIN, SIGNING_KEY_DOMAIN);
        assert_ne!(RECOVERY_CHALLENGE_DOMAIN, SIGN_DOMAIN);
        assert!(
            !RECOVERY_CHALLENGE_DOMAIN.starts_with(SIGN_DOMAIN),
            "recovery label must not have the kem-ek label as a prefix"
        );
        assert!(
            !SIGN_DOMAIN.starts_with(RECOVERY_CHALLENGE_DOMAIN),
            "kem-ek label must not have the recovery label as a prefix"
        );
    }

    /// The RECOVERY-AUTH keypair MUST be cryptographically independent of the MLS
    /// identity signing keypair, even though both descend from the same BIP-39
    /// seed — this is the entire point of [`RECOVERY_AUTH_KEY_DOMAIN`] being a
    /// distinct HKDF `info` label from [`SIGNING_KEY_DOMAIN`] (threat-model-checker
    /// finding, cycle 303: the server durably stores `recovery_pubkey`, and it must
    /// not be linkable to / substitutable for the MLS signing key the server is
    /// never supposed to learn).
    #[test]
    fn recovery_auth_keypair_differs_from_mls_signing_keypair() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(phrase).unwrap();
        let seed = mnemonic_to_seed(&m);
        let (mls_priv, mls_pub) = derive_signing_keypair(&*seed).unwrap();
        let (ra_priv, ra_pub) = derive_recovery_auth_keypair(&*seed).unwrap();
        assert_ne!(
            *mls_priv, *ra_priv,
            "recovery-auth private key must differ from the MLS identity signing private key"
        );
        assert_ne!(
            mls_pub, ra_pub,
            "recovery-auth public key (the value stored server-side) must differ from the \
             MLS identity signing public key"
        );
    }

    /// Sign/verify round-trip: sign the challenge message with the phrase-derived
    /// RECOVERY-AUTH private key (`derive_recovery_auth_keypair`, NOT the MLS
    /// identity signing key — see [`RECOVERY_AUTH_KEY_DOMAIN`]), verify with the
    /// derived public key.
    #[test]
    fn recovery_challenge_sign_verify_round_trip() {
        use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(phrase).unwrap();
        let seed = mnemonic_to_seed(&m);
        let (priv_key, pub_key) = derive_recovery_auth_keypair(&*seed).unwrap();
        let signing_key = SigningKey::from_bytes(&priv_key);
        let nonce = b"550e8400-e29b-41d4-a716-446655440000";
        let msg = recovery_challenge_message(nonce);
        let sig: Signature = signing_key.sign(&msg);
        let vk = VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(
            vk.verify_strict(&msg, &sig).is_ok(),
            "valid recovery signature must verify (strict)"
        );
        assert!(
            vk.verify(&msg, &sig).is_ok(),
            "valid recovery signature must verify"
        );
    }

    /// Flipping one byte of the nonce invalidates the signature.
    #[test]
    fn recovery_challenge_nonce_tamper_rejected() {
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(phrase).unwrap();
        let seed = mnemonic_to_seed(&m);
        let (priv_key, pub_key) = derive_recovery_auth_keypair(&*seed).unwrap();
        let signing_key = SigningKey::from_bytes(&priv_key);
        let nonce = b"nonce-mock-0001".to_vec();
        let sig = signing_key.sign(&recovery_challenge_message(&nonce));
        let mut tampered = nonce.clone();
        tampered[0] ^= 0x01;
        let vk = VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(
            vk.verify(&recovery_challenge_message(&tampered), &sig)
                .is_err(),
            "signature over a one-byte-different nonce must be rejected"
        );
    }

    /// Domain separation actually changes the signed bytes: a signature over the
    /// domain-separated message must NOT verify against the BARE nonce.
    #[test]
    fn recovery_challenge_domain_separation_changes_signed_bytes() {
        use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let m = parse_phrase(phrase).unwrap();
        let seed = mnemonic_to_seed(&m);
        let (priv_key, pub_key) = derive_recovery_auth_keypair(&*seed).unwrap();
        let signing_key = SigningKey::from_bytes(&priv_key);
        let nonce = b"nonce-mock-0001";
        let sig = signing_key.sign(&recovery_challenge_message(nonce));
        let vk = VerifyingKey::from_bytes(&pub_key).unwrap();
        assert!(
            vk.verify(nonce, &sig).is_err(),
            "domain-separated signature must not verify against the bare nonce"
        );
    }
}
