// ML-KEM-768 (FIPS 203) key encapsulation primitives.
//
// These are standalone KEM operations, independent of MLS or OPAQUE.
// They serve as the building blocks for ADR-0003 Phase A: post-quantum hybrid
// key exchange once openmls adds an ML-KEM ciphersuite.
//
// Key sizes (ML-KEM-768 / FIPS 203 §2.4):
//   Encapsulation key: 1184 bytes
//   Decapsulation key: 2400 bytes
//   Ciphertext:        1088 bytes
//   Shared secret:       32 bytes
//
// Security invariants:
// - Shared secrets are always returned as Zeroizing<Vec<u8>> — the heap buffer
//   is zeroed before deallocation, preventing key material residue in linear
//   memory. (Same transient-stack residue caveat as OPAQUE sessions applies.)
// - This module ONLY calls ml-kem (approved RustCrypto crate). No homegrown
//   crypto (rule: crypto-libraries-pinned).

use ml_kem::kem::{self, Decapsulate, Encapsulate};
use ml_kem::{Ciphertext, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use opaque_ke::rand::rngs::OsRng;
use zeroize::Zeroizing;

// Concrete key types for ML-KEM-768.
type Dk768 = kem::DecapsulationKey<MlKem768Params>;
type Ek768 = kem::EncapsulationKey<MlKem768Params>;

/// ML-KEM-768 encapsulation key size (bytes, FIPS 203 §2.4).
pub const EK_SIZE: usize = 1184;
/// ML-KEM-768 decapsulation key size (bytes, FIPS 203 §2.4).
pub const DK_SIZE: usize = 2400;
/// ML-KEM-768 ciphertext size (bytes, FIPS 203 §2.4).
pub const CT_SIZE: usize = 1088;
/// ML-KEM-768 shared secret size (bytes, FIPS 203 §2.4).
pub const SS_SIZE: usize = 32;

/// A freshly generated ML-KEM-768 keypair.
pub struct MlKem768KeyPair {
    /// Encapsulation key — 1184 bytes — distribute to the peer who encapsulates.
    pub encap_key: Vec<u8>,
    /// Decapsulation key — 2400 bytes — keep secret.
    /// Wrapped in Zeroizing so the heap buffer is wiped on drop.
    pub decap_key: Zeroizing<Vec<u8>>,
}

/// Generate a fresh ML-KEM-768 keypair from the OS CSPRNG.
pub fn generate() -> MlKem768KeyPair {
    let mut rng = OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);
    // EncodedSizeUser::as_bytes() returns Encoded<Self> = Array<u8, N> by value.
    // Bind to a local so the coercion target (&[u8]) is unambiguous.
    // Zeroizing wraps the decap heap copy; the transient stack Array during
    // .to_vec() shares the WASM linear-memory residue caveat documented in
    // wasm_exports.rs for OPAQUE session material.
    let ek_arr = ek.as_bytes();
    let dk_arr = dk.as_bytes();
    MlKem768KeyPair {
        encap_key: (ek_arr.as_ref() as &[u8]).to_vec(),
        decap_key: Zeroizing::new((dk_arr.as_ref() as &[u8]).to_vec()),
    }
}

/// Encapsulate: produce a (ciphertext, shared_secret) for the given encapsulation key.
///
/// Returns:
/// - `ciphertext` (1088 bytes) — send to the holder of the decapsulation key.
/// - `shared_secret` (32 bytes) — the locally derived shared key, wrapped in Zeroizing.
///
/// Errors if `ek_bytes` is not exactly EK_SIZE bytes.
/// Note: ml-kem 0.2.x does NOT perform the FIPS 203 §7.2 coefficient modulus check on the
/// encapsulation key — passing a malformed (non-reduced) key does not produce an error; it
/// produces a silently divergent shared secret. Callers who receive encap keys over an
/// untrusted channel should authenticate them before use (e.g. via a signature).
pub fn encapsulate(ek_bytes: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), &'static str> {
    let ek_encoded: ml_kem::Encoded<Ek768> = ek_bytes
        .try_into()
        .map_err(|_| "invalid encap key: expected 1184 bytes")?;
    let ek = Ek768::from_bytes(&ek_encoded);
    let mut rng = OsRng;
    let (ct, ss) = ek
        .encapsulate(&mut rng)
        .map_err(|_| "encapsulation failed")?;
    // Ciphertext<MlKem768> = Array<u8, CiphertextSize> — not sensitive.
    // SharedKey<MlKem768> = Array<u8, SharedKeySize> — sensitive; Zeroizing.
    Ok((
        (ct.as_ref() as &[u8]).to_vec(),
        Zeroizing::new((ss.as_ref() as &[u8]).to_vec()),
    ))
}

/// Decapsulate: recover the shared secret from a ciphertext using the decapsulation key.
///
/// Returns the 32-byte shared secret, wrapped in Zeroizing.
///
/// Errors if `dk_bytes` is not exactly DK_SIZE bytes, `ct_bytes` is not exactly CT_SIZE
/// bytes, or the decapsulation operation fails.
///
/// Note: ML-KEM uses implicit rejection (FIPS 203 §6.3.3) — a ciphertext encrypted
/// under a different key still decapsulates successfully, but returns a pseudorandom
/// value unrelated to the original shared secret. Callers must not rely on a decap
/// error as proof of tampering.
pub fn decapsulate(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let dk_encoded: ml_kem::Encoded<Dk768> = dk_bytes
        .try_into()
        .map_err(|_| "invalid decap key: expected 2400 bytes")?;
    let dk = Dk768::from_bytes(&dk_encoded);

    // Ciphertext<MlKem768> = Array<u8, MlKem768::CiphertextSize>.
    let ct: Ciphertext<MlKem768> = ct_bytes
        .try_into()
        .map_err(|_| "invalid ciphertext: expected 1088 bytes")?;

    let ss = dk.decapsulate(&ct).map_err(|_| "decapsulation failed")?;
    Ok(Zeroizing::new((ss.as_ref() as &[u8]).to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Key sizes ────────────────────────────────────────────────────────────────

    /// FIPS 203 §2.4 ML-KEM-768 key sizes.
    #[test]
    fn ml_kem_768_key_sizes_are_correct() {
        let pair = generate();
        assert_eq!(
            pair.encap_key.len(),
            EK_SIZE,
            "encap key must be {EK_SIZE} bytes"
        );
        assert_eq!(
            pair.decap_key.len(),
            DK_SIZE,
            "decap key must be {DK_SIZE} bytes"
        );
    }

    // ── Round-trip correctness ────────────────────────────────────────────────────

    /// Encap+decap produce the same shared secret.
    #[test]
    fn ml_kem_768_shared_secret_round_trip() {
        let pair = generate();
        let (ct, ss_enc) = encapsulate(&pair.encap_key).expect("encap must succeed");
        assert_eq!(ct.len(), CT_SIZE, "ciphertext must be {CT_SIZE} bytes");
        assert_eq!(
            ss_enc.len(),
            SS_SIZE,
            "encap shared secret must be {SS_SIZE} bytes"
        );

        let ss_dec = decapsulate(&pair.decap_key, &ct).expect("decap must succeed");
        assert_eq!(ss_dec.len(), SS_SIZE);
        assert_eq!(
            ss_enc.as_slice(),
            ss_dec.as_slice(),
            "encap and decap shared secrets must match"
        );
    }

    /// Different keypairs yield different shared secrets for independent encapsulations.
    #[test]
    fn ml_kem_768_different_keypairs_yield_different_secrets() {
        let pair_a = generate();
        let pair_b = generate();
        let (ct_a, ss_a) = encapsulate(&pair_a.encap_key).unwrap();
        let (ct_b, ss_b) = encapsulate(&pair_b.encap_key).unwrap();
        assert_ne!(ss_a.as_slice(), ss_b.as_slice());
        assert_ne!(ct_a, ct_b);
    }

    /// Each encapsulation call under the same key yields a distinct ciphertext and secret
    /// (randomised encapsulation — FIPS 203 §6.2).
    #[test]
    fn ml_kem_768_encapsulation_is_randomised() {
        let pair = generate();
        let (ct1, ss1) = encapsulate(&pair.encap_key).unwrap();
        let (ct2, ss2) = encapsulate(&pair.encap_key).unwrap();
        assert_ne!(ct1, ct2, "two encap calls must yield different ciphertexts");
        assert_ne!(
            ss1.as_slice(),
            ss2.as_slice(),
            "two encap calls must yield different shared secrets"
        );
    }

    // ── Implicit rejection (FIPS 203 §6.3.3) ─────────────────────────────────────

    /// Decapsulating with the wrong key produces a different secret (implicit rejection).
    #[test]
    fn ml_kem_768_wrong_decap_key_yields_different_secret() {
        let pair_a = generate();
        let pair_b = generate();
        let (ct, ss_correct) = encapsulate(&pair_a.encap_key).unwrap();
        // ML-KEM implicit rejection: wrong-key decap succeeds but returns
        // a pseudorandom value unrelated to the original shared secret.
        let ss_wrong = decapsulate(&pair_b.decap_key, &ct).unwrap();
        assert_ne!(
            ss_correct.as_slice(),
            ss_wrong.as_slice(),
            "wrong decap key must not produce the correct shared secret"
        );
    }

    // ── Input validation ─────────────────────────────────────────────────────────

    /// Too-short encap key is rejected.
    #[test]
    fn ml_kem_768_encap_rejects_short_key() {
        let short = vec![0u8; EK_SIZE - 1];
        assert!(encapsulate(&short).is_err(), "short encap key must error");
    }

    /// Too-short decap key is rejected.
    #[test]
    fn ml_kem_768_decap_rejects_short_dk() {
        let pair = generate();
        let (ct, _) = encapsulate(&pair.encap_key).unwrap();
        let short_dk = vec![0u8; DK_SIZE - 1];
        assert!(
            decapsulate(&short_dk, &ct).is_err(),
            "short decap key must error"
        );
    }

    /// Too-short ciphertext is rejected.
    #[test]
    fn ml_kem_768_decap_rejects_short_ciphertext() {
        let pair = generate();
        let short_ct = vec![0u8; CT_SIZE - 1];
        assert!(
            decapsulate(&pair.decap_key, &short_ct).is_err(),
            "short ciphertext must error"
        );
    }

    // ── FIPS 203 §6.3.3 implicit rejection (tampered ciphertext) ─────────────────

    /// Decapsulating a tampered ciphertext produces a deterministic pseudorandom value
    /// unrelated to the original shared secret (FIPS 203 §6.3.3 implicit rejection).
    ///
    /// This test uses a *tampered ciphertext* (not just a wrong key) because the spec's
    /// implicit-rejection guarantee specifically covers ciphertext manipulation — an
    /// adversary who flips a byte must not learn anything about the original secret.
    #[test]
    fn ml_kem_768_tampered_ciphertext_yields_pseudorandom_and_differs_from_original() {
        let pair = generate();
        let (ct, ss_original) = encapsulate(&pair.encap_key).expect("encap must succeed");

        // Tamper the ciphertext at the first byte (u-component start).
        let mut ct_head = ct.clone();
        ct_head[0] ^= 0x01;

        let ss_head = decapsulate(&pair.decap_key, &ct_head).expect("decap must succeed");
        assert_ne!(
            ss_original.as_slice(),
            ss_head.as_slice(),
            "head-byte tamper must produce a different (pseudorandom) shared secret"
        );
        // Determinism: same tampered ciphertext + same dk → same pseudorandom output.
        let ss_head2 = decapsulate(&pair.decap_key, &ct_head).expect("decap must succeed");
        assert_eq!(
            ss_head.as_slice(),
            ss_head2.as_slice(),
            "implicit rejection must be deterministic: same tampered CT always gives same pseudorandom secret"
        );

        // Also tamper a byte in the v-component (near the tail) to cover the re-encryption
        // check that K-PKE performs against both u and v components (FIPS 203 §6.3).
        let mut ct_tail = ct.clone();
        ct_tail[CT_SIZE - 1] ^= 0x80;

        let ss_tail = decapsulate(&pair.decap_key, &ct_tail).expect("decap must succeed");
        assert_ne!(
            ss_original.as_slice(),
            ss_tail.as_slice(),
            "tail-byte tamper must produce a different (pseudorandom) shared secret"
        );
        // The two tamper positions yield distinct pseudorandom outputs (different H(z, ct)).
        assert_ne!(
            ss_head.as_slice(),
            ss_tail.as_slice(),
            "head and tail tampers must yield distinct pseudorandom secrets"
        );
    }

    // ── IND-CCA2 one-way property (independent encapsulations) ───────────────────

    /// Demonstrates that two encapsulations under the same public key produce
    /// independent (ciphertext, shared_secret) pairs.
    ///
    /// This exercises the IND-CCA2 one-way property of ML-KEM-768: each encapsulation
    /// draws fresh randomness, so the two secrets are computationally independent.
    /// Note: ML-KEM itself does NOT provide forward secrecy — possession of dk lets an
    /// adversary decapsulate all past ciphertexts. Forward secrecy in ADR-0003 Phase B
    /// will come from the X25519 ephemeral component of the hybrid handshake, not from
    /// ML-KEM alone.
    #[test]
    fn ml_kem_768_independent_encaps_yield_independent_secrets() {
        let pair = generate();

        // Two independent encapsulations under the SAME public key.
        let (ct1, ss1) = encapsulate(&pair.encap_key).expect("first encap must succeed");
        let (ct2, ss2) = encapsulate(&pair.encap_key).expect("second encap must succeed");

        // Each call generates fresh randomness → distinct ciphertext and distinct secret.
        assert_ne!(
            ct1, ct2,
            "two encap calls under same ek must produce different ciphertexts"
        );
        assert_ne!(
            ss1.as_slice(),
            ss2.as_slice(),
            "two encap calls under same ek must produce different shared secrets"
        );

        // A party holding only ek cannot distinguish ss1 from ss2 without dk:
        // decap(dk, ct1) == ss1 and decap(dk, ct2) == ss2 are verified, but a party
        // who discards dk after encapsulation cannot call decap at all.
        let recovered1 = decapsulate(&pair.decap_key, &ct1).expect("decap ct1 must succeed");
        let recovered2 = decapsulate(&pair.decap_key, &ct2).expect("decap ct2 must succeed");
        assert_eq!(
            ss1.as_slice(),
            recovered1.as_slice(),
            "decap of ct1 must recover ss1"
        );
        assert_eq!(
            ss2.as_slice(),
            recovered2.as_slice(),
            "decap of ct2 must recover ss2"
        );
        // ss1 and ss2 are independent — one cannot be derived from the other or from ek.
        assert_ne!(recovered1.as_slice(), recovered2.as_slice());
    }
}

// ── ml-kem 0.2.3 Regression KAT (supply-chain guard) ─────────────────────────
//
// Deterministic regression KAT using fixed seeds: d = 0x00..1f, z = 0x20..3f,
// m = 0x40..5f. Expected values captured from ml-kem =0.2.3.
//
// Scope (ADR-0003 Phase B, Y-5 partial close):
//   This is a self-consistency / supply-chain regression guard — it detects
//   implementation drift or crate tampering. It does NOT use official NIST ACVP
//   vectors, so it is NOT a FIPS 203 §A.3 conformance test. A true conformance
//   KAT against NIST-sourced vectors is tracked as Y-5 follow-up.
//
// Re-verify pinned values if ml-kem version changes (see Y-6 in project-context.md).
// Gated on `#[cfg(test)]`; NOT compiled into the production WASM binary.
#[cfg(test)]
mod kat_tests {
    use super::{DK_SIZE, EK_SIZE, SS_SIZE};
    use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
    use ml_kem::{
        EncapsulateDeterministic, EncodedSizeUser, KemCore, MlKem768, MlKem768Params, B32,
    };

    /// 32-byte shared secret for seeds d=0x00..1f, z=0x20..3f, m=0x40..5f.
    /// Captured from ml-kem =0.2.3. Must be re-verified if ml-kem version changes.
    const KAT_SS: [u8; SS_SIZE] = [
        0x9c, 0xdd, 0xd0, 0x89, 0xff, 0xe7, 0x0e, 0x39, 0x96, 0xe7, 0x6f, 0x7c, 0x8d, 0x06, 0x74,
        0x6d, 0xf3, 0x4d, 0x07, 0xe8, 0x65, 0x7b, 0xc0, 0xfc, 0xf2, 0xbb, 0x0e, 0x1c, 0x30, 0x84,
        0xae, 0xa1,
    ];

    /// First 16 bytes of the encapsulation key for the same seed (supply-chain guard).
    const KAT_EK_PREFIX: [u8; 16] = [
        0x29, 0x8a, 0xa1, 0x0d, 0x42, 0x3c, 0x8d, 0xda, 0x06, 0x9d, 0x02, 0xbc, 0x59, 0xe6, 0xcd,
        0xf0,
    ];

    /// Regression KAT for ml-kem =0.2.3 (supply-chain / drift detection).
    ///
    /// Verifies:
    /// 1. Key sizes per FIPS 203 §2.4.
    /// 2. Determinism: same seed always produces the same keys and shared secret.
    /// 3. Shared secret consistency: encapsulator and decapsulator derive equal secrets.
    /// 4. Pinned output: SS matches reference captured from ml-kem 0.2.3, guarding
    ///    against crate tampering or undetected version drift.
    #[test]
    fn ml_kem_768_regression_kat_fixed_seed() {
        let d: B32 = core::array::from_fn::<u8, 32, _>(|i| i as u8).into();
        let z: B32 = core::array::from_fn::<u8, 32, _>(|i| (i + 32) as u8).into();
        let m: B32 = core::array::from_fn::<u8, 32, _>(|i| (i + 64) as u8).into();

        let (dk, ek): (
            DecapsulationKey<MlKem768Params>,
            EncapsulationKey<MlKem768Params>,
        ) = MlKem768::generate_deterministic(&d, &z);

        let ek_bytes = ek.as_bytes();
        let dk_bytes = dk.as_bytes();
        assert_eq!(ek_bytes.len(), EK_SIZE, "encap key size must be {EK_SIZE}");
        assert_eq!(dk_bytes.len(), DK_SIZE, "decap key size must be {DK_SIZE}");

        assert_eq!(
            &ek_bytes[..16],
            &KAT_EK_PREFIX,
            "ek prefix mismatch — crate may have been changed or tampered with"
        );

        let (ct, ss_enc) = ek.encapsulate_deterministic(&m).unwrap();
        let ss_dec = dk.decapsulate(&ct).unwrap();

        assert_eq!(ct.len(), 1088, "ciphertext size must be 1088");
        assert_eq!(ss_enc.len(), SS_SIZE, "encap SS size must be {SS_SIZE}");
        assert_eq!(ss_dec.len(), SS_SIZE, "decap SS size must be {SS_SIZE}");

        let ss_enc_slice: &[u8] = &ss_enc;
        let ss_dec_slice: &[u8] = &ss_dec;
        assert_eq!(
            ss_enc_slice, ss_dec_slice,
            "encap and decap shared secrets must match"
        );
        assert_eq!(
            ss_enc_slice, &KAT_SS,
            "shared secret differs from ml-kem 0.2.3 reference — re-verify if version changed"
        );
    }
}
