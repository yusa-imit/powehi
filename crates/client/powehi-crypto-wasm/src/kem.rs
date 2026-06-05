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
//   vectors. The NIST ACVP conformance KAT (Y-5 close) is in acvp_kat_tests below.
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

// ── NIST ACVP ML-KEM-768 Conformance KAT (Y-5 close) ────────────────────────
//
// FIPS 203 §6.2 / §6.3 ML-KEM encap + decap conformance vectors.
// Source: RustCrypto/KEMs ml-kem/tests/encap-decap.json (mirrors usnistgov/ACVP-Server@65370b8)
//   testGroup: ML-KEM-768, tcId 26, deferred: false, reason: "no modification"
//
// Unlike the regression KAT (which pins self-computed values), these expected
// outputs were independently computed by NIST, breaking the circular dependency.
// A FIPS 203-non-conformant implementation cannot produce the correct (ct, ss)
// for arbitrary NIST-sourced inputs, even if it passes self-consistency tests.
//
// The `m` field is the internal encapsulation randomness for ML-KEM.Encaps_internal
// (FIPS 203 §6.2, Algorithm 17), accessible via the `deterministic` dev-feature.
//
// Closes Y-5 (ADR-0003 Phase C): NIST ACVP ML-KEM-768 encap + decap conformance.
// Gated on `#[cfg(test)]`; NOT compiled into the production WASM binary.
#[cfg(test)]
mod acvp_kat_tests {
    use super::{CT_SIZE, DK_SIZE, EK_SIZE, SS_SIZE};
    use ml_kem::kem::{Decapsulate, DecapsulationKey, EncapsulationKey};
    use ml_kem::{
        Ciphertext, EncapsulateDeterministic, EncodedSizeUser, MlKem768, MlKem768Params, B32,
    };

    // Decode an uppercase hex string to bytes. Panics on invalid input.
    fn from_hex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex digit"))
            .collect()
    }

    // ── NIST ACVP ML-KEM-768 encapDecap vector (tcId 26) ─────────────────────
    // RustCrypto/KEMs ml-kem/tests/encap-decap.json, testGroup ML-KEM-768, tcId 26
    // Fields: ek (1184 B), dk (2400 B), m (32 B), c/ct (1088 B), k/ss (32 B)

    // Encapsulation key — 1184 bytes (2368 hex chars), 37 × 64-char lines.
    const ACVP_EK: &str = concat!(
        "89D2CB65F94DCBFC890EFC7D0E5A7A38344D1641A3D0B024D50797A5F23C3A18",
        "B3101A1269069F43A842BACC098A8821271C673DB1BEB33034E4D7774D16635C",
        "7C2C3C2763453538BC1632E1851591A51642974E5928ABB8E55FE55612F9B141",
        "AFF015545394B2092E590970EC29A7B7E7AA1FB4493BF7CB731906C2A5CB49E6",
        "614859064E19B8FA26AF51C44B5E7535BFDAC072B646D3EA490D277F0D97CED4",
        "7395FED91E8F2BCE0E3CA122C2025F74067AB928A822B35653A74F06757629AF",
        "B1A1CAF237100EA935E793C8F58A71B3D6AE2C8658B10150D4A38F572A0D49D2",
        "8AE89451D338326FDB3B4350036C1081117740EDB86B12081C5C1223DBB5660D",
        "5B3CB3787D481849304C68BE875466F14EE5495C2BD795AE412D09002D65B871",
        "9B90CBA3603AC4958EA03CC138C86F7851593125334701B677F82F4952A4C93B",
        "5B4C134BB42A857FD15C650864A6AA94EB691C0B691BE4684C1F5B7490467FC0",
        "1B1D1FDA4DDA35C4ECC231BC73A6FEF42C99D34EB82A4D014987B3E386910C62",
        "679A118F3C5BD9F467E4162042424357DB92EF484A4A1798C1257E870A30CB20",
        "AAA0335D83314FE0AA7E63A862648041A72A6321523220B1ACE9BB701B21AC12",
        "53CB812C15575A9085EABEADE73A4AE76E6A7B158A20586D78A5AC620A5C9ABC",
        "C9C043350A73656B0ABE822DA5E0BA76045FAD75401D7A3B703791B7E9926171",
        "0F86B72421D240A347638377205A152C794130A4E047742B888303BDDC309116",
        "764DE7424CEBEA6DB65348AC537E01A9CC56EA667D5AA87AC9AAA4317D262C10",
        "143050B8D07A728CA633C13E468ABCEAD372C77B8ECF3B986B98C1E55860B2B4",
        "216766AD874C35ED7205068739230220B5A2317D102C598356F168ACBE80608D",
        "E4C9A710B8DD07078CD7C671058AF1B0B8304A314F7B29BE78A933C7B9294424",
        "954A1BF8BC745DE86198659E0E1225A910726074969C39A97C19240601A46E01",
        "3DCDCB677A8CBD2C95A40629C256F24A328951DF57502AB30772CC7E5B850027",
        "C8551781CE4985BDACF6B865C104E8A4BC65C41694D456B7169E45AB3D7ACABE",
        "AFE23AD6A7B94D1979A2F4C1CAE7CD77D681D290B5D8E451BFDCCCF5310B9D12",
        "A88EC29B10255D5E17A192670AA9731C5CA67EC784C502781BE8527D6FC003C6",
        "701B3632284B40307A527C7620377FEB0B73F722C9E3CD4DEC64876B93AB5B7C",
        "FC4A657F852B659282864384F442B22E8A21109387B8B47585FC680D0BA45C7A",
        "8B1D7274BDA57845D100D0F42A3B74628773351FD7AC305B2497639BE90B3F4F",
        "71A6AA3561EECC6A691BB5CB3914D8634CA1E1AF543C049A8C6E868C51F0423B",
        "D2D5AE09B79E57C27F3FE3AE2B26A441BABFC6718CE8C05B4FE793B910B8FBCB",
        "BE7F1013242B40E0514D0BDC5C88BAC594C794CE5122FBF34896819147B92838",
        "1587963B0B90034AA07A10BE176E01C80AD6A4B71B10AF4241400A2A4CBBC059",
        "61A15EC1474ED51A3CC6D35800679A462809CAA3AB4F7094CD6610B4A700CBA9",
        "39E7EAC93E38C99755908727619ED76A34E53C4FA25BFC97008206697DD145E5",
        "B9188E5B014E941681E15FE3E132B8A3903474148BA28B987111C9BCB3989BBB",
        "C671C581B44A492845F288E62196E471FED3C39C1BBDDB0837D0D4706B0922C4"
    );

    // Decapsulation key — 2400 bytes (4800 hex chars), 75 × 64-char lines.
    // Structure (FIPS 203 §2.4): dk_PKE (1152 B) || ek (1184 B) || H(ek) (32 B) || z (32 B).
    const ACVP_DK: &str = concat!(
        "B09125AFB3CFB5295581373AB6885284D9706318280D223EDC987FD14410DBE8",
        "2E6AC89ADFAB70E67CA4B1C641AD037FD8C47870F159EC79CDCD52605B989049",
        "9BB6DBD8347F342C61436B642C0DDF4617DB06198B8285DCE4C09D9775A2F41C",
        "8CD18AF8E75F57D4127DF94D901AC83BACBD584CC50C43750F49B357F5935087",
        "5C9B475480A8AAA168592DDB158614A639813566D205368C6C39F0413CA3230D",
        "F60D44008282B682AC66B76C3C95F00B2A555035529C86EF3905B4A3968FEA78",
        "02B6C5EECB08E8F0C42D7AB7CD21A62FB136412A1840B52C99970CCF51892F73",
        "497C3775BE2189F7FC25E7C74D81FC217683292AA4866DDB04469855323A0810",
        "F0893DE5C7F94A9C0B5337DB83C44891B2E694695B76575032BF51761682958B",
        "D4F97BE9A355B4A85BB6858B7E5A5EF653AB781056AF9187D811C3A8936E5706",
        "503DB57062410BCC9421F1AB867A657856C411C4E025ECB3C387729AE8E112F3",
        "30B988E22F47C35C280750D21B107687AF7B329EF3CB5289F06FB7D44548391E",
        "97BA6DD499B5907C54958413D92AA99D5646CF47A8F48CB70A07AD056B4EEFE6",
        "C8C46645F7028A32410558638C48E83AC1570160C3833BF64052F5B7DF4364D3",
        "E0B24E790AA7C98CEE0441E6731D9DE22D156C61E1C740397672EF54724F01B9",
        "D49923AA321F86B98823F21360138392B90C69434635275F9BFBB9B8A99E8E1B",
        "7F4EC25F75DBCE33C13F750170BD6722EFE496E7463E16AAA5867B869A96AD41",
        "B22BD2556C924596FD778D79A102F6E46D8EB18FEFAC8DB19993E5414AC81670",
        "5286892492C8C9E852D6145DFF0C10E4A6703A459E7E732A6DFA2766A622B062",
        "2BFEDB8F41C125F61B2EC264853B9CCC165979F6A263BEB148905AAC7618A70E",
        "829E23F28696F92EF6FA07C102CDBDB1288BA5CFF3A81ABBA15974535FE3106A",
        "80068F14E98964572350A7112B1601C196710C096CCF164FBCE1AABAC9C5B953",
        "5070E61AB8068D611CA765FABB6412607DAB30C4FC6AD073731FDC4C48B88E26",
        "7C47B439AD2560C30561815CEB1F52C896489944BBBAB52B1B1D1680A1057964",
        "DAFA600C93A39A447DDBB0ADF911AFE3E823D8ACC7CC04659F625F2C1837BB17",
        "5282542CD22601F621581AB5A6C0384E087CCD32A5380B522FDD3A4202B5B41C",
        "85CAFF2903B2DC2645703D9BC711FBB404C0C0376187AC588AAF5718522D2273",
        "A9408DABCBC9701698D2DA172AA6267A4C9693A24011C2265A2B6DC8E96304A9",
        "8DDC5319A3140C399A08412C20F48537870BB84C32A094457895511FF7EC421D",
        "E01A64B78534653F78327441B90CD115939DFAAFA95B40D0A63D62D12EB5C909",
        "6018CC83871E44E6CD0BE26D16B7B5A209B8E6471D2954ADF9FABD0153707C9C",
        "AA2BCC38DED841C791A0EB597EEEE2C518D926EDB28AB53CAA5B7746466931B0",
        "AC9150688BF37049C1F82BCF648332434CD0A92FD2C958353A26CB65CB499057",
        "109B2D688CC43C4B385DA7C50868AF1B8075E57088F5DB12DFA493EACB6DC4EC",
        "6E205BAA2A89858EC2823C00553714CDE47A96E36C7C198B3EC57CCF74D92CDD",
        "B86AA0A8B8B5CA9D52BB60ABA79F4F72B0125532CEB7A9077480D2BB60DF51A9",
        "89D2CB65F94DCBFC890EFC7D0E5A7A38344D1641A3D0B024D50797A5F23C3A18",
        "B3101A1269069F43A842BACC098A8821271C673DB1BEB33034E4D7774D16635C",
        "7C2C3C2763453538BC1632E1851591A51642974E5928ABB8E55FE55612F9B141",
        "AFF015545394B2092E590970EC29A7B7E7AA1FB4493BF7CB731906C2A5CB49E6",
        "614859064E19B8FA26AF51C44B5E7535BFDAC072B646D3EA490D277F0D97CED4",
        "7395FED91E8F2BCE0E3CA122C2025F74067AB928A822B35653A74F06757629AF",
        "B1A1CAF237100EA935E793C8F58A71B3D6AE2C8658B10150D4A38F572A0D49D2",
        "8AE89451D338326FDB3B4350036C1081117740EDB86B12081C5C1223DBB5660D",
        "5B3CB3787D481849304C68BE875466F14EE5495C2BD795AE412D09002D65B871",
        "9B90CBA3603AC4958EA03CC138C86F7851593125334701B677F82F4952A4C93B",
        "5B4C134BB42A857FD15C650864A6AA94EB691C0B691BE4684C1F5B7490467FC0",
        "1B1D1FDA4DDA35C4ECC231BC73A6FEF42C99D34EB82A4D014987B3E386910C62",
        "679A118F3C5BD9F467E4162042424357DB92EF484A4A1798C1257E870A30CB20",
        "AAA0335D83314FE0AA7E63A862648041A72A6321523220B1ACE9BB701B21AC12",
        "53CB812C15575A9085EABEADE73A4AE76E6A7B158A20586D78A5AC620A5C9ABC",
        "C9C043350A73656B0ABE822DA5E0BA76045FAD75401D7A3B703791B7E9926171",
        "0F86B72421D240A347638377205A152C794130A4E047742B888303BDDC309116",
        "764DE7424CEBEA6DB65348AC537E01A9CC56EA667D5AA87AC9AAA4317D262C10",
        "143050B8D07A728CA633C13E468ABCEAD372C77B8ECF3B986B98C1E55860B2B4",
        "216766AD874C35ED7205068739230220B5A2317D102C598356F168ACBE80608D",
        "E4C9A710B8DD07078CD7C671058AF1B0B8304A314F7B29BE78A933C7B9294424",
        "954A1BF8BC745DE86198659E0E1225A910726074969C39A97C19240601A46E01",
        "3DCDCB677A8CBD2C95A40629C256F24A328951DF57502AB30772CC7E5B850027",
        "C8551781CE4985BDACF6B865C104E8A4BC65C41694D456B7169E45AB3D7ACABE",
        "AFE23AD6A7B94D1979A2F4C1CAE7CD77D681D290B5D8E451BFDCCCF5310B9D12",
        "A88EC29B10255D5E17A192670AA9731C5CA67EC784C502781BE8527D6FC003C6",
        "701B3632284B40307A527C7620377FEB0B73F722C9E3CD4DEC64876B93AB5B7C",
        "FC4A657F852B659282864384F442B22E8A21109387B8B47585FC680D0BA45C7A",
        "8B1D7274BDA57845D100D0F42A3B74628773351FD7AC305B2497639BE90B3F4F",
        "71A6AA3561EECC6A691BB5CB3914D8634CA1E1AF543C049A8C6E868C51F0423B",
        "D2D5AE09B79E57C27F3FE3AE2B26A441BABFC6718CE8C05B4FE793B910B8FBCB",
        "BE7F1013242B40E0514D0BDC5C88BAC594C794CE5122FBF34896819147B92838",
        "1587963B0B90034AA07A10BE176E01C80AD6A4B71B10AF4241400A2A4CBBC059",
        "61A15EC1474ED51A3CC6D35800679A462809CAA3AB4F7094CD6610B4A700CBA9",
        "39E7EAC93E38C99755908727619ED76A34E53C4FA25BFC97008206697DD145E5",
        "B9188E5B014E941681E15FE3E132B8A3903474148BA28B987111C9BCB3989BBB",
        "C671C581B44A492845F288E62196E471FED3C39C1BBDDB0837D0D4706B0922C4",
        "72E31DF613DA9A1DD33B5D2D8939684B89F7649E1C59B959FFBE972786C477F6",
        "6177DBF3B059173FD06AFCD90E80E862174FC57F97607BBFF5B73D6360FB5C37"
    );

    // Internal encapsulation randomness m — 32 bytes (64 hex chars).
    const ACVP_M: &str = "2CE74AD291133518FE60C7DF5D251B9D82ADD48462FF505C6E547E949E6B6BF7";

    // Expected ciphertext — 1088 bytes (2176 hex chars), 34 × 64-char lines.
    const ACVP_CT: &str = concat!(
        "56B42D593AAB8E8773BD92D76EABDDF3B1546F8326F57A7B773764B6C0DD3047",
        "0F68DFF82E0DCA92509274ECFE83A954735FDE6E14676DAAA3680C30D524F4EF",
        "A79ED6A1F9ED7E1C00560E8683538C3105AB931BE0D2B249B38CB9B13AF5CEAF",
        "7887A59DBA16688A7F28DE0B14D19F391EB41832A56479416CCF94E997390ED7",
        "878EEAFF49328A70E0AB5FCE6C63C09B35F4E45994DE615B88BB722F70E87D2B",
        "BD72AE71E1EE9008E459D8E743039A8DDEB874FCE5301A2F8C0EE8C2FEE7A4EE",
        "68B5ED6A6D9AB74F98BB3BA0FE89E82BD5A525C5E8790F818CCC605877D46C8B",
        "DB5C337B025BB840FF471896E43BFA99D73DBE31805C27A43E57F0618B3AE522",
        "A4644E0D4E4C1C548489431BE558F3BFC50E16617E110DD7AF9A6FD83E3FBB68",
        "C304D15F6CB700D61D7AA915A6751EA3BA80223E654132A20999A43BF4085927",
        "30B9A9499636C09FA729F9CB1F9D3442F47357A2B9CF15D3103B9BF396C23088",
        "F118EDE346B5C03891CFA5D517CEF8471322E7E31087C4B036ABAD784BFF72A9",
        "B11FA198FACBCB91F067FEAF76FCFE5327C1070B3DA6988400756760D2D1F060",
        "298F1683D51E3616E98C51C9C03AA42F2E633651A47AD3CC2AB4A852AE0C4B04",
        "B4E1C3DD944445A2B12B4F42A6435105C04122FC3587AFE409A00B308D63C5DD",
        "8163654504EEDBB7B5329577C35FBEB3F463872CAC28142B3C12A740EC6EA7CE",
        "9AD78C6FC8FE1B4DF5FC55C1667F31F2312DA07799DC870A478608549FEDAFE0",
        "21F1CF2984180364E90AD98D845652AA3CDD7A8EB09F5E51423FAB42A7B7BB4D",
        "514864BE8D71297E9C3B17A993F0AE62E8EF52637BD1B885BD9B6AB727854D70",
        "3D8DC478F96CB81FCE4C60383AC01FCF0F971D4C8F352B7A82E218652F2C106C",
        "A92AE686BACFCEF5D327347A97A9B375D67341552BC2C538778E0F9801823CCD",
        "FCD1EAADED55B18C9757E3F212B2889D3857DB51F981D16185FD0F900853A750",
        "05E3020A8B95B7D8F2F2631C70D78A957C7A62E1B3719070ACD1FD480C25B838",
        "47DA027B6EBBC2EEC2DF22C87F9B46D5D7BAF156B53CEE929572B92C4784C4E8",
        "29F3446A1FFE47F99DECD0436029DDEBD3ED8E87E5E73D123DBE8A4DDACF2ABD",
        "E87F33AE2B621C0EC5D5CAD1259DEEC2AEFF6088F04F27A20338B5762543E510",
        "0899A4CBFB7B3CA456B3A19B83A4C432230C23E1C7F107C4CB112152F1C0F30D",
        "A0BB33F4F11F47EEA43872BAFA84AE22256D708E0604DADE4B2A4DDE8CCCF119",
        "30E13553934AE3ECE52F3D7CCC00287377879FE6B8ECE7EF79423507C9DA3395",
        "59C20DE1C51955999BAE47401DC3CDFAA1B256D09C7DB9FC8698BFCEFA7302D5",
        "6FBCDE1FBAAA1C653454E6FD3D84E4F79A931C681CBB6CB462B10DAE112BDFB7",
        "F65C7FDF6E5FC594EC3A474A94BD97E6EC81F71C230BF70CA0F13CE3DFFBD9FF",
        "9804EFD8F37A4D3629B43A8F55544EBC5AC0ABD9A33D79699068346A0F1A3A96",
        "E115A5D80BE165B562D082984D5AACC3A2301981A6418F8BA7D7B0D7CA5875C6"
    );

    // Expected shared secret (k) — 32 bytes (64 hex chars).
    const ACVP_SS: &str = "2696D28E9C61C2A01CE9B1608DCB9D292785A0CD58EFB7FE13B1DE95F0DB55B3";

    /// NIST ACVP ML-KEM-768 encap conformance (FIPS 203 §6.2 ML-KEM.Encaps_internal).
    ///
    /// Given NIST-sourced (ek, m), verifies (ct, ss) matches NIST expected output.
    /// Closes Y-5 (ADR-0003 Phase C): FIPS 203 §6.2 conformance for ML-KEM-768.
    #[test]
    fn ml_kem_768_nist_acvp_encap_conformance() {
        let ek_bytes = from_hex(ACVP_EK);
        let m_bytes = from_hex(ACVP_M);
        let exp_ct = from_hex(ACVP_CT);
        let exp_ss = from_hex(ACVP_SS);

        assert_eq!(ek_bytes.len(), EK_SIZE, "ACVP ek must be {EK_SIZE} bytes");
        assert_eq!(m_bytes.len(), 32, "ACVP m must be 32 bytes");
        assert_eq!(exp_ct.len(), CT_SIZE, "ACVP ct must be {CT_SIZE} bytes");
        assert_eq!(exp_ss.len(), SS_SIZE, "ACVP ss must be {SS_SIZE} bytes");

        let ek_encoded: ml_kem::Encoded<EncapsulationKey<MlKem768Params>> = ek_bytes
            .as_slice()
            .try_into()
            .expect("ACVP ek must be parseable as Encoded<Ek768>");
        let ek = EncapsulationKey::<MlKem768Params>::from_bytes(&ek_encoded);

        let m_arr: [u8; 32] = m_bytes
            .as_slice()
            .try_into()
            .expect("ACVP m must be 32 bytes");
        let m: B32 = m_arr.into();

        let (ct, ss) = ek
            .encapsulate_deterministic(&m)
            .expect("ACVP encap must not fail");

        assert_eq!(
            ct.as_ref() as &[u8],
            exp_ct.as_slice(),
            "NIST ACVP ML-KEM-768 ciphertext mismatch — FIPS 203 §6.2 non-conformant"
        );
        assert_eq!(
            ss.as_ref() as &[u8],
            exp_ss.as_slice(),
            "NIST ACVP ML-KEM-768 shared secret (encap) mismatch — FIPS 203 §6.2 non-conformant"
        );
    }

    /// NIST ACVP ML-KEM-768 decap conformance (FIPS 203 §6.3 ML-KEM.Decaps_internal).
    ///
    /// Given NIST-sourced (dk, ct), verifies ss matches NIST expected output.
    /// Together with the encap test, this closes Y-5 for both directions.
    #[test]
    fn ml_kem_768_nist_acvp_decap_conformance() {
        let dk_bytes = from_hex(ACVP_DK);
        let ct_bytes = from_hex(ACVP_CT);
        let exp_ss = from_hex(ACVP_SS);

        assert_eq!(dk_bytes.len(), DK_SIZE, "ACVP dk must be {DK_SIZE} bytes");
        assert_eq!(ct_bytes.len(), CT_SIZE, "ACVP ct must be {CT_SIZE} bytes");
        assert_eq!(exp_ss.len(), SS_SIZE, "ACVP ss must be {SS_SIZE} bytes");

        let dk_encoded: ml_kem::Encoded<DecapsulationKey<MlKem768Params>> = dk_bytes
            .as_slice()
            .try_into()
            .expect("ACVP dk must be parseable as Encoded<Dk768>");
        let dk = DecapsulationKey::<MlKem768Params>::from_bytes(&dk_encoded);

        let ct: Ciphertext<MlKem768> = ct_bytes
            .as_slice()
            .try_into()
            .expect("ACVP ct must be parseable as Ciphertext<MlKem768>");

        let ss = dk.decapsulate(&ct).expect("ACVP decap must not fail");

        assert_eq!(
            ss.as_ref() as &[u8],
            exp_ss.as_slice(),
            "NIST ACVP ML-KEM-768 shared secret (decap) mismatch — FIPS 203 §6.3 non-conformant"
        );
    }
}
