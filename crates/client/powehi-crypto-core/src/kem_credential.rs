// ML-KEM-768 encapsulation-key authentication via Ed25519 (ADR-0003 Phase B, Y-3 fix).
//
// Y-3: The encapsulation key received from a peer is unauthenticated — a MITM or
// malicious server could substitute a different encap key, causing the encapsulator
// to produce a ciphertext that only the attacker can decapsulate (key substitution
// attack).
//
// Fix: the encap-key holder signs `SIGN_DOMAIN || 0x00 || ek_bytes` with their MLS
// Ed25519 identity key (via the openmls `Signer` trait). Peers MUST verify the
// signature against the trusted public key from the MLS group roster before
// encapsulating.  This binds the ML-KEM encap key to the MLS credential.
//
// Security properties:
// - Domain separation: SIGN_DOMAIN prevents cross-protocol reuse of the signature.
// - NUL separator: 0x00 byte between domain and data prevents the domain string from
//   extending into the encap key bytes.
// - Ed25519 is deterministic (RFC 8032) — same inputs always produce the same sig.
// - Uses openmls `Signer` trait / RustCrypto Ed25519 backend — no homegrown crypto.
// - The 64-byte signature is public data and may cross the WASM-JS boundary.
// - The private signing key NEVER crosses the WASM-JS boundary (stays in MLS_CTX).
//
// Trust model: verify_encap_key checks the signature mathematics only. The caller
// is responsible for sourcing sig_pub_key from a trusted channel — specifically,
// the member's sigKeyHex entry in the verified MLS group roster (mls_group_members).

use crate::kem::EK_SIZE;
use crate::mls_group::CIPHERSUITE;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::signatures::Signer;

/// Domain separator for signed ML-KEM-768 encapsulation keys (ADR-0003 Phase B).
pub const SIGN_DOMAIN: &[u8] = b"powehi-kem-ek-v1";

/// Ed25519 signature output length (bytes).
pub const SIG_SIZE: usize = 64;

/// Build the message over which the encap key signature is computed.
///
/// Format: `SIGN_DOMAIN || 0x00 || ek_bytes`
///
/// The 0x00 separator distinguishes the 16-byte domain string from the key bytes
/// and prevents the domain prefix from extending into the key data.
fn signing_message(ek_bytes: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(SIGN_DOMAIN.len() + 1 + ek_bytes.len());
    msg.extend_from_slice(SIGN_DOMAIN);
    msg.push(0x00);
    msg.extend_from_slice(ek_bytes);
    msg
}

/// Sign an ML-KEM-768 encapsulation key with the MLS Ed25519 identity signing key.
///
/// Returns 64 bytes (deterministic Ed25519 signature over
/// `SIGN_DOMAIN || 0x00 || ek_bytes`).
///
/// Signing uses the openmls `Signer` trait implementation on `SignatureKeyPair`,
/// which keeps the private key within the struct — no raw private key bytes are
/// exposed to calling code.
///
/// # Errors
/// - `ek_bytes` is not exactly `EK_SIZE` (1184) bytes.
/// - The Ed25519 signing operation fails (provider error).
pub fn sign_encap_key(ek_bytes: &[u8], signer: &SignatureKeyPair) -> Result<Vec<u8>, &'static str> {
    if ek_bytes.len() != EK_SIZE {
        return Err("invalid encap key: expected 1184 bytes");
    }
    let msg = signing_message(ek_bytes);
    signer.sign(&msg).map_err(|_| "encap key signing failed")
}

/// Verify an ML-KEM-768 encapsulation-key signature.
///
/// Returns `true` if the signature is valid under the given Ed25519 public key.
/// Returns `false` for an invalid signature — NOT an error; it is the expected
/// result when the encap key was substituted or the signature was tampered.
///
/// The caller MUST source `sig_pub_key` from the verified MLS group roster (e.g.
/// the `sigKeyHex` entry for the expected member from `mls_group_members`, hex-
/// decoded to raw bytes). This function does NOT verify the trust anchor.
///
/// A temporary stateless provider is used — no MLS identity is required.
///
/// # Errors
/// - `ek_bytes` is not exactly `EK_SIZE` (1184) bytes.
/// - `sig_pub_key` is not exactly 32 bytes (Ed25519 public key size).
pub fn verify_encap_key(
    ek_bytes: &[u8],
    signature: &[u8],
    sig_pub_key: &[u8],
    provider: &OpenMlsRustCrypto,
) -> Result<bool, &'static str> {
    if ek_bytes.len() != EK_SIZE {
        return Err("invalid encap key: expected 1184 bytes");
    }
    if signature.len() != SIG_SIZE {
        return Err("invalid signature: expected 64 bytes");
    }
    if sig_pub_key.len() != 32 {
        return Err("invalid public key: expected 32 bytes");
    }
    let msg = signing_message(ek_bytes);
    // CIPHERSUITE is hardcoded to MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 at
    // compile time, so UnsupportedSignatureScheme can never be returned. All remaining
    // error variants (InvalidSignature, CryptoLibraryError) represent a bad signature
    // — both are correctly mapped to Ok(false) (reject, not error).
    Ok(provider
        .crypto()
        .verify_signature(
            CIPHERSUITE.signature_algorithm(),
            &msg,
            sig_pub_key,
            signature,
        )
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mls_group::generate_identity;

    fn make_provider_and_signer() -> (OpenMlsRustCrypto, SignatureKeyPair) {
        let provider = OpenMlsRustCrypto::default();
        let identity = generate_identity(b"kem-credential-test-identity", &provider).unwrap();
        (provider, identity.signer)
    }

    // ── Round-trip ──────────────────────────────────────────────────────────────

    /// sign + verify: correct signature over correct encap key is accepted.
    #[test]
    fn sign_verify_round_trip() {
        let (provider, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        let sig = sign_encap_key(&ek, &signer).expect("signing must succeed");
        assert_eq!(sig.len(), SIG_SIZE, "Ed25519 signature must be 64 bytes");
        let pub_key = signer.to_public_vec();
        let valid =
            verify_encap_key(&ek, &sig, &pub_key, &provider).expect("verify must not error");
        assert!(valid, "valid signature must be accepted");
    }

    /// Ed25519 signing is deterministic: same key + same input → same output.
    #[test]
    fn signing_is_deterministic() {
        let (_, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        let sig1 = sign_encap_key(&ek, &signer).expect("first sign must succeed");
        let sig2 = sign_encap_key(&ek, &signer).expect("second sign must succeed");
        assert_eq!(sig1, sig2, "Ed25519 signing must be deterministic");
    }

    // ── Key substitution resistance ─────────────────────────────────────────────

    /// Wrong public key (different identity) → signature rejected.
    /// Defends against a verifier trusting the wrong identity's public key.
    #[test]
    fn wrong_public_key_rejects_signature() {
        let (provider, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        let sig = sign_encap_key(&ek, &signer).expect("signing must succeed");

        let provider2 = OpenMlsRustCrypto::default();
        let attacker = generate_identity(b"attacker-identity", &provider2).unwrap();
        let wrong_pub = attacker.signer.to_public_vec();

        let valid =
            verify_encap_key(&ek, &sig, &wrong_pub, &provider).expect("verify must not error");
        assert!(!valid, "signature under wrong public key must be rejected");
    }

    /// Tampered encap key bytes → signature rejected.
    /// This is the core key-substitution attack: attacker replaces the encap key.
    #[test]
    fn tampered_encap_key_rejects_signature() {
        let (provider, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        let sig = sign_encap_key(&ek, &signer).expect("signing must succeed");
        let pub_key = signer.to_public_vec();

        let mut tampered = ek.clone();
        tampered[0] ^= 0x01;

        let valid =
            verify_encap_key(&tampered, &sig, &pub_key, &provider).expect("verify must not error");
        assert!(!valid, "substituted encap key must be rejected");
    }

    /// Tampered signature → rejected.
    #[test]
    fn tampered_signature_is_rejected() {
        let (provider, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        let mut sig = sign_encap_key(&ek, &signer).expect("signing must succeed");
        let pub_key = signer.to_public_vec();

        sig[0] ^= 0x01;

        let valid =
            verify_encap_key(&ek, &sig, &pub_key, &provider).expect("verify must not error");
        assert!(!valid, "tampered signature must be rejected");
    }

    // ── Cross-key isolation ─────────────────────────────────────────────────────

    /// Two different encap keys produce different signatures from the same signer.
    #[test]
    fn different_encap_keys_produce_different_signatures() {
        let (_, signer) = make_provider_and_signer();
        let ek_a = vec![0x01u8; EK_SIZE];
        let ek_b = vec![0x02u8; EK_SIZE];
        let sig_a = sign_encap_key(&ek_a, &signer).expect("sign_a must succeed");
        let sig_b = sign_encap_key(&ek_b, &signer).expect("sign_b must succeed");
        assert_ne!(
            sig_a, sig_b,
            "distinct encap keys must yield distinct signatures"
        );
    }

    // ── Input validation ────────────────────────────────────────────────────────

    /// sign_encap_key rejects wrong-length encap key.
    #[test]
    fn sign_rejects_short_encap_key() {
        let (_, signer) = make_provider_and_signer();
        assert!(
            sign_encap_key(&vec![0u8; EK_SIZE - 1], &signer).is_err(),
            "short encap key must error in sign"
        );
    }

    /// verify_encap_key rejects wrong-length encap key.
    #[test]
    fn verify_rejects_short_encap_key() {
        let (provider, _) = make_provider_and_signer();
        assert!(
            verify_encap_key(&vec![0u8; EK_SIZE - 1], &[0u8; 64], &[0u8; 32], &provider).is_err(),
            "short encap key must error in verify"
        );
    }

    /// verify_encap_key rejects a signature that is not 64 bytes.
    #[test]
    fn verify_rejects_wrong_length_signature() {
        let (provider, _) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        assert!(
            verify_encap_key(&ek, &[0u8; 63], &[0u8; 32], &provider).is_err(),
            "63-byte signature must error"
        );
        assert!(
            verify_encap_key(&ek, &[0u8; 65], &[0u8; 32], &provider).is_err(),
            "65-byte signature must error"
        );
    }

    /// verify_encap_key rejects a public key that is not 32 bytes.
    #[test]
    fn verify_rejects_wrong_length_pub_key() {
        let (provider, _) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        assert!(
            verify_encap_key(&ek, &[0u8; 64], &[0u8; 31], &provider).is_err(),
            "31-byte pub key must error"
        );
        assert!(
            verify_encap_key(&ek, &[0u8; 64], &[0u8; 33], &provider).is_err(),
            "33-byte pub key must error"
        );
    }

    // ── KAT (supply-chain / wire-format regression) ────────────────────────────

    /// Known-Answer Test: sign all-zero encap key with a known Ed25519 key pair.
    ///
    /// Pins the exact 64-byte Ed25519 signature output for:
    ///   - signing key  = ed25519-dalek 2.2.0 `SigningKey::from_bytes([0x42; 32])`
    ///   - encap key    = all-zero 1184 bytes
    ///   - message      = SIGN_DOMAIN || 0x00 || ek_bytes
    ///
    /// Purpose: detects silent library drift (openmls / ed25519-dalek version bump
    /// that changes the wire format) and supply-chain tampering. Re-capture using
    /// the `kem_credential_kat_capture` test if the signing library is intentionally
    /// upgraded. Ed25519 is deterministic (RFC 8032 §5.1) so the value is stable.
    #[test]
    fn sign_encap_key_kat_wire_format() {
        use openmls::prelude::SignatureScheme;
        // Fixed seed: [0x42; 32]. Public key derived via ed25519-dalek 2.2.0.
        // Captured from `kem_credential_kat_capture` (below).
        const KAT_SEED: [u8; 32] = [0x42u8; 32];
        const KAT_PUB: [u8; 32] = [
            0x21, 0x52, 0xf8, 0xd1, 0x9b, 0x79, 0x1d, 0x24, 0x45, 0x32, 0x42, 0xe1, 0x5f, 0x2e,
            0xab, 0x6c, 0xb7, 0xcf, 0xfa, 0x7b, 0x6a, 0x5e, 0xd3, 0x00, 0x97, 0x96, 0x0e, 0x06,
            0x98, 0x81, 0xdb, 0x12,
        ];
        // Expected signature for SIGN_DOMAIN || 0x00 || [0u8; 1184] with the above key.
        // Captured from kat_capture run on openmls_basic_credential 0.5.0 + ed25519-dalek 2.2.0.
        // Re-capture (see kat_capture test) if ed25519-dalek is intentionally upgraded.
        const KAT_SIG: [u8; SIG_SIZE] = [
            0x79, 0x5b, 0x94, 0x29, 0x5f, 0xbf, 0x60, 0xb7, 0x7c, 0x08, 0x52, 0xd0, 0x90, 0x70,
            0x56, 0xcc, 0x04, 0x62, 0x9c, 0x45, 0x61, 0x62, 0x80, 0xe4, 0x1d, 0x13, 0x3f, 0x56,
            0xb2, 0x0c, 0xb9, 0x85, 0x05, 0xa5, 0xb3, 0xca, 0xe7, 0x90, 0xe2, 0x4b, 0x71, 0x0b,
            0xd4, 0xa3, 0x24, 0x52, 0x5c, 0xdb, 0x60, 0xb3, 0x21, 0xb0, 0x25, 0x06, 0x21, 0x38,
            0x44, 0xf3, 0xea, 0x03, 0x09, 0x75, 0xea, 0x05,
        ];

        let signer = SignatureKeyPair::from_raw(
            SignatureScheme::ED25519,
            KAT_SEED.to_vec(),
            KAT_PUB.to_vec(),
        );
        let provider = OpenMlsRustCrypto::default();
        let ek = vec![0u8; EK_SIZE];

        let sig = sign_encap_key(&ek, &signer).expect("KAT signing must succeed");
        assert_eq!(
            sig.as_slice(),
            &KAT_SIG,
            "KAT mismatch — wire format changed; re-capture if ed25519-dalek upgraded"
        );
        let pub_key = signer.to_public_vec();
        let valid =
            verify_encap_key(&ek, &sig, &pub_key, &provider).expect("KAT verify must not error");
        assert!(valid, "KAT signature must verify under its own public key");
    }

    /// KAT capture helper — prints private/public key bytes and signature for hardcoding.
    /// Run with `cargo test kat_capture -- --nocapture --ignored` to update KAT constants
    /// when ed25519-dalek is intentionally upgraded.
    ///
    /// WARNING: any change to the hardcoded KAT_SIG/KAT_PUB constants in
    /// `sign_encap_key_kat_wire_format` MUST be reviewed by the crypto-reviewer agent
    /// (skill: crypto-review) with the ed25519-dalek version delta in the diff.
    /// Do NOT commit rotated KAT constants without that review — the KAT is a
    /// supply-chain guard and silently rotating it defeats its purpose.
    #[test]
    #[ignore = "capture-only: run manually to update KAT constants when library changes"]
    fn kem_credential_kat_capture() {
        // Derive a deterministic Ed25519 key pair from a fixed seed via ed25519-dalek 2.x.
        // The same version is used by openmls_basic_credential so sign+verify are consistent.
        let seed = [0x42u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_bytes = signing_key.verifying_key().to_bytes().to_vec();
        let private_bytes = signing_key.to_bytes().to_vec();

        let signer = SignatureKeyPair::from_raw(
            openmls::prelude::SignatureScheme::ED25519,
            private_bytes.clone(),
            public_bytes.clone(),
        );
        let provider = OpenMlsRustCrypto::default();
        let ek = vec![0u8; EK_SIZE];
        let sig = sign_encap_key(&ek, &signer).expect("sign must succeed");
        let pub_key = signer.to_public_vec();
        let valid = verify_encap_key(&ek, &sig, &pub_key, &provider).expect("verify");
        assert!(valid, "freshly generated key must verify");
        eprintln!("=== KAT CAPTURE ===");
        eprintln!(
            "KAT_SEED: {:?}",
            private_bytes
                .iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        eprintln!(
            "KAT_PUB:  {:?}",
            public_bytes
                .iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        eprintln!(
            "KAT_SIG:  {:?}",
            sig.iter()
                .map(|b| format!("0x{b:02x}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // ── Domain-separation regression ────────────────────────────────────────────

    /// A signature over raw ek_bytes (no domain prefix) must be rejected by
    /// verify_encap_key, which expects `SIGN_DOMAIN || 0x00 || ek_bytes`.
    ///
    /// This guards against cross-protocol signature reuse: a signature produced
    /// by a signer over a different message format cannot be substituted for a
    /// valid signed encap key.
    #[test]
    fn raw_signature_without_domain_is_rejected() {
        let (provider, signer) = make_provider_and_signer();
        let ek = vec![0u8; EK_SIZE];
        // Sign the raw encap key bytes — no domain prefix, no NUL separator.
        let raw_sig = signer.sign(&ek).expect("raw signing must succeed");
        let pub_key = signer.to_public_vec();
        // verify_encap_key checks SIGN_DOMAIN || 0x00 || ek; a signature over
        // raw ek_bytes is over a different message and must be rejected.
        let valid =
            verify_encap_key(&ek, &raw_sig, &pub_key, &provider).expect("verify must not error");
        assert!(
            !valid,
            "signature over raw ek_bytes (no domain) must be rejected by verify_encap_key"
        );
    }
}
