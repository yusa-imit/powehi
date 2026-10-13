//! Pairwise Safety Number (prd.md §5.6), shared by the WASM worker and the CLI.
//!
//! Moved verbatim from `powehi-crypto-wasm`; the known-answer test pins the construction so
//! both clients keep producing the same number for the same two signature keys.

use sha2::{Digest, Sha512};

/// Domain-separation prefix for the safety number derivation (prd.md §5.6).
/// Pinning the construction version here makes any future format change detectable.
const SAFETY_NUMBER_DOMAIN: &[u8] = b"powehi-safety-number-v1";

/// Render a SHA-512 digest as the 12-group decimal safety number format
/// (prd.md §5.6 "숫자 6자리 그룹"): 12 six-digit decimal groups, space-separated,
/// 83 characters total. Shared by both the pairwise and group constructions.
pub fn digits_from_hash(hash: &[u8; 64]) -> String {
    // 12 groups × 4 bytes = 48 bytes; SHA-512 provides 64 bytes, 16 bytes unused.
    // Each u32 mod 1_000_000 → 6-digit group (prd.md §5.6).
    // Bias: 2^32 mod 1_000_000 = 967_296; values 0-967_295 appear once more in a
    // uniform 32-bit space — negligible (< 0.03%) for a human-verified fingerprint.
    let groups: Vec<String> = (0..12)
        .map(|i| {
            let val = u32::from_be_bytes([
                hash[4 * i],
                hash[4 * i + 1],
                hash[4 * i + 2],
                hash[4 * i + 3],
            ]);
            format!("{:06}", val % 1_000_000)
        })
        .collect();
    groups.join(" ")
}

/// Safety number of two Ed25519 signature public keys, each exactly 32 bytes.
///
/// Returns an 83-char string: 12 six-digit decimal groups separated by spaces.
/// Symmetric: same result for (a,b) and (b,a).
///
/// Construction: SHA-512(DOMAIN || 0x00 || len(first) || first || len(second) || second)
/// where first/second are sorted lexicographically. Domain separation + length prefixes
/// prevent cross-protocol collisions and extension attacks.
pub fn pairwise(key_a: &[u8], key_b: &[u8]) -> Result<String, &'static str> {
    if key_a.len() != 32 || key_b.len() != 32 {
        return Err("safety number keys must be exactly 32 bytes");
    }
    // Sort lexicographically so (a,b) and (b,a) hash identically.
    // Both operands are public keys — no timing side-channel concern.
    let (first, second) = if key_a <= key_b {
        (key_a, key_b)
    } else {
        (key_b, key_a)
    };
    let mut h = Sha512::new();
    h.update(SAFETY_NUMBER_DOMAIN);
    h.update([0u8]); // separator between domain and data
    h.update((first.len() as u32).to_be_bytes()); // length-prefix (always 32; explicit for framing)
    h.update(first);
    h.update((second.len() as u32).to_be_bytes());
    h.update(second);
    let hash: [u8; 64] = h.finalize().into();
    Ok(digits_from_hash(&hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_and_format() {
        let (a, b) = ([0x0au8; 32], [0xb0u8; 32]);
        let sn = pairwise(&a, &b).unwrap();
        assert_eq!(sn, pairwise(&b, &a).unwrap());
        assert_eq!(sn.len(), 83);
        assert_eq!(sn.split(' ').count(), 12);
        assert!(sn
            .split(' ')
            .all(|g| g.len() == 6 && g.bytes().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(pairwise(&[1u8; 31], &[2u8; 32]).is_err());
        assert!(pairwise(&[1u8; 32], &[2u8; 33]).is_err());
        assert!(pairwise(&[], &[2u8; 32]).is_err());
    }

    /// Same vector as the WASM crate's frozen KAT: a change here breaks cross-client checks.
    #[test]
    fn known_answer() {
        assert_eq!(
            pairwise(&[1u8; 32], &[2u8; 32]).unwrap(),
            "689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986"
        );
    }
}
