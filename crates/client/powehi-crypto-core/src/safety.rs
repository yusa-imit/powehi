//! Pairwise and group Safety Numbers (prd.md §5.6), shared by the WASM worker and the CLI.
//!
//! Moved verbatim from `powehi-crypto-wasm`; the known-answer test pins the construction so
//! both clients keep producing the same number for the same keys.

use sha2::{Digest, Sha512};

/// Domain-separation prefix for the safety number derivation (prd.md §5.6).
/// Pinning the construction version here makes any future format change detectable.
const SAFETY_NUMBER_DOMAIN: &[u8] = b"powehi-safety-number-v1";

/// Domain separator of the group construction: a different prefix keeps a group number from
/// ever colliding with a pairwise one over the same keys. Frozen: it is the construction the
/// web client already shows, so the CLI must produce the same number for the same roster.
const GROUP_SAFETY_NUMBER_DOMAIN: &[u8] = b"powehi-group-safety-number-v1";

/// Most members a group safety number covers (bounds the hash input). Callers must bound the
/// collection itself, e.g. `group.members().take(GROUP_MAX_MEMBERS + 1)`.
pub const GROUP_MAX_MEMBERS: usize = 512;

/// Why [`group`] refused a roster. `TooMany` means "cannot be verified", not tampering; the
/// UI must render it apart from a mismatch. `DuplicateKey` breaks RFC 9420 §7.3 (unique
/// `signature_key`) and must be treated as an anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GroupSafetyError {
    #[error("group safety number requires at least 2 members")]
    TooFew,
    #[error("group safety number: too many members")]
    TooMany,
    #[error("safety number keys must be exactly 32 bytes")]
    BadKeyLength,
    #[error("group safety number keys must be distinct")]
    DuplicateKey,
}

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

/// Safety number of a group (prd.md §5.6, 8.17): the digest of every member's 32-byte Ed25519
/// signature key, so all members who see the same roster read the same number. Order-independent.
/// It fingerprints the roster only: no group id, epoch or credential label, so it does not
/// detect a fork that keeps the same members (that is the epoch authenticator's job).
///
/// Construction: SHA-512(DOMAIN || 0x00 || count u32 BE || (len u32 BE || key)...) over the
/// keys sorted lexicographically. Fails closed on fewer than 2 keys, more than
/// [`GROUP_MAX_MEMBERS`], a key that is not 32 bytes, or a duplicate key.
///
/// Caller contract: pass the keys of the local, active ratchet tree (own leaf included), never
/// a server-reported list; choose pairwise vs group by conversation kind, not member count.
pub fn group(keys: &[&[u8]]) -> Result<String, GroupSafetyError> {
    if keys.len() < 2 {
        return Err(GroupSafetyError::TooFew);
    }
    if keys.len() > GROUP_MAX_MEMBERS {
        return Err(GroupSafetyError::TooMany);
    }
    if keys.iter().any(|k| k.len() != 32) {
        return Err(GroupSafetyError::BadKeyLength);
    }
    let mut sorted: Vec<&[u8]> = keys.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(GroupSafetyError::DuplicateKey);
    }
    let mut h = Sha512::new();
    h.update(GROUP_SAFETY_NUMBER_DOMAIN);
    h.update([0u8]);
    h.update((sorted.len() as u32).to_be_bytes());
    for key in sorted {
        h.update((key.len() as u32).to_be_bytes());
        h.update(key);
    }
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

    #[test]
    fn group_is_order_independent_and_distinct_from_pairwise() {
        let (a, b, c) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let sn = group(&[&a, &b, &c]).unwrap();
        assert_eq!(sn, group(&[&c, &a, &b]).unwrap());
        assert_eq!(sn.len(), 83);
        assert_ne!(sn, group(&[&a, &b]).unwrap());
        assert_ne!(group(&[&a, &b]).unwrap(), pairwise(&a, &b).unwrap());
        assert_ne!(sn, group(&[&a, &b, &[4u8; 32]]).unwrap());
    }

    #[test]
    fn group_rejects_bad_rosters() {
        let (a, b) = ([1u8; 32], [2u8; 32]);
        assert!(group(&[]).is_err());
        assert!(group(&[&a]).is_err());
        assert!(group(&[&a, &a]).is_err());
        assert!(group(&[&a, &b, &a]).is_err());
        assert!(group(&[&a, &[2u8; 31]]).is_err());
        let keys: Vec<[u8; 32]> = (0..=GROUP_MAX_MEMBERS as u32)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        assert!(group(&refs).is_err());
        assert!(group(&refs[..GROUP_MAX_MEMBERS]).is_ok());
    }

    /// Same vector as the WASM crate's frozen group KAT: a change here breaks cross-client checks.
    #[test]
    fn group_known_answer() {
        let sn = group(&[&[0x33u8; 32], &[0x22u8; 32], &[0x11u8; 32]]).unwrap();
        assert_eq!(
            sn,
            "096245 143897 685064 159306 343313 225158 468638 270220 280240 781420 559783 744730"
        );
    }

    #[test]
    fn group_errors_are_typed() {
        let a = [1u8; 32];
        assert_eq!(group(&[&a]), Err(GroupSafetyError::TooFew));
        assert_eq!(group(&[&a, &a]), Err(GroupSafetyError::DuplicateKey));
        assert_eq!(
            group(&[&a, &[2u8; 33]]),
            Err(GroupSafetyError::BadKeyLength)
        );
        assert_eq!(
            group(&[&a, &[2u8; 31]]),
            Err(GroupSafetyError::BadKeyLength)
        );
        let keys: Vec<[u8; 32]> = (0..=GROUP_MAX_MEMBERS as u32)
            .map(|i| {
                let mut k = [0u8; 32];
                k[..4].copy_from_slice(&i.to_be_bytes());
                k
            })
            .collect();
        let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
        assert_eq!(group(&refs), Err(GroupSafetyError::TooMany));
        // The web client matches this exact string to render "too many members".
        assert_eq!(
            GroupSafetyError::TooMany.to_string(),
            "group safety number: too many members"
        );
    }

    proptest::proptest! {
        #[test]
        fn pairwise_is_symmetric(a in proptest::array::uniform32(0u8..), b in proptest::array::uniform32(0u8..)) {
            proptest::prop_assert_eq!(pairwise(&a, &b), pairwise(&b, &a));
        }

        #[test]
        fn group_ignores_order_and_detects_a_swapped_member(
            keys in proptest::collection::hash_set(proptest::array::uniform32(0u8..), 3..12),
            replacement in proptest::array::uniform32(0u8..),
            rot in 0usize..12,
        ) {
            let mut keys: Vec<[u8; 32]> = keys.into_iter().collect();
            keys.sort_unstable();
            let refs: Vec<&[u8]> = keys.iter().map(|k| k.as_slice()).collect();
            let base = group(&refs).unwrap();
            let mut rotated = refs.clone();
            rotated.rotate_left(rot % refs.len());
            proptest::prop_assert_eq!(&base, &group(&rotated).unwrap());
            if !keys.contains(&replacement) {
                let mut swapped = refs.clone();
                swapped[0] = replacement.as_slice();
                proptest::prop_assert_ne!(&base, &group(&swapped).unwrap());
            }
        }
    }
}
