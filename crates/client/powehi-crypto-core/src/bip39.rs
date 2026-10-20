//! BIP-39 mnemonic codes on RustCrypto primitives only (`sha2`, `pbkdf2`, `hmac`).
//!
//! Replaces the `bip39` crate (issue #13, Phase 8 item 8.2). Only the encoding
//! lives here: entropy ↔ words with the SHA-256 checksum, and the PBKDF2-
//! HMAC-SHA512 seed. The hash and KDF are RustCrypto's; the English wordlist
//! is the official BIP-39 list (SHA-256 pinned by a test).
//!
//! The entropy buffer is `Zeroizing`; `Debug` never prints it.
//!
//! **Stack-residue caveat:** `pbkdf2`/`hmac` keep the keyed HMAC state and the last
//! U block on the stack, and `Sha256::digest` leaves its block buffer there; none of
//! these implement `Zeroize`. The salt is public, so the keyed state is as sensitive
//! as the phrase. The returned seed and the stored entropy are wiped on drop; the
//! stack residue is the same as with the former `bip39` crate.

use core::fmt;

use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

const WORDLIST_TXT: &str = include_str!("bip39_english.txt");
const WORD_COUNT: usize = 2048;
const BITS_PER_WORD: usize = 11;
const PBKDF2_ROUNDS: u32 = 2048;
const MAX_ENTROPY_BYTES: usize = 32;

/// Reasons a phrase or entropy buffer is rejected. Content-free by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Bip39Error {
    /// Entropy length is not 16, 20, 24, 28 or 32 bytes.
    #[error("invalid entropy length")]
    EntropyLength,
    /// Word count is not 12, 15, 18, 21 or 24.
    #[error("invalid word count")]
    WordCount,
    /// A word is not in the English wordlist.
    #[error("unknown word")]
    UnknownWord,
    /// The checksum bits do not match the entropy.
    #[error("bad checksum")]
    Checksum,
}

/// A validated BIP-39 mnemonic (English), stored as its entropy.
pub struct Mnemonic {
    entropy: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Mnemonic(..)")
    }
}

fn wordlist() -> impl Iterator<Item = &'static str> {
    WORDLIST_TXT.lines()
}

fn word_at(index: usize) -> &'static str {
    assert!(index < WORD_COUNT, "word index out of range");
    wordlist().nth(index).unwrap_or("")
}

fn word_index(word: &str) -> Option<usize> {
    wordlist().position(|w| w == word)
}

fn checksum_bits(entropy: &[u8]) -> u8 {
    Sha256::digest(entropy)[0]
}

fn entropy_len_ok(len: usize) -> bool {
    matches!(len, 16 | 20 | 24 | 28 | 32)
}

impl Mnemonic {
    /// Build a mnemonic from 16/20/24/28/32 bytes of entropy.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, Bip39Error> {
        if !entropy_len_ok(entropy.len()) {
            return Err(Bip39Error::EntropyLength);
        }
        Ok(Self {
            entropy: Zeroizing::new(entropy.to_vec()),
        })
    }

    /// Parse a whitespace-separated phrase; words must match the list exactly
    /// (lowercase), and the checksum must verify.
    pub fn parse_normalized(phrase: &str) -> Result<Self, Bip39Error> {
        let mut bits = Zeroizing::new(Vec::<bool>::with_capacity(24 * BITS_PER_WORD));
        let mut words = 0usize;
        for word in phrase.split_whitespace() {
            words += 1;
            if words > 24 {
                return Err(Bip39Error::WordCount);
            }
            let index = word_index(word).ok_or(Bip39Error::UnknownWord)?;
            for shift in (0..BITS_PER_WORD).rev() {
                bits.push((index >> shift) & 1 == 1);
            }
        }
        if words < 12 || !words.is_multiple_of(3) {
            return Err(Bip39Error::WordCount);
        }
        let entropy_bits = words * BITS_PER_WORD * 32 / 33;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
        for (i, bit) in bits[..entropy_bits].iter().enumerate() {
            entropy[i / 8] |= u8::from(*bit) << (7 - i % 8);
        }
        let cs_len = words * BITS_PER_WORD - entropy_bits;
        let expected = checksum_bits(&entropy);
        let got = bits[entropy_bits..]
            .iter()
            .fold(0u8, |acc, b| (acc << 1) | u8::from(*b));
        if got != expected >> (8 - cs_len) {
            return Err(Bip39Error::Checksum);
        }
        assert!(entropy.len() <= MAX_ENTROPY_BYTES);
        Ok(Self { entropy })
    }

    /// The words, in order.
    pub fn words(&self) -> impl Iterator<Item = &'static str> {
        let entropy_bits = self.entropy.len() * 8;
        let cs_len = entropy_bits / 32;
        let total = (entropy_bits + cs_len) / BITS_PER_WORD;
        let cs = checksum_bits(&self.entropy);
        let bit = move |i: usize, entropy: &[u8]| -> usize {
            if i < entropy_bits {
                usize::from((entropy[i / 8] >> (7 - i % 8)) & 1)
            } else {
                usize::from((cs >> (7 - (i - entropy_bits))) & 1)
            }
        };
        let entropy = self.entropy.clone();
        (0..total).map(move |w| {
            let index = (0..BITS_PER_WORD).fold(0usize, |acc, b| {
                (acc << 1) | bit(w * BITS_PER_WORD + b, &entropy)
            });
            word_at(index)
        })
    }

    /// PBKDF2-HMAC-SHA512 seed (2048 rounds, salt `"mnemonic"`), empty passphrase.
    pub fn to_seed(&self) -> Zeroizing<[u8; 64]> {
        self.to_seed_with_passphrase("")
    }

    fn to_seed_with_passphrase(&self, passphrase: &str) -> Zeroizing<[u8; 64]> {
        let mut sentence = Zeroizing::new(String::with_capacity(256));
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                sentence.push(' ');
            }
            sentence.push_str(w);
        }
        let mut salt = Zeroizing::new(String::from("mnemonic"));
        salt.push_str(passphrase);
        let mut seed = Zeroizing::new([0u8; 64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            sentence.as_bytes(),
            salt.as_bytes(),
            PBKDF2_ROUNDS,
            seed.as_mut(),
        );
        seed
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, w) in self.words().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(w)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex_of(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn wordlist_is_the_official_english_list() {
        assert_eq!(wordlist().count(), WORD_COUNT);
        let digest = Sha256::digest(WORDLIST_TXT.as_bytes());
        assert_eq!(
            hex_of(&digest),
            "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
        );
    }

    /// Official BIP-39 vectors (Trezor `vectors.json`, passphrase "TREZOR").
    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
    ];

    #[test]
    fn official_vectors_entropy_to_mnemonic_to_seed() {
        for (entropy, phrase, seed) in VECTORS {
            let m = Mnemonic::from_entropy(&hex(entropy)).unwrap();
            assert_eq!(m.to_string(), *phrase);
            assert_eq!(hex_of(&*m.to_seed_with_passphrase("TREZOR")), *seed);
            let parsed = Mnemonic::parse_normalized(phrase).unwrap();
            assert_eq!(*parsed.entropy, hex(entropy));
        }
    }

    #[test]
    fn eighteen_word_vector() {
        let m = Mnemonic::from_entropy(&[0x7f; 24]).unwrap();
        assert_eq!(
            m.to_string(),
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will"
        );
        assert_eq!(
            hex_of(&*m.to_seed_with_passphrase("TREZOR")),
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd"
        );
    }

    /// Empty-passphrase seeds of a 24-word (production length) and an 18-word phrase, captured
    /// from the former `bip39 = 2.2.2` crate before it was removed.
    #[test]
    fn empty_passphrase_seed_matches_former_crate() {
        let art = format!("{} art", "abandon ".repeat(23).trim_end());
        let legal = "legal winner thank year wave sausage worth useful legal winner thank year \
                     wave sausage worth useful legal will";
        let cases = [
            (art.as_str(), "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"),
            (legal, "b059400ce0f55498a5527667e77048bb482ff6daa16c37b4b9e8af70c85b3f4df588004f19812a1a027c9a51e5e94259a560268e91cd10e206451a129826e740"),
        ];
        for (phrase, seed) in cases {
            let m = Mnemonic::parse_normalized(phrase).unwrap();
            assert_eq!(hex_of(&*m.to_seed()), seed);
        }
    }

    proptest::proptest! {
        #[test]
        fn entropy_words_parse_round_trip(
            len_idx in 0usize..5,
            bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 32),
        ) {
            let len = [16usize, 20, 24, 28, 32][len_idx];
            let m = Mnemonic::from_entropy(&bytes[..len]).unwrap();
            let phrase = m.to_string();
            proptest::prop_assert_eq!(phrase.split(' ').count(), len * 3 / 4);
            let parsed = Mnemonic::parse_normalized(&phrase).unwrap();
            proptest::prop_assert_eq!(&*parsed.entropy, &bytes[..len]);
        }
    }

    #[test]
    fn bad_checksum_is_a_typed_error() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";
        assert_eq!(
            Mnemonic::parse_normalized(bad).unwrap_err(),
            Bip39Error::Checksum
        );
    }

    #[test]
    fn unknown_word_and_bad_counts_are_typed_errors() {
        assert_eq!(
            Mnemonic::parse_normalized("invalid phrase that is not bip39").unwrap_err(),
            Bip39Error::UnknownWord
        );
        assert_eq!(
            Mnemonic::parse_normalized("abandon abandon").unwrap_err(),
            Bip39Error::WordCount
        );
        let long = "abandon ".repeat(25);
        assert_eq!(
            Mnemonic::parse_normalized(&long).unwrap_err(),
            Bip39Error::WordCount
        );
        assert_eq!(
            Mnemonic::from_entropy(&[0u8; 15]).unwrap_err(),
            Bip39Error::EntropyLength
        );
    }

    #[test]
    fn debug_does_not_print_words() {
        let m = Mnemonic::from_entropy(&[0u8; 32]).unwrap();
        assert!(!format!("{m:?}").contains("abandon"));
    }
}
