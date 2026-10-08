//! Pure-Rust crypto core shared by the WASM worker and the CLI client.
//!
//! MLS (openmls, RFC 9420), OPAQUE (opaque-ke, RFC 9807), ML-KEM-768, media
//! AEAD and recovery-phrase derivation. No `wasm-bindgen`/`js-sys` here: the
//! browser glue lives in `powehi-crypto-wasm`, which re-exports these modules.
//! Library code never uses `unwrap()`/`expect()` and never logs plaintext,
//! PII, or ciphertext.

pub mod kem;
pub mod kem_credential;
pub mod media;
pub mod mls_group;
pub mod opaque;
pub mod recovery;
