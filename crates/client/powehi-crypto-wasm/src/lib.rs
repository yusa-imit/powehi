// WASM crypto worker — Phase 2 implementation.
// Uses openmls (RFC 9420) + opaque-ke (RFC 9807) only; no homegrown crypto.
//
// The crate compiles on both the native host target (for `cargo test`) and
// wasm32 (for the browser worker). Library code never uses `unwrap()`/`expect()`
// and never logs plaintext, PII, or ciphertext.

use wasm_bindgen::prelude::*;

pub mod kem;
pub mod kem_credential;
pub mod mls_group;
pub mod opaque;
pub mod recovery;
pub mod wasm_exports;

#[wasm_bindgen]
pub fn version() -> String {
    format!("powehi-crypto-wasm {}", env!("CARGO_PKG_VERSION"))
}
