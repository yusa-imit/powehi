// WASM crypto worker — Phase 2 implementation.
// Uses openmls (RFC 9420) + opaque-ke (RFC 9807) only; no homegrown crypto.
//
// The crate compiles on both the native host target (for `cargo test`) and
// wasm32 (for the browser worker). Library code never uses `unwrap()`/`expect()`
// and never logs plaintext, PII, or ciphertext.

use wasm_bindgen::prelude::*;

pub mod kem;
pub mod kem_credential;
pub mod media;
pub mod mls_group;
pub mod opaque;
pub mod recovery;
pub mod wasm_exports;

#[wasm_bindgen]
pub fn version() -> String {
    format!("powehi-crypto-wasm {}", env!("CARGO_PKG_VERSION"))
}

/// Runs once when the WASM module is instantiated (before any other export is
/// callable). Installs `console_error_panic_hook` so a panic — e.g. deep
/// inside openmls's storage read path on a corrupt state blob — surfaces to
/// the browser console as a real message + location instead of an opaque
/// "unreachable executed" trap. Diagnostics only; never touches key material.
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    #[cfg(target_arch = "wasm32")]
    console_error_panic_hook::set_once();
}
