// WASM crypto worker — Phase 2 implementation.
// Uses openmls + opaque-ke only; no homegrown crypto.

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn version() -> String {
    format!("powehi-crypto-wasm {}", env!("CARGO_PKG_VERSION"))
}
