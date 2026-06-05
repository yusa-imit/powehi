//! wasm-bindgen integration tests — KEM handle cap as JsError (YELLOW-2, cycle 97).
//!
//! These tests verify that the wasm-bindgen exports return a proper JavaScript
//! Error at the JS boundary when the KEM handle cap is exceeded (ADR-0003
//! Phase C, Y-8 fix).  They run only under wasm32 via wasm-pack:
//!
//!   wasm-pack test --node crates/client/powehi-crypto-wasm
//!
//! Unlike the native unit tests in wasm_exports.rs (which test the pure
//! `kem_cap_check` helper directly), these tests exercise the full wasm-bindgen
//! call path through `map_err(js_err)` and verify that the resulting error is a
//! real JavaScript Error object with the expected message string.

use js_sys::Reflect;
use powehi_crypto_wasm::wasm_exports::{
    ml_kem_768_drop_decap_key, ml_kem_768_drop_shared_secret, ml_kem_768_encap_v2,
    ml_kem_768_keygen_v2, mls_clear_session,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

// ── Helpers ────────────────────────────────────────────────────────────────────

fn get_str_field(obj: &JsValue, field: &str) -> String {
    Reflect::get(obj, &JsValue::from_str(field))
        .expect("field must be present in JsValue object")
        .as_string()
        .expect("field value must be a string")
}

/// Extract the message string from a JsError.
///
/// `JsError` wraps a JavaScript Error object; use `js_sys::Error::message()`
/// to read the message rather than relying on `Display` (not guaranteed).
fn js_err_message(err: JsError) -> String {
    use wasm_bindgen::JsCast as _;
    JsValue::from(err)
        .dyn_into::<js_sys::Error>()
        .map(|e| e.message().as_string().unwrap_or_default())
        .unwrap_or_else(|v| format!("(non-Error JsValue: {v:?})"))
}

// ── KEM keygen_v2 cap test ─────────────────────────────────────────────────────

/// `ml_kem_768_keygen_v2` must return a JsError when KEM_DECAP_KEYS is full.
///
/// Fills KEM_DECAP_KEYS to MAX_KEM_HANDLES (256) via repeated keygen calls,
/// then asserts the 257th call returns `Err(JsError)` containing "cap exceeded".
/// Verifies the full wasm-bindgen export path through `map_err(js_err)`.
#[wasm_bindgen_test]
fn test_keygen_v2_cap_exceeded_returns_js_error() {
    mls_clear_session();

    // Fill KEM_DECAP_KEYS to the 256-entry cap.
    let mut dk_handles: Vec<String> = Vec::with_capacity(256);
    for _ in 0..256 {
        let result = ml_kem_768_keygen_v2().expect("keygen_v2 must succeed below cap");
        dk_handles.push(get_str_field(&result, "decapKeyHandle"));
    }

    // 257th call must fail with a JsError.
    let err_result = ml_kem_768_keygen_v2();
    assert!(
        err_result.is_err(),
        "ml_kem_768_keygen_v2 must return Err when KEM_DECAP_KEYS cap (256) is exceeded"
    );
    let msg = js_err_message(err_result.unwrap_err());
    assert!(
        msg.contains("cap exceeded"),
        "JsError message must contain 'cap exceeded', got: {msg}"
    );

    // Drop all handles so the thread-local is clean for subsequent tests.
    for h in &dk_handles {
        ml_kem_768_drop_decap_key(h);
    }
}

// ── KEM encap_v2 cap test ──────────────────────────────────────────────────────

/// `ml_kem_768_encap_v2` must return a JsError when KEM_SHARED_SECRETS is full.
///
/// Fills KEM_SHARED_SECRETS to MAX_KEM_HANDLES (256) via repeated encap calls,
/// then asserts the 257th call returns `Err(JsError)` containing "cap exceeded".
/// Uses the same `KEM_SHARED_SECRETS` map that `ml_kem_768_decap_v2` also checks,
/// so this test also covers the decap_v2 cap path.
#[wasm_bindgen_test]
fn test_encap_v2_cap_exceeded_returns_js_error() {
    mls_clear_session();

    // Generate one keypair to obtain a valid encap key for repeated encapsulations.
    let kp = ml_kem_768_keygen_v2().expect("keygen_v2 must succeed");
    let encap_key: Vec<u8> = {
        let ek_js =
            Reflect::get(&kp, &JsValue::from_str("encapKey")).expect("encapKey must be present");
        js_sys::Uint8Array::from(ek_js).to_vec()
    };

    // Fill KEM_SHARED_SECRETS to the 256-entry cap.
    let mut ss_handles: Vec<String> = Vec::with_capacity(256);
    for _ in 0..256 {
        let result = ml_kem_768_encap_v2(&encap_key).expect("encap_v2 must succeed below cap");
        ss_handles.push(get_str_field(&result, "sharedSecretHandle"));
    }

    // 257th call must fail with a JsError.
    let err_result = ml_kem_768_encap_v2(&encap_key);
    assert!(
        err_result.is_err(),
        "ml_kem_768_encap_v2 must return Err when KEM_SHARED_SECRETS cap (256) is exceeded"
    );
    let msg = js_err_message(err_result.unwrap_err());
    assert!(
        msg.contains("cap exceeded"),
        "JsError message must contain 'cap exceeded', got: {msg}"
    );

    // Drop all shared-secret handles.
    for h in &ss_handles {
        ml_kem_768_drop_shared_secret(h);
    }
    // mls_clear_session also drops the decap key created by keygen above.
    mls_clear_session();
}
