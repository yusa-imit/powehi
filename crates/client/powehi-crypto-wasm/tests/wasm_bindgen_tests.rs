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
use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use powehi_crypto_wasm::opaque::DefaultCipherSuite;
use powehi_crypto_wasm::wasm_exports::{
    ml_kem_768_drop_decap_key, ml_kem_768_drop_shared_secret, ml_kem_768_encap_v2,
    ml_kem_768_keygen_v2, mls_clear_session, opaque_login_finish, opaque_login_start,
    opaque_registration_finish, opaque_registration_start,
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

fn get_bytes_field(obj: &JsValue, field: &str) -> Vec<u8> {
    let val = Reflect::get(obj, &JsValue::from_str(field))
        .expect("field must be present in JsValue object");
    js_sys::Uint8Array::from(val).to_vec()
}

/// Minimal server-side OPAQUE simulation, delegating entirely to `opaque-ke`.
/// Duplicated (not shared) from `opaque.rs`'s own `#[cfg(test)] mod tests` —
/// that module is private to its own compilation unit, unreachable from this
/// separate integration-test binary. Test-only; never compiled into the
/// production WASM binary (this file only builds under `wasm-pack test`).
///
/// Scope note: this simulates the server using THIS crate's own
/// `DefaultCipherSuite` (`powehi_crypto_wasm::opaque`), not the real server
/// adapter's separately-declared `DefaultCipherSuite` in
/// `crates/adapters/outbound/powehi-opaque`. The two are currently
/// field-for-field identical (Ristretto255 + TripleDH/SHA-512 + Argon2id), so
/// a round trip here IS representative of a real client<->server exchange
/// today — but this test does NOT itself prove that cross-crate agreement;
/// a ciphersuite drift between the two crates is a pre-existing, separate gap
/// this diff does not close.
fn server_register(
    setup: &ServerSetup<DefaultCipherSuite>,
    identity: &[u8],
    client_request_bytes: &[u8],
) -> Vec<u8> {
    let request =
        RegistrationRequest::<DefaultCipherSuite>::deserialize(client_request_bytes).unwrap();
    ServerRegistration::<DefaultCipherSuite>::start(setup, request, identity)
        .unwrap()
        .message
        .serialize()
        .to_vec()
}

fn server_store_password_file(client_upload_bytes: &[u8]) -> Vec<u8> {
    let upload =
        RegistrationUpload::<DefaultCipherSuite>::deserialize(client_upload_bytes).unwrap();
    ServerRegistration::<DefaultCipherSuite>::finish(upload)
        .serialize()
        .to_vec()
}

fn server_login_start(
    setup: &ServerSetup<DefaultCipherSuite>,
    identity: &[u8],
    password_file_bytes: &[u8],
    client_request_bytes: &[u8],
) -> Vec<u8> {
    let mut rng = OsRng;
    let password_file =
        ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes).unwrap();
    let request =
        CredentialRequest::<DefaultCipherSuite>::deserialize(client_request_bytes).unwrap();
    let start = ServerLogin::start(
        &mut rng,
        setup,
        Some(password_file),
        request,
        identity,
        ServerLoginParameters::default(),
    )
    .unwrap();
    start.message.serialize().to_vec()
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

// ── OPAQUE password zeroize (real exported fn, real wasm32 execution) ──────────
//
// Cycle 396's crypto-reviewer non-blocking advisory A-3: no `#[wasm_bindgen_test]`
// coverage asserted the caller's password buffer is actually all-zero after each
// of the 4 OPAQUE exports returns. Native `cargo test` cannot close this gap —
// `wasm_exports.rs`'s own test module doc comment notes `js_sys` (used internally
// by `js_obj`/`bytes_js` to build the returned `JsValue`) panics outside a real
// wasm32 + JS-engine environment, so native tests call the inner `opaque::`
// functions instead, which bypass `PasswordScrubGuard` entirely (it only wraps
// the `#[wasm_bindgen]` exports in `wasm_exports.rs`, not `opaque.rs`). These
// tests call the actual exported functions directly, running as real wasm32
// code under `wasm-pack test --node`, where `js_sys` is fully functional.
//
// Coverage note (what this does NOT close): these tests call the exported
// functions as plain Rust (`opaque_registration_start(&mut password)`), not
// through the wasm-bindgen-generated JS glue (`pkg/*.js`'s `passArray8ToWasm0`
// malloc + `__wbg___wbindgen_copy_to_typed_array_*` copy-back) that a real
// browser/Comlink caller goes through — a plain Rust `&mut [u8]` call has no
// malloc'd linear-memory copy to begin with, so it cannot exercise the
// malloc-copy-then-copy-back ordering the JS glue performs. What it DOES prove:
// `PasswordScrubGuard`'s `Drop` reliably fires on every real exit path of the
// real exported function — success and error alike — when actually running in
// the wasm32 target with the real `js_obj`/`bytes_js` machinery in the body
// (not just reasoned about via compile-error probes, as cycle 396's review did).
// Closing the remaining JS-glue-copy-back gap needs either a JS-level assertion
// (e.g. a Vitest test loading the real WASM module directly, which needs a
// `wasm-pack build` step wired into the `vitest` CI job first — `app/src/wasm/`
// is a gitignored local-dev artifact, not built there today) or a
// wasm-bindgen-internals technique for invoking the generated JS wrapper from
// within a `#[wasm_bindgen_test]`; still open, candidate for a future cycle.

/// `opaque_registration_start` must zero the password buffer after a
/// successful call.
#[wasm_bindgen_test]
fn test_opaque_registration_start_zeroizes_password_on_success() {
    mls_clear_session();
    let mut password = b"correct horse battery staple".to_vec();

    let result = opaque_registration_start(&mut password);

    assert!(
        result.is_ok(),
        "registration_start must succeed with a well-formed password"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero after opaque_registration_start returns"
    );

    // Hygiene: this call left a live OPAQUE_REG session in the thread-local —
    // consistent with the file's existing convention of leaving no state
    // behind for the next test (cf. the KEM cap tests above).
    mls_clear_session();
}

/// `opaque_login_start` must zero the password buffer after a successful call.
#[wasm_bindgen_test]
fn test_opaque_login_start_zeroizes_password_on_success() {
    mls_clear_session();
    let mut password = b"correct horse battery staple".to_vec();

    let result = opaque_login_start(&mut password);

    assert!(
        result.is_ok(),
        "login_start must succeed with a well-formed password"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero after opaque_login_start returns"
    );

    mls_clear_session();
}

/// `opaque_registration_finish` must zero the password buffer after a
/// successful call — the harder case, since success requires a full
/// client<->server round trip (via the local `server_*` simulation helpers
/// above) rather than just a well-formed input.
#[wasm_bindgen_test]
fn test_opaque_registration_finish_zeroizes_password_on_success() {
    mls_clear_session();
    let mut rng = OsRng;
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    let identity = b"wasm-test-reg@powehi.test";

    let mut password = b"wasm-bindgen-test-password".to_vec();
    let start_result =
        opaque_registration_start(&mut password).expect("registration_start must succeed");
    let session_id = get_str_field(&start_result, "sessionId");
    let request_bytes = get_bytes_field(&start_result, "message");
    let server_response = server_register(&setup, identity, &request_bytes);

    // registration_start already zeroed `password` above — opaque-ke 4.0.1
    // requires the password again at finish (it re-runs the KSF), so refill it
    // with the same real value rather than reusing the now-zeroed buffer.
    password = b"wasm-bindgen-test-password".to_vec();
    let finish_result = opaque_registration_finish(&session_id, &mut password, &server_response);

    assert!(
        finish_result.is_ok(),
        "registration_finish must succeed given a valid server response"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero after opaque_registration_finish returns (success path)"
    );
}

/// `opaque_login_finish` must zero the password buffer after a successful
/// call — same round-trip shape as the registration_finish test above, plus
/// `server_store_password_file`/`server_login_start` to reach a valid
/// `CredentialResponse`.
#[wasm_bindgen_test]
fn test_opaque_login_finish_zeroizes_password_on_success() {
    mls_clear_session();
    let mut rng = OsRng;
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    let identity = b"wasm-test-login@powehi.test";

    let mut password = b"wasm-bindgen-test-password".to_vec();
    let reg_start =
        opaque_registration_start(&mut password).expect("registration_start must succeed");
    let reg_session_id = get_str_field(&reg_start, "sessionId");
    let reg_request = get_bytes_field(&reg_start, "message");
    let reg_response = server_register(&setup, identity, &reg_request);

    password = b"wasm-bindgen-test-password".to_vec();
    let reg_finish = opaque_registration_finish(&reg_session_id, &mut password, &reg_response)
        .expect("registration_finish must succeed");
    let upload = get_bytes_field(&reg_finish, "upload");
    let password_file = server_store_password_file(&upload);

    password = b"wasm-bindgen-test-password".to_vec();
    let login_start_result = opaque_login_start(&mut password).expect("login_start must succeed");
    let login_session_id = get_str_field(&login_start_result, "sessionId");
    let login_request = get_bytes_field(&login_start_result, "message");
    let login_response = server_login_start(&setup, identity, &password_file, &login_request);

    password = b"wasm-bindgen-test-password".to_vec();
    let login_finish_result =
        opaque_login_finish(&login_session_id, &mut password, &login_response);

    assert!(
        login_finish_result.is_ok(),
        "login_finish must succeed with the correct password and a valid server response"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero after opaque_login_finish returns (success path)"
    );
}

/// `opaque_registration_finish` must zero the password buffer even when the
/// call fails (unknown session id — the earliest possible error return, before
/// the `opaque::` call is ever reached), proving `PasswordScrubGuard` covers
/// error paths too, not just the success path above.
#[wasm_bindgen_test]
fn test_opaque_registration_finish_zeroizes_password_on_error() {
    mls_clear_session();
    let mut password = b"wasm-bindgen-test-password".to_vec();

    let result = opaque_registration_finish("nonexistent-session-id", &mut password, &[0u8; 32]);

    assert!(
        result.is_err(),
        "registration_finish with an unknown session id must return an error"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero even on the error path"
    );
}

/// Same invariant as above for `opaque_login_finish`.
#[wasm_bindgen_test]
fn test_opaque_login_finish_zeroizes_password_on_error() {
    mls_clear_session();
    let mut password = b"wasm-bindgen-test-password".to_vec();

    let result = opaque_login_finish("nonexistent-session-id", &mut password, &[0u8; 32]);

    assert!(
        result.is_err(),
        "login_finish with an unknown session id must return an error"
    );
    assert!(
        password.iter().all(|&b| b == 0),
        "password buffer must be all-zero even on the error path"
    );
}

/// Negative control the success-path tests above cannot provide: registers
/// with one real password, then attempts login with a DIFFERENT, genuinely
/// non-zero password of the SAME BYTE LENGTH — must be rejected client-side
/// (RFC 9807 MAC verification), AND the buffer must still be zeroed.
///
/// Why this matters beyond RFC compliance: a regression where
/// `PasswordScrubGuard` zeroizes EAGERLY — before the password ever reaches
/// `opaque-ke` — rather than on scope exit (after use) would make every one
/// of the 4 exports silently derive from an all-zero password regardless of
/// what the caller actually passed in. Under that regression, registration
/// and login would "agree" no matter what password string was used (both
/// always resolve to the same all-zero-derived secret), so every success-path
/// test above would stay green even though the password never mattered. This
/// test pins that a genuinely different password IS what reaches `opaque-ke`:
/// if the guard were scrubbing before use, this wrong-password login would
/// spuriously SUCCEED (since both sides would actually be zero-derived), and
/// `assert!(result.is_err())` below would fail.
///
/// The two passwords are deliberately padded to the SAME length (32 bytes
/// each). OPAQUE hashes the password bytes directly (no fixed-width digest
/// first), so two different-LENGTH all-zero buffers would still hash to two
/// different curve points and legitimately fail login even under the eager-
/// scrub bug above — silently defeating this test's purpose without the
/// equal-length constraint (caught by mutation-testing an earlier draft of
/// this test that used unequal-length passwords: it stayed green under the
/// eager-scrub mutation for the wrong reason).
#[wasm_bindgen_test]
fn test_opaque_login_finish_wrong_password_fails_and_zeroizes() {
    mls_clear_session();
    let mut rng = OsRng;
    let setup = ServerSetup::<DefaultCipherSuite>::new(&mut rng);
    let identity = b"wasm-test-wrong-pw@powehi.test";
    const PW_LEN: usize = 32;
    let real_password = [b'A'; PW_LEN];
    let different_password = [b'B'; PW_LEN];
    assert_eq!(
        real_password.len(),
        different_password.len(),
        "test setup invariant: both passwords must be the same length"
    );

    let mut password = real_password.to_vec();
    let reg_start =
        opaque_registration_start(&mut password).expect("registration_start must succeed");
    let reg_session_id = get_str_field(&reg_start, "sessionId");
    let reg_request = get_bytes_field(&reg_start, "message");
    let reg_response = server_register(&setup, identity, &reg_request);

    password = real_password.to_vec();
    let reg_finish = opaque_registration_finish(&reg_session_id, &mut password, &reg_response)
        .expect("registration_finish must succeed");
    let upload = get_bytes_field(&reg_finish, "upload");
    let password_file = server_store_password_file(&upload);

    // Login with a DIFFERENT, genuinely non-zero, SAME-LENGTH password.
    let mut wrong_password = different_password.to_vec();
    let login_start_result =
        opaque_login_start(&mut wrong_password).expect("login_start must succeed");
    let login_session_id = get_str_field(&login_start_result, "sessionId");
    let login_request = get_bytes_field(&login_start_result, "message");
    let login_response = server_login_start(&setup, identity, &password_file, &login_request);

    wrong_password = different_password.to_vec();
    let login_finish_result =
        opaque_login_finish(&login_session_id, &mut wrong_password, &login_response);

    assert!(
        login_finish_result.is_err(),
        "login with the wrong password must be rejected client-side — an \
         unexpected success here would mean PasswordScrubGuard is zeroing the \
         password before it reaches opaque-ke, not after"
    );
    assert!(
        wrong_password.iter().all(|&b| b == 0),
        "password buffer must be all-zero even on a wrong-password rejection"
    );
}
