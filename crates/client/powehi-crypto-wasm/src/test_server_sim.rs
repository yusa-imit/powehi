//! TEST-ONLY OPAQUE server simulation. **NEVER SHIP THIS MODULE.**
//!
//! Compiled only under the default-off `test-server-sim` Cargo feature, which
//! is passed by exactly one caller: the root `package.json` `build:wasm:node`
//! script (`wasm-pack build --target nodejs --out-dir pkg-node`, a gitignored
//! test-only artifact consumed by `app/src/workers/opaqueWasmZeroize.node.test.ts`).
//! The production build (`build:wasm`, `--target web --out-dir pkg`) passes no
//! `--features` flag at all, so none of the `#[wasm_bindgen]` exports below
//! exist in the artifact the browser loads. `cargo build --workspace` /
//! `cargo test` likewise never enable it.
//!
//! WHY THIS EXISTS (scope, mirroring the note above the OPAQUE zeroize tests in
//! `tests/wasm_bindgen_tests.rs`): asserting that `PasswordScrubGuard` zeroizes
//! the *caller's own JS `Uint8Array`* — i.e. that wasm-bindgen's generated glue
//! (`passArray8ToWasm0` malloc + `__wbg___wbindgen_copy_to_typed_array_*`
//! copy-back) actually propagates the scrub back across the boundary — requires
//! driving the real exports from JS. For `opaque_registration_finish` /
//! `opaque_login_finish` that means reaching their SUCCESS paths, which needs a
//! live OPAQUE server counterpart: the messages carry fresh `OsRng` ephemerals
//! on every call, so a pre-recorded server-response fixture can never validate.
//! `tests/wasm_bindgen_tests.rs` gets that counterpart for free by linking
//! `opaque-ke`'s server types into its own native test binary, but those helpers
//! are private to that binary and unreachable from the `--target nodejs` JS
//! artifact. This module re-exposes the same logic — the same `opaque-ke` server
//! types, the same `crate::opaque::DefaultCipherSuite` — behind JS-callable
//! wrappers so the Vitest suite can complete a real round trip.
//!
//! WHAT THIS IS NOT: not a server implementation, not a security boundary, not
//! reviewed for production properties. It performs no rate limiting, no identity
//! authentication, no persistence, and caps nothing (handle maps are unbounded —
//! irrelevant in a single-shot test process, unacceptable anywhere else). No
//! cryptographic primitive is implemented here; every operation delegates to the
//! audited `opaque-ke` crate, same as `src/opaque.rs`.
//!
//! Design note (deliberate, keeps the blast radius minimal even in the test
//! build): the server's long-term `ServerSetup` (OPRF seed + AKE keypair) and
//! the per-identity `ServerRegistration` password file NEVER cross the WASM-JS
//! boundary. They live in a thread-local keyed by an opaque string handle —
//! the same convention `wasm_exports.rs` uses for `KEM_DECAP_KEYS`. The only
//! bytes returned to JS are the two OPAQUE wire messages the client genuinely
//! must consume (`RegistrationResponse`, `CredentialResponse`).
//!
//! Every export is prefixed `__powehi_test_only_server_sim_` so its presence in
//! any shipped bundle is greppable and unmistakable. See also the
//! `cargo:warning` this crate's `build.rs` emits whenever the feature is on.

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use opaque_ke::rand::rngs::OsRng;
use opaque_ke::{
    CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
    ServerRegistration, ServerSetup,
};
use wasm_bindgen::prelude::*;

use crate::opaque::DefaultCipherSuite;

/// One simulated server: its long-term setup plus the password files it has
/// "stored", keyed by identity. Never leaves the WASM linear memory.
struct SimServer {
    setup: ServerSetup<DefaultCipherSuite>,
    password_files: HashMap<String, ServerRegistration<DefaultCipherSuite>>,
}

thread_local! {
    static SIM_SERVERS: RefCell<HashMap<String, SimServer>> = RefCell::new(HashMap::new());
}

static SIM_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_handle() -> String {
    format!(
        "test-server-sim-{}",
        SIM_COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn err(msg: &str) -> JsError {
    JsError::new(msg)
}

/// Create a fresh simulated OPAQUE server; returns its opaque handle.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__powehi_test_only_server_sim_new")]
pub fn test_only_server_sim_new() -> String {
    let mut rng = OsRng;
    let server = SimServer {
        setup: ServerSetup::<DefaultCipherSuite>::new(&mut rng),
        password_files: HashMap::new(),
    };
    let handle = next_handle();
    SIM_SERVERS.with(|s| s.borrow_mut().insert(handle.clone(), server));
    handle
}

/// Drop a simulated server and everything it holds.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__powehi_test_only_server_sim_drop")]
pub fn test_only_server_sim_drop(server_handle: &str) {
    SIM_SERVERS.with(|s| s.borrow_mut().remove(server_handle));
}

/// Server side of registration step 2: consume the client's
/// `RegistrationRequest` and return the serialized `RegistrationResponse`.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__powehi_test_only_server_sim_register")]
pub fn test_only_server_sim_register(
    server_handle: &str,
    identity: &str,
    registration_request: &[u8],
) -> Result<Vec<u8>, JsError> {
    let request = RegistrationRequest::<DefaultCipherSuite>::deserialize(registration_request)
        .map_err(|_| err("test-server-sim: malformed RegistrationRequest"))?;
    SIM_SERVERS.with(|servers| {
        let servers = servers.borrow();
        let server = servers
            .get(server_handle)
            .ok_or_else(|| err("test-server-sim: unknown server handle"))?;
        let start = ServerRegistration::<DefaultCipherSuite>::start(
            &server.setup,
            request,
            identity.as_bytes(),
        )
        .map_err(|_| err("test-server-sim: ServerRegistration::start failed"))?;
        Ok(start.message.serialize().to_vec())
    })
}

/// Server side of registration step 4: consume the client's
/// `RegistrationUpload` and retain the resulting password file under `identity`.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__powehi_test_only_server_sim_store_password_file")]
pub fn test_only_server_sim_store_password_file(
    server_handle: &str,
    identity: &str,
    registration_upload: &[u8],
) -> Result<(), JsError> {
    let upload = RegistrationUpload::<DefaultCipherSuite>::deserialize(registration_upload)
        .map_err(|_| err("test-server-sim: malformed RegistrationUpload"))?;
    let password_file = ServerRegistration::<DefaultCipherSuite>::finish(upload);
    SIM_SERVERS.with(|servers| {
        let mut servers = servers.borrow_mut();
        let server = servers
            .get_mut(server_handle)
            .ok_or_else(|| err("test-server-sim: unknown server handle"))?;
        server
            .password_files
            .insert(identity.to_owned(), password_file);
        Ok(())
    })
}

/// Server side of login step 2: consume the client's `CredentialRequest` and
/// return the serialized `CredentialResponse` (KE2).
///
/// The `ServerLogin` state is intentionally dropped rather than retained: the
/// invariant under test is entirely client-side (the caller's password buffer
/// after `opaque_login_finish` returns), so the server never needs to consume
/// the client's `CredentialFinalization`. Cross-checking the AKE session keys
/// end-to-end is already covered natively by `opaque.rs`'s
/// `test_opaque_registration_login_roundtrip`.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__powehi_test_only_server_sim_login_start")]
pub fn test_only_server_sim_login_start(
    server_handle: &str,
    identity: &str,
    credential_request: &[u8],
) -> Result<Vec<u8>, JsError> {
    let request = CredentialRequest::<DefaultCipherSuite>::deserialize(credential_request)
        .map_err(|_| err("test-server-sim: malformed CredentialRequest"))?;
    SIM_SERVERS.with(|servers| {
        let servers = servers.borrow();
        let server = servers
            .get(server_handle)
            .ok_or_else(|| err("test-server-sim: unknown server handle"))?;
        let password_file = server
            .password_files
            .get(identity)
            .ok_or_else(|| err("test-server-sim: no password file for identity"))?
            .clone();
        let mut rng = OsRng;
        let start = ServerLogin::start(
            &mut rng,
            &server.setup,
            Some(password_file),
            request,
            identity.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| err("test-server-sim: ServerLogin::start failed"))?;
        Ok(start.message.serialize().to_vec())
    })
}

/// Loud runtime marker: present in a build **only** when the test-only
/// `test-server-sim` feature was enabled. The Vitest suite asserts it exists
/// (positive control that the feature actually propagated through wasm-pack);
/// its absence from the production `pkg/` artifact is the corresponding
/// negative control.
///
/// TEST-ONLY — see the module doc comment.
#[wasm_bindgen(js_name = "__POWEHI_TEST_SERVER_SIM_BUILD_DO_NOT_SHIP")]
pub fn powehi_test_server_sim_build_marker() -> String {
    "powehi-crypto-wasm was built with the TEST-ONLY `test-server-sim` feature. \
     This artifact must never be served to a browser."
        .to_owned()
}
