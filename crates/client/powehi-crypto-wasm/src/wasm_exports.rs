// wasm-bindgen exports for the Comlink crypto worker.
//
// All functions are exported via #[wasm_bindgen] and are callable from the
// browser worker thread through the Comlink proxy defined in
// app/src/workers/crypto.worker.ts.
//
// State lifetime: thread_local! storage survives for the worker thread's
// lifetime (WASM is single-threaded). State is lost if the worker is
// terminated and restarted; durable persistence is handled in Phase 4
// (Dexie encrypted storage).
//
// Security: no plaintext, password, key material, or ciphertext is ever
// included in an error message (rule: no-plaintext-logging).

use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use js_sys::{Object, Reflect, Uint8Array};
use opaque_ke::rand::rngs::OsRng;
use openmls::prelude::{tls_codec::Deserialize as _, *};
use openmls_rust_crypto::OpenMlsRustCrypto;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::mls_group::{
    add_member, create_group, decrypt_message, encrypt_message, generate_identity,
    generate_key_package, join_group, Identity,
};
use crate::opaque::{self, DefaultCipherSuite, EXPORT_KEY_LEN};

// ── ID generation ──────────────────────────────────────────────────────────────

static SESSION_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_id() -> String {
    SESSION_COUNTER.fetch_add(1, Ordering::Relaxed).to_string()
}

// ── Thread-local state ─────────────────────────────────────────────────────────

struct OpaqueRegSession {
    state: opaque_ke::ClientRegistration<DefaultCipherSuite>,
}

struct OpaqueLoginSession {
    state: opaque_ke::ClientLogin<DefaultCipherSuite>,
}

/// In-memory context for one MLS identity: the identity material, the
/// RustCrypto provider (key store), and all groups this identity belongs to.
struct MlsContext {
    identity: Identity,
    provider: OpenMlsRustCrypto,
    groups: HashMap<String, MlsGroup>,
}

thread_local! {
    static OPAQUE_REG:   RefCell<HashMap<String, OpaqueRegSession>>   = RefCell::new(HashMap::new());
    static OPAQUE_LOGIN: RefCell<HashMap<String, OpaqueLoginSession>> = RefCell::new(HashMap::new());
    static MLS_CTX:      RefCell<HashMap<String, MlsContext>>         = RefCell::new(HashMap::new());
}

// ── JS object helpers ──────────────────────────────────────────────────────────

fn js_obj(fields: &[(&str, JsValue)]) -> Result<JsValue, JsError> {
    let obj = Object::new();
    for (key, val) in fields {
        Reflect::set(&obj, &JsValue::from_str(key), val)
            .map_err(|_| JsError::new("js object construction failed"))?;
    }
    Ok(obj.into())
}

fn bytes_js(b: &[u8]) -> JsValue {
    Uint8Array::from(b).into()
}

fn js_err(msg: &str) -> JsError {
    JsError::new(msg)
}

// ── OPAQUE exports ─────────────────────────────────────────────────────────────

/// Start OPAQUE registration (client step 1).
///
/// Returns `{ sessionId: string, message: Uint8Array }`.
/// Send `message` (RegistrationRequest) to the server.
/// Pass `sessionId` to `opaque_registration_finish`.
#[wasm_bindgen]
pub fn opaque_registration_start(password: &[u8]) -> Result<JsValue, JsError> {
    let mut rng = OsRng;
    let (state, message) =
        opaque::registration_start(password, &mut rng).map_err(|e| js_err(&e.to_string()))?;
    let session_id = next_id();
    OPAQUE_REG.with(|s| {
        s.borrow_mut()
            .insert(session_id.clone(), OpaqueRegSession { state });
    });
    js_obj(&[
        ("sessionId", JsValue::from_str(&session_id)),
        ("message", bytes_js(&message)),
    ])
}

/// Finish OPAQUE registration (client step 3).
///
/// Returns `{ exportKey: Uint8Array, upload: Uint8Array }`.
/// Send `upload` (RegistrationUpload) to the server.
/// `exportKey` is the 32-byte durable key for wrapping local key material.
/// The session is consumed: calling again with the same `sessionId` returns an error.
#[wasm_bindgen]
pub fn opaque_registration_finish(
    session_id: &str,
    password: &[u8],
    server_response: &[u8],
) -> Result<JsValue, JsError> {
    let state = OPAQUE_REG
        .with(|s| s.borrow_mut().remove(session_id))
        .ok_or_else(|| js_err("unknown opaque registration session"))?
        .state;
    let mut rng = OsRng;
    let (result, upload) = opaque::registration_finish(state, password, server_response, &mut rng)
        .map_err(|e| js_err(&e.to_string()))?;
    // Zeroizing ensures the Rust-side copy is wiped from linear memory on drop.
    let export_key = Zeroizing::new(result.export_key[..EXPORT_KEY_LEN].to_vec());
    js_obj(&[
        ("exportKey", bytes_js(&export_key)),
        ("upload", bytes_js(&upload)),
    ])
}

/// Start OPAQUE login (client step 1).
///
/// Returns `{ sessionId: string, message: Uint8Array }`.
/// Send `message` (CredentialRequest) to the server.
#[wasm_bindgen]
pub fn opaque_login_start(password: &[u8]) -> Result<JsValue, JsError> {
    let mut rng = OsRng;
    let (state, message) =
        opaque::login_start(password, &mut rng).map_err(|e| js_err(&e.to_string()))?;
    let session_id = next_id();
    OPAQUE_LOGIN.with(|s| {
        s.borrow_mut()
            .insert(session_id.clone(), OpaqueLoginSession { state });
    });
    js_obj(&[
        ("sessionId", JsValue::from_str(&session_id)),
        ("message", bytes_js(&message)),
    ])
}

/// Finish OPAQUE login (client step 3).
///
/// Returns `{ exportKey: Uint8Array, finalization: Uint8Array }`.
/// Send `finalization` (CredentialFinalization) to the server.
/// Wrong password returns an Err — never produces a key on failure.
/// The session is consumed.
#[wasm_bindgen]
pub fn opaque_login_finish(
    session_id: &str,
    password: &[u8],
    server_response: &[u8],
) -> Result<JsValue, JsError> {
    let state = OPAQUE_LOGIN
        .with(|s| s.borrow_mut().remove(session_id))
        .ok_or_else(|| js_err("unknown opaque login session"))?
        .state;
    let result = opaque::login_finish_full(state, password, server_response)
        .map_err(|e| js_err(&e.to_string()))?;
    // Zeroizing ensures the Rust-side copy is wiped from linear memory on drop.
    let export_key = Zeroizing::new(result.export_key[..EXPORT_KEY_LEN].to_vec());
    let finalization = result.message.serialize().to_vec();
    js_obj(&[
        ("exportKey", bytes_js(&export_key)),
        ("finalization", bytes_js(&finalization)),
    ])
}

// ── MLS exports ────────────────────────────────────────────────────────────────

/// Derive the openmls GroupId as a lowercase hex string for use as map key.
fn group_id_hex(group: &MlsGroup) -> String {
    group
        .group_id()
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Create a new MLS identity and return a fresh KeyPackage for distribution.
///
/// Returns `{ identityId: string, keyPackage: Uint8Array }`.
/// Upload `keyPackage` to the KeyPackage Service.
/// Keep `identityId` for subsequent MLS calls.
#[wasm_bindgen]
pub fn mls_init_identity(identity_bytes: &[u8]) -> Result<JsValue, JsError> {
    let provider = OpenMlsRustCrypto::default();
    let identity =
        generate_identity(identity_bytes, &provider).map_err(|e| js_err(&e.to_string()))?;
    let bundle = generate_key_package(&identity, &provider).map_err(|e| js_err(&e.to_string()))?;
    // Wrap the KeyPackage in MlsMessageOut for transport (standard MLS KeyPackage format).
    let key_package = MlsMessageOut::from(bundle)
        .to_bytes()
        .map_err(|_| js_err("key package serialization failed"))?;
    let identity_id = next_id();
    MLS_CTX.with(|ctx| {
        ctx.borrow_mut().insert(
            identity_id.clone(),
            MlsContext {
                identity,
                provider,
                groups: HashMap::new(),
            },
        );
    });
    js_obj(&[
        ("identityId", JsValue::from_str(&identity_id)),
        ("keyPackage", bytes_js(&key_package)),
    ])
}

/// Generate a fresh KeyPackage for an existing identity.
///
/// Returns `{ keyPackage: Uint8Array }`.
/// Each KeyPackage is single-use; generate one per intended group add.
#[wasm_bindgen]
pub fn mls_get_key_package(identity_id: &str) -> Result<JsValue, JsError> {
    let key_package = MLS_CTX.with(|ctx| -> Result<Vec<u8>, JsError> {
        let ctx = ctx.borrow();
        let c = ctx
            .get(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        let bundle =
            generate_key_package(&c.identity, &c.provider).map_err(|e| js_err(&e.to_string()))?;
        MlsMessageOut::from(bundle)
            .to_bytes()
            .map_err(|_| js_err("key package serialization failed"))
    })?;
    js_obj(&[("keyPackage", bytes_js(&key_package))])
}

/// Create a new MLS group with the identity as sole member.
///
/// Returns `{ groupId: string }`.
#[wasm_bindgen]
pub fn mls_create_group(identity_id: &str) -> Result<JsValue, JsError> {
    // Phase 1: borrow (shared) to read identity+provider; create_group uses
    // interior mutability inside OpenMlsRustCrypto, so borrow() suffices.
    let group = MLS_CTX.with(|ctx| -> Result<MlsGroup, JsError> {
        let ctx = ctx.borrow();
        let c = ctx
            .get(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        create_group(&c.identity, &c.provider).map_err(|e| js_err(&e.to_string()))
    })?;
    // Phase 2: borrow_mut to insert (borrow from phase 1 is already released).
    let group_id = group_id_hex(&group);
    MLS_CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let c = ctx
            .get_mut(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        c.groups.insert(group_id.clone(), group);
        Ok::<_, JsError>(())
    })?;
    js_obj(&[("groupId", JsValue::from_str(&group_id))])
}

/// Add a peer's KeyPackage to the group, advancing the epoch.
///
/// Returns `{ welcome: Uint8Array }`.
/// Send `welcome` to the new member so they can call `mls_join_group`.
#[wasm_bindgen]
pub fn mls_add_member(
    identity_id: &str,
    group_id: &str,
    key_package_bytes: &[u8],
) -> Result<JsValue, JsError> {
    let welcome = MLS_CTX.with(|ctx| -> Result<Vec<u8>, JsError> {
        let mut ctx = ctx.borrow_mut();
        let c = ctx
            .get_mut(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        let group = c
            .groups
            .get_mut(group_id)
            .ok_or_else(|| js_err("unknown mls group"))?;
        // Key packages travel as MlsMessageOut::KeyPackage bytes.  Deserialize
        // the outer MlsMessageIn frame, then validate and verify the contained
        // KeyPackageIn to obtain a trusted KeyPackage before using it in the group.
        let msg = MlsMessageIn::tls_deserialize_exact(key_package_bytes)
            .map_err(|_| js_err("invalid key package message"))?;
        let kp_in = match msg.extract() {
            MlsMessageBodyIn::KeyPackage(kp_in) => kp_in,
            _ => return Err(js_err("expected key package message body")),
        };
        // Disjoint field access: c.groups is mutably borrowed via `group`;
        // c.provider is independently immutably borrowed for validation.
        let kp = kp_in
            .validate(c.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|_| js_err("key package signature validation failed"))?;
        // Disjoint field borrows: c.groups (via group) is mut; c.identity + c.provider are shared.
        add_member(group, &c.identity.signer, kp, &c.provider).map_err(|e| js_err(&e.to_string()))
    })?;
    js_obj(&[("welcome", bytes_js(&welcome))])
}

/// Join a group from a Welcome message.
///
/// Returns `{ groupId: string }`.
/// The `groupId` matches the creator's groupId (derived from the openmls GroupId).
#[wasm_bindgen]
pub fn mls_join_group(identity_id: &str, welcome_bytes: &[u8]) -> Result<JsValue, JsError> {
    // Phase 1: borrow to join (uses identity's provider for decryption).
    let group = MLS_CTX.with(|ctx| -> Result<MlsGroup, JsError> {
        let ctx = ctx.borrow();
        let c = ctx
            .get(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        join_group(welcome_bytes, &c.provider).map_err(|e| js_err(&e.to_string()))
    })?;
    // Phase 2: borrow_mut to store the joined group.
    let group_id = group_id_hex(&group);
    MLS_CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let c = ctx
            .get_mut(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        c.groups.insert(group_id.clone(), group);
        Ok::<_, JsError>(())
    })?;
    js_obj(&[("groupId", JsValue::from_str(&group_id))])
}

/// Encrypt a plaintext application message.
///
/// Returns `{ ciphertext: Uint8Array }`.
#[wasm_bindgen]
pub fn mls_encrypt(
    identity_id: &str,
    group_id: &str,
    plaintext: &[u8],
) -> Result<JsValue, JsError> {
    let ciphertext = MLS_CTX.with(|ctx| -> Result<Vec<u8>, JsError> {
        let mut ctx = ctx.borrow_mut();
        let c = ctx
            .get_mut(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        let group = c
            .groups
            .get_mut(group_id)
            .ok_or_else(|| js_err("unknown mls group"))?;
        encrypt_message(group, &c.identity.signer, plaintext, &c.provider)
            .map_err(|e| js_err(&e.to_string()))
    })?;
    js_obj(&[("ciphertext", bytes_js(&ciphertext))])
}

/// Decrypt an MLS application message.
///
/// Returns `{ plaintext: Uint8Array }`.
/// Stale-epoch ciphertext (from before a commit) returns an error.
#[wasm_bindgen]
pub fn mls_decrypt(
    identity_id: &str,
    group_id: &str,
    ciphertext: &[u8],
) -> Result<JsValue, JsError> {
    let plaintext = MLS_CTX.with(|ctx| -> Result<Vec<u8>, JsError> {
        let mut ctx = ctx.borrow_mut();
        let c = ctx
            .get_mut(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        let group = c
            .groups
            .get_mut(group_id)
            .ok_or_else(|| js_err("unknown mls group"))?;
        decrypt_message(group, ciphertext, &c.provider).map_err(|e| js_err(&e.to_string()))
    })?;
    js_obj(&[("plaintext", bytes_js(&plaintext))])
}

// ── Tests ──────────────────────────────────────────────────────────────────────
//
// Native tests bypass js_sys (which panics on non-wasm32) and test the
// underlying thread_local state management directly.  End-to-end wasm-bindgen
// interop tests live in tests/wasm_bindgen_tests.rs (wasm32 only).

#[cfg(test)]
mod tests {
    use super::*;

    // ── OPAQUE session state ──────────────────────────────────────────────────

    /// OPAQUE registration sessions are stored and removed correctly.
    #[test]
    fn test_opaque_registration_session_lifecycle() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::registration_start(b"password123", &mut rng).unwrap();
        let id = next_id();
        OPAQUE_REG.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueRegSession { state });
        });
        assert!(
            OPAQUE_REG.with(|s| s.borrow().contains_key(&id)),
            "session should be stored"
        );
        // Removing the session returns Some.
        let removed = OPAQUE_REG.with(|s| s.borrow_mut().remove(&id));
        assert!(removed.is_some(), "session should be removable");
        // Second removal returns None (single-use).
        let removed2 = OPAQUE_REG.with(|s| s.borrow_mut().remove(&id));
        assert!(removed2.is_none(), "session must be single-use");
    }

    /// OPAQUE login sessions are stored and removed correctly.
    #[test]
    fn test_opaque_login_session_lifecycle() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::login_start(b"password123", &mut rng).unwrap();
        let id = next_id();
        OPAQUE_LOGIN.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueLoginSession { state });
        });
        assert!(
            OPAQUE_LOGIN.with(|s| s.borrow().contains_key(&id)),
            "session should be stored"
        );
        let removed = OPAQUE_LOGIN.with(|s| s.borrow_mut().remove(&id));
        assert!(removed.is_some(), "session should be removable");
    }

    // ── MLS context state ─────────────────────────────────────────────────────

    /// MLS context is stored and group can be created in it.
    #[test]
    fn test_mls_context_and_group_lifecycle() {
        let provider = OpenMlsRustCrypto::default();
        let identity = generate_identity(b"alice@mls-test", &provider).unwrap();
        let id = next_id();
        MLS_CTX.with(|ctx| {
            ctx.borrow_mut().insert(
                id.clone(),
                MlsContext {
                    identity,
                    provider,
                    groups: HashMap::new(),
                },
            );
        });
        assert!(
            MLS_CTX.with(|ctx| ctx.borrow().contains_key(&id)),
            "mls context should be stored"
        );

        // Create a group directly through the internal API (avoids js_sys).
        let group = MLS_CTX
            .with(|ctx| {
                let ctx = ctx.borrow();
                let c = ctx.get(&id).unwrap();
                create_group(&c.identity, &c.provider)
            })
            .unwrap();
        let gid = group_id_hex(&group);
        MLS_CTX.with(|ctx| {
            let mut ctx = ctx.borrow_mut();
            let c = ctx.get_mut(&id).unwrap();
            c.groups.insert(gid.clone(), group);
        });
        let group_count =
            MLS_CTX.with(|ctx| ctx.borrow().get(&id).map(|c| c.groups.len()).unwrap_or(0));
        assert_eq!(group_count, 1, "one group should be stored in the context");
    }

    /// Unknown identity IDs produce error results (not panics).
    #[test]
    fn test_unknown_identity_error() {
        // Trying to retrieve a non-existent MLS context returns None.
        let missing = MLS_CTX.with(|ctx| ctx.borrow().get("no-such-id").map(|_| ()));
        assert!(missing.is_none(), "unknown identity must not be found");
    }

    /// next_id generates unique IDs.
    #[test]
    fn test_next_id_unique() {
        let a = next_id();
        let b = next_id();
        assert_ne!(a, b, "consecutive IDs must be unique");
    }
}
