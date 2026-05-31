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

// ── Safety Numbers ─────────────────────────────────────────────────────────────

/// Domain-separation prefix for the safety number derivation (prd.md §5.6).
/// Pinning the construction version here makes any future format change detectable.
const SAFETY_NUMBER_DOMAIN: &[u8] = b"powehi-safety-number-v1";

/// Inner computation for safety numbers — testable without js_sys.
///
/// Inputs are two Ed25519 signature public keys, each exactly 32 bytes.
/// Returns a 83-char string: 12 six-digit decimal groups separated by spaces
/// (prd.md §5.6 "숫자 6자리 그룹"). Symmetric: same result for (a,b) and (b,a).
///
/// Construction: SHA-512(DOMAIN || 0x00 || len(first) || first || len(second) || second)
/// where first/second are sorted lexicographically. Domain separation + length prefixes
/// prevent cross-protocol collisions and extension attacks.
fn compute_safety_number_inner(key_a: &[u8], key_b: &[u8]) -> Result<String, &'static str> {
    use sha2::{Digest, Sha512};
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
    let hash = h.finalize(); // 64 bytes
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
    Ok(groups.join(" "))
}

/// Get public identity info for all current members of an MLS group.
///
/// Returns a JS Array of `{ leafIndex: number, sigKeyHex: string }` objects.
/// `sigKeyHex` is the member's Ed25519 signature public key as a lowercase hex string.
/// All data here is public — signature public keys are distributed openly in MLS.
#[wasm_bindgen]
pub fn mls_group_members(identity_id: &str, group_id: &str) -> Result<JsValue, JsError> {
    MLS_CTX.with(|ctx| -> Result<JsValue, JsError> {
        let ctx = ctx.borrow();
        let c = ctx
            .get(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        let group = c
            .groups
            .get(group_id)
            .ok_or_else(|| js_err("unknown mls group"))?;
        let arr = js_sys::Array::new();
        for member in group.members() {
            let leaf_index = member.index.u32();
            let sig_key_hex: String = member
                .signature_key
                .as_slice()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let obj = js_obj(&[
                ("leafIndex", JsValue::from_f64(leaf_index as f64)),
                ("sigKeyHex", JsValue::from_str(&sig_key_hex)),
            ])?;
            arr.push(&obj);
        }
        Ok(arr.into())
    })
}

/// Compute a Safety Number from two Ed25519 signature public keys.
///
/// Returns `{ safetyNumber: string }` — 12 six-digit decimal groups separated by spaces
/// (prd.md §5.6, 83 characters total including spaces).
/// Symmetric: `mls_compute_safety_number(a, b) == mls_compute_safety_number(b, a)`.
/// Both keys MUST be exactly 32 bytes (Ed25519 public key size); wrong length → error.
#[wasm_bindgen]
pub fn mls_compute_safety_number(sig_key_a: &[u8], sig_key_b: &[u8]) -> Result<JsValue, JsError> {
    let safety_number = compute_safety_number_inner(sig_key_a, sig_key_b).map_err(js_err)?;
    js_obj(&[("safetyNumber", JsValue::from_str(&safety_number))])
}

// ── Session lifecycle ──────────────────────────────────────────────────────────

/// Clear all MLS and OPAQUE session state from the WASM heap on logout.
///
/// Drops all MLS identities, groups, and any in-flight OPAQUE sessions so the
/// next login starts with a clean slate and cannot access prior-session keys.
///
/// Limitation: WASM linear memory is not physically zeroed — the allocator marks
/// freed pages as available but the byte values persist until overwritten by
/// subsequent allocations. This is a fundamental WASM constraint; the functional
/// guarantee is that no Rust-level reference to the prior session's material
/// remains accessible after this call returns.
#[wasm_bindgen]
pub fn mls_clear_session() {
    MLS_CTX.with(|ctx| ctx.borrow_mut().clear());
    OPAQUE_REG.with(|s| s.borrow_mut().clear());
    OPAQUE_LOGIN.with(|s| s.borrow_mut().clear());
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

    // ── Session clear ─────────────────────────────────────────────────────────

    /// mls_clear_session removes all MLS identities and groups.
    #[test]
    fn test_clear_session_removes_mls_contexts() {
        let provider = OpenMlsRustCrypto::default();
        let identity = generate_identity(b"bob@session-clear-test", &provider).unwrap();
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
            "context should be present before clear"
        );

        mls_clear_session();

        assert!(
            !MLS_CTX.with(|ctx| ctx.borrow().contains_key(&id)),
            "context must be absent after clear"
        );
        assert_eq!(
            MLS_CTX.with(|ctx| ctx.borrow().len()),
            0,
            "MLS_CTX must be empty after clear"
        );
    }

    /// mls_clear_session removes in-flight OPAQUE registration sessions.
    #[test]
    fn test_clear_session_removes_opaque_reg_sessions() {
        let mut rng = OsRng;
        let (state, _) = opaque::registration_start(b"pw", &mut rng).unwrap();
        let id = next_id();
        OPAQUE_REG.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueRegSession { state })
        });
        assert!(OPAQUE_REG.with(|s| s.borrow().contains_key(&id)));

        mls_clear_session();

        assert_eq!(
            OPAQUE_REG.with(|s| s.borrow().len()),
            0,
            "OPAQUE_REG must be empty after clear"
        );
    }

    /// mls_clear_session removes in-flight OPAQUE login sessions.
    #[test]
    fn test_clear_session_removes_opaque_login_sessions() {
        let mut rng = OsRng;
        let (state, _) = opaque::login_start(b"pw", &mut rng).unwrap();
        let id = next_id();
        OPAQUE_LOGIN.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueLoginSession { state })
        });
        assert!(OPAQUE_LOGIN.with(|s| s.borrow().contains_key(&id)));

        mls_clear_session();

        assert_eq!(
            OPAQUE_LOGIN.with(|s| s.borrow().len()),
            0,
            "OPAQUE_LOGIN must be empty after clear"
        );
    }

    /// mls_clear_session is idempotent: calling it on empty state does not panic.
    #[test]
    fn test_clear_session_idempotent_on_empty_state() {
        mls_clear_session();
        mls_clear_session();
        assert_eq!(MLS_CTX.with(|ctx| ctx.borrow().len()), 0);
        assert_eq!(OPAQUE_REG.with(|s| s.borrow().len()), 0);
        assert_eq!(OPAQUE_LOGIN.with(|s| s.borrow().len()), 0);
    }

    // ── Safety Numbers ────────────────────────────────────────────────────────

    /// Safety numbers are symmetric: (a, b) == (b, a).
    #[test]
    fn test_safety_number_symmetry() {
        let key_a = [0xABu8; 32];
        let key_b = [0x12u8; 32];
        let ab = compute_safety_number_inner(&key_a, &key_b).unwrap();
        let ba = compute_safety_number_inner(&key_b, &key_a).unwrap();
        assert_eq!(ab, ba, "safety numbers must be symmetric");
    }

    /// Safety number output format: 12 groups of 6 decimal digits, space-separated (prd.md §5.6).
    #[test]
    fn test_safety_number_format() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let sn = compute_safety_number_inner(&key_a, &key_b).unwrap();
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), 12, "must have exactly 12 groups");
        for g in &groups {
            assert_eq!(g.len(), 6, "each group must be exactly 6 characters");
            assert!(
                g.chars().all(|c| c.is_ascii_digit()),
                "each group must be digits only"
            );
        }
        // Total length: 12 × 6 digits + 11 spaces = 83 characters.
        assert_eq!(sn.len(), 83, "total string must be 83 characters");
    }

    /// Different key pairs produce different safety numbers.
    #[test]
    fn test_safety_number_different_pairs_differ() {
        let pair1 = compute_safety_number_inner(&[0x01u8; 32], &[0x02u8; 32]).unwrap();
        let pair2 = compute_safety_number_inner(&[0x03u8; 32], &[0x04u8; 32]).unwrap();
        assert_ne!(
            pair1, pair2,
            "distinct key pairs must give distinct safety numbers"
        );
    }

    /// Non-32-byte inputs are rejected (crypto-reviewer finding R5).
    #[test]
    fn test_safety_number_rejects_wrong_length() {
        assert!(
            compute_safety_number_inner(&[0x01u8; 31], &[0x02u8; 32]).is_err(),
            "31-byte key_a must error"
        );
        assert!(
            compute_safety_number_inner(&[0x01u8; 32], &[0x02u8; 33]).is_err(),
            "33-byte key_b must error"
        );
        assert!(
            compute_safety_number_inner(&[], &[0x02u8; 32]).is_err(),
            "empty key must error"
        );
    }

    /// Known-answer test — detects silent changes to the derivation construction.
    /// The expected value was produced by the initial correct implementation and frozen here.
    /// Any change to domain string, length encoding, or hash algo will break this test.
    #[test]
    fn test_safety_number_known_answer() {
        let key_a = [0x01u8; 32];
        let key_b = [0x02u8; 32];
        let sn = compute_safety_number_inner(&key_a, &key_b).unwrap();
        // KAT: SHA-512(b"powehi-safety-number-v1" || 0x00 || 00000020 || [01;32] || 00000020 || [02;32])
        // First is [0x01;32] (less than [0x02;32]), second is [0x02;32].
        assert_eq!(
            sn,
            "689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
            "safety number derivation must not change silently"
        );
    }
}
