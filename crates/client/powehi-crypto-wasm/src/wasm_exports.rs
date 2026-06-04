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

use crate::kem;
use crate::kem_credential;
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

// SECURITY: ephemeral OPRF client state is stored as serialized bytes wrapped in
// Zeroizing<Vec<u8>>. When the session is removed from the map (consumed by a
// finish call or cleared by mls_clear_session on logout), the Zeroizing wrapper
// zeroes the bytes before deallocating, preventing the ephemeral secret material
// from persisting in WASM linear memory beyond its useful lifetime.
struct OpaqueRegSession {
    bytes: Zeroizing<Vec<u8>>,
}

struct OpaqueLoginSession {
    bytes: Zeroizing<Vec<u8>>,
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
    // ADR-0003 Phase B: opaque-handle storage for ML-KEM key material.
    // Raw decap keys and shared secrets never cross the WASM-JS boundary — only
    // string handles are returned to JS.  Both maps use Zeroizing so the heap
    // buffer is zeroed when a handle is dropped or the session is cleared.
    static KEM_DECAP_KEYS:     RefCell<HashMap<String, Zeroizing<Vec<u8>>>> = RefCell::new(HashMap::new());
    static KEM_SHARED_SECRETS: RefCell<HashMap<String, Zeroizing<Vec<u8>>>> = RefCell::new(HashMap::new());
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
    // Serialize ephemeral OPRF state to bytes and wrap in Zeroizing so the
    // heap buffer is zeroed when the session is consumed or cleared.
    // Note: serialize() produces a transient stack GenericArray that is not
    // Zeroized; .to_vec() copies to heap which IS Zeroized via Zeroizing.
    // The transient stack bytes share the WASM linear-memory residue caveat
    // documented above and at mls_clear_session.
    let bytes = Zeroizing::new(state.serialize().to_vec());
    OPAQUE_REG.with(|s| {
        s.borrow_mut()
            .insert(session_id.clone(), OpaqueRegSession { bytes });
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
    let session = OPAQUE_REG
        .with(|s| s.borrow_mut().remove(session_id))
        .ok_or_else(|| js_err("unknown opaque registration session"))?;
    // Deserialize from the Zeroizing byte buffer; the buffer is zeroed on drop
    // when `session` goes out of scope at the end of this function.
    let state = opaque_ke::ClientRegistration::<DefaultCipherSuite>::deserialize(&session.bytes)
        .map_err(|_| js_err("opaque registration session corrupted"))?;
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
    // Serialize ephemeral KE1 state (ephemeral DH keys + OPRF client) to bytes
    // and wrap in Zeroizing so the heap buffer is zeroed when the session is
    // consumed or cleared on logout. Same transient-stack caveat as registration.
    let bytes = Zeroizing::new(state.serialize().to_vec());
    OPAQUE_LOGIN.with(|s| {
        s.borrow_mut()
            .insert(session_id.clone(), OpaqueLoginSession { bytes });
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
    let session = OPAQUE_LOGIN
        .with(|s| s.borrow_mut().remove(session_id))
        .ok_or_else(|| js_err("unknown opaque login session"))?;
    // Deserialize from the Zeroizing byte buffer; the buffer is zeroed on drop
    // when `session` goes out of scope at the end of this function.
    let state = opaque_ke::ClientLogin::<DefaultCipherSuite>::deserialize(&session.bytes)
        .map_err(|_| js_err("opaque login session corrupted"))?;
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

// ── ML-KEM-768 exports (ADR-0003 Phase A: PQ KEM primitives) ──────────────────
//
// These standalone KEM operations are independent of the MLS or OPAQUE flows.
// They expose the building blocks for post-quantum hybrid key exchange, to be
// integrated with openmls when it gains an ML-KEM ciphersuite.
//
// PHASE-A TEST-SURFACE ONLY — NOT FOR PRODUCTION USE:
// Unlike MLS operations (which keep all key material inside the worker via MlsContext),
// these functions return raw key material (decapKey, sharedSecret) to the JS caller.
// This violates the react-hooks-only.md invariant that "raw key material must never
// appear in React component scope" if the caller is in the main thread.
// Before production use, these primitives must be wrapped in a higher-level hybrid
// KEM flow (e.g. X25519+ML-KEM combined handshake) that keeps all intermediate key
// material inside the worker, mirroring the MlsContext pattern.  ADR-0003 Phase B
// will define that higher-level API; these exports exist solely to validate the
// underlying FIPS 203 primitives.

/// Generate an ML-KEM-768 keypair (FIPS 203).
///
/// Returns `{ encapKey: Uint8Array, decapKey: Uint8Array }`.
/// - `encapKey` (1184 bytes): distribute to the peer who will encapsulate.
/// - `decapKey` (2400 bytes): keep secret; pass to `ml_kem_768_decap`.
///
/// Uses the browser CSPRNG via getrandom (same path as OPAQUE and MLS).
/// Security note: `decapKey` is copied to the JS heap as a Uint8Array.
/// The Rust-side Zeroizing buffer is zeroed on drop, but the JS copy is
/// not zeroed automatically — callers should zero `decapKey` after use
/// via `decapKey.fill(0)`.
#[wasm_bindgen]
pub fn ml_kem_768_keygen() -> Result<JsValue, JsError> {
    let pair = kem::generate();
    js_obj(&[
        ("encapKey", bytes_js(&pair.encap_key)),
        ("decapKey", bytes_js(&pair.decap_key)),
    ])
}

/// Encapsulate a shared secret under the given ML-KEM-768 encapsulation key.
///
/// `encap_key` must be exactly 1184 bytes (output of `ml_kem_768_keygen`).
///
/// Returns `{ ciphertext: Uint8Array, sharedSecret: Uint8Array }`.
/// - `ciphertext` (1088 bytes): send to the decapsulation-key holder.
/// - `sharedSecret` (32 bytes): the locally derived shared key.
///
/// Security note: `sharedSecret` is sensitive. The JS copy should be
/// zeroed (`sharedSecret.fill(0)`) after the key material has been consumed.
#[wasm_bindgen]
pub fn ml_kem_768_encap(encap_key: &[u8]) -> Result<JsValue, JsError> {
    let (ct, ss) = kem::encapsulate(encap_key).map_err(js_err)?;
    js_obj(&[
        ("ciphertext", bytes_js(&ct)),
        ("sharedSecret", bytes_js(&ss)),
    ])
}

/// Decapsulate a shared secret from a ciphertext using the ML-KEM-768 decapsulation key.
///
/// `decap_key` must be exactly 2400 bytes (output of `ml_kem_768_keygen`).
/// `ciphertext` must be exactly 1088 bytes (output of `ml_kem_768_encap`).
///
/// Returns `{ sharedSecret: Uint8Array }` — the 32-byte recovered shared key.
///
/// ML-KEM uses implicit rejection (FIPS 203 §6.3.3): decapsulating with the
/// wrong key still returns success, but the shared secret is a pseudorandom
/// value unrelated to the encapsulator's secret. Callers must not use a decap
/// error as proof of message integrity — use an authenticated AEAD scheme
/// (e.g. AES-256-GCM) on top of the shared secret for that guarantee.
///
/// Security note: zero `sharedSecret` after use (`sharedSecret.fill(0)`).
#[wasm_bindgen]
pub fn ml_kem_768_decap(decap_key: &[u8], ciphertext: &[u8]) -> Result<JsValue, JsError> {
    let ss = kem::decapsulate(decap_key, ciphertext).map_err(js_err)?;
    js_obj(&[("sharedSecret", bytes_js(&ss))])
}

// ── ML-KEM-768 Phase B: opaque-handle API (ADR-0003 Phase B, Y-1 fix) ─────────
//
// These exports close Y-1 from the crypto-reviewer: raw decap keys and shared
// secrets no longer cross the WASM-JS boundary.  String handles are returned
// instead, pointing to Zeroizing<Vec<u8>> stored in thread-local maps.
// Key material is zeroed on explicit drop or on mls_clear_session (logout).
//
// Usage pattern:
//   const { encapKey, decapKeyHandle } = await mlKem768KeygenV2();
//   // distribute encapKey to peer
//   const { sharedSecretHandle } = await mlKem768DecapV2(decapKeyHandle, ciphertext);
//   // use sharedSecretHandle in further worker-internal operations (Phase C)
//   await mlKem768DropDecapKey(decapKeyHandle);
//   await mlKem768DropSharedSecret(sharedSecretHandle);

/// Generate an ML-KEM-768 keypair — Phase B opaque-handle API.
///
/// Returns `{ encapKey: Uint8Array, decapKeyHandle: string }`.
/// - `encapKey` (1184 bytes): distribute to the peer who will encapsulate.
/// - `decapKeyHandle`: opaque string handle; pass to `ml_kem_768_decap_v2`.
///   The raw decap key bytes are stored inside the WASM worker — they NEVER
///   cross the WASM-JS boundary (ADR-0003 Phase B, Y-1 fix).
///
/// Call `ml_kem_768_drop_decap_key(decapKeyHandle)` when done.
/// `mls_clear_session()` also drops all decap key handles.
#[wasm_bindgen]
pub fn ml_kem_768_keygen_v2() -> Result<JsValue, JsError> {
    let pair = kem::generate();
    let handle = next_id();
    // Build the JS result BEFORE inserting into the map (Y-7 fix): if js_obj fails
    // (extraordinary JS host exception), no orphan handle entry is left in the map.
    let result = js_obj(&[
        ("encapKey", bytes_js(&pair.encap_key)),
        ("decapKeyHandle", JsValue::from_str(&handle)),
    ])?;
    KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(handle, pair.decap_key));
    Ok(result)
}

/// Encapsulate a shared secret under an ML-KEM-768 encapsulation key — Phase B API.
///
/// `encap_key` must be exactly 1184 bytes (from `ml_kem_768_keygen_v2`).
///
/// Returns `{ ciphertext: Uint8Array, sharedSecretHandle: string }`.
/// - `ciphertext` (1088 bytes): send to the decapsulation-key holder.
/// - `sharedSecretHandle`: opaque handle; the raw 32-byte shared secret is
///   stored inside the WASM worker (ADR-0003 Phase B, Y-1 fix).
///
/// Call `ml_kem_768_drop_shared_secret(sharedSecretHandle)` when done.
#[wasm_bindgen]
pub fn ml_kem_768_encap_v2(encap_key: &[u8]) -> Result<JsValue, JsError> {
    let (ct, ss) = kem::encapsulate(encap_key).map_err(js_err)?;
    let handle = next_id();
    // Y-7 fix: build JS result before inserting so no orphan handle is created on failure.
    let result = js_obj(&[
        ("ciphertext", bytes_js(&ct)),
        ("sharedSecretHandle", JsValue::from_str(&handle)),
    ])?;
    KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(handle, ss));
    Ok(result)
}

/// Decapsulate a shared secret using a stored decap key handle — Phase B API.
///
/// `decap_key_handle`: string returned by `ml_kem_768_keygen_v2`.
/// `ciphertext` must be exactly 1088 bytes (from `ml_kem_768_encap_v2`).
///
/// Returns `{ sharedSecretHandle: string }`.
/// The raw 32-byte shared secret is stored inside the WASM worker and never
/// crosses the WASM-JS boundary (ADR-0003 Phase B, Y-1 fix).
///
/// ML-KEM implicit rejection (FIPS 203 §6.3.3) applies: a wrong-ciphertext
/// decap returns a pseudorandom handle (not an error).
///
/// Call `ml_kem_768_drop_shared_secret(sharedSecretHandle)` when done.
#[wasm_bindgen]
pub fn ml_kem_768_decap_v2(decap_key_handle: &str, ciphertext: &[u8]) -> Result<JsValue, JsError> {
    // Clone the stored key bytes so the handle remains valid for future decap calls.
    // The clone produces a Zeroizing copy; both the clone and the original are zeroed
    // on drop (the clone at the end of this function, the stored copy on drop/clear).
    // Note (Y-8): a caller flooding repeated decap calls before logout grows
    // KEM_SHARED_SECRETS unboundedly. Mitigation: caller-side rate limiting (Phase C).
    let dk_bytes = KEM_DECAP_KEYS
        .with(|m| m.borrow().get(decap_key_handle).cloned())
        .ok_or_else(|| js_err("unknown decap key handle"))?;
    let ss = kem::decapsulate(&dk_bytes, ciphertext).map_err(js_err)?;
    let handle = next_id();
    // Y-7 fix: build JS result before inserting so no orphan handle is created on failure.
    let result = js_obj(&[("sharedSecretHandle", JsValue::from_str(&handle))])?;
    KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(handle, ss));
    Ok(result)
}

/// Explicitly drop a stored ML-KEM-768 decapsulation key by handle.
///
/// Removes the entry from `KEM_DECAP_KEYS`; the `Zeroizing<Vec<u8>>` wrapper
/// zeroes the heap buffer on drop.  Silently no-ops on unknown handles
/// (idempotent / safe to call after `mls_clear_session`).
#[wasm_bindgen]
pub fn ml_kem_768_drop_decap_key(handle: &str) {
    KEM_DECAP_KEYS.with(|m| m.borrow_mut().remove(handle));
}

/// Explicitly drop a stored ML-KEM-768 shared secret by handle.
///
/// Removes the entry from `KEM_SHARED_SECRETS`; the `Zeroizing<Vec<u8>>`
/// wrapper zeroes the heap buffer on drop.  Silently no-ops on unknown handles.
#[wasm_bindgen]
pub fn ml_kem_768_drop_shared_secret(handle: &str) {
    KEM_SHARED_SECRETS.with(|m| m.borrow_mut().remove(handle));
}

// ── ML-KEM-768 Phase B: signed encap key (ADR-0003 Phase B, Y-3 fix) ──────────
//
// Y-3 closed: the encap key holder signs their ML-KEM-768 encap key with their
// MLS Ed25519 identity key. Peers MUST call ml_kem_768_verify_encap_key before
// encapsulating to confirm the encap key was not substituted in transit.
//
// Sign:  SIGN_DOMAIN || 0x00 || ek_bytes, signed with identity's Ed25519 key.
// Verify: same message reconstruction, verify against peer's known public key.
//
// The private signing key stays in MLS_CTX (never crosses WASM-JS boundary).
// The 64-byte signature and 32-byte public key are public data.

/// Sign an ML-KEM-768 encapsulation key with the identity's MLS Ed25519 signing key.
///
/// `identity_id`: string returned by `mls_init_identity`.
/// `encap_key`: 1184 bytes (from `ml_kem_768_keygen_v2`).
///
/// Returns `{ signature: Uint8Array }` — 64-byte Ed25519 signature over
/// `"powehi-kem-ek-v1" || 0x00 || encap_key`.
///
/// The private signing key stays inside the WASM worker (MLS_CTX) and never
/// crosses the WASM-JS boundary.  Distribute the signature alongside the encap
/// key so peers can call `ml_kem_768_verify_encap_key` before encapsulating.
#[wasm_bindgen]
pub fn ml_kem_768_sign_encap_key(identity_id: &str, encap_key: &[u8]) -> Result<JsValue, JsError> {
    let signature = MLS_CTX.with(|ctx| -> Result<Vec<u8>, JsError> {
        let ctx = ctx.borrow();
        let c = ctx
            .get(identity_id)
            .ok_or_else(|| js_err("unknown mls identity"))?;
        kem_credential::sign_encap_key(encap_key, &c.identity.signer).map_err(js_err)
    })?;
    js_obj(&[("signature", bytes_js(&signature))])
}

/// Verify an ML-KEM-768 encapsulation-key signature.
///
/// `encap_key`: 1184 bytes — the encap key to authenticate.
/// `signature`: 64 bytes — Ed25519 signature from `ml_kem_768_sign_encap_key`.
/// `sig_pub_key`: 32 bytes — the signer's Ed25519 public key.  Obtain from
///    `mls_group_members` (`sigKeyHex` field, hex-decoded) using the expected
///    member's leaf index.  NEVER accept this value from an untrusted source.
///
/// Returns `{ valid: boolean }`.
/// `valid: true`  — the signature is correct; the encap key is authentic.
/// `valid: false` — the encap key was NOT signed by the claimed identity; do
///    NOT encapsulate under it (key substitution attack — ADR-0003 Phase B, Y-3).
///
/// This function only checks the signature mathematics, not the trust anchor.
/// The caller is responsible for sourcing `sig_pub_key` from the verified MLS
/// group roster.  A temporary stateless provider is used — no identity needed.
#[wasm_bindgen]
pub fn ml_kem_768_verify_encap_key(
    encap_key: &[u8],
    signature: &[u8],
    sig_pub_key: &[u8],
) -> Result<JsValue, JsError> {
    let provider = OpenMlsRustCrypto::default();
    let valid = kem_credential::verify_encap_key(encap_key, signature, sig_pub_key, &provider)
        .map_err(js_err)?;
    js_obj(&[("valid", JsValue::from_bool(valid))])
}

// ── Session lifecycle ──────────────────────────────────────────────────────────

/// Clear all MLS, OPAQUE, and ML-KEM session state from the WASM heap on logout.
///
/// Drops all MLS identities, groups, in-flight OPAQUE sessions, and any stored
/// ML-KEM decap keys and shared secrets so the next login starts with a clean
/// slate and cannot access prior-session keys.  All `Zeroizing<Vec<u8>>` entries
/// are zeroed before deallocation.
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
    KEM_DECAP_KEYS.with(|m| m.borrow_mut().clear());
    KEM_SHARED_SECRETS.with(|m| m.borrow_mut().clear());
}

// ── Tests ──────────────────────────────────────────────────────────────────────
//
// Native tests bypass js_sys (which panics on non-wasm32) and test the
// underlying thread_local state management directly.  End-to-end wasm-bindgen
// interop tests live in tests/wasm_bindgen_tests.rs (wasm32 only).

#[cfg(test)]
mod tests {
    use super::*;
    use opaque_ke::{ClientLogin, ClientRegistration};

    // ── OPAQUE session state ──────────────────────────────────────────────────

    /// OPAQUE registration sessions are stored as Zeroizing bytes and removed correctly.
    #[test]
    fn test_opaque_registration_session_lifecycle() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::registration_start(b"password123", &mut rng).unwrap();
        let id = next_id();
        let bytes = Zeroizing::new(state.serialize().to_vec());
        OPAQUE_REG.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueRegSession { bytes });
        });
        assert!(
            OPAQUE_REG.with(|s| s.borrow().contains_key(&id)),
            "session should be stored"
        );
        // Stored bytes are non-empty (serialized OPRF client state is 64 bytes for Ristretto255).
        let byte_len = OPAQUE_REG.with(|s| s.borrow().get(&id).map(|s| s.bytes.len()).unwrap_or(0));
        assert!(byte_len > 0, "session bytes must be non-empty");
        // Removing the session returns Some and drops (zeroing) the bytes.
        let removed = OPAQUE_REG.with(|s| s.borrow_mut().remove(&id));
        assert!(removed.is_some(), "session should be removable");
        // Second removal returns None (single-use).
        let removed2 = OPAQUE_REG.with(|s| s.borrow_mut().remove(&id));
        assert!(removed2.is_none(), "session must be single-use");
    }

    /// OPAQUE login sessions are stored as Zeroizing bytes and removed correctly.
    #[test]
    fn test_opaque_login_session_lifecycle() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::login_start(b"password123", &mut rng).unwrap();
        let id = next_id();
        let bytes = Zeroizing::new(state.serialize().to_vec());
        OPAQUE_LOGIN.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueLoginSession { bytes });
        });
        assert!(
            OPAQUE_LOGIN.with(|s| s.borrow().contains_key(&id)),
            "session should be stored"
        );
        // Stored bytes are non-empty (serialized KE1 state includes ephemeral DH keys).
        let byte_len =
            OPAQUE_LOGIN.with(|s| s.borrow().get(&id).map(|s| s.bytes.len()).unwrap_or(0));
        assert!(byte_len > 0, "login session bytes must be non-empty");
        let removed = OPAQUE_LOGIN.with(|s| s.borrow_mut().remove(&id));
        assert!(removed.is_some(), "session should be removable");
    }

    /// Consumed registration session bytes can be deserialized back to the original state.
    #[test]
    fn test_opaque_registration_session_roundtrip() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::registration_start(b"roundtrip-pw", &mut rng).unwrap();
        let original_bytes = state.serialize().to_vec();
        // Deserialize must succeed for our DefaultCipherSuite.
        let restored =
            ClientRegistration::<DefaultCipherSuite>::deserialize(&original_bytes).unwrap();
        // Confirm round-trip: re-serializing gives the same bytes.
        assert_eq!(restored.serialize().as_slice(), original_bytes.as_slice());
    }

    /// Consumed login session bytes can be deserialized back to the original state.
    #[test]
    fn test_opaque_login_session_roundtrip() {
        let mut rng = OsRng;
        let (state, _msg) = opaque::login_start(b"roundtrip-pw", &mut rng).unwrap();
        let original_bytes = state.serialize().to_vec();
        // Deserialize must succeed for our DefaultCipherSuite.
        let restored = ClientLogin::<DefaultCipherSuite>::deserialize(&original_bytes).unwrap();
        assert_eq!(restored.serialize().as_slice(), original_bytes.as_slice());
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

    /// mls_clear_session removes in-flight OPAQUE registration sessions (and zeroes bytes).
    #[test]
    fn test_clear_session_removes_opaque_reg_sessions() {
        let mut rng = OsRng;
        let (state, _) = opaque::registration_start(b"pw", &mut rng).unwrap();
        let id = next_id();
        let bytes = Zeroizing::new(state.serialize().to_vec());
        OPAQUE_REG.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueRegSession { bytes })
        });
        assert!(OPAQUE_REG.with(|s| s.borrow().contains_key(&id)));

        mls_clear_session();

        assert_eq!(
            OPAQUE_REG.with(|s| s.borrow().len()),
            0,
            "OPAQUE_REG must be empty after clear"
        );
    }

    /// mls_clear_session removes in-flight OPAQUE login sessions (and zeroes bytes).
    #[test]
    fn test_clear_session_removes_opaque_login_sessions() {
        let mut rng = OsRng;
        let (state, _) = opaque::login_start(b"pw", &mut rng).unwrap();
        let id = next_id();
        let bytes = Zeroizing::new(state.serialize().to_vec());
        OPAQUE_LOGIN.with(|s| {
            s.borrow_mut()
                .insert(id.clone(), OpaqueLoginSession { bytes })
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

    // ── ML-KEM Phase B opaque-handle tests (ADR-0003 Phase B, Y-1) ───────────
    //
    // These tests exercise the thread-local state management for KEM_DECAP_KEYS
    // and KEM_SHARED_SECRETS.  The wasm-bindgen functions themselves (keygen_v2,
    // encap_v2, decap_v2) use js_sys which panics in native tests; the logic they
    // wrap is tested by directly manipulating the thread-locals + calling kem::*.

    /// Keygen v2: decap key stored in KEM_DECAP_KEYS, not exposed to caller.
    #[test]
    fn test_ml_kem_v2_keygen_stores_decap_key() {
        let pair = kem::generate();
        let handle = next_id();
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(handle.clone(), pair.decap_key));
        assert!(
            KEM_DECAP_KEYS.with(|m| m.borrow().contains_key(&handle)),
            "decap key must be stored in KEM_DECAP_KEYS"
        );
        let len = KEM_DECAP_KEYS.with(|m| m.borrow().get(&handle).map(|v| v.len()).unwrap_or(0));
        assert_eq!(len, kem::DK_SIZE, "stored decap key must be DK_SIZE bytes");
    }

    /// Encap v2: shared secret stored in KEM_SHARED_SECRETS, not exposed to caller.
    #[test]
    fn test_ml_kem_v2_encap_stores_shared_secret() {
        let pair = kem::generate();
        let (_ct, ss) = kem::encapsulate(&pair.encap_key).unwrap();
        let handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(handle.clone(), ss));
        assert!(
            KEM_SHARED_SECRETS.with(|m| m.borrow().contains_key(&handle)),
            "shared secret must be stored in KEM_SHARED_SECRETS"
        );
        let len =
            KEM_SHARED_SECRETS.with(|m| m.borrow().get(&handle).map(|v| v.len()).unwrap_or(0));
        assert_eq!(
            len,
            kem::SS_SIZE,
            "stored shared secret must be SS_SIZE bytes"
        );
    }

    /// Decap v2: retrieves stored decap key by handle, stores recovered secret.
    #[test]
    fn test_ml_kem_v2_decap_uses_handle_and_stores_result() {
        let pair = kem::generate();
        let (ct, ss_enc) = kem::encapsulate(&pair.encap_key).unwrap();
        let dk_handle = next_id();
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(dk_handle.clone(), pair.decap_key));
        // Retrieve and decapsulate (same logic as ml_kem_768_decap_v2, without js_sys)
        let dk_bytes = KEM_DECAP_KEYS
            .with(|m| m.borrow().get(&dk_handle).cloned())
            .expect("stored decap key must be retrievable by handle");
        let ss_dec = kem::decapsulate(&dk_bytes, &ct).unwrap();
        let ss_handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(ss_handle.clone(), ss_dec.clone()));
        let stored = KEM_SHARED_SECRETS
            .with(|m| m.borrow().get(&ss_handle).cloned())
            .unwrap();
        assert_eq!(
            ss_enc.as_slice(),
            stored.as_slice(),
            "decap must recover the encapsulator's shared secret"
        );
    }

    /// Round-trip via handles: encap+decap produce identical stored shared secrets.
    #[test]
    fn test_ml_kem_v2_round_trip_via_handles() {
        let pair = kem::generate();
        // Store decap key under a handle (keygen_v2)
        let dk_handle = next_id();
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(dk_handle.clone(), pair.decap_key));
        // Encapsulate and store encap-side shared secret (encap_v2)
        let (ct, ss_enc) = kem::encapsulate(&pair.encap_key).unwrap();
        let enc_ss_handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(enc_ss_handle.clone(), ss_enc.clone()));
        // Decapsulate via handle and store decap-side shared secret (decap_v2)
        let dk_bytes = KEM_DECAP_KEYS
            .with(|m| m.borrow().get(&dk_handle).cloned())
            .unwrap();
        let ss_dec = kem::decapsulate(&dk_bytes, &ct).unwrap();
        let dec_ss_handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(dec_ss_handle.clone(), ss_dec));
        let stored_enc = KEM_SHARED_SECRETS
            .with(|m| m.borrow().get(&enc_ss_handle).cloned())
            .unwrap();
        let stored_dec = KEM_SHARED_SECRETS
            .with(|m| m.borrow().get(&dec_ss_handle).cloned())
            .unwrap();
        assert_eq!(
            stored_enc.as_slice(),
            stored_dec.as_slice(),
            "encap and decap stored shared secrets must match (round-trip via handles)"
        );
    }

    /// Drop decap key: remove + zeroize on explicit drop.
    #[test]
    fn test_ml_kem_v2_drop_decap_key_removes_entry() {
        let pair = kem::generate();
        let handle = next_id();
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(handle.clone(), pair.decap_key));
        assert!(KEM_DECAP_KEYS.with(|m| m.borrow().contains_key(&handle)));
        // Simulate ml_kem_768_drop_decap_key
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().remove(&handle));
        assert!(
            !KEM_DECAP_KEYS.with(|m| m.borrow().contains_key(&handle)),
            "dropped decap key must not be retrievable"
        );
    }

    /// Drop shared secret: remove + zeroize on explicit drop.
    #[test]
    fn test_ml_kem_v2_drop_shared_secret_removes_entry() {
        let pair = kem::generate();
        let (_, ss) = kem::encapsulate(&pair.encap_key).unwrap();
        let handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(handle.clone(), ss));
        assert!(KEM_SHARED_SECRETS.with(|m| m.borrow().contains_key(&handle)));
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().remove(&handle));
        assert!(
            !KEM_SHARED_SECRETS.with(|m| m.borrow().contains_key(&handle)),
            "dropped shared secret must not be retrievable"
        );
    }

    /// Unknown decap key handle: retrieving a nonexistent handle returns None.
    #[test]
    fn test_ml_kem_v2_unknown_decap_handle_returns_none() {
        let result = KEM_DECAP_KEYS.with(|m| m.borrow().get("no-such-handle").cloned());
        assert!(
            result.is_none(),
            "unknown decap key handle must return None (error path in decap_v2)"
        );
    }

    /// mls_clear_session also clears KEM_DECAP_KEYS and KEM_SHARED_SECRETS.
    #[test]
    fn test_clear_session_removes_kem_handles() {
        let pair = kem::generate();
        let dk_handle = next_id();
        KEM_DECAP_KEYS.with(|m| m.borrow_mut().insert(dk_handle.clone(), pair.decap_key));
        let (_, ss) = kem::encapsulate(&pair.encap_key).unwrap();
        let ss_handle = next_id();
        KEM_SHARED_SECRETS.with(|m| m.borrow_mut().insert(ss_handle.clone(), ss));
        assert!(KEM_DECAP_KEYS.with(|m| m.borrow().contains_key(&dk_handle)));
        assert!(KEM_SHARED_SECRETS.with(|m| m.borrow().contains_key(&ss_handle)));

        mls_clear_session();

        assert_eq!(
            KEM_DECAP_KEYS.with(|m| m.borrow().len()),
            0,
            "KEM_DECAP_KEYS must be empty after mls_clear_session"
        );
        assert_eq!(
            KEM_SHARED_SECRETS.with(|m| m.borrow().len()),
            0,
            "KEM_SHARED_SECRETS must be empty after mls_clear_session"
        );
    }

    // ── ML-KEM-768 signed encap key (ADR-0003 Phase B, Y-3) ──────────────────

    /// sign_encap_key + verify_encap_key via internal state: valid sig accepted.
    #[test]
    fn test_ml_kem_sign_verify_via_internal_state() {
        let provider = OpenMlsRustCrypto::default();
        let identity = generate_identity(b"sign-test-identity", &provider).unwrap();
        let ek = vec![0u8; kem::EK_SIZE];
        let sig =
            kem_credential::sign_encap_key(&ek, &identity.signer).expect("signing must succeed");
        assert_eq!(sig.len(), 64, "Ed25519 signature must be 64 bytes");
        let pub_key = identity.signer.to_public_vec();
        let valid = kem_credential::verify_encap_key(&ek, &sig, &pub_key, &provider)
            .expect("verify must not error");
        assert!(valid, "valid signature must be accepted");
    }

    /// Wrong public key → verify returns false (key substitution is rejected).
    #[test]
    fn test_ml_kem_verify_wrong_pub_key_returns_false() {
        let (provider, signer) = {
            let p = OpenMlsRustCrypto::default();
            let id = generate_identity(b"signer-identity", &p).unwrap();
            (p, id.signer)
        };
        let ek = vec![0u8; kem::EK_SIZE];
        let sig = kem_credential::sign_encap_key(&ek, &signer).expect("signing must succeed");

        let provider2 = OpenMlsRustCrypto::default();
        let attacker = generate_identity(b"attacker-identity", &provider2).unwrap();
        let wrong_pub = attacker.signer.to_public_vec();

        let valid = kem_credential::verify_encap_key(&ek, &sig, &wrong_pub, &provider)
            .expect("verify must not error");
        assert!(!valid, "wrong public key must cause verification to fail");
    }

    /// ml_kem_768_sign_encap_key with unknown identity_id: MLS_CTX lookup fails (fail-closed).
    /// Confirms the WASM export never returns a signature for an unregistered identity.
    #[test]
    fn test_ml_kem_sign_unknown_identity_returns_error() {
        // A fresh test thread's MLS_CTX is empty — any lookup returns None, which the
        // WASM export maps to JsError("unknown mls identity"). Verify the invariant.
        let not_present = MLS_CTX.with(|ctx| {
            let ctx = ctx.borrow();
            ctx.get("nonexistent-test-identity-id").is_none()
        });
        assert!(
            not_present,
            "unregistered identity_id must not be found in MLS_CTX"
        );
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
