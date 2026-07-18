// Comlink crypto worker — all cryptographic operations run here in an isolated
// Web Worker thread. The WASM module (powehi-crypto-wasm) is loaded lazily on
// first use and keeps in-memory MLS + OPAQUE state for the worker lifetime.
//
// Callers create a Comlink proxy in the main thread:
//   const worker = new Worker(new URL('./workers/crypto.worker.ts', import.meta.url), { type: 'module' });
//   const crypto = Comlink.wrap<CryptoWorkerApi>(worker);
//
// Security: plaintext, passwords, export keys never cross the worker boundary
// in logs; they are always Uint8Array parameters / return values passed via
// the structured-clone algorithm.

import * as Comlink from "comlink";
import { decryptField, deriveDbKey, encryptField } from "../db/encryption";

// ── Return-type contracts ───────────────────────────────────────────────────

export type OpaqueStartResult = { sessionId: string; message: Uint8Array };
export type RegFinishResult = { upload: Uint8Array };
export type LoginFinishResult = { finalization: Uint8Array };
export type MlsIdentityResult = {
	identityId: string;
	keyPackage: Uint8Array;
	pqDecapKeyHandle: string;
};
// §8.5 recovery: only the phrase-derived identity variant additionally returns
// the 32-byte Ed25519 recovery public key (recoveryPubkey). Kept as a distinct
// type so `mlsInitIdentity` and other MlsIdentityResult consumers are NOT
// (incorrectly) typed as returning it.
export type MlsIdentityFromPhraseResult = MlsIdentityResult & {
	recoveryPubkey: Uint8Array;
};
export type MlsGroupResult = { groupId: string };
export type MlsKeyPackageResult = { keyPackage: Uint8Array; pqDecapKeyHandle: string };
// MLS full-context export/import (worker-reload persistence, wasm_exports.rs
// "MLS full-context export/import" section). stateBytes/state_bytes carry live
// key material — callers MUST only ever persist/pass bytes that round-tripped
// through the encrypted-db.ts AES-GCM at-rest layer (see gate 1 in that module).
export type MlsExportStateResult = { stateBytes: Uint8Array; generation: number };
export type MlsImportStateResult = { identityId: string; groupIds: string[]; generation: number };

/**
 * Thrown by mlsImportState when the WASM freshness/format gate rejects a blob
 * (stale-generation, corrupt/tampered-at-rest, or unsupported-version). A
 * content-free discriminated category — carries NO blob bytes, key material,
 * or generation value, only a stable `name` — so callers can distinguish a
 * genuine import rejection from a routine "no stored envelope yet" case
 * without violating no-plaintext-logging. The `name` survives Comlink's error
 * serialization, so main-thread callers can branch on `err.name`.
 */
export class MlsImportRejectedError extends Error {
	constructor() {
		super("mls_import_rejected");
		this.name = "MlsImportRejectedError";
	}
}

// prd.md §5.3 Phase B — extract ML-KEM encap key from a peer's KeyPackage extension.
export type MlsPqEncapKeyResult = { encapKey: Uint8Array; signature: Uint8Array };
export type MlsWelcomeResult = { welcome: Uint8Array };
export type MlsCiphertextResult = { ciphertext: Uint8Array };
export type MlsPlaintextResult = { plaintext: Uint8Array };
export type MlsGroupMember = { leafIndex: number; sigKeyHex: string };
export type MlsSafetyNumberResult = { safetyNumber: string };
// ADR-0003 Phase B: opaque-handle types — raw key bytes stay inside the worker.
export type MlKemKeygenV2Result = { encapKey: Uint8Array; decapKeyHandle: string };
export type MlKemEncapV2Result = { ciphertext: Uint8Array; sharedSecretHandle: string };
export type MlKemDecapV2Result = { sharedSecretHandle: string };
// ADR-0003 Phase B, Y-3: signed encap key credential.
export type MlKemSignResult = { signature: Uint8Array };
export type MlKemVerifyResult = { valid: boolean };
// prd.md §5.3 Phase B — PQ group binding derived from ML-KEM shared secret.
export type MlsPqBindingResult = { bindingHex: string };
// §9.2 Media encryption: AES-256-GCM opaque-handle types.
// mediaKeyHandle: the 32-byte AES-256-GCM key stays inside the worker; only the
// opaque string handle crosses the worker boundary (sender path).
export type MediaEncryptResult = {
	ciphertext: Uint8Array;
	mediaKeyHandle: string;
	iv: Uint8Array;
	blobHash: Uint8Array;
};

// prd.md §9.4.2 Chunked media encryption (large video streaming). Same
// opaque-handle pattern as MediaEncryptResult, plus totalSize (true plaintext
// length) and chunkSize (constant 16 MiB, echoed back for forward-compat).
export type MediaEncryptChunkedResult = {
	ciphertext: Uint8Array;
	mediaKeyHandle: string;
	iv: Uint8Array;
	blobHash: Uint8Array;
	totalSize: number;
	chunkSize: number;
};

// ── Internal WASM raw return types (include exportKey — consumed in worker) ──

type WasmRegFinishResult = { exportKey: Uint8Array; upload: Uint8Array };
type WasmLoginFinishResult = { exportKey: Uint8Array; finalization: Uint8Array };

// ── Minimal type contract for the wasm-bindgen generated module ─────────────

interface WasmModule {
	default: () => Promise<void>;
	version: () => string;
	opaque_registration_start: (password: Uint8Array) => OpaqueStartResult;
	opaque_registration_finish: (
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	) => WasmRegFinishResult;
	opaque_login_start: (password: Uint8Array) => OpaqueStartResult;
	opaque_login_finish: (
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	) => WasmLoginFinishResult;
	mls_init_identity: (identityBytes: Uint8Array) => MlsIdentityResult;
	mls_get_key_package: (identityId: string) => MlsKeyPackageResult;
	mls_create_group: (identityId: string) => MlsGroupResult;
	mls_add_member: (identityId: string, groupId: string, keyPackage: Uint8Array) => MlsWelcomeResult;
	mls_join_group: (identityId: string, welcome: Uint8Array) => MlsGroupResult;
	mls_encrypt: (identityId: string, groupId: string, plaintext: Uint8Array) => MlsCiphertextResult;
	mls_decrypt: (identityId: string, groupId: string, ciphertext: Uint8Array) => MlsPlaintextResult;
	mls_group_members: (identityId: string, groupId: string) => MlsGroupMember[];
	mls_compute_safety_number: (sigKeyA: Uint8Array, sigKeyB: Uint8Array) => MlsSafetyNumberResult;
	mls_clear_session: () => void;
	// MLS full-context export/import (worker-reload persistence).
	mls_export_state: (identityId: string, generation: number) => MlsExportStateResult;
	mls_import_state: (stateBytes: Uint8Array, minGeneration: number) => MlsImportStateResult;
	// §8.5 Recovery: BIP-39 phrase generation and phrase-derived identity.
	mls_generate_recovery_phrase: () => { words: string[] };
	mls_init_identity_from_phrase: (
		phrase: string,
		identityBytes: Uint8Array,
	) => MlsIdentityFromPhraseResult;
	mls_sign_recovery_challenge: (
		phrase: string,
		loginNonce: Uint8Array,
	) => { signature: Uint8Array };
	// Post-quantum KEM (FIPS 203 ML-KEM-768) — ADR-0003 Phase A primitives.
	ml_kem_768_keygen: () => { encapKey: Uint8Array; decapKey: Uint8Array };
	ml_kem_768_encap: (encapKey: Uint8Array) => { ciphertext: Uint8Array; sharedSecret: Uint8Array };
	ml_kem_768_decap: (decapKey: Uint8Array, ciphertext: Uint8Array) => { sharedSecret: Uint8Array };
	// ADR-0003 Phase B: opaque-handle API — raw key bytes never cross the WASM-JS boundary.
	ml_kem_768_keygen_v2: () => MlKemKeygenV2Result;
	ml_kem_768_encap_v2: (encapKey: Uint8Array) => MlKemEncapV2Result;
	ml_kem_768_decap_v2: (decapKeyHandle: string, ciphertext: Uint8Array) => MlKemDecapV2Result;
	ml_kem_768_drop_decap_key: (handle: string) => void;
	ml_kem_768_drop_shared_secret: (handle: string) => void;
	// ADR-0003 Phase B, Y-3: signed encap key credential.
	ml_kem_768_sign_encap_key: (identityId: string, encapKey: Uint8Array) => MlKemSignResult;
	ml_kem_768_verify_encap_key: (
		encapKey: Uint8Array,
		signature: Uint8Array,
		sigPubKey: Uint8Array,
	) => MlKemVerifyResult;
	// §9.2 Media encryption: AES-256-GCM opaque-handle API.
	media_encrypt: (plaintext: Uint8Array) => MediaEncryptResult;
	media_decrypt: (mediaKeyHandle: string, iv: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
	// Receiver-side opaque-handle pattern (cycle 309): import a raw key once, then
	// decrypt only via the handle — the raw key never re-enters JS scope after import.
	media_import_key: (rawKey: Uint8Array) => { mediaKeyHandle: string };
	media_decrypt_with_handle: (
		mediaKeyHandle: string,
		iv: Uint8Array,
		ciphertext: Uint8Array,
		blobHash: Uint8Array,
	) => Uint8Array;
	media_drop_key: (handle: string) => boolean;
	// §9.2 media_message_create: build + MLS-encrypt a media app message.
	// Raw media key stays in WASM; only MLS ciphertext crosses the WASM-JS boundary.
	media_message_create: (
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		mimeType?: string,
	) => { ciphertext: Uint8Array };
	// prd.md §9.4.2 Chunked media encryption (large video streaming) — AES-256-GCM
	// chunked at 16MiB with zero-padded last chunk for size-bucket leak mitigation.
	media_encrypt_chunked: (plaintext: Uint8Array) => MediaEncryptChunkedResult;
	media_decrypt_chunked_with_handle: (
		mediaKeyHandle: string,
		iv: Uint8Array,
		ciphertext: Uint8Array,
		blobHash: Uint8Array,
		totalSize: number,
	) => Uint8Array;
	media_message_create_chunked: (
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		totalSize: number,
		mimeType?: string,
	) => { ciphertext: Uint8Array };
	// §9.4.1 Thumbnail encryption: AES-256-GCM opaque-handle API.
	// Thumbnail key stays in WASM on the sender path (same as mediaKey).
	media_thumbnail_encrypt: (thumbBytes: Uint8Array) => { thumbHandle: string };
	media_thumbnail_drop: (handle: string) => boolean;
	media_thumbnail_decrypt_with_handle: (
		mediaKeyHandle: string,
		ct: Uint8Array,
		iv: Uint8Array,
	) => { pixels: Uint8Array<ArrayBuffer> };
	media_message_create_with_thumbnail: (
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		thumbHandle: string,
		mimeType?: string,
	) => { ciphertext: Uint8Array };
	// prd.md §5.3 Phase B — extract PQ KEM encap key + signature from a KeyPackage.
	mls_pq_extract_encap_key: (keyPackageBytes: Uint8Array) => MlsPqEncapKeyResult;
	// prd.md §5.3 Phase B — extract AND verify in one step (recommended; prevents skipped verification).
	mls_pq_extract_and_verify_encap_key: (
		keyPackageBytes: Uint8Array,
		sigPubKey: Uint8Array,
	) => MlsPqEncapKeyResult;
	// prd.md §5.3 Phase B — derive PQ group binding from a shared-secret handle.
	mls_pq_derive_binding: (ssHandle: string, groupId: string) => MlsPqBindingResult;
}

// ── IndexedDB key — held inside the worker, never crosses to main thread ─────

// The DB key lives here for the authenticated session lifetime. The main thread
// calls initDbKey(exportKeyBytes) once after OPAQUE login/registration, then uses
// encryptDbField/decryptDbField for all IndexedDB field operations.
let dbKey: CryptoKey | null = null;

// ── WASM lazy-init ──────────────────────────────────────────────────────────

// The WASM module is resolved at build time by wasm-pack + Vite.
// The path below is relative to the built output; adjust if the wasm-pack
// output directory changes in package.json build:wasm script.
let wasmModule: WasmModule | null = null;

async function getWasm(): Promise<WasmModule> {
	if (wasmModule !== null) return wasmModule;
	// Dynamic import so the WASM bundle is only fetched when the worker starts.
	const mod = (await import(
		/* @vite-ignore */
		"../wasm/powehi_crypto_wasm.js"
	)) as unknown as WasmModule;
	// Run the wasm-bindgen init function (fetches + compiles the .wasm binary).
	await mod.default();
	wasmModule = mod;
	return mod;
}

// ── Worker API ──────────────────────────────────────────────────────────────

const api = {
	/** WASM module version string. */
	async version(): Promise<string> {
		const wasm = await getWasm();
		return wasm.version();
	},

	// ── OPAQUE ───────────────────────────────────────────────────────────────

	/**
	 * Start OPAQUE registration (client step 1).
	 * Returns { sessionId, message }. Send `message` to the server.
	 */
	async opaqueRegistrationStart(password: Uint8Array): Promise<OpaqueStartResult> {
		const wasm = await getWasm();
		return wasm.opaque_registration_start(password);
	},

	/**
	 * Finish OPAQUE registration (client step 3).
	 * Returns { upload }. Send `upload` to the server.
	 * The OPAQUE export key is derived into the IndexedDB AES-GCM-256 key here
	 * in the worker — it never crosses the worker/main-thread boundary.
	 * The session is consumed — calling again with the same sessionId errors.
	 */
	async opaqueRegistrationFinish(
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	): Promise<RegFinishResult> {
		const wasm = await getWasm();
		const result = wasm.opaque_registration_finish(sessionId, password, serverResponse);
		// Derive and hold the DB key inside the worker (F1: export key never leaves).
		dbKey = await deriveDbKey(result.exportKey);
		return { upload: result.upload };
	},

	/**
	 * Start OPAQUE login (client step 1).
	 * Returns { sessionId, message }. Send `message` to the server.
	 */
	async opaqueLoginStart(password: Uint8Array): Promise<OpaqueStartResult> {
		const wasm = await getWasm();
		return wasm.opaque_login_start(password);
	},

	/**
	 * Finish OPAQUE login (client step 3).
	 * Returns { finalization }. Send `finalization` to the server.
	 * The OPAQUE export key is derived into the IndexedDB AES-GCM-256 key here
	 * in the worker — it never crosses the worker/main-thread boundary.
	 * Wrong password → rejection; DB key is never set on failure.
	 */
	async opaqueLoginFinish(
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	): Promise<LoginFinishResult> {
		const wasm = await getWasm();
		const result = wasm.opaque_login_finish(sessionId, password, serverResponse);
		// Derive and hold the DB key inside the worker (F1: export key never leaves).
		dbKey = await deriveDbKey(result.exportKey);
		return { finalization: result.finalization };
	},

	// ── MLS ──────────────────────────────────────────────────────────────────

	/**
	 * Initialize a new MLS identity. Returns { identityId, keyPackage }.
	 * Upload `keyPackage` to the KeyPackage Service.
	 */
	async mlsInitIdentity(identityBytes: Uint8Array): Promise<MlsIdentityResult> {
		const wasm = await getWasm();
		return wasm.mls_init_identity(identityBytes);
	},

	/**
	 * Generate 24 BIP-39 recovery words (§8.5).
	 * Words are returned to the caller for display; they are NEVER stored by this worker.
	 * The caller must display them once and then discard the array.
	 */
	async generateRecoveryPhrase(): Promise<{ words: string[] }> {
		const wasm = await getWasm();
		return wasm.mls_generate_recovery_phrase();
	},

	/**
	 * Initialise an MLS identity derived from a BIP-39 recovery phrase (§8.5).
	 * The signing key inside WASM is derived from the full BIP-39 seed; identityBytes
	 * is a 16-byte public label (SHA-256(phrase)[0..16]) included in the KeyPackage.
	 * Returns { identityId, keyPackage } — same shape as mlsInitIdentity.
	 */
	async mlsInitIdentityFromPhrase(
		phrase: string,
		identityBytes: Uint8Array,
	): Promise<MlsIdentityFromPhraseResult> {
		const wasm = await getWasm();
		return wasm.mls_init_identity_from_phrase(phrase, identityBytes);
	},

	/**
	 * Sign the server's recovery-challenge login nonce with the phrase-derived
	 * recovery-auth key (§8.5 account restore) — a key cryptographically distinct
	 * from and independent of the MLS identity signing key, since its public half
	 * (`recoveryPubkey`) is durably stored server-side and must never be linkable
	 * to the MLS identity key the server is never supposed to learn. `loginNonce`
	 * must be the UTF-8 bytes of the server's `login_nonce` string (new
	 * TextEncoder().encode). Returns { signature } — the 64-byte Ed25519
	 * signature. The signing key never leaves WASM; only the signature crosses
	 * the boundary.
	 */
	async mlsSignRecoveryChallenge(
		phrase: string,
		loginNonce: Uint8Array,
	): Promise<{ signature: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.mls_sign_recovery_challenge(phrase, loginNonce);
	},

	/**
	 * Generate a fresh (single-use) KeyPackage for an existing identity.
	 * Returns { keyPackage }.
	 */
	async mlsGetKeyPackage(identityId: string): Promise<MlsKeyPackageResult> {
		const wasm = await getWasm();
		return wasm.mls_get_key_package(identityId);
	},

	/**
	 * Extract the ML-KEM-768 encapsulation key and its Ed25519 signature from a
	 * peer's KeyPackage (prd.md §5.3 Phase B).  Returns { encapKey, signature }.
	 * Call mlKem768VerifyEncapKey before using the encap key to add a member.
	 */
	async mlsPqExtractEncapKey(keyPackageBytes: Uint8Array): Promise<MlsPqEncapKeyResult> {
		const wasm = await getWasm();
		return wasm.mls_pq_extract_encap_key(keyPackageBytes);
	},

	/**
	 * Extract AND verify the ML-KEM-768 encapsulation key from a peer's KeyPackage
	 * in one atomic step (prd.md §5.3 Phase B, ADR-0003 Y-3).
	 * Preferred over mlsPqExtractEncapKey — verification cannot be accidentally skipped.
	 * `sigPubKey`: 32-byte Ed25519 public key from the peer's group roster entry.
	 */
	async mlsPqExtractAndVerifyEncapKey(
		keyPackageBytes: Uint8Array,
		sigPubKey: Uint8Array,
	): Promise<MlsPqEncapKeyResult> {
		const wasm = await getWasm();
		return wasm.mls_pq_extract_and_verify_encap_key(keyPackageBytes, sigPubKey);
	},

	/**
	 * Derive an 8-byte PQ group binding (16-char hex) from an ML-KEM shared-secret handle
	 * and **drop** the handle (prd.md §5.3 Phase B).
	 *
	 * HKDF-SHA256(ikm=ss, salt=None, info=b"powehi-pq-binding-v1" || groupId) → 8 bytes.
	 * Drops the handle from WASM storage regardless of success or error.
	 * Returns { bindingHex } on success; throws if the handle is unknown.
	 */
	async mlsPqDeriveBinding(ssHandle: string, groupId: string): Promise<MlsPqBindingResult> {
		const wasm = await getWasm();
		return wasm.mls_pq_derive_binding(ssHandle, groupId);
	},

	/**
	 * Create a new MLS group with the given identity as the sole member.
	 * Returns { groupId }.
	 */
	async mlsCreateGroup(identityId: string): Promise<MlsGroupResult> {
		const wasm = await getWasm();
		return wasm.mls_create_group(identityId);
	},

	/**
	 * Add a peer to the group (by their KeyPackage). Advances the epoch.
	 * Returns { welcome }. Send `welcome` to the new member.
	 */
	async mlsAddMember(
		identityId: string,
		groupId: string,
		keyPackage: Uint8Array,
	): Promise<MlsWelcomeResult> {
		const wasm = await getWasm();
		return wasm.mls_add_member(identityId, groupId, keyPackage);
	},

	/**
	 * Join an MLS group from a Welcome message.
	 * Returns { groupId } — the same groupId used by the creator.
	 */
	async mlsJoinGroup(identityId: string, welcome: Uint8Array): Promise<MlsGroupResult> {
		const wasm = await getWasm();
		return wasm.mls_join_group(identityId, welcome);
	},

	/**
	 * Encrypt plaintext as an MLS application message.
	 * Returns { ciphertext }.
	 */
	async mlsEncrypt(
		identityId: string,
		groupId: string,
		plaintext: Uint8Array,
	): Promise<MlsCiphertextResult> {
		const wasm = await getWasm();
		return wasm.mls_encrypt(identityId, groupId, plaintext);
	},

	/**
	 * Decrypt an MLS application message.
	 * Returns { plaintext }. Stale-epoch messages error (forward secrecy).
	 */
	async mlsDecrypt(
		identityId: string,
		groupId: string,
		ciphertext: Uint8Array,
	): Promise<MlsPlaintextResult> {
		const wasm = await getWasm();
		return wasm.mls_decrypt(identityId, groupId, ciphertext);
	},

	/**
	 * Export the full MLS context (identity + provider key store + every group)
	 * for at-rest persistence across a worker reload (wasm_exports.rs).
	 *
	 * `generation` MUST be a monotonically increasing counter the caller
	 * maintains — pass the last-used value + 1. Returns { stateBytes, generation }.
	 *
	 * SECURITY: stateBytes contains live key material (Ed25519 signing key) and
	 * MLS epoch secrets for every group. Callers MUST persist it only through
	 * the encrypted-db.ts AES-GCM at-rest layer — never log it, never send it
	 * to the server (no-plaintext-logging: the blob itself is key material).
	 */
	async mlsExportState(identityId: string, generation: number): Promise<MlsExportStateResult> {
		const wasm = await getWasm();
		return wasm.mls_export_state(identityId, generation);
	},

	/**
	 * Reconstruct a full MLS context from bytes produced by mlsExportState,
	 * installing it under a freshly minted identityId (wasm_exports.rs).
	 *
	 * `minGeneration` is the anti-replay floor: a blob whose bundled generation
	 * is strictly less than it is rejected. It defaults to 0 and is normally
	 * NOT supplied by the caller — the useCryptoWorker persistence wrapper owns
	 * the only trustworthy floor (the in-session high-water-mark) and injects
	 * it. On the first import of a fresh worker the floor is 0, so no authentic
	 * blob is rejected (cross-reload wholesale replay is out of scope for this
	 * gate — see useCryptoWorker.ts SECURITY header); a later in-session import
	 * cannot roll back below already-advanced state.
	 *
	 * SECURITY (gate 1, mandatory precondition): `stateBytes` MUST only ever be
	 * bytes that already round-tripped through the encrypted-db.ts AES-GCM
	 * *authenticated* decryption path — never raw/unauthenticated bytes. A
	 * well-formed-but-corrupt envelope can panic deep inside openmls's storage
	 * read path; AEAD-at-rest integrity is what makes that path safe to call.
	 *
	 * Returns { identityId, groupIds, generation } on success; throws on a
	 * stale/corrupt/wrong-version blob. Does NOT return a fresh KeyPackage —
	 * callers should separately call mlsGetKeyPackage(identityId) afterward.
	 */
	async mlsImportState(stateBytes: Uint8Array, minGeneration = 0): Promise<MlsImportStateResult> {
		const wasm = await getWasm();
		try {
			return wasm.mls_import_state(stateBytes, minGeneration);
		} catch (caught) {
			// Only normalize a DELIBERATE WASM-side rejection (mls_import_state's
			// documented Err path: stale generation, unsupported version, corrupt/
			// malformed structure, missing group — see wasm_exports.rs
			// import_mls_context_inner) to the content-free MlsImportRejectedError
			// category. wasm-bindgen constructs those via `JsError::new`, which
			// throws a genuine `Error` instance whose `.name` is exactly "Error".
			//
			// An unexpected WASM trap (a real Rust panic deep in openmls's storage
			// read path — see the gate-1 doc above) surfaces to JS as a
			// `WebAssembly.RuntimeError` (`.name === "RuntimeError"`), and any other
			// unrecognized thrown value is likewise NOT a routine "bad blob"
			// rejection. Rethrow those as-is instead of collapsing them into
			// MlsImportRejectedError — crypto-reviewer finding Y1: misclassifying a
			// genuine internal failure as a routine stale/corrupt-envelope
			// rejection previously let callers (Login.tsx) treat it as safe to
			// discard/replace the on-disk state, when it is not.
			if (caught instanceof Error && caught.name === "Error") {
				throw new MlsImportRejectedError();
			}
			throw caught;
		}
	},

	/**
	 * Get public identity info for all current members of an MLS group.
	 * Returns an array of { leafIndex, sigKeyHex } objects.
	 * sigKeyHex is the Ed25519 signature public key as hex — public data only.
	 */
	async mlsGroupMembers(identityId: string, groupId: string): Promise<MlsGroupMember[]> {
		const wasm = await getWasm();
		return wasm.mls_group_members(identityId, groupId) as unknown as MlsGroupMember[];
	},

	/**
	 * Compute a Safety Number from two Ed25519 signature public keys.
	 * Returns { safetyNumber } — 12 five-digit groups separated by spaces.
	 * Symmetric: (a, b) == (b, a).
	 */
	async mlsComputeSafetyNumber(
		sigKeyA: Uint8Array,
		sigKeyB: Uint8Array,
	): Promise<MlsSafetyNumberResult> {
		const wasm = await getWasm();
		return wasm.mls_compute_safety_number(sigKeyA, sigKeyB);
	},

	// ── IndexedDB field encryption ────────────────────────────────────────────

	/**
	 * Encrypt a sensitive IndexedDB field value with the session DB key.
	 * Returns base64url( IV || AES-GCM-ciphertext ).
	 * Throws if initDbKey has not been called.
	 */
	async encryptDbField(value: string): Promise<string> {
		if (dbKey === null) throw new Error("db key not initialised");
		return encryptField(dbKey, value);
	},

	/**
	 * Decrypt an IndexedDB field value encrypted by encryptDbField.
	 * Throws on wrong key or tampered ciphertext (AES-GCM auth tag).
	 * NEVER log the surrounding row context — no-plaintext-logging invariant.
	 */
	async decryptDbField(value: string): Promise<string> {
		if (dbKey === null) throw new Error("db key not initialised");
		return decryptField(dbKey, value);
	},

	/**
	 * Clear the IndexedDB key from worker memory.
	 * Call from the auth store logout reducer so the key does not linger after sign-out.
	 */
	dropDbKey(): void {
		dbKey = null;
	},

	/**
	 * Clear all MLS identities, groups, and in-flight OPAQUE sessions from WASM heap.
	 * Call from the auth store logout reducer so the prior session's key material is
	 * no longer accessible after sign-out.
	 *
	 * Note: WASM linear memory is not physically zeroed — the allocator marks freed
	 * memory as available, but bytes persist until overwritten. The guarantee is that
	 * no Rust-level reference to prior-session material remains after this call.
	 */
	async clearSessionState(): Promise<void> {
		const wasm = await getWasm();
		wasm.mls_clear_session();
	},

	// ── ML-KEM-768 (FIPS 203) — ADR-0003 Phase A PQ KEM primitives ──────────────
	//
	// PHASE-A TEST-SURFACE ONLY — NOT FOR PRODUCTION USE:
	// These methods return raw key material (decapKey, sharedSecret) across the
	// Comlink worker boundary to the main thread, which violates the rule that
	// "raw key material must never appear in React component scope" (react-hooks-only.md).
	// Production code must NOT call these methods from React components or stores.
	// They exist solely to validate the FIPS 203 primitives end-to-end.
	// ADR-0003 Phase B will define a higher-level hybrid KEM API where all intermediate
	// key material stays inside the worker (mirroring the MLS mlsEncrypt/mlsDecrypt pattern).

	/**
	 * Generate an ML-KEM-768 keypair.
	 * Returns { encapKey: 1184 bytes, decapKey: 2400 bytes }.
	 * Zero decapKey after use: decapKey.fill(0).
	 * PHASE-A ONLY: decapKey crosses the worker boundary — do not use in production code.
	 */
	async mlKem768Keygen(): Promise<{ encapKey: Uint8Array; decapKey: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_keygen();
	},

	/**
	 * Encapsulate a shared secret under the given ML-KEM-768 encapsulation key.
	 * encapKey must be 1184 bytes (from mlKem768Keygen).
	 * Returns { ciphertext: 1088 bytes, sharedSecret: 32 bytes }.
	 * Zero sharedSecret after use: sharedSecret.fill(0).
	 */
	async mlKem768Encap(
		encapKey: Uint8Array,
	): Promise<{ ciphertext: Uint8Array; sharedSecret: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_encap(encapKey);
	},

	/**
	 * Decapsulate a shared secret from a ciphertext using the ML-KEM-768 decapsulation key.
	 * decapKey must be 2400 bytes, ciphertext must be 1088 bytes.
	 * Returns { sharedSecret: 32 bytes }. Zero sharedSecret after use.
	 * Note: ML-KEM implicit rejection — wrong key returns a pseudorandom secret, not an error.
	 */
	async mlKem768Decap(
		decapKey: Uint8Array,
		ciphertext: Uint8Array,
	): Promise<{ sharedSecret: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_decap(decapKey, ciphertext);
	},

	// ── ML-KEM-768 Phase B: opaque-handle API (ADR-0003 Phase B, Y-1 fix) ─────
	//
	// These methods close Y-1: raw decap keys and shared secrets are stored inside
	// the WASM worker and never cross the Comlink boundary to the main thread.
	// Only encapKey (public) and opaque string handles are returned to callers.

	/**
	 * Generate an ML-KEM-768 keypair — Phase B opaque-handle API.
	 * Returns { encapKey: 1184 bytes, decapKeyHandle: string }.
	 * decapKey bytes stay inside the WASM worker (Y-1 fix).
	 * Call mlKem768DropDecapKey(handle) when done.
	 */
	async mlKem768KeygenV2(): Promise<MlKemKeygenV2Result> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_keygen_v2();
	},

	/**
	 * Encapsulate a shared secret — Phase B opaque-handle API.
	 * encapKey must be 1184 bytes (from mlKem768KeygenV2).
	 * Returns { ciphertext: 1088 bytes, sharedSecretHandle: string }.
	 * sharedSecret bytes stay inside the WASM worker (Y-1 fix).
	 * Call mlKem768DropSharedSecret(handle) when done.
	 */
	async mlKem768EncapV2(encapKey: Uint8Array): Promise<MlKemEncapV2Result> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_encap_v2(encapKey);
	},

	/**
	 * Decapsulate using a stored decap key handle — Phase B opaque-handle API.
	 * decapKeyHandle: string from mlKem768KeygenV2.
	 * ciphertext: 1088 bytes from mlKem768EncapV2.
	 * Returns { sharedSecretHandle: string }.
	 * sharedSecret bytes stay inside the WASM worker (Y-1 fix).
	 * Call mlKem768DropSharedSecret(handle) when done.
	 */
	async mlKem768DecapV2(
		decapKeyHandle: string,
		ciphertext: Uint8Array,
	): Promise<MlKemDecapV2Result> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_decap_v2(decapKeyHandle, ciphertext);
	},

	/**
	 * Explicitly drop a stored ML-KEM-768 decap key by handle.
	 * The Zeroizing wrapper zeroes the heap buffer before deallocation.
	 * Idempotent: no-ops on unknown handles.
	 */
	async mlKem768DropDecapKey(handle: string): Promise<void> {
		const wasm = await getWasm();
		wasm.ml_kem_768_drop_decap_key(handle);
	},

	/**
	 * Explicitly drop a stored ML-KEM-768 shared secret by handle.
	 * The Zeroizing wrapper zeroes the heap buffer before deallocation.
	 * Idempotent: no-ops on unknown handles.
	 */
	async mlKem768DropSharedSecret(handle: string): Promise<void> {
		const wasm = await getWasm();
		wasm.ml_kem_768_drop_shared_secret(handle);
	},

	// ── ML-KEM-768 Phase B: signed encap key (ADR-0003 Phase B, Y-3 fix) ─────
	//
	// These methods close Y-3: the encap key holder authenticates the encap key
	// by signing it with the MLS Ed25519 identity key. Peers MUST verify the
	// signature before encapsulating to prevent key substitution attacks.

	/**
	 * Sign an ML-KEM-768 encap key with the identity's MLS Ed25519 signing key.
	 * identityId: from mlsInitIdentity; encapKey: 1184 bytes from mlKem768KeygenV2.
	 * Returns { signature: 64 bytes }.
	 * The private signing key stays inside the WASM worker (ADR-0003 Phase B, Y-3).
	 * Distribute the signature alongside the encap key so peers can verify it.
	 */
	async mlKem768SignEncapKey(identityId: string, encapKey: Uint8Array): Promise<MlKemSignResult> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_sign_encap_key(identityId, encapKey);
	},

	/**
	 * Verify an ML-KEM-768 encap key signature before encapsulating.
	 * encapKey: 1184 bytes. signature: 64 bytes from mlKem768SignEncapKey.
	 * sigPubKey: 32 bytes — the signer's Ed25519 public key from the MLS roster
	 *   (mls_group_members sigKeyHex, hex-decoded). MUST come from a trusted source.
	 * Returns { valid: boolean }.
	 * If valid is false, the encap key was substituted — do NOT encapsulate under it.
	 */
	async mlKem768VerifyEncapKey(
		encapKey: Uint8Array,
		signature: Uint8Array,
		sigPubKey: Uint8Array,
	): Promise<MlKemVerifyResult> {
		const wasm = await getWasm();
		return wasm.ml_kem_768_verify_encap_key(encapKey, signature, sigPubKey);
	},

	// ── §9.2 Media encryption (AES-256-GCM opaque-handle API) ────────────────

	/**
	 * Encrypt a media file with a fresh AES-256-GCM key and IV (prd.md §9.2).
	 *
	 * Returns { ciphertext, mediaKeyHandle, iv, blobHash }.
	 * Upload `ciphertext` to R2 via the presigned URL from POST /v1/media/upload-url.
	 * The raw 32-byte AES key stays inside the worker; only the opaque handle crosses.
	 *
	 * Call mediaDropKey(mediaKeyHandle) when the handle is no longer needed.
	 */
	async mediaEncrypt(plaintext: Uint8Array): Promise<MediaEncryptResult> {
		const wasm = await getWasm();
		return wasm.media_encrypt(plaintext);
	},

	/**
	 * Decrypt an R2 blob using a stored media key handle (sender re-decrypt path).
	 *
	 * @param mediaKeyHandle  handle returned by mediaEncrypt
	 * @param iv              12-byte nonce returned by mediaEncrypt
	 * @param ciphertext      encrypted blob from R2
	 */
	async mediaDecrypt(
		mediaKeyHandle: string,
		iv: Uint8Array,
		ciphertext: Uint8Array,
	): Promise<Uint8Array> {
		const wasm = await getWasm();
		return wasm.media_decrypt(mediaKeyHandle, iv, ciphertext);
	},

	/**
	 * Import a raw 32-byte media key into the opaque handle map (receiver path,
	 * cycle 309 — closes the cycle-119 YELLOW). The mediaKey bytes arrive inside the
	 * MLS-decrypted application message payload; call this immediately after
	 * mlsDecrypt, then zero the caller's own copy (`mediaKey.fill(0)`) — from then
	 * on only the returned handle is used, mirroring the sender path's mediaEncrypt.
	 *
	 * @param rawKey  32-byte AES-256-GCM key from the MLS message payload
	 */
	async mediaImportKey(rawKey: Uint8Array): Promise<{ mediaKeyHandle: string }> {
		const wasm = await getWasm();
		return wasm.media_import_key(rawKey);
	},

	/**
	 * Decrypt an R2 blob using an imported media key handle (receiver path).
	 *
	 * R-2 (crypto-reviewer, NIST SP 800-38D §5.2.1.1): blobHash is the SHA-256 of the
	 * ciphertext embedded in the MLS message by the sender. WASM verifies it before
	 * AES-GCM decrypt to detect a server-side R2 blob swap without exposing an oracle.
	 *
	 * @param mediaKeyHandle  handle returned by mediaImportKey
	 * @param iv              12-byte nonce from the MLS message payload
	 * @param ciphertext      encrypted blob from R2
	 * @param blobHash        32-byte SHA-256(ciphertext) from the MLS message payload
	 */
	async mediaDecryptWithHandle(
		mediaKeyHandle: string,
		iv: Uint8Array,
		ciphertext: Uint8Array,
		blobHash: Uint8Array,
	): Promise<Uint8Array> {
		const wasm = await getWasm();
		return wasm.media_decrypt_with_handle(mediaKeyHandle, iv, ciphertext, blobHash);
	},

	/**
	 * Explicitly drop a stored media key handle (zeroes the 32-byte key on drop).
	 * Returns true if the handle was found and removed.
	 */
	async mediaDropKey(handle: string): Promise<boolean> {
		const wasm = await getWasm();
		return wasm.media_drop_key(handle);
	},

	/**
	 * Build and MLS-encrypt a media attachment message (prd.md §9.2 sender path).
	 *
	 * The raw 32-byte AES-256-GCM media key is retrieved from the handle inside WASM,
	 * wrapped in a JSON payload, and MLS-encrypted — the raw key never crosses the
	 * WASM-JS boundary.  POST the returned ciphertext to /v1/groups/:id/messages.
	 *
	 * @param identityId     Local MLS identity handle (from mlsInitIdentity).
	 * @param groupId        MLS group UUID.
	 * @param mediaKeyHandle Handle returned by mediaEncrypt.
	 * @param blobId         MediaId UUID from requestMediaUpload.
	 * @param blobHash       32-byte SHA-256 of the ciphertext (from mediaEncrypt.blobHash).
	 * @param iv             12-byte AES-GCM nonce (from mediaEncrypt.iv).
	 */
	async mediaMessageCreate(
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		mimeType?: string,
	): Promise<{ ciphertext: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.media_message_create(
			identityId,
			groupId,
			mediaKeyHandle,
			blobId,
			blobHash,
			iv,
			mimeType,
		);
	},

	// ── §9.4.2 Chunked media encryption (large video streaming) ──────────────

	/**
	 * Encrypt a large media file with chunked AES-256-GCM (prd.md §9.4.2).
	 *
	 * Chunks are 16MiB with the last chunk zero-padded for size-bucket leak
	 * mitigation; per-chunk nonces are derived internally from the returned
	 * base `iv`. Returns { ciphertext, mediaKeyHandle, iv, blobHash, totalSize,
	 * chunkSize }. Upload `ciphertext` to R2 exactly like mediaEncrypt.
	 * The raw 32-byte AES key stays inside the worker; only the opaque handle
	 * crosses. Call mediaDropKey(mediaKeyHandle) when the handle is no longer needed.
	 */
	async mediaEncryptChunked(plaintext: Uint8Array): Promise<MediaEncryptChunkedResult> {
		const wasm = await getWasm();
		return wasm.media_encrypt_chunked(plaintext);
	},

	/**
	 * Decrypt+reassemble a chunked R2 blob using an imported media key handle
	 * (receiver path, prd.md §9.4.2).
	 *
	 * WASM verifies the blob hash before any AES-GCM attempt, same as
	 * mediaDecryptWithHandle (R-2, blob-swap detection).
	 *
	 * @param mediaKeyHandle  handle returned by mediaImportKey
	 * @param iv              12-byte base nonce from the MLS message payload
	 * @param ciphertext      encrypted blob from R2
	 * @param blobHash        32-byte SHA-256(ciphertext) from the MLS message payload
	 * @param totalSize       true plaintext length from the MLS message payload
	 */
	async mediaDecryptChunkedWithHandle(
		mediaKeyHandle: string,
		iv: Uint8Array,
		ciphertext: Uint8Array,
		blobHash: Uint8Array,
		totalSize: number,
	): Promise<Uint8Array> {
		const wasm = await getWasm();
		return wasm.media_decrypt_chunked_with_handle(
			mediaKeyHandle,
			iv,
			ciphertext,
			blobHash,
			totalSize,
		);
	},

	/**
	 * Build and MLS-encrypt a chunked media attachment message (prd.md §9.4.2 sender path).
	 *
	 * The raw 32-byte AES-256-GCM media key is retrieved from the handle inside WASM,
	 * wrapped in a JSON payload (`{ type: "video", ..., chunked: true, totalSize, chunkSize }`),
	 * and MLS-encrypted — the raw key never crosses the WASM-JS boundary.
	 * POST the returned ciphertext to /v1/groups/:id/messages.
	 *
	 * @param identityId     Local MLS identity handle (from mlsInitIdentity).
	 * @param groupId        MLS group UUID.
	 * @param mediaKeyHandle Handle returned by mediaEncryptChunked.
	 * @param blobId         MediaId UUID from requestMediaUpload.
	 * @param blobHash       32-byte SHA-256 of the ciphertext (from mediaEncryptChunked.blobHash).
	 * @param iv             12-byte AES-GCM base nonce (from mediaEncryptChunked.iv).
	 * @param totalSize      true plaintext length (from mediaEncryptChunked.totalSize).
	 */
	async mediaMessageCreateChunked(
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		totalSize: number,
		mimeType?: string,
	): Promise<{ ciphertext: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.media_message_create_chunked(
			identityId,
			groupId,
			mediaKeyHandle,
			blobId,
			blobHash,
			iv,
			totalSize,
			mimeType,
		);
	},

	// ── §9.4.1 Thumbnail encryption (AES-256-GCM opaque-handle API) ──────────

	/**
	 * Encrypt thumbnail bytes with a fresh AES-256-GCM key (prd.md §9.4.1).
	 * The thumbnail key stays inside the WASM worker — only an opaque handle is returned.
	 * Call mediaThumbnailDrop(thumbHandle) when done (or after mediaMessageCreateWithThumbnail).
	 * Returns `{ thumbHandle: string }`.
	 */
	async mediaThumbnailEncrypt(thumbBytes: Uint8Array): Promise<{ thumbHandle: string }> {
		const wasm = await getWasm();
		return wasm.media_thumbnail_encrypt(thumbBytes);
	},

	/**
	 * Drop a stored thumbnail key handle (zeroes the 32-byte key on drop).
	 * Idempotent: no-ops on unknown handles.
	 */
	async mediaThumbnailDrop(handle: string): Promise<boolean> {
		const wasm = await getWasm();
		return wasm.media_thumbnail_drop(handle);
	},

	/**
	 * Decrypt thumbnail bytes using an imported key handle (receiver path).
	 * Import the raw thumbnail key via `mediaImportKey` first (and zero the raw copy
	 * immediately) — this mirrors the main media-key receiver flow (cycle 309/311).
	 * Returns `{ pixels: Uint8Array }`. Drop the handle via `mediaDropKey` when done.
	 */
	async mediaThumbnailDecryptWithHandle(
		mediaKeyHandle: string,
		ct: Uint8Array,
		iv: Uint8Array,
	): Promise<{ pixels: Uint8Array<ArrayBuffer> }> {
		const wasm = await getWasm();
		return wasm.media_thumbnail_decrypt_with_handle(mediaKeyHandle, ct, iv);
	},

	/**
	 * Build and MLS-encrypt a media message with an inline encrypted thumbnail (prd.md §9.4.1).
	 * Both the main media key and the thumbnail key stay inside the WASM worker.
	 * After this call: drop both handles via mediaDropKey + mediaThumbnailDrop.
	 */
	async mediaMessageCreateWithThumbnail(
		identityId: string,
		groupId: string,
		mediaKeyHandle: string,
		blobId: string,
		blobHash: Uint8Array,
		iv: Uint8Array,
		thumbHandle: string,
		mimeType?: string,
	): Promise<{ ciphertext: Uint8Array }> {
		const wasm = await getWasm();
		return wasm.media_message_create_with_thumbnail(
			identityId,
			groupId,
			mediaKeyHandle,
			blobId,
			blobHash,
			iv,
			thumbHandle,
			mimeType,
		);
	},
};

export type CryptoWorkerApi = typeof api;

Comlink.expose(api);
