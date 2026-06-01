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
export type MlsIdentityResult = { identityId: string; keyPackage: Uint8Array };
export type MlsGroupResult = { groupId: string };
export type MlsKeyPackageResult = { keyPackage: Uint8Array };
export type MlsWelcomeResult = { welcome: Uint8Array };
export type MlsCiphertextResult = { ciphertext: Uint8Array };
export type MlsPlaintextResult = { plaintext: Uint8Array };
export type MlsGroupMember = { leafIndex: number; sigKeyHex: string };
export type MlsSafetyNumberResult = { safetyNumber: string };

// ── Minimal type contract for the wasm-bindgen generated module ─────────────

interface WasmModule {
	default: () => Promise<void>;
	version: () => string;
	opaque_registration_start: (password: Uint8Array) => OpaqueStartResult;
	opaque_registration_finish: (
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	) => RegFinishResult;
	opaque_login_start: (password: Uint8Array) => OpaqueStartResult;
	opaque_login_finish: (
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	) => LoginFinishResult;
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
	 * Generate a fresh (single-use) KeyPackage for an existing identity.
	 * Returns { keyPackage }.
	 */
	async mlsGetKeyPackage(identityId: string): Promise<MlsKeyPackageResult> {
		const wasm = await getWasm();
		return wasm.mls_get_key_package(identityId);
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
};

export type CryptoWorkerApi = typeof api;

Comlink.expose(api);
