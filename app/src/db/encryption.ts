// IndexedDB encryption layer — AES-GCM-256 field encryption.
//
// Key material derives from the OPAQUE export key via HKDF-SHA-256.
// Keys MUST be held in-memory only (in the crypto worker); never persisted
// to IndexedDB or localStorage.
//
// Design: explicit encrypt/decrypt at the EncryptedPowehiDb boundary via the
// FieldEncryptor interface. Production wires the Comlink crypto worker;
// tests wire DirectFieldEncryptor (SubtleCrypto directly, no worker round-trip).

// Fixed domain-separated salt for HKDF.
// Changing this after deployment invalidates all stored data.
const DB_KEY_SALT = new TextEncoder().encode("powehi-indexed-db-v1");
const DB_KEY_INFO = new TextEncoder().encode("powehi-idb-aes-gcm-256-v1");

// 12-byte AES-GCM nonce — recommended by NIST SP 800-38D §5.2.1.1.
const GCM_IV_BYTES = 12;
// 16-byte AES-GCM authentication tag — SubtleCrypto default per §5.2.1.2.
const GCM_TAG_BYTES = 16;

function uint8ToBase64url(bytes: Uint8Array): string {
	let binary = "";
	const len = bytes.length;
	for (let i = 0; i < len; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function base64urlToUint8(b64url: string): Uint8Array {
	const padded = b64url.replace(/-/g, "+").replace(/_/g, "/");
	const padding = (4 - (padded.length % 4)) % 4;
	const b64 = padded + "=".repeat(padding);
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

/**
 * Derives an AES-GCM-256 CryptoKey from the OPAQUE export key bytes.
 * exportKeyBytes is the raw Uint8Array returned by opaqueLoginFinish / opaqueRegistrationFinish.
 * The derived key is non-extractable and can only encrypt/decrypt (no re-export).
 *
 * This function is called inside the crypto worker — the resulting CryptoKey
 * stays in the worker and never crosses to the main thread (prd.md §5.1 / react-hooks-only.md).
 *
 * Nonce-collision budget (NIST SP 800-38D §8.3): random 96-bit IVs stay under
 * the 2^-32 collision probability limit up to ~2^32 encryptions per key.
 * A session writing ~10^4 fields/hour over 24h reaches ~10^6 < 2^32.
 * If session duration or write rate grows dramatically, add a rekey trigger here.
 */
export async function deriveDbKey(exportKeyBytes: Uint8Array): Promise<CryptoKey> {
	const hkdfKey = await crypto.subtle.importKey("raw", exportKeyBytes, "HKDF", false, [
		"deriveKey",
	]);
	return crypto.subtle.deriveKey(
		{ name: "HKDF", hash: "SHA-256", salt: DB_KEY_SALT, info: DB_KEY_INFO },
		hkdfKey,
		{ name: "AES-GCM", length: 256 },
		false,
		["encrypt", "decrypt"],
	);
}

/**
 * Encrypts a UTF-8 string with AES-GCM-256.
 * Returns base64url( 12-byte-IV || authenticated-ciphertext ).
 * Every call generates a fresh random IV — output is non-deterministic.
 */
export async function encryptField(key: CryptoKey, value: string): Promise<string> {
	const iv = crypto.getRandomValues(new Uint8Array(GCM_IV_BYTES));
	const ciphertext = await crypto.subtle.encrypt(
		{ name: "AES-GCM", iv },
		key,
		new TextEncoder().encode(value),
	);
	const combined = new Uint8Array(GCM_IV_BYTES + ciphertext.byteLength);
	combined.set(iv, 0);
	// .set() copies — subarray() shares the backing buffer and MUST NOT be used here.
	combined.set(new Uint8Array(ciphertext), GCM_IV_BYTES);
	return uint8ToBase64url(combined);
}

/**
 * Decrypts a field encrypted by encryptField.
 * Throws DOMException (OperationError) on wrong key or tampered ciphertext —
 * AES-GCM authentication tag guarantees integrity.
 *
 * NEVER log the row context alongside this error — category-only propagation
 * preserves the no-plaintext-logging invariant (rules/no-plaintext-logging.md).
 */
export async function decryptField(key: CryptoKey, enc: string): Promise<string> {
	const combined = base64urlToUint8(enc);
	// Minimum: 12 bytes IV + 0 bytes plaintext + 16 bytes GCM tag = 28 bytes.
	if (combined.length < GCM_IV_BYTES + GCM_TAG_BYTES) {
		throw new Error("invalid ciphertext: too short");
	}
	// .slice() copies — subarray() shares the backing buffer and MUST NOT be used here.
	const iv = combined.slice(0, GCM_IV_BYTES);
	const ciphertext = combined.slice(GCM_IV_BYTES);
	const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
	return new TextDecoder().decode(plaintext);
}

// ── FieldEncryptor — the abstraction EncryptedPowehiDb uses ──────────────────

/**
 * Interface satisfied by both the production Comlink crypto-worker proxy
 * and DirectFieldEncryptor (test use only).
 */
export interface FieldEncryptor {
	encryptDbField(value: string): Promise<string>;
	decryptDbField(value: string): Promise<string>;
}

/**
 * Test-only adapter that wraps a CryptoKey directly.
 * Production code uses the Comlink crypto-worker proxy (see workers/crypto.worker.ts).
 */
export class DirectFieldEncryptor implements FieldEncryptor {
	constructor(private key: CryptoKey) {}
	async encryptDbField(value: string): Promise<string> {
		return encryptField(this.key, value);
	}
	async decryptDbField(value: string): Promise<string> {
		return decryptField(this.key, value);
	}
}
