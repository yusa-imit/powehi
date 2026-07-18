// §9.2 Media encryption — API contract tests for the crypto worker media methods.
//
// Cryptographic correctness (AES-256-GCM round-trips, tag verification, etc.) is
// tested in crates/client/powehi-crypto-wasm/src/media.rs (native Rust tests).
// These tests verify the TypeScript API contract: return shapes, security invariants,
// and opaque-handle semantics at the worker boundary.

import { describe, expect, it } from "vitest";
import { getCryptoWorkerProxy } from "../hooks/__mocks__/useCryptoWorker";

const worker = getCryptoWorkerProxy();

describe("mediaEncrypt — API contract (prd.md §9.2 sender path)", () => {
	it("returns ciphertext as Uint8Array", async () => {
		const plaintext = new Uint8Array(32);
		const result = await worker.mediaEncrypt(plaintext);
		expect(result.ciphertext).toBeInstanceOf(Uint8Array);
	});

	it("returns mediaKeyHandle as a string (raw key never crosses worker boundary)", async () => {
		const plaintext = new Uint8Array(16);
		const result = await worker.mediaEncrypt(plaintext);
		expect(typeof result.mediaKeyHandle).toBe("string");
	});

	it("result does not expose raw media key bytes", async () => {
		const plaintext = new Uint8Array(16);
		const result = await worker.mediaEncrypt(plaintext);
		// @ts-expect-error — no raw key field must exist in the result
		expect(result.mediaKey).toBeUndefined();
		// @ts-expect-error — no raw key bytes field
		expect(result.key).toBeUndefined();
	});

	it("returns iv as Uint8Array of 12 bytes (GCM nonce size)", async () => {
		const plaintext = new Uint8Array(32);
		const result = await worker.mediaEncrypt(plaintext);
		expect(result.iv).toBeInstanceOf(Uint8Array);
		expect(result.iv.length).toBe(12);
	});

	it("returns blobHash as Uint8Array of 32 bytes (SHA-256 digest size)", async () => {
		const plaintext = new Uint8Array(32);
		const result = await worker.mediaEncrypt(plaintext);
		expect(result.blobHash).toBeInstanceOf(Uint8Array);
		expect(result.blobHash.length).toBe(32);
	});
});

describe("mediaDecrypt — API contract (sender re-decrypt via handle)", () => {
	it("returns plaintext as Uint8Array", async () => {
		const { ciphertext, mediaKeyHandle, iv } = await worker.mediaEncrypt(new Uint8Array(32));
		const plaintext = await worker.mediaDecrypt(mediaKeyHandle, iv, ciphertext);
		expect(plaintext).toBeInstanceOf(Uint8Array);
	});
});

describe("mediaImportKey / mediaDecryptWithHandle — API contract (receiver path, cycle 309)", () => {
	it("mediaImportKey returns mediaKeyHandle as a string (raw key never re-enters JS scope)", async () => {
		const rawKey = new Uint8Array(32);
		const result = await worker.mediaImportKey(rawKey);
		expect(typeof result.mediaKeyHandle).toBe("string");
	});

	it("returns plaintext as Uint8Array given an imported key handle", async () => {
		const rawKey = new Uint8Array(32);
		const { mediaKeyHandle } = await worker.mediaImportKey(rawKey);
		const iv = new Uint8Array(12);
		const ciphertext = new Uint8Array(48); // 32 + 16-byte tag
		const blobHash = new Uint8Array(32);
		const result = await worker.mediaDecryptWithHandle(mediaKeyHandle, iv, ciphertext, blobHash);
		expect(result).toBeInstanceOf(Uint8Array);
	});

	it("result does not expose the key material back to the caller", async () => {
		const rawKey = new Uint8Array(32);
		const { mediaKeyHandle } = await worker.mediaImportKey(rawKey);
		const iv = new Uint8Array(12);
		const ciphertext = new Uint8Array(48);
		const blobHash = new Uint8Array(32);
		const result = await worker.mediaDecryptWithHandle(mediaKeyHandle, iv, ciphertext, blobHash);
		// The return type is Uint8Array (plaintext), not an object with a key field.
		expect(result).toBeInstanceOf(Uint8Array);
		// @ts-expect-error — no key field on the return value
		expect(result.mediaKey).toBeUndefined();
	});
});

describe("mediaDropKey — API contract", () => {
	it("returns boolean", async () => {
		const { mediaKeyHandle } = await worker.mediaEncrypt(new Uint8Array(16));
		const removed = await worker.mediaDropKey(mediaKeyHandle);
		expect(typeof removed).toBe("boolean");
	});

	it("returns true for a known handle", async () => {
		const { mediaKeyHandle } = await worker.mediaEncrypt(new Uint8Array(16));
		const removed = await worker.mediaDropKey(mediaKeyHandle);
		expect(removed).toBe(true);
	});
});
