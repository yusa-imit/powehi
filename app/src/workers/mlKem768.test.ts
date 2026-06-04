// ML-KEM-768 (FIPS 203) crypto worker API contract tests.
//
// The real WASM cannot run in Vitest (requires a browser environment).
// Cryptographic correctness is tested in crates/client/powehi-crypto-wasm/src/kem.rs.
// These tests verify the TypeScript API contract — correct return shapes, byte sizes,
// and argument structure — using the standard mock proxy.
//
// Key sizes per FIPS 203 §2.4:
//   encapKey: 1184 bytes, decapKey: 2400 bytes, ciphertext: 1088 bytes, sharedSecret: 32 bytes

import { describe, expect, it } from "vitest";
import { getCryptoWorkerProxy } from "../hooks/__mocks__/useCryptoWorker";

// Use the mock proxy directly — same object returned to callers of getCryptoWorkerProxy().
const worker = getCryptoWorkerProxy();

describe("mlKem768Keygen — API contract", () => {
	it("returns encapKey as a Uint8Array of exactly 1184 bytes (FIPS 203 §2.4)", async () => {
		const result = await worker.mlKem768Keygen();
		expect(result.encapKey).toBeInstanceOf(Uint8Array);
		expect(result.encapKey.length).toBe(1184);
	});

	it("returns decapKey as a Uint8Array of exactly 2400 bytes (FIPS 203 §2.4)", async () => {
		const result = await worker.mlKem768Keygen();
		expect(result.decapKey).toBeInstanceOf(Uint8Array);
		expect(result.decapKey.length).toBe(2400);
	});
});

describe("mlKem768Encap — API contract", () => {
	it("returns ciphertext as a Uint8Array of exactly 1088 bytes (FIPS 203 §2.4)", async () => {
		const { encapKey } = await worker.mlKem768Keygen();
		const result = await worker.mlKem768Encap(encapKey);
		expect(result.ciphertext).toBeInstanceOf(Uint8Array);
		expect(result.ciphertext.length).toBe(1088);
	});

	it("returns sharedSecret as a Uint8Array of exactly 32 bytes (FIPS 203 §2.4)", async () => {
		const { encapKey } = await worker.mlKem768Keygen();
		const result = await worker.mlKem768Encap(encapKey);
		expect(result.sharedSecret).toBeInstanceOf(Uint8Array);
		expect(result.sharedSecret.length).toBe(32);
	});
});

describe("mlKem768Decap — API contract", () => {
	it("returns sharedSecret as a Uint8Array of exactly 32 bytes (FIPS 203 §2.4)", async () => {
		const { encapKey, decapKey } = await worker.mlKem768Keygen();
		const { ciphertext } = await worker.mlKem768Encap(encapKey);
		const result = await worker.mlKem768Decap(decapKey, ciphertext);
		expect(result.sharedSecret).toBeInstanceOf(Uint8Array);
		expect(result.sharedSecret.length).toBe(32);
	});
});

// ── ADR-0003 Phase B: opaque-handle API (Y-1 fix) ──────────────────────────────
//
// These tests verify that the Phase B API returns opaque handles (strings) instead
// of raw key bytes, enforcing the invariant that sensitive key material stays inside
// the WASM worker and never crosses the Comlink boundary to the main thread.

describe("mlKem768KeygenV2 — opaque-handle API (ADR-0003 Phase B, Y-1)", () => {
	it("returns encapKey as a Uint8Array of exactly 1184 bytes (FIPS 203 §2.4)", async () => {
		const result = await worker.mlKem768KeygenV2();
		expect(result.encapKey).toBeInstanceOf(Uint8Array);
		expect(result.encapKey.length).toBe(1184);
	});

	it("returns decapKeyHandle as a non-empty string — not raw key bytes (Y-1 invariant)", async () => {
		const result = await worker.mlKem768KeygenV2();
		expect(typeof result.decapKeyHandle).toBe("string");
		expect(result.decapKeyHandle.length).toBeGreaterThan(0);
	});

	it("does not expose decapKey bytes in keygen result (Y-1 fix)", async () => {
		const result = await worker.mlKem768KeygenV2();
		// @ts-expect-error — decapKey must not exist on the Phase B result type
		expect(result.decapKey).toBeUndefined();
	});
});

describe("mlKem768EncapV2 — opaque-handle API (ADR-0003 Phase B, Y-1)", () => {
	it("returns ciphertext as a Uint8Array of exactly 1088 bytes (FIPS 203 §2.4)", async () => {
		const { encapKey } = await worker.mlKem768KeygenV2();
		const result = await worker.mlKem768EncapV2(encapKey);
		expect(result.ciphertext).toBeInstanceOf(Uint8Array);
		expect(result.ciphertext.length).toBe(1088);
	});

	it("returns sharedSecretHandle as a non-empty string — not raw secret bytes (Y-1 invariant)", async () => {
		const { encapKey } = await worker.mlKem768KeygenV2();
		const result = await worker.mlKem768EncapV2(encapKey);
		expect(typeof result.sharedSecretHandle).toBe("string");
		expect(result.sharedSecretHandle.length).toBeGreaterThan(0);
	});

	it("does not expose sharedSecret bytes in encap result (Y-1 fix)", async () => {
		const { encapKey } = await worker.mlKem768KeygenV2();
		const result = await worker.mlKem768EncapV2(encapKey);
		// @ts-expect-error — sharedSecret must not exist on the Phase B result type
		expect(result.sharedSecret).toBeUndefined();
	});
});

describe("mlKem768DecapV2 — opaque-handle API (ADR-0003 Phase B, Y-1)", () => {
	it("returns sharedSecretHandle as a non-empty string — not raw secret bytes (Y-1 invariant)", async () => {
		const { encapKey, decapKeyHandle } = await worker.mlKem768KeygenV2();
		const { ciphertext } = await worker.mlKem768EncapV2(encapKey);
		const result = await worker.mlKem768DecapV2(decapKeyHandle, ciphertext);
		expect(typeof result.sharedSecretHandle).toBe("string");
		expect(result.sharedSecretHandle.length).toBeGreaterThan(0);
	});

	it("does not expose sharedSecret bytes in decap result (Y-1 fix)", async () => {
		const { encapKey, decapKeyHandle } = await worker.mlKem768KeygenV2();
		const { ciphertext } = await worker.mlKem768EncapV2(encapKey);
		const result = await worker.mlKem768DecapV2(decapKeyHandle, ciphertext);
		// @ts-expect-error — sharedSecret must not exist on the Phase B result type
		expect(result.sharedSecret).toBeUndefined();
	});
});

describe("mlKem768DropDecapKey — explicit cleanup (ADR-0003 Phase B)", () => {
	it("resolves without error for a known handle", async () => {
		const { decapKeyHandle } = await worker.mlKem768KeygenV2();
		await expect(worker.mlKem768DropDecapKey(decapKeyHandle)).resolves.toBeUndefined();
	});

	it("resolves without error for an unknown handle (idempotent)", async () => {
		await expect(worker.mlKem768DropDecapKey("nonexistent-handle")).resolves.toBeUndefined();
	});
});

describe("mlKem768DropSharedSecret — explicit cleanup (ADR-0003 Phase B)", () => {
	it("resolves without error for a known handle", async () => {
		const { encapKey } = await worker.mlKem768KeygenV2();
		const { sharedSecretHandle } = await worker.mlKem768EncapV2(encapKey);
		await expect(worker.mlKem768DropSharedSecret(sharedSecretHandle)).resolves.toBeUndefined();
	});

	it("resolves without error for an unknown handle (idempotent)", async () => {
		await expect(worker.mlKem768DropSharedSecret("nonexistent-handle")).resolves.toBeUndefined();
	});
});
