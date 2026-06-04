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
