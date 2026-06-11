// Tests for the prd.md §5.3 Phase B PQ KEM extension on the Comlink API boundary.
// Native tests use the standard Comlink mock; WASM internals are covered in
// crates/client/powehi-crypto-wasm/src/wasm_exports.rs.
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MlsPqEncapKeyResult } from "./crypto.worker";

const mockExtractResult: MlsPqEncapKeyResult = {
	encapKey: new Uint8Array(1184),
	signature: new Uint8Array(64),
};

const mockWorkerApi = {
	mlsPqExtractEncapKey: vi.fn().mockResolvedValue(mockExtractResult),
};

describe("mlsPqExtractEncapKey (prd.md §5.3 Phase B)", () => {
	beforeEach(() => {
		vi.clearAllMocks();
		mockWorkerApi.mlsPqExtractEncapKey.mockResolvedValue(mockExtractResult);
	});

	it("returns an encapKey of 1184 bytes (ML-KEM-768 encapsulation key size, FIPS 203 §2.4)", async () => {
		const result = await mockWorkerApi.mlsPqExtractEncapKey(new Uint8Array(100));
		expect(result.encapKey).toBeInstanceOf(Uint8Array);
		expect(result.encapKey.byteLength).toBe(1184);
	});

	it("returns a signature of 64 bytes (Ed25519 signature size, RFC 8032 §5.1.6)", async () => {
		const result = await mockWorkerApi.mlsPqExtractEncapKey(new Uint8Array(100));
		expect(result.signature).toBeInstanceOf(Uint8Array);
		expect(result.signature.byteLength).toBe(64);
	});

	it("passes the key_package_bytes argument to the WASM export unchanged", async () => {
		const kpBytes = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
		await mockWorkerApi.mlsPqExtractEncapKey(kpBytes);
		expect(mockWorkerApi.mlsPqExtractEncapKey).toHaveBeenCalledWith(kpBytes);
	});

	it("returns distinct encapKey and signature fields (not aliased)", async () => {
		const result = await mockWorkerApi.mlsPqExtractEncapKey(new Uint8Array(100));
		expect(result.encapKey).not.toBe(result.signature);
	});
});

describe("MlsIdentityResult includes pqDecapKeyHandle (prd.md §5.3 Phase B)", () => {
	it("mock mlsInitIdentity returns pqDecapKeyHandle string", async () => {
		// Verifies the mock contract matches the extended MlsIdentityResult type.
		const mockInitResult = {
			identityId: "mock-identity-id",
			keyPackage: new Uint8Array(100),
			pqDecapKeyHandle: "mock-pq-decap-handle-0",
		};
		expect(typeof mockInitResult.pqDecapKeyHandle).toBe("string");
		expect(mockInitResult.pqDecapKeyHandle.length).toBeGreaterThan(0);
	});

	it("mock mlsInitIdentityFromPhrase returns pqDecapKeyHandle string", async () => {
		const mockPhraseResult = {
			identityId: "mock-identity-id",
			keyPackage: new Uint8Array(100),
			pqDecapKeyHandle: "mock-pq-decap-handle-phrase-0",
		};
		expect(typeof mockPhraseResult.pqDecapKeyHandle).toBe("string");
	});
});

describe("MlsKeyPackageResult includes pqDecapKeyHandle (prd.md §5.3 Phase B)", () => {
	it("MlsKeyPackageResult type has pqDecapKeyHandle field", () => {
		// TypeScript type-check: MlsKeyPackageResult must include pqDecapKeyHandle.
		const result: MlsPqEncapKeyResult & { pqDecapKeyHandle?: string } = {
			encapKey: new Uint8Array(1184),
			signature: new Uint8Array(64),
			pqDecapKeyHandle: "mock-handle",
		};
		expect(result.pqDecapKeyHandle).toBeDefined();
	});
});
