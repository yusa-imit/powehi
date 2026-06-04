// ML-KEM-768 signed encap key (ADR-0003 Phase B, Y-3 fix) — API contract tests.
//
// Y-3: The encap key received from a peer is unauthenticated — a MITM could
// substitute a different encap key.  Fix: sign the encap key with the MLS
// Ed25519 identity key; peers verify before encapsulating.
//
// Cryptographic correctness is tested in:
//   crates/client/powehi-crypto-wasm/src/kem_credential.rs (native Rust tests)
// These tests verify the TypeScript API contract — return shapes and type invariants.

import { describe, expect, it } from "vitest";
import { getCryptoWorkerProxy } from "../hooks/__mocks__/useCryptoWorker";

const worker = getCryptoWorkerProxy();

describe("mlKem768SignEncapKey — API contract (ADR-0003 Phase B, Y-3)", () => {
	it("returns signature as a Uint8Array of exactly 64 bytes (Ed25519 output size)", async () => {
		const encapKey = new Uint8Array(1184);
		const result = await worker.mlKem768SignEncapKey("mock-identity-id", encapKey);
		expect(result.signature).toBeInstanceOf(Uint8Array);
		expect(result.signature.length).toBe(64);
	});

	it("result does not expose the private signing key — only signature is returned", async () => {
		const encapKey = new Uint8Array(1184);
		const result = await worker.mlKem768SignEncapKey("mock-identity-id", encapKey);
		// @ts-expect-error — no private key field must exist in the result
		expect(result.privateKey).toBeUndefined();
		// @ts-expect-error — no signer field must exist in the result
		expect(result.signer).toBeUndefined();
	});
});

describe("mlKem768VerifyEncapKey — API contract (ADR-0003 Phase B, Y-3)", () => {
	it("returns valid as a boolean", async () => {
		const encapKey = new Uint8Array(1184);
		const signature = new Uint8Array(64);
		const sigPubKey = new Uint8Array(32);
		const result = await worker.mlKem768VerifyEncapKey(encapKey, signature, sigPubKey);
		expect(typeof result.valid).toBe("boolean");
	});

	it("result does not expose any key material", async () => {
		const encapKey = new Uint8Array(1184);
		const signature = new Uint8Array(64);
		const sigPubKey = new Uint8Array(32);
		const result = await worker.mlKem768VerifyEncapKey(encapKey, signature, sigPubKey);
		// @ts-expect-error — no key material field must be exposed
		expect(result.privateKey).toBeUndefined();
		// @ts-expect-error — no shared secret field must be exposed
		expect(result.sharedSecret).toBeUndefined();
	});

	it("sign+verify round-trip: mock sign result passes mock verify", async () => {
		const encapKey = new Uint8Array(1184);
		const { signature } = await worker.mlKem768SignEncapKey("mock-identity-id", encapKey);
		const sigPubKey = new Uint8Array(32);
		const { valid } = await worker.mlKem768VerifyEncapKey(encapKey, signature, sigPubKey);
		// Mock always returns true — verifies the API can be chained without errors.
		expect(valid).toBe(true);
	});
});
