// cycle 391's crypto-reviewer advisory A5 — the OPAQUE `exportKey` returned by
// `opaque_registration_finish`/`opaque_login_finish` (crypto.worker.ts) is a
// fresh, solely-owned JS-heap `Uint8Array` (see wasm_exports.rs `bytes_js`,
// which always copies — same precondition verified for the media key in
// cycle 391), consumed once by `deriveDbKey`'s `crypto.subtle.importKey`, then
// never used again — but was previously left unzeroed in the worker's own
// heap until GC. `deriveDbKeyAndScrub` is the extracted fix (see
// crypto.worker.ts): derive, then scrub the caller's buffer in `finally`.
// Tested directly here since `crypto.subtle` (unlike the real Worker/wasm-pack
// plumbing) is available in the JSDOM test environment — see db/encryption.test.ts.
import { describe, expect, it } from "vitest";
import { decryptField, deriveDbKey, encryptField } from "../db/encryption";
import { deriveDbKeyAndScrub } from "./crypto.worker";

const FAKE_EXPORT_KEY = new Uint8Array(32).fill(0xab);

describe("deriveDbKeyAndScrub", () => {
	it("returns a non-extractable AES-GCM CryptoKey", async () => {
		const key = await deriveDbKeyAndScrub(FAKE_EXPORT_KEY.slice());
		expect(key.type).toBe("secret");
		expect(key.algorithm.name).toBe("AES-GCM");
		expect(key.extractable).toBe(false);
	});

	it("derives from the real source bytes, not a pre-zeroed buffer (scrubbing doesn't change the derivation)", async () => {
		// Reference key comes from the plain, un-scrubbed deriveDbKey against an
		// untouched copy of the same source bytes — this is the ground truth a
		// scrub-before-derive mutant (deriving from all-zero bytes instead of the
		// real export key) would NOT reproduce, unlike comparing two
		// deriveDbKeyAndScrub calls against each other (which stays green even
		// under that mutant, since both sides would derive from zeros identically).
		const reference = await deriveDbKey(FAKE_EXPORT_KEY.slice());
		const ciphertext = await encryptField(reference, "hello powehi");
		const scrubbed = await deriveDbKeyAndScrub(FAKE_EXPORT_KEY.slice());
		await expect(decryptField(scrubbed, ciphertext)).resolves.toBe("hello powehi");
	});

	it("does NOT derive the same key as an all-zero export key (pins that real bytes were used)", async () => {
		const scrubbed = await deriveDbKeyAndScrub(FAKE_EXPORT_KEY.slice());
		const ciphertext = await encryptField(scrubbed, "hello powehi");
		const zeroKey = await deriveDbKey(new Uint8Array(32));
		await expect(decryptField(zeroKey, ciphertext)).rejects.toThrow();
	});

	it("zeroes the caller's export-key buffer after a successful derivation", async () => {
		const exportKey = FAKE_EXPORT_KEY.slice();
		await deriveDbKeyAndScrub(exportKey);
		expect(Array.from(exportKey)).toEqual(new Array(32).fill(0));
	});

	it("zeroes the caller's export-key buffer even when derivation rejects", async () => {
		const tooShort = new Uint8Array(16).fill(0xcd);
		await expect(deriveDbKeyAndScrub(tooShort)).rejects.toThrow("export key too short");
		expect(Array.from(tooShort)).toEqual(new Array(16).fill(0));
	});
});
