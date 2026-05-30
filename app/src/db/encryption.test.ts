import { describe, expect, it } from "vitest";
import { decryptField, deriveDbKey, encryptField } from "./encryption";

// 32 bytes of fake OPAQUE export key material — never used outside tests.
const FAKE_EXPORT_KEY = new Uint8Array(32).fill(0xab);
const FAKE_EXPORT_KEY_B = new Uint8Array(32).fill(0xcd);

describe("deriveDbKey", () => {
	it("throws when export key is shorter than 32 bytes", async () => {
		await expect(deriveDbKey(new Uint8Array(31).fill(0xab))).rejects.toThrow(
			"export key too short",
		);
	});

	it("returns a non-extractable AES-GCM CryptoKey", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		expect(key.type).toBe("secret");
		expect(key.algorithm.name).toBe("AES-GCM");
		expect(key.extractable).toBe(false);
		expect(key.usages).toContain("encrypt");
		expect(key.usages).toContain("decrypt");
	});

	it("is deterministic — same export key produces the same derived key material", async () => {
		const keyA = await deriveDbKey(FAKE_EXPORT_KEY);
		const keyB = await deriveDbKey(FAKE_EXPORT_KEY);
		// Export keys are non-extractable, but we can verify they encrypt identically.
		// Use a fixed plaintext + fixed IV to test derived key equality.
		const iv = new Uint8Array(12).fill(0x01);
		const ptBytes = new TextEncoder().encode("determinism-check");
		const ctA = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyA, ptBytes);
		const ctB = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyB, ptBytes);
		expect(new Uint8Array(ctA)).toEqual(new Uint8Array(ctB));
	});

	it("different export keys produce different derived keys", async () => {
		const keyA = await deriveDbKey(FAKE_EXPORT_KEY);
		const keyB = await deriveDbKey(FAKE_EXPORT_KEY_B);
		const iv = new Uint8Array(12).fill(0x01);
		const ptBytes = new TextEncoder().encode("key-isolation");
		const ctA = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyA, ptBytes);
		const ctB = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, keyB, ptBytes);
		expect(new Uint8Array(ctA)).not.toEqual(new Uint8Array(ctB));
	});
});

describe("encryptField / decryptField", () => {
	it("round-trips a plaintext string", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		const original = "MLS state bytes in base64: dGVzdA==";
		const enc = await encryptField(key, original);
		const dec = await decryptField(key, enc);
		expect(dec).toBe(original);
	});

	it("round-trips the empty string", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		const enc = await encryptField(key, "");
		const dec = await decryptField(key, enc);
		expect(dec).toBe("");
	});

	it("produces different ciphertext on each call (random IV)", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		const enc1 = await encryptField(key, "same-plaintext");
		const enc2 = await encryptField(key, "same-plaintext");
		expect(enc1).not.toBe(enc2);
	});

	it("decryptField throws on wrong key (AES-GCM auth tag mismatch)", async () => {
		const keyA = await deriveDbKey(FAKE_EXPORT_KEY);
		const keyB = await deriveDbKey(FAKE_EXPORT_KEY_B);
		const enc = await encryptField(keyA, "secret-mls-state");
		await expect(decryptField(keyB, enc)).rejects.toThrow("decrypt_failed");
	});

	it("decryptField throws on tampered ciphertext", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		const enc = await encryptField(key, "integrity-check");
		// Corrupt 4 characters inside the ciphertext body (positions 20-23 are past
		// the 16-char IV prefix and within a full 4-char base64 group, so this reliably
		// changes the decoded bytes and fails the AES-GCM authentication tag check).
		// "ZZZZ" differs from any authentic ciphertext group at that position.
		const tampered = `${enc.slice(0, 20)}ZZZZ${enc.slice(24)}`;
		await expect(decryptField(key, tampered)).rejects.toThrow();
	});

	it("decryptField throws on a truncated ciphertext that is too short", async () => {
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		// Minimum is 12 (IV) + 16 (GCM tag) = 28 bytes → ≥ 38 base64url chars.
		// 36 base64url chars ≈ 27 bytes — one byte short of the minimum.
		await expect(decryptField(key, "A".repeat(36))).rejects.toThrow();
	});
});
