import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { EncryptedPowehiDb } from "./encrypted-db";
import { DirectFieldEncryptor, deriveDbKey } from "./encryption";
import { PowehiDb } from "./schema";

const FAKE_EXPORT_KEY = new Uint8Array(32).fill(0x42);
const FAKE_EXPORT_KEY_B = new Uint8Array(32).fill(0x99);

describe("EncryptedPowehiDb", () => {
	let rawDb: PowehiDb;
	let encDb: EncryptedPowehiDb;
	let encryptor: DirectFieldEncryptor;

	beforeEach(async () => {
		rawDb = new PowehiDb();
		await rawDb.open();
		const key = await deriveDbKey(FAKE_EXPORT_KEY);
		encryptor = new DirectFieldEncryptor(key);
		encDb = new EncryptedPowehiDb(rawDb, encryptor);
	});

	it("addMessage + getMessage round-trips with encryption", async () => {
		const row = {
			id: "msg-1",
			groupId: "grp-1",
			ciphertextB64: "c2Vuc2l0aXZlLWNpcGhlcnRleHQ=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1_000_000,
		};
		await encDb.addMessage(row);
		const retrieved = await encDb.getMessage("msg-1");
		expect(retrieved).toBeDefined();
		expect(retrieved?.ciphertextB64).toBe("c2Vuc2l0aXZlLWNpcGhlcnRleHQ=");
		expect(retrieved?.groupId).toBe("grp-1");
	});

	it("raw DB stores an encrypted blob — not the original plaintext ciphertext", async () => {
		const originalCiphertext = "c2Vuc2l0aXZlLWRhdGE=";
		await encDb.addMessage({
			id: "msg-2",
			groupId: "grp-2",
			ciphertextB64: originalCiphertext,
			senderDeviceId: "dev-2",
			epochSeq: 1,
			receivedAt: 2_000_000,
		});
		// Read the raw (unencrypted-wrapper) record directly from the store.
		const rawRow = await rawDb.messages.get("msg-2");
		expect(rawRow).toBeDefined();
		// The raw stored value must not equal the original ciphertextB64.
		expect(rawRow?.ciphertextB64).not.toBe(originalCiphertext);
		// It should look like a base64url blob (no spaces, contains URL-safe chars).
		expect(rawRow?.ciphertextB64).toMatch(/^[A-Za-z0-9\-_]+$/);
	});

	it("getMessagesByGroup decrypts all messages and returns them sorted by epochSeq", async () => {
		await encDb.addMessage({
			id: "m1",
			groupId: "g-shared",
			ciphertextB64: "Zmlyc3Q=",
			senderDeviceId: "d1",
			epochSeq: 1,
			receivedAt: 1000,
		});
		await encDb.addMessage({
			id: "m2",
			groupId: "g-shared",
			ciphertextB64: "c2Vjb25k",
			senderDeviceId: "d2",
			epochSeq: 0,
			receivedAt: 2000,
		});
		await encDb.addMessage({
			id: "m3",
			groupId: "g-other",
			ciphertextB64: "b3RoZXI=",
			senderDeviceId: "d3",
			epochSeq: 0,
			receivedAt: 3000,
		});
		const msgs = await encDb.getMessagesByGroup("g-shared");
		expect(msgs).toHaveLength(2);
		// sorted by epochSeq ascending (Y5 — MLS replay-protection ordering)
		expect(msgs[0].epochSeq).toBe(0);
		expect(msgs[1].epochSeq).toBe(1);
		expect(msgs[0].ciphertextB64).toBe("c2Vjb25k");
		expect(msgs[1].ciphertextB64).toBe("Zmlyc3Q=");
	});

	it("setIdentity + getIdentity round-trips deviceId (no export key stored)", async () => {
		await encDb.setIdentity({ id: 1, deviceId: "dev-abc" });
		const identity = await encDb.getIdentity();
		expect(identity?.deviceId).toBe("dev-abc");
	});

	it("putVerifiedContact + getVerifiedContact + deleteVerifiedContact lifecycle", async () => {
		await encDb.putVerifiedContact({
			contactId: "peer-device-id",
			safetyNumber:
				"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
			verifiedAt: 99_999,
		});

		const contact = await encDb.getVerifiedContact("peer-device-id");
		expect(contact?.safetyNumber).toBe(
			"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
		);
		expect(contact?.verifiedAt).toBe(99_999);

		await encDb.deleteVerifiedContact("peer-device-id");
		const gone = await encDb.getVerifiedContact("peer-device-id");
		expect(gone).toBeUndefined();
	});

	it("different keys cannot decrypt each other's data", async () => {
		const keyB = await deriveDbKey(FAKE_EXPORT_KEY_B);
		const encryptorB = new DirectFieldEncryptor(keyB);
		const encDbB = new EncryptedPowehiDb(rawDb, encryptorB);

		await encDb.addGroup({
			id: "grp-x",
			name: "Secret Group",
			mlsStateB64: "bWxzLXN0YXRl",
			lastActivity: 500,
		});

		// Reading with a different key should throw (AES-GCM auth failure).
		await expect(encDbB.getGroup("grp-x")).rejects.toThrow();
	});
});
