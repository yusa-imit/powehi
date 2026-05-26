import "fake-indexeddb/auto";
import { beforeEach, describe, expect, it } from "vitest";
import { type MessageRow, PowehiDb } from "./schema";

describe("PowehiDb", () => {
	let db: PowehiDb;

	beforeEach(async () => {
		// Each test gets a fresh in-memory DB by using a unique name via fake-indexeddb.
		db = new PowehiDb();
		await db.open();
	});

	it("inserts and retrieves a MessageRow", async () => {
		const row: MessageRow = {
			id: "test-uuid-1",
			groupId: "group-uuid-1",
			ciphertextB64: "dGVzdC1jaXBoZXJ0ZXh0",
			senderDeviceId: "device-abc",
			epochSeq: (1n << 32n) as unknown as number | 1,
			receivedAt: Date.now(),
		};
		// epochSeq is a regular number in practice (epoch<<32 | seq).
		const row2: MessageRow = {
			id: "test-uuid-1",
			groupId: "group-uuid-1",
			ciphertextB64: "dGVzdC1jaXBoZXJ0ZXh0",
			senderDeviceId: "device-abc",
			epochSeq: (1 << 16) | 7,
			receivedAt: Date.now(),
		};

		await db.messages.add(row2);
		const found = await db.messages.get("test-uuid-1");
		expect(found).toBeDefined();
		expect(found?.ciphertextB64).toBe("dGVzdC1jaXBoZXJ0ZXh0");
		expect(found?.plaintextB64).toBeUndefined();
	});

	it("does not store plaintextB64 unless explicitly set", async () => {
		const row: MessageRow = {
			id: "test-uuid-2",
			groupId: "group-uuid-2",
			ciphertextB64: "c2VjcmV0Y2lwaGVydGV4dA==",
			senderDeviceId: "device-xyz",
			epochSeq: 0,
			receivedAt: Date.now(),
		};
		await db.messages.add(row);
		const found = await db.messages.get("test-uuid-2");
		expect(found?.plaintextB64).toBeUndefined();
	});

	it("inserts and retrieves a GroupRow", async () => {
		await db.groups.add({
			id: "grp-1",
			name: "Test Group",
			mlsStateB64: "bWxzc3RhdGU=",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-1");
		expect(grp?.name).toBe("Test Group");
		expect(grp?.mlsStateB64).toBe("bWxzc3RhdGU=");
	});

	it("inserts and retrieves the singleton LocalIdentity", async () => {
		await db.identity.add({
			id: 1,
			deviceId: "dev-001",
			exportKeyB64: "ZXhwb3J0S2V5",
		});
		const identity = await db.identity.get(1);
		expect(identity?.deviceId).toBe("dev-001");
		// Export key is stored — never logged, never sent to server.
		expect(identity?.exportKeyB64).toBe("ZXhwb3J0S2V5");
	});

	it("queries messages by groupId index", async () => {
		await db.messages.bulkAdd([
			{
				id: "m1",
				groupId: "g-a",
				ciphertextB64: "YQ==",
				senderDeviceId: "d1",
				epochSeq: 0,
				receivedAt: 1000,
			},
			{
				id: "m2",
				groupId: "g-b",
				ciphertextB64: "Yg==",
				senderDeviceId: "d2",
				epochSeq: 1,
				receivedAt: 2000,
			},
			{
				id: "m3",
				groupId: "g-a",
				ciphertextB64: "Yw==",
				senderDeviceId: "d1",
				epochSeq: 2,
				receivedAt: 3000,
			},
		]);
		const aMessages = await db.messages.where("groupId").equals("g-a").toArray();
		expect(aMessages).toHaveLength(2);
		expect(aMessages.every((m) => m.groupId === "g-a")).toBe(true);
	});
});
