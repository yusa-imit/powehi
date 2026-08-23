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
		});
		const identity = await db.identity.get(1);
		expect(identity?.deviceId).toBe("dev-001");
		// exportKeyB64 was removed in schema v3 — OPAQUE export key lives in
		// the crypto worker only and must not be persisted (crypto-reviewer R1).
	});

	it("stores and retrieves mlsIdentityId and mlsIdentityB64 on LocalIdentity (v4)", async () => {
		await db.identity.put({
			id: 1,
			deviceId: "dev-v4",
			mlsIdentityId: "uuid-mls-123",
			mlsIdentityB64: "AAAAAAAAAAAAAAAAAAAAAA==",
		});
		const found = await db.identity.get(1);
		expect(found?.mlsIdentityId).toBe("uuid-mls-123");
		expect(found?.mlsIdentityB64).toBe("AAAAAAAAAAAAAAAAAAAAAA==");
	});

	it("stores and retrieves muted/sound/vibrate/notificationSoundId/chatTheme on GroupRow (v12)", async () => {
		await db.groups.add({
			id: "grp-v12",
			name: "Prefs Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
			muted: true,
			sound: false,
			vibrate: false,
			notificationSoundId: "chime",
			chatTheme: "ocean",
		});
		const grp = await db.groups.get("grp-v12");
		expect(grp?.muted).toBe(true);
		expect(grp?.sound).toBe(false);
		expect(grp?.vibrate).toBe(false);
		expect(grp?.notificationSoundId).toBe("chime");
		expect(grp?.chatTheme).toBe("ocean");
	});

	it("leaves muted/sound/vibrate/notificationSoundId/chatTheme undefined when not set (v12)", async () => {
		await db.groups.add({
			id: "grp-v12-default",
			name: "Default Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v12-default");
		expect(grp?.muted).toBeUndefined();
		expect(grp?.sound).toBeUndefined();
		expect(grp?.vibrate).toBeUndefined();
		expect(grp?.notificationSoundId).toBeUndefined();
		expect(grp?.chatTheme).toBeUndefined();
	});

	it("stores and retrieves slowModeDelay on GroupRow (v16)", async () => {
		await db.groups.add({
			id: "grp-v16",
			name: "Slow Mode Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
			slowModeDelay: 30,
		});
		const grp = await db.groups.get("grp-v16");
		expect(grp?.slowModeDelay).toBe(30);
	});

	it("leaves slowModeDelay undefined when not set (v16)", async () => {
		await db.groups.add({
			id: "grp-v16-default",
			name: "Default Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v16-default");
		expect(grp?.slowModeDelay).toBeUndefined();
	});

	it("stores and retrieves draft on GroupRow (v17, raw store — encryption is EncryptedPowehiDb's job)", async () => {
		await db.groups.add({
			id: "grp-v17",
			name: "Draft Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
			draft: "unsent message text",
		});
		const grp = await db.groups.get("grp-v17");
		expect(grp?.draft).toBe("unsent message text");
	});

	it("leaves draft undefined when not set (v17)", async () => {
		await db.groups.add({
			id: "grp-v17-default",
			name: "Default Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v17-default");
		expect(grp?.draft).toBeUndefined();
	});

	it("stores and retrieves archived/pinnedTop on GroupRow (v18)", async () => {
		await db.groups.add({
			id: "grp-v18",
			name: "Archived Pinned Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
			archived: true,
			pinnedTop: true,
		});
		const grp = await db.groups.get("grp-v18");
		expect(grp?.archived).toBe(true);
		expect(grp?.pinnedTop).toBe(true);
	});

	it("leaves archived/pinnedTop undefined when not set (v18)", async () => {
		await db.groups.add({
			id: "grp-v18-default",
			name: "Default Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v18-default");
		expect(grp?.archived).toBeUndefined();
		expect(grp?.pinnedTop).toBeUndefined();
	});

	it("stores and retrieves description on GroupRow (v19, raw store — encryption is EncryptedPowehiDb's job)", async () => {
		await db.groups.add({
			id: "grp-v19",
			name: "Described Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
			description: "Where we plan the launch",
		});
		const grp = await db.groups.get("grp-v19");
		expect(grp?.description).toBe("Where we plan the launch");
	});

	it("leaves description undefined when not set (v19)", async () => {
		await db.groups.add({
			id: "grp-v19-default",
			name: "Default Group",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v19-default");
		expect(grp?.description).toBeUndefined();
	});

	it("stores and retrieves nickname on GroupRow (v20, raw store — encryption is EncryptedPowehiDb's job)", async () => {
		await db.groups.add({
			id: "grp-v20",
			name: "Nicknamed Contact",
			mlsStateB64: "",
			lastActivity: Date.now(),
			nickname: "Buddy",
		});
		const grp = await db.groups.get("grp-v20");
		expect(grp?.nickname).toBe("Buddy");
	});

	it("leaves nickname undefined when not set (v20)", async () => {
		await db.groups.add({
			id: "grp-v20-default",
			name: "Default Contact",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v20-default");
		expect(grp?.nickname).toBeUndefined();
	});

	it("stores and retrieves starred on MessageRow (v21, raw store — encryption is EncryptedPowehiDb's job)", async () => {
		await db.messages.add({
			id: "msg-v21",
			groupId: "group-uuid-v21",
			ciphertextB64: "dGVzdA==",
			senderDeviceId: "device-v21",
			epochSeq: 0,
			receivedAt: Date.now(),
			starred: true,
		});
		const msg = await db.messages.get("msg-v21");
		expect(msg?.starred).toBe(true);
	});

	it("leaves starred undefined when not set (v21)", async () => {
		await db.messages.add({
			id: "msg-v21-default",
			groupId: "group-uuid-v21",
			ciphertextB64: "dGVzdA==",
			senderDeviceId: "device-v21",
			epochSeq: 0,
			receivedAt: Date.now(),
		});
		const msg = await db.messages.get("msg-v21-default");
		expect(msg?.starred).toBeUndefined();
	});

	it("stores and retrieves lastSeenAt on GroupRow (v22, raw store — not sensitive, never encrypted)", async () => {
		const now = Date.now();
		await db.groups.add({
			id: "grp-v22",
			name: "Presence Contact",
			mlsStateB64: "",
			lastActivity: now,
			lastSeenAt: now,
		});
		const grp = await db.groups.get("grp-v22");
		expect(grp?.lastSeenAt).toBe(now);
	});

	it("leaves lastSeenAt undefined when not set (v22)", async () => {
		await db.groups.add({
			id: "grp-v22-default",
			name: "Default Contact",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		const grp = await db.groups.get("grp-v22-default");
		expect(grp?.lastSeenAt).toBeUndefined();
	});

	it("stores and retrieves customStatusEmoji/customStatusText on LocalIdentity (v23, raw store — encryption is EncryptedPowehiDb's concern, not the raw schema's)", async () => {
		await db.identity.put({
			id: 1,
			deviceId: "dev-v23",
			customStatusEmoji: "🎉",
			customStatusText: "Having fun",
		});
		const identity = await db.identity.get(1);
		expect(identity?.customStatusEmoji).toBe("🎉");
		expect(identity?.customStatusText).toBe("Having fun");
	});

	it("leaves customStatusEmoji/customStatusText undefined when not set (v23)", async () => {
		// put(), not add() — the identity singleton (id:1) row may already exist from an
		// earlier test in this file (each `new PowehiDb()` reconnects to the same
		// fake-indexeddb-backed store, it is not actually a fresh DB per test).
		await db.identity.put({
			id: 1,
			deviceId: "dev-v23-default",
		});
		const identity = await db.identity.get(1);
		expect(identity?.customStatusEmoji).toBeUndefined();
		expect(identity?.customStatusText).toBeUndefined();
	});

	it("stores and retrieves mediaJson on MessageRow (v27, raw store — encryption is EncryptedPowehiDb's job)", async () => {
		const mediaJson = JSON.stringify({
			blobId: "blob-v27",
			blobHash: [1, 2, 3],
			mediaKey: [4, 5, 6],
			iv: [7, 8, 9],
		});
		await db.messages.add({
			id: "msg-v27",
			groupId: "group-uuid-v27",
			ciphertextB64: "ZGVhZA==",
			senderDeviceId: "device-v27",
			epochSeq: 0,
			receivedAt: Date.now(),
			mediaJson,
		});
		const msg = await db.messages.get("msg-v27");
		expect(msg?.mediaJson).toBe(mediaJson);
	});

	it("leaves mediaJson undefined when not set (v27)", async () => {
		await db.messages.add({
			id: "msg-v27-default",
			groupId: "group-uuid-v27",
			ciphertextB64: "ZGVhZA==",
			senderDeviceId: "device-v27",
			epochSeq: 0,
			receivedAt: Date.now(),
		});
		const msg = await db.messages.get("msg-v27-default");
		expect(msg?.mediaJson).toBeUndefined();
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
