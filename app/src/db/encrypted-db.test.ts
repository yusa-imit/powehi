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

	it("getMessagesByGroup decrypts all messages and returns them sorted by receivedAt", async () => {
		// m1: high epochSeq (1), low receivedAt (1000) — incoming, received earlier.
		// m2: low epochSeq (0), high receivedAt (2000) — outgoing or later-arriving.
		// Y1 fix: sort by receivedAt so both namespaces (MLS epoch ints and Date.now() ms)
		// interleave correctly; m1 must sort first despite the higher epochSeq.
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
		// sorted by receivedAt ascending: m1 (1000) before m2 (2000)
		expect(msgs[0].receivedAt).toBe(1000);
		expect(msgs[1].receivedAt).toBe(2000);
		expect(msgs[0].ciphertextB64).toBe("Zmlyc3Q=");
		expect(msgs[1].ciphertextB64).toBe("c2Vjb25k");
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

	it("getGroupDisappearingTtl returns undefined for unknown group", async () => {
		const ttl = await encDb.getGroupDisappearingTtl("no-such-group");
		expect(ttl).toBeUndefined();
	});

	it("setGroupDisappearingTtl persists and getGroupDisappearingTtl reads it back", async () => {
		await encDb.addGroup({
			id: "grp-ttl",
			name: "TTL Group",
			mlsStateB64: "c3RhdGU=",
			lastActivity: 1000,
		});
		await encDb.setGroupDisappearingTtl("grp-ttl", 3600);
		const ttl = await encDb.getGroupDisappearingTtl("grp-ttl");
		expect(ttl).toBe(3600);
	});

	it("setGroupDisappearingTtl can clear the timer (undefined)", async () => {
		await encDb.addGroup({
			id: "grp-ttl2",
			name: "TTL Group 2",
			mlsStateB64: "c3RhdGUy",
			lastActivity: 2000,
		});
		await encDb.setGroupDisappearingTtl("grp-ttl2", 86400);
		await encDb.setGroupDisappearingTtl("grp-ttl2", undefined);
		const ttl = await encDb.getGroupDisappearingTtl("grp-ttl2");
		expect(ttl).toBeUndefined();
	});

	it("setGroupDisappearingTtl does not disturb encrypted mlsStateB64", async () => {
		await encDb.addGroup({
			id: "grp-ttl3",
			name: "State-Check Group",
			mlsStateB64: "c2Vuc2l0aXZlLXN0YXRl",
			lastActivity: 3000,
		});
		await encDb.setGroupDisappearingTtl("grp-ttl3", 604800);
		const group = await encDb.getGroup("grp-ttl3");
		expect(group?.mlsStateB64).toBe("c2Vuc2l0aXZlLXN0YXRl");
		expect(group?.disappearingTtlSeconds).toBe(604800);
	});

	it("getGroupDraft returns undefined for unknown group", async () => {
		const draft = await encDb.getGroupDraft("no-such-group");
		expect(draft).toBeUndefined();
	});

	it("setGroupDraft persists and getGroupDraft reads it back", async () => {
		await encDb.addGroup({
			id: "grp-draft",
			name: "Draft Group",
			mlsStateB64: "c3RhdGU=",
			lastActivity: 1000,
		});
		await encDb.setGroupDraft("grp-draft", "unsent message text");
		const draft = await encDb.getGroupDraft("grp-draft");
		expect(draft).toBe("unsent message text");
	});

	it("setGroupDraft can clear the draft (undefined)", async () => {
		await encDb.addGroup({
			id: "grp-draft2",
			name: "Draft Group 2",
			mlsStateB64: "c3RhdGUy",
			lastActivity: 2000,
		});
		await encDb.setGroupDraft("grp-draft2", "will be cleared");
		await encDb.setGroupDraft("grp-draft2", undefined);
		const draft = await encDb.getGroupDraft("grp-draft2");
		expect(draft).toBeUndefined();
	});

	it("setGroupDraft does not disturb encrypted mlsStateB64/name", async () => {
		await encDb.addGroup({
			id: "grp-draft3",
			name: "State-Check Group",
			mlsStateB64: "c2Vuc2l0aXZlLXN0YXRl",
			lastActivity: 3000,
		});
		await encDb.setGroupDraft("grp-draft3", "draft text here");
		const group = await encDb.getGroup("grp-draft3");
		expect(group?.mlsStateB64).toBe("c2Vuc2l0aXZlLXN0YXRl");
		expect(group?.name).toBe("State-Check Group");
		expect(group?.draft).toBe("draft text here");
	});

	it("raw DB stores an encrypted blob — not the original plaintext draft", async () => {
		await encDb.addGroup({
			id: "grp-draft4",
			name: "Draft Group 4",
			mlsStateB64: "c3RhdGU0",
			lastActivity: 4000,
		});
		const originalDraft = "a secret unsent message";
		await encDb.setGroupDraft("grp-draft4", originalDraft);

		const rawRow = await rawDb.groups.get("grp-draft4");
		expect(rawRow?.draft).toBeDefined();
		expect(rawRow?.draft).not.toBe(originalDraft);
		expect(rawRow?.draft).toMatch(/^[A-Za-z0-9\-_]+$/);
	});

	it("getGroupDescription returns undefined for unknown group", async () => {
		const description = await encDb.getGroupDescription("no-such-group");
		expect(description).toBeUndefined();
	});

	it("setGroupDescription persists and getGroupDescription reads it back", async () => {
		await encDb.addGroup({
			id: "grp-desc",
			name: "Description Group",
			mlsStateB64: "c3RhdGU=",
			lastActivity: 1000,
		});
		await encDb.setGroupDescription("grp-desc", "Where we plan the launch");
		const description = await encDb.getGroupDescription("grp-desc");
		expect(description).toBe("Where we plan the launch");
	});

	it("setGroupDescription can clear the description (undefined)", async () => {
		await encDb.addGroup({
			id: "grp-desc2",
			name: "Description Group 2",
			mlsStateB64: "c3RhdGUy",
			lastActivity: 2000,
		});
		await encDb.setGroupDescription("grp-desc2", "will be cleared");
		await encDb.setGroupDescription("grp-desc2", undefined);
		const description = await encDb.getGroupDescription("grp-desc2");
		expect(description).toBeUndefined();
	});

	it("setGroupDescription does not disturb encrypted mlsStateB64/name", async () => {
		await encDb.addGroup({
			id: "grp-desc3",
			name: "State-Check Group",
			mlsStateB64: "c2Vuc2l0aXZlLXN0YXRl",
			lastActivity: 3000,
		});
		await encDb.setGroupDescription("grp-desc3", "description text here");
		const group = await encDb.getGroup("grp-desc3");
		expect(group?.mlsStateB64).toBe("c2Vuc2l0aXZlLXN0YXRl");
		expect(group?.name).toBe("State-Check Group");
		expect(group?.description).toBe("description text here");
	});

	it("raw DB stores an encrypted blob — not the original plaintext description", async () => {
		await encDb.addGroup({
			id: "grp-desc4",
			name: "Description Group 4",
			mlsStateB64: "c3RhdGU0",
			lastActivity: 4000,
		});
		const originalDescription = "a secret group topic";
		await encDb.setGroupDescription("grp-desc4", originalDescription);

		const rawRow = await rawDb.groups.get("grp-desc4");
		expect(rawRow?.description).toBeDefined();
		expect(rawRow?.description).not.toBe(originalDescription);
		expect(rawRow?.description).toMatch(/^[A-Za-z0-9\-_]+$/);
	});

	it("getGroupNickname returns undefined for unknown group", async () => {
		const nickname = await encDb.getGroupNickname("no-such-group");
		expect(nickname).toBeUndefined();
	});

	it("setGroupNickname persists and getGroupNickname reads it back", async () => {
		await encDb.addGroup({
			id: "grp-nick",
			name: "Nickname Contact",
			mlsStateB64: "c3RhdGU=",
			lastActivity: 1000,
		});
		await encDb.setGroupNickname("grp-nick", "Buddy");
		const nickname = await encDb.getGroupNickname("grp-nick");
		expect(nickname).toBe("Buddy");
	});

	it("setGroupNickname can clear the nickname (undefined)", async () => {
		await encDb.addGroup({
			id: "grp-nick2",
			name: "Nickname Contact 2",
			mlsStateB64: "c3RhdGUy",
			lastActivity: 2000,
		});
		await encDb.setGroupNickname("grp-nick2", "will be cleared");
		await encDb.setGroupNickname("grp-nick2", undefined);
		const nickname = await encDb.getGroupNickname("grp-nick2");
		expect(nickname).toBeUndefined();
	});

	it("setGroupNickname does not disturb encrypted mlsStateB64/name", async () => {
		await encDb.addGroup({
			id: "grp-nick3",
			name: "State-Check Contact",
			mlsStateB64: "c2Vuc2l0aXZlLXN0YXRl",
			lastActivity: 3000,
		});
		await encDb.setGroupNickname("grp-nick3", "nickname text here");
		const group = await encDb.getGroup("grp-nick3");
		expect(group?.mlsStateB64).toBe("c2Vuc2l0aXZlLXN0YXRl");
		expect(group?.name).toBe("State-Check Contact");
		expect(group?.nickname).toBe("nickname text here");
	});

	it("raw DB stores an encrypted blob — not the original plaintext nickname", async () => {
		await encDb.addGroup({
			id: "grp-nick4",
			name: "Nickname Contact 4",
			mlsStateB64: "c3RhdGU0",
			lastActivity: 4000,
		});
		const originalNickname = "a secret pet name";
		await encDb.setGroupNickname("grp-nick4", originalNickname);

		const rawRow = await rawDb.groups.get("grp-nick4");
		expect(rawRow?.nickname).toBeDefined();
		expect(rawRow?.nickname).not.toBe(originalNickname);
		expect(rawRow?.nickname).toMatch(/^[A-Za-z0-9\-_]+$/);
	});

	it("markMessageEdited persists the new text (encrypted at rest) and survives reload", async () => {
		await encDb.addMessage({
			id: "msg-edit",
			groupId: "grp-edit",
			ciphertextB64: "b3JpZ2luYWw=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		await encDb.markMessageEdited("msg-edit", "bmV3IHRleHQ=");

		const retrieved = await encDb.getMessage("msg-edit");
		expect(retrieved?.editedText).toBe("bmV3IHRleHQ=");
		// Original ciphertext untouched.
		expect(retrieved?.ciphertextB64).toBe("b3JpZ2luYWw=");

		// Raw stored value must not equal the plaintext-encoded edit — it's encrypted at rest.
		const rawRow = await rawDb.messages.get("msg-edit");
		expect(rawRow?.editedText).not.toBe("bmV3IHRleHQ=");
	});

	it("markMessageEdited is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.markMessageEdited("no-such-msg", "bmV3")).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("markMessageDeleted tombstones the row with a deletion timestamp", async () => {
		await encDb.addMessage({
			id: "msg-delete",
			groupId: "grp-delete",
			ciphertextB64: "dG9EZWxldGU=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		expect((await encDb.getMessage("msg-delete"))?.deletedAt).toBeUndefined();

		await encDb.markMessageDeleted("msg-delete");
		const retrieved = await encDb.getMessage("msg-delete");
		expect(retrieved?.deletedAt).toBeGreaterThan(0);
		// Ciphertext row remains (tombstone, not a hard delete) — consistent with UI's
		// "message was deleted" placeholder rendering rather than removing history.
		expect(retrieved?.ciphertextB64).toBe("dG9EZWxldGU=");
	});

	it("markMessageReactionDelta adds the first reaction (encrypted at rest) and survives reload", async () => {
		await encDb.addMessage({
			id: "msg-react",
			groupId: "grp-react",
			ciphertextB64: "cmVhY3Rpb25zVGFyZ2V0",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		await encDb.markMessageReactionDelta("msg-react", "\u{1F44D}", "dev-1", "add");

		const retrieved = await encDb.getMessage("msg-react");
		expect(JSON.parse(retrieved?.reactionsJson ?? "{}")).toEqual({ "\u{1F44D}": ["dev-1"] });
		// Original ciphertext untouched.
		expect(retrieved?.ciphertextB64).toBe("cmVhY3Rpb25zVGFyZ2V0");

		// Raw stored value must not equal the plaintext JSON — it's encrypted at rest.
		const rawRow = await rawDb.messages.get("msg-react");
		expect(rawRow?.reactionsJson).not.toBe(retrieved?.reactionsJson);
	});

	it("markMessageReactionDelta merges concurrent adds from different senders instead of clobbering", async () => {
		await encDb.addMessage({
			id: "msg-react-concurrent",
			groupId: "grp-react",
			ciphertextB64: "Y29uY3VycmVudA==",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		// Two devices react with different emoji "at the same time" — both calls are
		// in flight before either resolves, exercising the race markMessageRead's
		// readBy fix already closed for reactions too.
		await Promise.all([
			encDb.markMessageReactionDelta("msg-react-concurrent", "\u{1F44D}", "dev-1", "add"),
			encDb.markMessageReactionDelta("msg-react-concurrent", "❤️", "dev-2", "add"),
		]);

		const retrieved = await encDb.getMessage("msg-react-concurrent");
		expect(JSON.parse(retrieved?.reactionsJson ?? "{}")).toEqual({
			"\u{1F44D}": ["dev-1"],
			"❤️": ["dev-2"],
		});
	});

	it("markMessageReactionDelta removes a sender, dropping the emoji key once empty", async () => {
		await encDb.addMessage({
			id: "msg-react-remove",
			groupId: "grp-react",
			ciphertextB64: "cmVtb3Zl",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		await encDb.markMessageReactionDelta("msg-react-remove", "\u{1F44D}", "dev-1", "add");
		await encDb.markMessageReactionDelta("msg-react-remove", "\u{1F44D}", "dev-2", "add");
		await encDb.markMessageReactionDelta("msg-react-remove", "\u{1F44D}", "dev-1", "remove");

		const retrieved = await encDb.getMessage("msg-react-remove");
		expect(JSON.parse(retrieved?.reactionsJson ?? "{}")).toEqual({ "\u{1F44D}": ["dev-2"] });

		await encDb.markMessageReactionDelta("msg-react-remove", "\u{1F44D}", "dev-2", "remove");
		const final = await encDb.getMessage("msg-react-remove");
		expect(JSON.parse(final?.reactionsJson ?? "{}")).toEqual({});
	});

	it("markMessageReactionDelta is a no-op when the target row does not exist locally", async () => {
		await expect(
			encDb.markMessageReactionDelta("no-such-msg", "\u{1F44D}", "dev-1", "add"),
		).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("markMessagePoll persists the poll state (encrypted at rest) and survives reload", async () => {
		await encDb.addMessage({
			id: "msg-poll",
			groupId: "grp-poll",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		const pollJson = JSON.stringify({
			question: "Lunch?",
			options: [
				{ text: "Pizza", voters: ["dev-1"] },
				{ text: "Sushi", voters: [] },
			],
		});
		await encDb.markMessagePoll("msg-poll", pollJson);

		const retrieved = await encDb.getMessage("msg-poll");
		expect(retrieved?.pollJson).toBe(pollJson);
		expect(retrieved?.ciphertextB64).toBe("");

		// Raw stored value must not equal the plaintext JSON — it's encrypted at rest.
		const rawRow = await rawDb.messages.get("msg-poll");
		expect(rawRow?.pollJson).not.toBe(pollJson);
	});

	it("markMessagePoll is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.markMessagePoll("no-such-msg", JSON.stringify({}))).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("putMessage persists a scheduled message's plaintextB64 encrypted at rest and survives reload", async () => {
		const scheduledFor = 5000;
		await encDb.putMessage({
			id: "msg-sched-content",
			groupId: "grp-sched-content",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			plaintextB64: "bGF0ZXIgdGV4dA==",
			scheduledFor,
		});

		const retrieved = await encDb.getMessage("msg-sched-content");
		expect(retrieved?.plaintextB64).toBe("bGF0ZXIgdGV4dA==");
		expect(retrieved?.scheduledFor).toBe(scheduledFor);

		// Raw stored value must not equal the plaintext base64 — it's encrypted at rest,
		// same as every other message-content field (ciphertextB64/editedText/pollJson/etc).
		const rawRow = await rawDb.messages.get("msg-sched-content");
		expect(rawRow?.plaintextB64).not.toBe("bGF0ZXIgdGV4dA==");
		// scheduledFor itself is not encrypted — a timestamp, same tier as expiresAt/lastSeenAt.
		expect(rawRow?.scheduledFor).toBe(scheduledFor);
	});

	it("putMessage preserves locally-accumulated mutable fields when replayed for an existing id (F4 redelivery fix)", async () => {
		await encDb.addMessage({
			id: "msg-redelivered",
			groupId: "grp-1",
			ciphertextB64: "b3JpZ2luYWw=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			plaintextB64: "aGVsbG8=",
			expiresAt: 5000,
		});
		await encDb.markMessageReactionDelta("msg-redelivered", "👍", "dev-2", "add");
		await encDb.markMessageRead("msg-redelivered", ["dev-2"]);
		await encDb.markMessageStarred("msg-redelivered", true);
		await encDb.markMessageDelivered("msg-redelivered");
		await encDb.markMessageEdited("msg-redelivered", "ZWRpdGVk");
		await encDb.markMessageDeleted("msg-redelivered");

		// Simulate a redelivered envelope (e.g. ack DELETE failed, page reloaded, server
		// re-sends the same message id) — persistIncoming builds a fresh row with no
		// knowledge of the reactions/read/starred/etc state accumulated locally, and
		// recomputes a LATER expiresAt from "now" (would silently restart the TTL if
		// not preserved). Deliberately varies ciphertextB64/expiresAt from the original
		// so the assertions below can't pass vacuously off an early-return-on-existing.
		await encDb.putMessage({
			id: "msg-redelivered",
			groupId: "grp-1",
			ciphertextB64: "cmVwbGF5ZWQ=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			plaintextB64: "aGVsbG8=",
			expiresAt: 9999,
		});

		const retrieved = await encDb.getMessage("msg-redelivered");
		// Fresh core field actually applied — proves this isn't a vacuous early-return.
		expect(retrieved?.ciphertextB64).toBe("cmVwbGF5ZWQ=");
		// Locally-accumulated mutable fields preserved, not clobbered.
		expect(retrieved?.read).toBe(true);
		expect(retrieved?.readByJson).toBe(JSON.stringify(["dev-2"]));
		expect(retrieved?.starred).toBe(true);
		expect(retrieved?.delivered).toBe(true);
		expect(retrieved?.editedText).toBe("ZWRpdGVk");
		expect(retrieved?.deletedAt).toBeDefined();
		expect(retrieved?.expiresAt).toBe(5000);
		expect(JSON.parse(retrieved?.reactionsJson ?? "{}")).toEqual({ "👍": ["dev-2"] });
	});

	it("putMessage preserves an existing pollJson on replay instead of wiping accumulated votes", async () => {
		await encDb.putMessage({
			id: "msg-poll-redelivered",
			groupId: "grp-1",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			pollJson: JSON.stringify({ question: "q", options: [{ text: "a", voters: ["dev-2"] }] }),
		});
		await encDb.markMessagePoll(
			"msg-poll-redelivered",
			JSON.stringify({ question: "q", options: [{ text: "a", voters: ["dev-2", "dev-3"] }] }),
		);

		// A second putMessage against the same poll id (e.g. a replayed create) must not
		// wipe the votes accumulated since creation.
		await encDb.putMessage({
			id: "msg-poll-redelivered",
			groupId: "grp-1",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});

		const retrieved = await encDb.getMessage("msg-poll-redelivered");
		expect(JSON.parse(retrieved?.pollJson ?? "{}")).toEqual({
			question: "q",
			options: [{ text: "a", voters: ["dev-2", "dev-3"] }],
		});
	});

	it("putMessage still creates a fresh row (no merge) when no existing row is found", async () => {
		await encDb.putMessage({
			id: "msg-fresh",
			groupId: "grp-1",
			ciphertextB64: "bmV3",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		const retrieved = await encDb.getMessage("msg-fresh");
		expect(retrieved?.ciphertextB64).toBe("bmV3");
		expect(retrieved?.read).toBeUndefined();
		expect(retrieved?.reactionsJson).toBeUndefined();
	});

	it("clearMessageScheduled clears scheduledFor on the row", async () => {
		await encDb.addMessage({
			id: "msg-sched",
			groupId: "grp-sched",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			scheduledFor: 5000,
		});
		expect((await encDb.getMessage("msg-sched"))?.scheduledFor).toBe(5000);

		await encDb.clearMessageScheduled("msg-sched");
		const retrieved = await encDb.getMessage("msg-sched");
		expect(retrieved?.scheduledFor).toBeUndefined();
		// Row itself remains — this fires the scheduled message, it doesn't delete it.
		expect(retrieved).toBeDefined();
	});

	it("clearMessageScheduled is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.clearMessageScheduled("no-such-msg")).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("deleteMessage removes the row entirely", async () => {
		await encDb.addMessage({
			id: "msg-cancel",
			groupId: "grp-cancel",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			scheduledFor: 5000,
		});
		expect(await encDb.getMessage("msg-cancel")).toBeDefined();

		await encDb.deleteMessage("msg-cancel");
		expect(await encDb.getMessage("msg-cancel")).toBeUndefined();
	});

	it("deleteMessage is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.deleteMessage("no-such-msg")).resolves.not.toThrow();
	});

	it("deleteMessage refuses to delete a row that is not a scheduled message (defense-in-depth)", async () => {
		await encDb.addMessage({
			id: "msg-real",
			groupId: "grp-real",
			ciphertextB64: "cmVhbE1lc3NhZ2U=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		await encDb.deleteMessage("msg-real");
		expect(await encDb.getMessage("msg-real")).toBeDefined();
	});

	it("deleteMessage refuses to delete a message that already fired (scheduledFor cleared)", async () => {
		await encDb.addMessage({
			id: "msg-fired",
			groupId: "grp-fired",
			ciphertextB64: "",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			scheduledFor: undefined,
		});
		await encDb.deleteMessage("msg-fired");
		expect(await encDb.getMessage("msg-fired")).toBeDefined();
	});

	it("putMessage persists replyToJson (encrypted at rest) and survives reload", async () => {
		const replyToJson = JSON.stringify({ messageId: "quoted-msg", excerpt: "original text" });
		await encDb.putMessage({
			id: "msg-reply",
			groupId: "grp-reply",
			ciphertextB64: "cmVwbHlDaXBoZXJ0ZXh0",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
			replyToJson,
		});

		const retrieved = await encDb.getMessage("msg-reply");
		expect(retrieved?.replyToJson).toBe(replyToJson);

		// Raw stored value must not equal the plaintext JSON — it's encrypted at rest.
		const rawRow = await rawDb.messages.get("msg-reply");
		expect(rawRow?.replyToJson).not.toBe(replyToJson);
	});

	it("markMessageDelivered sets delivered:true on the row", async () => {
		await encDb.addMessage({
			id: "msg-delivered",
			groupId: "grp-delivered",
			ciphertextB64: "ZGVsaXZlcmVkVGFyZ2V0",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		expect((await encDb.getMessage("msg-delivered"))?.delivered).toBeUndefined();

		await encDb.markMessageDelivered("msg-delivered");
		const retrieved = await encDb.getMessage("msg-delivered");
		expect(retrieved?.delivered).toBe(true);
		// Ciphertext row untouched.
		expect(retrieved?.ciphertextB64).toBe("ZGVsaXZlcmVkVGFyZ2V0");
	});

	it("markMessageDelivered is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.markMessageDelivered("no-such-msg")).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("markMessageRead sets read:true and stores readByJson", async () => {
		await encDb.addMessage({
			id: "msg-read",
			groupId: "grp-read",
			ciphertextB64: "cmVhZFRhcmdldA==",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		expect((await encDb.getMessage("msg-read"))?.read).toBeUndefined();

		await encDb.markMessageRead("msg-read", ["dev-2", "dev-3"]);
		const retrieved = await encDb.getMessage("msg-read");
		expect(retrieved?.read).toBe(true);
		expect(retrieved?.readByJson).toBe(JSON.stringify(["dev-2", "dev-3"]));
		// Ciphertext row untouched.
		expect(retrieved?.ciphertextB64).toBe("cmVhZFRhcmdldA==");
	});

	it("markMessageRead is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.markMessageRead("no-such-msg", ["dev-x"])).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("markMessageStarred sets starred:true on the row", async () => {
		await encDb.addMessage({
			id: "msg-starred",
			groupId: "grp-starred",
			ciphertextB64: "c3RhcnJlZFRhcmdldA==",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		expect((await encDb.getMessage("msg-starred"))?.starred).toBeUndefined();

		await encDb.markMessageStarred("msg-starred", true);
		const retrieved = await encDb.getMessage("msg-starred");
		expect(retrieved?.starred).toBe(true);
		// Ciphertext row untouched.
		expect(retrieved?.ciphertextB64).toBe("c3RhcnJlZFRhcmdldA==");
	});

	it("markMessageStarred can toggle back to false, unlike the one-way delivered/read flags", async () => {
		await encDb.addMessage({
			id: "msg-unstarred",
			groupId: "grp-starred",
			ciphertextB64: "dW5zdGFyVGFyZ2V0",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});
		await encDb.markMessageStarred("msg-unstarred", true);
		expect((await encDb.getMessage("msg-unstarred"))?.starred).toBe(true);

		await encDb.markMessageStarred("msg-unstarred", false);
		expect((await encDb.getMessage("msg-unstarred"))?.starred).toBe(false);
	});

	it("markMessageStarred is a no-op when the target row does not exist locally", async () => {
		await expect(encDb.markMessageStarred("no-such-msg", true)).resolves.not.toThrow();
		const retrieved = await encDb.getMessage("no-such-msg");
		expect(retrieved).toBeUndefined();
	});

	it("markMessageRead unions readBy across sequential calls instead of overwriting", async () => {
		await encDb.addMessage({
			id: "msg-read-union",
			groupId: "grp-read",
			ciphertextB64: "dW5pb25UYXJnZXQ=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});

		await encDb.markMessageRead("msg-read-union", ["dev-2"]);
		await encDb.markMessageRead("msg-read-union", ["dev-3"]);

		const retrieved = await encDb.getMessage("msg-read-union");
		expect(retrieved?.read).toBe(true);
		expect(JSON.parse(retrieved?.readByJson ?? "[]")).toEqual(["dev-2", "dev-3"]);
	});

	it("markMessageRead deduplicates a reader id passed again", async () => {
		await encDb.addMessage({
			id: "msg-read-dedup",
			groupId: "grp-read",
			ciphertextB64: "ZGVkdXBUYXJnZXQ=",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});

		await encDb.markMessageRead("msg-read-dedup", ["dev-2"]);
		await encDb.markMessageRead("msg-read-dedup", ["dev-2"]);

		const retrieved = await encDb.getMessage("msg-read-dedup");
		expect(JSON.parse(retrieved?.readByJson ?? "[]")).toEqual(["dev-2"]);
	});

	// security-auditor YELLOW, cycle 321: two read_receipts for the same message
	// from different devices arriving in quick succession previously raced —
	// each computed `readBy` from a stale in-memory snapshot, and the later
	// Dexie write overwrote (not merged) the earlier one's entry. Fired
	// concurrently (no await between them) to reproduce the race; the fix reads
	// the persisted row inside a Dexie transaction before writing the merge, so
	// both entries must survive regardless of settle order.
	it("markMessageRead does not lose an entry when two receipts race concurrently", async () => {
		await encDb.addMessage({
			id: "msg-read-race",
			groupId: "grp-read",
			ciphertextB64: "cmFjZVRhcmdldA==",
			senderDeviceId: "dev-1",
			epochSeq: 0,
			receivedAt: 1000,
		});

		await Promise.all([
			encDb.markMessageRead("msg-read-race", ["dev-2"]),
			encDb.markMessageRead("msg-read-race", ["dev-3"]),
		]);

		const retrieved = await encDb.getMessage("msg-read-race");
		expect(retrieved?.read).toBe(true);
		const readBy = JSON.parse(retrieved?.readByJson ?? "[]") as string[];
		expect(new Set(readBy)).toEqual(new Set(["dev-2", "dev-3"]));
	});

	// crypto-reviewer finding 2 (RED): the MLS provider-state generation counter
	// must be bundled INSIDE the same authenticated ciphertext as the state blob
	// (a single JSON envelope, encrypted once) rather than stored as an
	// independent, unencrypted Dexie column — otherwise an attacker with raw
	// IndexedDB write access could roll the counter back to 0 on its own and
	// replay an older-but-still-AEAD-valid state blob, defeating the freshness/
	// anti-replay gate entirely.
	describe("setMlsProviderState / getMlsProviderState (finding 2: bundled generation envelope)", () => {
		it("round-trips stateB64 + generation through a single encrypted field", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-mls-1" });
			await encDb.setMlsProviderState("c3RhdGUtYnl0ZXM=", 7);

			const state = await encDb.getMlsProviderState();
			expect(state?.stateB64).toBe("c3RhdGUtYnl0ZXM=");
			expect(state?.generation).toBe(7);
		});

		it("stores ONE encrypted blob, not a separate plaintext generation column", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-mls-2" });
			await encDb.setMlsProviderState("cGxhaW50ZXh0LXN0YXRl", 3);

			const rawRow = await rawDb.identity.get(1);
			expect(rawRow).toBeDefined();
			// No independent plaintext generation column exists on the raw row.
			expect(
				(rawRow as unknown as Record<string, unknown>).mlsProviderStateGeneration,
			).toBeUndefined();
			// The raw field is encrypted — neither the state bytes nor a bare "7"
			// integer appear in plaintext, and it must not parse as our envelope JSON.
			expect(rawRow?.mlsProviderStateB64).not.toBe(
				JSON.stringify({ stateB64: "cGxhaW50ZXh0LXN0YXRl", generation: 3 }),
			);
			expect(() => JSON.parse(rawRow?.mlsProviderStateB64 ?? "")).toThrow();
		});

		it("tampering the raw ciphertext (simulating rolled-back generation) fails AEAD auth on read, not a silent bypass", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-mls-3" });
			await encDb.setMlsProviderState("b3JpZ2luYWwtc3RhdGU=", 5);

			const rawRow = await rawDb.identity.get(1);
			const tampered = `${(rawRow?.mlsProviderStateB64 ?? "").slice(0, -2)}xx`;
			await rawDb.identity.update(1, { mlsProviderStateB64: tampered });

			// Because generation now lives inside the same AEAD-protected envelope as
			// the state bytes, a raw-storage tamper attempt (the only way to try to
			// roll back generation independently) corrupts the ciphertext and fails
			// authentication on decrypt — it can no longer silently reset just the
			// counter while leaving a valid-looking envelope.
			await expect(encDb.getMlsProviderState()).rejects.toThrow();
		});

		it("getMlsProviderState returns undefined when no envelope has ever been persisted", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-mls-4" });
			const state = await encDb.getMlsProviderState();
			expect(state).toBeUndefined();
		});

		it("setMlsProviderState is a no-op (does not throw) when the identity row does not exist yet", async () => {
			await expect(encDb.setMlsProviderState("c3RhdGU=", 1)).resolves.not.toThrow();
		});
	});

	describe("setCustomStatus / getCustomStatus", () => {
		it("round-trips emoji + text through two encrypted fields", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-1" });
			await encDb.setCustomStatus({ emoji: "🎉", text: "Having fun" });

			const status = await encDb.getCustomStatus();
			expect(status).toEqual({ emoji: "🎉", text: "Having fun" });
		});

		it("raw row stores encrypted blobs, not the plaintext emoji/text", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-2" });
			await encDb.setCustomStatus({ emoji: "🏠", text: "Working from home" });

			const rawRow = await rawDb.identity.get(1);
			expect(rawRow?.customStatusEmoji).toBeDefined();
			expect(rawRow?.customStatusEmoji).not.toBe("🏠");
			expect(rawRow?.customStatusText).toBeDefined();
			expect(rawRow?.customStatusText).not.toBe("Working from home");
		});

		it("does not touch deviceId/mlsIdentityId when setting a status", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-3", mlsIdentityId: "mls-3" });
			await encDb.setCustomStatus({ emoji: "📵", text: "Do not disturb" });

			const rawRow = await rawDb.identity.get(1);
			expect(rawRow?.deviceId).toBe("dev-status-3");
			expect(rawRow?.mlsIdentityId).toBe("mls-3");
		});

		it("passing null clears both fields", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-4" });
			await encDb.setCustomStatus({ emoji: "🌴", text: "On vacation" });
			expect(await encDb.getCustomStatus()).not.toBeNull();

			await encDb.setCustomStatus(null);
			expect(await encDb.getCustomStatus()).toBeNull();
			const rawRow = await rawDb.identity.get(1);
			expect(rawRow?.customStatusEmoji).toBeUndefined();
			expect(rawRow?.customStatusText).toBeUndefined();
		});

		it("getCustomStatus returns null when no status has ever been persisted", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-5" });
			expect(await encDb.getCustomStatus()).toBeNull();
		});

		it("getCustomStatus returns null when the identity row does not exist yet", async () => {
			expect(await encDb.getCustomStatus()).toBeNull();
		});

		it("setCustomStatus is a no-op (does not throw) when the identity row does not exist yet", async () => {
			await expect(
				encDb.setCustomStatus({ emoji: "🎧", text: "In a meeting" }),
			).resolves.not.toThrow();
		});

		it("an emoji-only status omits the text field", async () => {
			await encDb.setIdentity({ id: 1, deviceId: "dev-status-6" });
			await encDb.setCustomStatus({ emoji: "🎧", text: "" });

			const status = await encDb.getCustomStatus();
			expect(status).toEqual({ emoji: "🎧", text: "" });
			const rawRow = await rawDb.identity.get(1);
			expect(rawRow?.customStatusText).toBeUndefined();
		});
	});
});
