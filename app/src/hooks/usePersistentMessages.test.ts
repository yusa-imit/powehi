import "fake-indexeddb/auto";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as EncryptedDbModule from "../db/encrypted-db";
import { DirectFieldEncryptor, deriveDbKey } from "../db/encryption";
import { db } from "../db/schema";
import { useAuthStore } from "../store/auth";
import { base64ToText, textToBase64 } from "../utils/base64";
import * as CryptoWorkerHook from "./useCryptoWorker";
import type { IncomingMessage, MediaPayload } from "./useMessages";
import { usePersistentMessages } from "./usePersistentMessages";

// The fake encryptor satisfies FieldEncryptor without needing the Comlink proxy.
const FAKE_KEY = new Uint8Array(32).fill(0x42);
let encryptor: DirectFieldEncryptor;

const DEVICE_ID = "device-aaa";
const GROUP_ID = "gggggggg-gggg-gggg-gggg-gggggggggggg";
const SENDER_ID = "ssssssss-ssss-ssss-ssss-ssssssssssss";
const ENV_ID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";

const makeIncoming = (overrides: Partial<IncomingMessage> = {}): IncomingMessage => ({
	id: ENV_ID,
	senderId: SENDER_ID,
	groupId: GROUP_ID,
	text: "hello",
	ciphertextB64: btoa("fake-ciphertext"),
	epochSeq: 1000,
	...overrides,
});

beforeEach(async () => {
	// Delete the database before each test so state from previous tests does not
	// leak into subsequent ones (fake-indexeddb is shared within a test file).
	await new Promise<void>((resolve) => {
		const req = indexedDB.deleteDatabase("PowehiDb");
		req.onsuccess = () => resolve();
		req.onerror = () => resolve(); // Resolve anyway — test will fail meaningfully if DB state is stale
		req.onblocked = () => resolve();
	});

	const key = await deriveDbKey(FAKE_KEY);
	encryptor = new DirectFieldEncryptor(key);

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		encryptor as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	useAuthStore.setState({ phase: "app", deviceId: DEVICE_ID, sessionToken: "token" });
});

afterEach(() => {
	vi.restoreAllMocks();
	// useAuthStore is a real zustand store subscribed to via useSyncExternalStore;
	// @testing-library/react's auto-cleanup unmount runs as an outer afterEach (registered at
	// module import time), so this reset still lands on a mounted component and must be
	// wrapped in act() to avoid the "not wrapped in act" warning.
	act(() => {
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
	});
});

describe("usePersistentMessages", () => {
	it("returns empty rows when groupId is undefined", () => {
		const { result } = renderHook(() => usePersistentMessages(undefined));
		expect(result.current.rows).toHaveLength(0);
	});

	it("returns empty rows when no messages exist for the group", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await waitFor(() => {
			expect(result.current.rows).toHaveLength(0);
		});
	});

	it("persistIncoming adds message to rows immediately", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		// Flush the initial useEffect DB load before testing. Without this,
		// the async getMessagesByGroup may resolve inside the act below and
		// setRows([]) overrides the optimistic update (same race as cycle 84).
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe(ENV_ID);
		// plaintextB64 stores base64-encoded UTF-8 (safe encoding contract).
		expect(result.current.rows[0].plaintextB64).toBe(textToBase64("hello"));
		expect(base64ToText(result.current.rows[0].plaintextB64 ?? "")).toBe("hello");
	});

	it("persistIncoming deduplicates — same id added twice stays one row", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		// Flush the initial useEffect DB load before testing deduplication.
		// Without this, the async getMessagesByGroup promise may resolve inside
		// the act below and setRows([]) could override the optimistic update.
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
			result.current.persistIncoming(makeIncoming());
		});

		expect(result.current.rows).toHaveLength(1);
	});

	it("persistIncoming sorts rows by receivedAt (wall-clock), not epochSeq", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		// Flush initial DB load so the setRows([]) from useEffect doesn't race.
		await act(async () => {});

		// id-first arrives earlier (mocked receivedAt=1000) but has a higher epochSeq.
		// id-second arrives later (mocked receivedAt=2000) but has a lower epochSeq.
		// With the Y1 fix, sort is by receivedAt — id-first must appear first.
		let nowValue = 1000;
		const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => nowValue);

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "id-first", epochSeq: 999 }));
		});
		nowValue = 2000;
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "id-second", epochSeq: 1 }));
		});

		nowSpy.mockRestore();

		expect(result.current.rows[0].id).toBe("id-first");
		expect(result.current.rows[1].id).toBe("id-second");
	});

	it("Y1 — outgoing message with large epochSeq sorts before later incoming", async () => {
		// Before Y1 fix: outgoing epochSeq = Date.now() ≈ 1.7e12 always sorted AFTER
		// every incoming message (MLS epoch sequences are small integers like 0, 1, 2…).
		// After fix: both sort by receivedAt — earlier wall-clock time comes first.
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		let nowValue = 1_000_000;
		const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => nowValue);

		// Persist an outgoing message first (receivedAt=1_000_000, epochSeq=Date.now()~large).
		await act(async () => {
			result.current.persistOutgoing("out-id", GROUP_ID, "sent first", btoa("ct"));
		});
		nowValue = 2_000_000;
		// Persist an incoming message second (receivedAt=2_000_000, epochSeq=0 from MLS).
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "in-id", epochSeq: 0 }));
		});

		nowSpy.mockRestore();

		// Outgoing was created at t=1_000_000, incoming at t=2_000_000.
		// receivedAt sort must preserve this chronological order.
		expect(result.current.rows[0].id).toBe("out-id");
		expect(result.current.rows[1].id).toBe("in-id");
	});

	it("persistOutgoing adds message to rows immediately with deviceId as sender", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing("out-id", GROUP_ID, "sent text", btoa("ct"));
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe("out-id");
		expect(result.current.rows[0].senderDeviceId).toBe(DEVICE_ID);
		// plaintextB64 is base64-encoded UTF-8.
		expect(base64ToText(result.current.rows[0].plaintextB64 ?? "")).toBe("sent text");
	});

	it("persistOutgoing threads a reply context into replyToJson", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		const replyTo = { messageId: "quoted-1", excerpt: "original text" };

		await act(async () => {
			result.current.persistOutgoing("out-reply-id", GROUP_ID, "my reply", btoa("ct"), replyTo);
		});

		expect(result.current.rows[0].replyToJson).toBe(JSON.stringify(replyTo));
	});

	it("persistOutgoing leaves replyToJson undefined when no reply context is given", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing("out-noreply-id", GROUP_ID, "text", btoa("ct"));
		});

		expect(result.current.rows[0].replyToJson).toBeUndefined();
	});

	it("persistOutgoing threads a media payload into mediaJson", async () => {
		const media: MediaPayload = {
			blobId: "blob-out-1",
			blobHash: [1, 2, 3],
			mediaKey: [4, 5, 6],
			iv: [7, 8, 9],
		};
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing(
				"out-media-id",
				GROUP_ID,
				"Image attachment",
				btoa("ct"),
				undefined,
				undefined,
				media,
			);
		});

		expect(result.current.rows[0].mediaJson).toBe(JSON.stringify(media));
	});

	it("persistOutgoing leaves mediaJson undefined when no media is given (the normal outgoing-media case — see MessageRow.mediaJson's ASYMMETRY note)", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing("out-nomedia-id", GROUP_ID, "Image attachment", btoa("ct"));
		});

		expect(result.current.rows[0].mediaJson).toBeUndefined();
	});

	it("persistOutgoing threads expiresAt into the row (disappearing-message sender copy)", async () => {
		const EXPIRES_AT = Date.now() + 60_000;
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing(
				"out-ttl-id",
				GROUP_ID,
				"self-destructs",
				btoa("ct"),
				undefined,
				EXPIRES_AT,
			);
		});

		expect(result.current.rows[0].expiresAt).toBe(EXPIRES_AT);
	});

	it("persistOutgoing leaves expiresAt undefined when no TTL is given", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing("out-no-ttl-id", GROUP_ID, "permanent", btoa("ct"));
		});

		expect(result.current.rows[0].expiresAt).toBeUndefined();
	});

	it("purgeExpired removes a persisted outgoing disappearing message — durably, not just in memory", async () => {
		let nowValue = 1_000_000;
		const nowSpy = vi.spyOn(Date, "now").mockImplementation(() => nowValue);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing(
				"out-expiring-id",
				GROUP_ID,
				"bye",
				btoa("ct"),
				undefined,
				nowValue + 1000,
			);
		});
		expect(result.current.rows).toHaveLength(1);
		// persistOutgoing's putMessage is fire-and-forget — wait for it to actually land
		// in Dexie before purging, otherwise the durable-deletion assertion below is racy.
		await waitFor(async () => {
			expect(await db.messages.get("out-expiring-id")).toBeDefined();
		});

		nowValue += 2000; // past expiresAt
		await act(async () => {
			result.current.purgeExpired();
		});
		nowSpy.mockRestore();

		expect(result.current.rows).toHaveLength(0);
		// The regression this test guards against: before the fix, persistOutgoing never
		// set expiresAt, so the sender's own copy had no index entry and durably survived
		// purgeExpiredMessages's `where("expiresAt").belowOrEqual(now)` sweep forever.
		await waitFor(async () => {
			expect(await db.messages.get("out-expiring-id")).toBeUndefined();
		});
	});

	it("persistOutgoing is no-op when deviceId is null", async () => {
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });

		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistOutgoing("out-id", GROUP_ID, "text", btoa("ct"));
		});

		expect(result.current.rows).toHaveLength(0);
	});

	it("rows resets to empty when groupId changes to undefined", async () => {
		const { result, rerender } = renderHook(
			({ gid }: { gid: string | undefined }) => usePersistentMessages(gid),
			{ initialProps: { gid: GROUP_ID as string | undefined } },
		);

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
		});
		expect(result.current.rows).toHaveLength(1);

		rerender({ gid: undefined });

		await waitFor(() => {
			expect(result.current.rows).toHaveLength(0);
		});
	});

	it("writeErrorCount starts at 0", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		expect(result.current.writeErrorCount).toBe(0);
	});

	it("writeErrorCount increments when putMessage throws on persistIncoming", async () => {
		vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "putMessage").mockRejectedValueOnce(
			new Error("db full"),
		);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("writeErrorCount increments when putMessage throws on persistOutgoing", async () => {
		vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "putMessage").mockRejectedValueOnce(
			new Error("quota exceeded"),
		);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistOutgoing("out-id", GROUP_ID, "text", btoa("ct"));
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistIncoming stores expiresAt in row", async () => {
		const EXPIRES_AT = Date.now() + 60_000;
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ expiresAt: EXPIRES_AT }));
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].expiresAt).toBe(EXPIRES_AT);
	});

	it("persistIncoming threads msg.replyTo into replyToJson", async () => {
		const replyTo = { messageId: "quoted-2", excerpt: "their earlier text" };
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ replyTo }));
		});

		expect(result.current.rows[0].replyToJson).toBe(JSON.stringify(replyTo));
	});

	it("persistIncoming leaves replyToJson undefined when the message is not a reply", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
		});

		expect(result.current.rows[0].replyToJson).toBeUndefined();
	});

	it("persistIncoming threads msg.media (including the real mediaKey) into mediaJson", async () => {
		const media: MediaPayload = {
			blobId: "blob-in-1",
			blobHash: [1, 2, 3],
			mediaKey: [10, 20, 30],
			iv: [4, 5, 6],
			mimeType: "image/jpeg",
		};
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ media }));
		});

		expect(result.current.rows[0].mediaJson).toBe(JSON.stringify(media));
	});

	it("persistIncoming leaves mediaJson undefined when the message has no media attachment", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming());
		});

		expect(result.current.rows[0].mediaJson).toBeUndefined();
	});

	it("purgeExpired removes expired rows from local state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const PAST = Date.now() - 1_000;
		const FUTURE = Date.now() + 60_000;

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "expired-msg", expiresAt: PAST }));
			result.current.persistIncoming(makeIncoming({ id: "live-msg", expiresAt: FUTURE }));
		});

		expect(result.current.rows).toHaveLength(2);

		await act(async () => {
			result.current.purgeExpired();
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe("live-msg");
	});

	it("purgeExpired leaves rows with no expiresAt untouched", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "no-ttl", expiresAt: undefined }));
		});

		expect(result.current.rows).toHaveLength(1);

		await act(async () => {
			result.current.purgeExpired();
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe("no-ttl");
	});

	it("persistEdit updates rows state with the new text (base64-encoded)", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "edit-target" }));
		});
		await act(async () => {
			result.current.persistEdit("edit-target", "corrected text");
		});

		expect(result.current.rows[0].editedText).toBe(textToBase64("corrected text"));
		expect(base64ToText(result.current.rows[0].editedText ?? "")).toBe("corrected text");
	});

	it("persistEdit is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistEdit("edit-target", "text");
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("persistDelete marks the row deletedAt in rows state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "delete-target" }));
		});
		await act(async () => {
			result.current.persistDelete("delete-target");
		});

		expect(result.current.rows[0].deletedAt).toBeGreaterThan(0);
	});

	it("persistDelete is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistDelete("delete-target");
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("writeErrorCount increments when markMessageEdited throws on persistEdit", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageEdited",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistEdit("edit-target", "text");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("writeErrorCount increments when markMessageDeleted throws on persistDelete", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageDeleted",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistDelete("delete-target");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistReaction adds a reaction and merges a second sender's add for the same emoji", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "react-target" }));
		});
		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-a", "add");
		});
		expect(result.current.rows[0].reactionsJson).toBe(JSON.stringify({ "\u{1F44D}": ["dev-a"] }));

		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-b", "add");
		});
		expect(result.current.rows[0].reactionsJson).toBe(
			JSON.stringify({ "\u{1F44D}": ["dev-a", "dev-b"] }),
		);
	});

	it("persistReaction removes a sender, dropping the emoji key once its senders list is empty", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "react-target" }));
		});
		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-a", "add");
		});
		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-a", "remove");
		});

		expect(result.current.rows[0].reactionsJson).toBe(JSON.stringify({}));
	});

	it("persistReaction is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-a", "add");
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("persistPollCreate creates a row with the serialized poll and empty ciphertextB64 sentinel", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const poll = { question: "Lunch?", options: [{ text: "Pizza", voters: [] as string[] }] };
		await act(async () => {
			result.current.persistPollCreate("poll-1", GROUP_ID, poll);
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe("poll-1");
		expect(result.current.rows[0].pollJson).toBe(JSON.stringify(poll));
		expect(result.current.rows[0].ciphertextB64).toBe("");
		expect(result.current.rows[0].senderDeviceId).toBe(DEVICE_ID);
	});

	it("persistPollCreate threads expiresAt through so a poll in a disappearing chat can be purged", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const poll = { question: "Lunch?", options: [{ text: "Pizza", voters: [] as string[] }] };
		const expiresAt = Date.now() + 60_000;
		await act(async () => {
			result.current.persistPollCreate("poll-ttl-1", GROUP_ID, poll, expiresAt);
		});

		expect(result.current.rows[0].expiresAt).toBe(expiresAt);
	});

	it("persistPollCreate leaves expiresAt undefined when no TTL is given", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistPollCreate("poll-no-ttl-1", GROUP_ID, { question: "Q", options: [] });
		});

		expect(result.current.rows[0].expiresAt).toBeUndefined();
	});

	it("persistPollCreate is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistPollCreate("poll-1", GROUP_ID, { question: "Q", options: [] });
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("persistPollVote updates rows state with the serialized post-vote poll", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const poll = { question: "Lunch?", options: [{ text: "Pizza", voters: [] as string[] }] };
		await act(async () => {
			result.current.persistPollCreate("poll-1", GROUP_ID, poll);
		});
		const voted = { question: "Lunch?", options: [{ text: "Pizza", voters: ["me"] }] };
		await act(async () => {
			result.current.persistPollVote("poll-1", voted);
		});

		expect(result.current.rows[0].pollJson).toBe(JSON.stringify(voted));
	});

	it("writeErrorCount increments when markMessagePoll throws on persistPollVote", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessagePoll",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistPollVote("poll-1", { question: "Q", options: [] });
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("writeErrorCount increments when markMessageReactionDelta throws on persistReaction", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageReactionDelta",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistReaction("react-target", "\u{1F44D}", "dev-a", "add");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistScheduledCreate creates a row with the encoded text, empty ciphertextB64 sentinel, and scheduledFor", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const scheduledFor = Date.now() + 60_000;
		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "later text", scheduledFor);
		});

		expect(result.current.rows).toHaveLength(1);
		expect(result.current.rows[0].id).toBe("sched-1");
		expect(result.current.rows[0].plaintextB64).toBe(textToBase64("later text"));
		expect(result.current.rows[0].ciphertextB64).toBe("");
		expect(result.current.rows[0].senderDeviceId).toBe(DEVICE_ID);
		expect(result.current.rows[0].scheduledFor).toBe(scheduledFor);
	});

	it("persistScheduledCreate threads expiresAt through so a scheduled message in a disappearing chat can be purged", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		const scheduledFor = Date.now() + 60_000;
		const expiresAt = Date.now() + 30_000;
		await act(async () => {
			result.current.persistScheduledCreate(
				"sched-ttl-1",
				GROUP_ID,
				"later text",
				scheduledFor,
				expiresAt,
			);
		});

		expect(result.current.rows[0].expiresAt).toBe(expiresAt);
	});

	it("persistScheduledCreate leaves expiresAt undefined when no TTL is given", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-no-ttl-1", GROUP_ID, "text", Date.now() + 1000);
		});

		expect(result.current.rows[0].expiresAt).toBeUndefined();
	});

	it("persistScheduledCreate is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("writeErrorCount increments when putMessage throws on persistScheduledCreate", async () => {
		vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "putMessage").mockRejectedValueOnce(
			new Error("db full"),
		);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistScheduledFire clears scheduledFor in rows state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		await act(async () => {
			result.current.persistScheduledFire("sched-1");
		});

		expect(result.current.rows[0].scheduledFor).toBeUndefined();
	});

	it("persistScheduledFire durably clears scheduledFor in Dexie, not just in-memory rows", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		// Wait for the create's own putMessage to land before firing — same
		// create-then-mutate race persistPollCreate/persistPollVote document (both await
		// an encryptDbField round-trip before their Dexie write), not the thing under test.
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});
		await act(async () => {
			result.current.persistScheduledFire("sched-1");
		});

		await waitFor(async () => {
			const row = await db.messages.get("sched-1");
			expect(row?.scheduledFor).toBeUndefined();
		});
	});

	it("writeErrorCount increments when clearMessageScheduled throws on persistScheduledFire", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"clearMessageScheduled",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledFire("sched-1");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistCancelScheduled removes the row from rows state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		expect(result.current.rows).toHaveLength(1);

		await act(async () => {
			result.current.persistCancelScheduled("sched-1");
		});

		expect(result.current.rows).toHaveLength(0);
	});

	it("persistCancelScheduled durably deletes the row from Dexie, not just in-memory rows", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		// Wait for the create's own putMessage to land before cancelling — same
		// create-then-mutate race persistPollCreate/persistPollVote document (both await
		// an encryptDbField round-trip before their Dexie write), not the thing under test.
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});
		await act(async () => {
			result.current.persistCancelScheduled("sched-1");
		});

		await waitFor(async () => {
			const row = await db.messages.get("sched-1");
			expect(row).toBeUndefined();
		});
	});

	it("writeErrorCount increments when deleteMessage throws on persistCancelScheduled", async () => {
		vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "deleteMessage").mockRejectedValueOnce(
			new Error("db full"),
		);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistCancelScheduled("sched-1");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("claimScheduledFire returns the row's content for a not-yet-fired scheduled row", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});

		const claimed = await result.current.claimScheduledFire("sched-1");
		expect(claimed?.id).toBe("sched-1");
		expect(base64ToText(claimed?.plaintextB64 ?? "")).toBe("text");
	});

	it("claimScheduledFire atomically deletes the row it claims, so a second claim of the same id fails — closes the concurrent-double-send race a plain check-then-act can't (crypto-reviewer RED finding, cycle 341)", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});

		const firstClaim = await result.current.claimScheduledFire("sched-1");
		expect(firstClaim).toBeDefined();
		await expect(db.messages.get("sched-1")).resolves.toBeUndefined();

		// A second claim (this tab retrying, or another tab's sweep) must not succeed —
		// there is nothing left to claim, and critically nothing left to re-encrypt/re-send.
		const secondClaim = await result.current.claimScheduledFire("sched-1");
		expect(secondClaim).toBeUndefined();
	});

	it("claimScheduledFire returns undefined after the row is cancelled — closes the cross-tab race where a stale tab's fire sweep would otherwise send a message the user cancelled elsewhere", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});
		await act(async () => {
			result.current.persistCancelScheduled("sched-1");
		});
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeUndefined();
		});

		await expect(result.current.claimScheduledFire("sched-1")).resolves.toBeUndefined();
	});

	it("claimScheduledFire returns undefined once the row has already fired (scheduledFor cleared)", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistScheduledCreate("sched-1", GROUP_ID, "text", Date.now() + 1000);
		});
		await waitFor(async () => {
			expect(await db.messages.get("sched-1")).toBeDefined();
		});
		await act(async () => {
			result.current.persistScheduledFire("sched-1");
		});
		await waitFor(async () => {
			const row = await db.messages.get("sched-1");
			expect(row?.scheduledFor).toBeUndefined();
		});

		await expect(result.current.claimScheduledFire("sched-1")).resolves.toBeUndefined();
	});

	it("claimScheduledFire returns undefined for an id that was never persisted", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		// fake-indexeddb's own internal callbacks are scheduled via setImmediate/setTimeout
		// (a real macrotask, not a microtask — see its scheduling.js), and this test (unlike
		// its siblings) has no further act()-wrapped call after the initial flush to
		// incidentally absorb a late-resolving getMessagesByGroup() setRows. Flush a real
		// timer tick inside act() so that update lands inside act()'s tracking too.
		await act(async () => {
			await new Promise((resolve) => setTimeout(resolve, 0));
			await new Promise((resolve) => setTimeout(resolve, 0));
			await new Promise((resolve) => setTimeout(resolve, 0));
			await new Promise((resolve) => setTimeout(resolve, 0));
		});

		await expect(result.current.claimScheduledFire("never-existed")).resolves.toBeUndefined();
	});

	it("claimScheduledFire fails closed (undefined) when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await expect(result.current.claimScheduledFire("sched-1")).resolves.toBeUndefined();
	});

	it("claimScheduledFire fails closed (undefined) when the Dexie transaction throws", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"claimScheduledFire",
		).mockRejectedValueOnce(new Error("AEAD failure"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await expect(result.current.claimScheduledFire("sched-1")).resolves.toBeUndefined();
	});

	it("persistDelivered marks the row delivered:true in rows state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "delivered-target" }));
		});
		await act(async () => {
			result.current.persistDelivered("delivered-target");
		});

		expect(result.current.rows[0].delivered).toBe(true);
	});

	it("persistDelivered is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistDelivered("delivered-target");
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("writeErrorCount increments when markMessageDelivered throws on persistDelivered", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageDelivered",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistDelivered("delivered-target");
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("persistRead marks the row read:true and stores readByJson in rows state", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "read-target" }));
		});
		await act(async () => {
			result.current.persistRead("read-target", ["dev-a", "dev-b"]);
		});

		expect(result.current.rows[0].read).toBe(true);
		expect(result.current.rows[0].readByJson).toBe(JSON.stringify(["dev-a", "dev-b"]));
	});

	it("persistRead is a no-op when the crypto worker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(null);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {
			result.current.persistRead("read-target", ["dev-a"]);
		});
		expect(result.current.rows).toHaveLength(0);
	});

	it("writeErrorCount increments when markMessageRead throws on persistRead", async () => {
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageRead",
		).mockRejectedValueOnce(new Error("db full"));
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});

		await act(async () => {
			result.current.persistRead("read-target", ["dev-a"]);
		});

		await waitFor(() => {
			expect(result.current.writeErrorCount).toBe(1);
		});
	});

	it("pendingWriteIds tracks a persistEdit write in flight and clears once it settles", async () => {
		let resolveWrite: () => void = () => {};
		const writePromise = new Promise<void>((resolve) => {
			resolveWrite = resolve;
		});
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageEdited",
		).mockReturnValueOnce(writePromise);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "pending-edit-target" }));
		});

		act(() => {
			result.current.persistEdit("pending-edit-target", "new text");
		});
		// The encryptDbField + IndexedDB write is still in flight — a rehydration
		// reconciliation running right now must not trust a fresh Dexie read yet.
		expect(result.current.pendingWriteIds.has("pending-edit-target")).toBe(true);

		await act(async () => {
			resolveWrite();
			await writePromise;
		});
		expect(result.current.pendingWriteIds.has("pending-edit-target")).toBe(false);
	});

	it("pendingWriteIds clears a persistReaction write even when the underlying write rejects", async () => {
		let rejectWrite: (err: Error) => void = () => {};
		const writePromise = new Promise<void>((_resolve, reject) => {
			rejectWrite = reject;
		});
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageReactionDelta",
		).mockReturnValueOnce(writePromise);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "pending-reaction-target" }));
		});

		act(() => {
			result.current.persistReaction("pending-reaction-target", "\u{1F44D}", "dev-a", "add");
		});
		expect(result.current.pendingWriteIds.has("pending-reaction-target")).toBe(true);

		await act(async () => {
			rejectWrite(new Error("db full"));
			await writePromise.catch(() => {});
		});
		expect(result.current.pendingWriteIds.has("pending-reaction-target")).toBe(false);
		expect(result.current.writeErrorCount).toBe(1);
	});

	it("pendingWriteIds tracks a persistDelivered write in flight and clears once it settles", async () => {
		let resolveWrite: () => void = () => {};
		const writePromise = new Promise<void>((resolve) => {
			resolveWrite = resolve;
		});
		vi.spyOn(
			EncryptedDbModule.EncryptedPowehiDb.prototype,
			"markMessageDelivered",
		).mockReturnValueOnce(writePromise);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "pending-delivered-target" }));
		});

		act(() => {
			result.current.persistDelivered("pending-delivered-target");
		});
		expect(result.current.pendingWriteIds.has("pending-delivered-target")).toBe(true);

		await act(async () => {
			resolveWrite();
			await writePromise;
		});
		expect(result.current.pendingWriteIds.has("pending-delivered-target")).toBe(false);
	});

	it("pendingWriteIds clears a persistRead write even when the underlying write rejects", async () => {
		let rejectWrite: (err: Error) => void = () => {};
		const writePromise = new Promise<void>((_resolve, reject) => {
			rejectWrite = reject;
		});
		vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "markMessageRead").mockReturnValueOnce(
			writePromise,
		);
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));
		await act(async () => {});
		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "pending-read-target" }));
		});

		act(() => {
			result.current.persistRead("pending-read-target", ["dev-a"]);
		});
		expect(result.current.pendingWriteIds.has("pending-read-target")).toBe(true);

		await act(async () => {
			rejectWrite(new Error("db full"));
			await writePromise.catch(() => {});
		});
		expect(result.current.pendingWriteIds.has("pending-read-target")).toBe(false);
		expect(result.current.writeErrorCount).toBe(1);
	});

	it("no plaintext is logged — calls produce no console output", async () => {
		const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ text: "SECRET_PLAINTEXT_CONTENT" }));
		});

		expect(logSpy).not.toHaveBeenCalled();
		expect(warnSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();
		logSpy.mockRestore();
		warnSpy.mockRestore();
		errorSpy.mockRestore();
	});
});
