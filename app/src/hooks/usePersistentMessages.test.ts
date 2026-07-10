import "fake-indexeddb/auto";
import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as EncryptedDbModule from "../db/encrypted-db";
import { DirectFieldEncryptor, deriveDbKey } from "../db/encryption";
import { useAuthStore } from "../store/auth";
import { base64ToText, textToBase64 } from "../utils/base64";
import * as CryptoWorkerHook from "./useCryptoWorker";
import type { IncomingMessage } from "./useMessages";
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
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
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
