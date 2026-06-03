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

	it("persistIncoming sorts rows by epochSeq", async () => {
		const { result } = renderHook(() => usePersistentMessages(GROUP_ID));

		await act(async () => {
			result.current.persistIncoming(makeIncoming({ id: "id-b", epochSeq: 2000 }));
			result.current.persistIncoming(makeIncoming({ id: "id-a", epochSeq: 1000 }));
		});

		expect(result.current.rows[0].id).toBe("id-a");
		expect(result.current.rows[1].id).toBe("id-b");
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
