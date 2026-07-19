/**
 * useThumbnail — unit tests (prd.md §9.4.1 inline thumbnail).
 *
 * Security invariants verified:
 * - The canonical thumbnail.key (number[], in React chats state) is NEVER
 *   zeroed — only the hook's local copy is, after import and before decrypt
 *   (cycle 316: zeroing the canonical array broke redecrypt on remount, since
 *   `chats` state is long-lived and message components fully unmount/remount
 *   on chat switch, reusing the same `thumbnail` object reference).
 * - The imported key handle is dropped on every path (success and failure).
 * - Object URL is revoked on unmount to prevent memory leaks.
 * - Invalid thumbnail dimensions are rejected before import (fail closed).
 * - Decryption failure is non-fatal; objectUrl stays null.
 * - cancelled flag prevents stale objectUrl after unmount.
 */

import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as CryptoWorkerHook from "./useCryptoWorker";
import type { ThumbnailPayload } from "./useMessages";
import { useThumbnail } from "./useThumbnail";

const MOCK_BLOB_URL = "blob:http://localhost/mock-thumb-url";
const MOCK_PIXELS = new Uint8Array(new ArrayBuffer(64 * 64 * 3));

const makeThumbnail = (overrides: Partial<ThumbnailPayload> = {}): ThumbnailPayload => ({
	ct: Array.from<number>({ length: 100 }).fill(1),
	key: Array.from<number>({ length: 32 }).fill(0xab),
	iv: Array.from<number>({ length: 12 }).fill(0xcd),
	...overrides,
});

const MOCK_HANDLE = "mock-thumb-key-handle-0";

const mediaImportKeyFn = vi.fn(async (_rawKey: Uint8Array) => ({
	mediaKeyHandle: MOCK_HANDLE,
}));
const mediaThumbnailDecryptFn = vi.fn(
	async (_mediaKeyHandle: string, _ct: Uint8Array, _iv: Uint8Array) => ({
		pixels: MOCK_PIXELS,
	}),
);
const mediaDropKeyFn = vi.fn(async (_handle: string) => true);

const mockWorker = {
	mediaImportKey: mediaImportKeyFn,
	mediaThumbnailDecryptWithHandle: mediaThumbnailDecryptFn,
	mediaDropKey: mediaDropKeyFn,
};

describe("useThumbnail (prd.md §9.4.1)", () => {
	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		globalThis.URL.createObjectURL = vi.fn().mockReturnValue(MOCK_BLOB_URL);
		globalThis.URL.revokeObjectURL = vi.fn();
		mediaImportKeyFn.mockClear();
		mediaImportKeyFn.mockResolvedValue({ mediaKeyHandle: MOCK_HANDLE });
		mediaThumbnailDecryptFn.mockClear();
		mediaThumbnailDecryptFn.mockResolvedValue({ pixels: MOCK_PIXELS });
		mediaDropKeyFn.mockClear();
		mediaDropKeyFn.mockResolvedValue(true);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("returns null objectUrl when thumbnail is undefined", () => {
		const { result } = renderHook(() => useThumbnail(undefined));
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("returns null objectUrl when cryptoWorker is unavailable", async () => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			null as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		const { result } = renderHook(() => useThumbnail(makeThumbnail()));
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("creates object URL after successful decryption", async () => {
		const thumb = makeThumbnail();
		const { result } = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(result.current.objectUrl).toBe(MOCK_BLOB_URL));
		expect(mediaImportKeyFn).toHaveBeenCalledOnce();
		expect(mediaThumbnailDecryptFn).toHaveBeenCalledWith(
			MOCK_HANDLE,
			expect.any(Uint8Array),
			expect.any(Uint8Array),
		);
		expect(mediaDropKeyFn).toHaveBeenCalledWith(MOCK_HANDLE);
	});

	it("security: never zeroes the canonical thumbnail.key (number[]) in chats state", async () => {
		const thumb = makeThumbnail();
		const originalKey = [...thumb.key];
		expect(originalKey.every((b) => b === 0xab)).toBe(true);

		// mediaImportKeyFn's default resolves synchronously with the local key
		// copy still live in the mock-call record; the hook zeroes that SAME
		// object right after — snapshot the bytes at call-time instead of
		// asserting on the (later-mutated) recorded reference.
		let seenAtCallTime: Uint8Array | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			seenAtCallTime = new Uint8Array(rawKey);
			return { mediaKeyHandle: MOCK_HANDLE };
		});

		const { result } = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(result.current.objectUrl).toBe(MOCK_BLOB_URL));

		// mediaImportKey received the real key bytes (not an already-zeroed copy).
		expect(seenAtCallTime).toEqual(new Uint8Array(originalKey));
		// Only the hook's local copy is zeroed after import — the canonical
		// number[] in chats state must survive intact so a later remount (chat
		// revisit) can still decrypt it.
		expect(thumb.key).toEqual(originalKey);
	});

	it("regression (cycle 316): a remount after first decrypt still decrypts successfully", async () => {
		// Reuses the SAME thumbnail object reference across two mounts, mirroring
		// the real app: `chats` state is long-lived and the unvirtualized message
		// list fully unmounts/remounts each message's components on chat switch
		// (content-derived React keys), but the underlying `ChatMessage.thumbnail`
		// object is never re-created.
		const thumb = makeThumbnail();

		const first = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(first.result.current.objectUrl).toBe(MOCK_BLOB_URL));
		first.unmount();

		mediaImportKeyFn.mockClear();
		mediaThumbnailDecryptFn.mockClear();
		let seenOnSecondMount: Uint8Array | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			seenOnSecondMount = new Uint8Array(rawKey);
			return { mediaKeyHandle: MOCK_HANDLE };
		});

		const second = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(second.result.current.objectUrl).toBe(MOCK_BLOB_URL));
		expect(seenOnSecondMount).toEqual(new Uint8Array(32).fill(0xab));
		second.unmount();
	});

	it("revokes object URL on unmount", async () => {
		const { result, unmount } = renderHook(() => useThumbnail(makeThumbnail()));
		await waitFor(() => expect(result.current.objectUrl).toBe(MOCK_BLOB_URL));

		unmount();

		expect(globalThis.URL.revokeObjectURL).toHaveBeenCalledWith(MOCK_BLOB_URL);
	});

	it("returns null when key length is not 32", async () => {
		const thumb = makeThumbnail({
			key: Array.from<number>({ length: 31 }).fill(1),
		});
		const { result } = renderHook(() => useThumbnail(thumb));
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("returns null when iv length is not 12", async () => {
		const thumb = makeThumbnail({
			iv: Array.from<number>({ length: 11 }).fill(1),
		});
		const { result } = renderHook(() => useThumbnail(thumb));
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("returns null when ct is empty", async () => {
		const thumb = makeThumbnail({ ct: [] });
		const { result } = renderHook(() => useThumbnail(thumb));
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("returns null when ct exceeds 16384 bytes", async () => {
		const thumb = makeThumbnail({
			ct: Array.from<number>({ length: 16_385 }).fill(1),
		});
		const { result } = renderHook(() => useThumbnail(thumb));
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(mediaImportKeyFn).not.toHaveBeenCalled();
		expect(mediaThumbnailDecryptFn).not.toHaveBeenCalled();
	});

	it("accepts ct at exactly 16384 bytes (boundary)", async () => {
		const thumb = makeThumbnail({
			ct: Array.from<number>({ length: 16_384 }).fill(1),
		});
		const { result } = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(result.current.objectUrl).toBe(MOCK_BLOB_URL));
		expect(mediaThumbnailDecryptFn).toHaveBeenCalledOnce();
	});

	it("handles decryption failure gracefully — objectUrl stays null", async () => {
		mediaThumbnailDecryptFn.mockRejectedValueOnce(new Error("AES-GCM auth tag mismatch"));
		const { result } = renderHook(() => useThumbnail(makeThumbnail()));
		// After the reject, no object URL should be created.
		await act(async () => {});
		expect(result.current.objectUrl).toBeNull();
		expect(globalThis.URL.createObjectURL).not.toHaveBeenCalled();
		// The handle must still be dropped on the failure path (finally block).
		expect(mediaDropKeyFn).toHaveBeenCalledWith(MOCK_HANDLE);
	});

	it("zeroes the local key copy even when mediaImportKey throws (crypto-reviewer YELLOW, cycle 316)", async () => {
		let seenAtCallTime: Uint8Array | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			seenAtCallTime = rawKey;
			throw new Error("WASM handle table full");
		});

		const { result } = renderHook(() => useThumbnail(makeThumbnail()));
		await act(async () => {});

		expect(result.current.objectUrl).toBeNull();
		expect(seenAtCallTime).not.toBeNull();
		// The finally block zeroes the same Uint8Array reference the mock saw,
		// regardless of the import throwing.
		expect(seenAtCallTime).toEqual(new Uint8Array(32).fill(0));
	});

	it("does not call setObjectUrl after unmount (cancelled flag)", async () => {
		// Delay decrypt so unmount happens before resolution.
		let resolveDecrypt!: (v: { pixels: Uint8Array<ArrayBuffer> }) => void;
		mediaThumbnailDecryptFn.mockReturnValueOnce(
			new Promise<{ pixels: Uint8Array<ArrayBuffer> }>((resolve) => {
				resolveDecrypt = resolve;
			}),
		);

		const { unmount } = renderHook(() => useThumbnail(makeThumbnail()));
		// Unmount before the decrypt resolves.
		unmount();
		// Now resolve — the cancelled flag should prevent setObjectUrl.
		await act(async () => {
			resolveDecrypt({ pixels: MOCK_PIXELS });
		});

		// createObjectURL should NOT have been called because the hook was cancelled.
		expect(globalThis.URL.createObjectURL).not.toHaveBeenCalled();
	});

	it("aborts the queued/in-flight decrypt's signal on unmount (crypto-reviewer advisory B, cycle 312)", async () => {
		const abortSpy = vi.spyOn(AbortController.prototype, "abort");
		const { unmount } = renderHook(() => useThumbnail(makeThumbnail()));

		unmount();

		expect(abortSpy).toHaveBeenCalledOnce();
	});
});
