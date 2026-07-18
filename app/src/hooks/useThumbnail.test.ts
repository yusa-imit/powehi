/**
 * useThumbnail — unit tests (prd.md §9.4.1 inline thumbnail).
 *
 * Security invariants verified:
 * - thumbnail.key (number[]) is zeroed after import (before decrypt).
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

	it("security: zeroes thumbnail.key (number[]) after decryption", async () => {
		const thumb = makeThumbnail();
		const originalKey = [...thumb.key];
		expect(originalKey.every((b) => b === 0xab)).toBe(true);

		const { result } = renderHook(() => useThumbnail(thumb));
		await waitFor(() => expect(result.current.objectUrl).toBe(MOCK_BLOB_URL));

		// The hook creates Uint8Array(thumbnail.key), calls key.fill(0), then thumbnail.key.fill(0).
		// The number[] backing array must be all-zero after decryption.
		expect(thumb.key.every((b) => b === 0)).toBe(true);
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
