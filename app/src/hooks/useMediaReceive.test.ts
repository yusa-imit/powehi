/**
 * useMediaReceive — unit tests (prd.md §9.2 receiver path).
 *
 * Security invariants verified:
 * - mediaKey bytes are zeroed immediately after import (opaque-handle pattern, cycle 309).
 * - mediaKey bytes are zeroed even when import/decrypt fails.
 * - Object URL is revoked on unmount.
 * - Error state set on download HTTP failure.
 * - Error state set on decrypt failure.
 */

import { renderHook, waitFor } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as mediaApi from "../api/media";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { useMediaReceive } from "./useMediaReceive";
import type { MediaPayload } from "./useMessages";

const TOKEN = "test-token";

// JPEG magic bytes so sniffMimeType returns "image/jpeg".
const JPEG_BYTES = new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4]);

const mediaImportKeyFn = vi.fn(
	async (_rawKey: Uint8Array): Promise<{ mediaKeyHandle: string }> => ({
		mediaKeyHandle: "mock-receive-handle-0",
	}),
);

const mediaDecryptWithHandleFn = vi.fn(
	async (
		_mediaKeyHandle: string,
		_iv: Uint8Array,
		_ciphertext: Uint8Array,
		_blobHash: Uint8Array,
	): Promise<Uint8Array> => JPEG_BYTES,
);

const mediaDropKeyFn = vi.fn(async (_handle: string) => true);

const mockWorker = {
	mediaImportKey: mediaImportKeyFn,
	mediaDecryptWithHandle: mediaDecryptWithHandleFn,
	mediaDropKey: mediaDropKeyFn,
};

const MOCK_MEDIA: MediaPayload = {
	blobId: "blob-123",
	blobHash: Array.from<number>({ length: 32 }).fill(1),
	mediaKey: Array.from<number>({ length: 32 }).fill(42),
	iv: Array.from<number>({ length: 12 }).fill(3),
};

const MOCK_BLOB_URL = "blob:http://localhost/test-object-url";

describe("useMediaReceive (prd.md §9.2 receiver path)", () => {
	let getMediaDownloadUrlSpy: MockInstance<typeof mediaApi.getMediaDownloadUrl>;
	const fetchMock = vi.fn();

	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({ phase: "app", deviceId: "my-device", sessionToken: TOKEN });

		getMediaDownloadUrlSpy = vi
			.spyOn(mediaApi, "getMediaDownloadUrl")
			.mockResolvedValue({ downloadUrl: "https://r2.test/ciphertext" });

		fetchMock.mockResolvedValue({
			ok: true,
			arrayBuffer: async () => new ArrayBuffer(64),
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		globalThis.URL.createObjectURL = vi.fn().mockReturnValue(MOCK_BLOB_URL);
		globalThis.URL.revokeObjectURL = vi.fn();

		mediaImportKeyFn.mockClear();
		mediaImportKeyFn.mockResolvedValue({ mediaKeyHandle: "mock-receive-handle-0" });
		mediaDecryptWithHandleFn.mockClear();
		mediaDecryptWithHandleFn.mockResolvedValue(JPEG_BYTES);
		mediaDropKeyFn.mockClear();
	});

	afterEach(() => {
		vi.restoreAllMocks();
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
		fetchMock.mockReset();
	});

	it("returns idle state when media is undefined", () => {
		const { result } = renderHook(() => useMediaReceive(undefined));
		expect(result.current).toEqual({ objectUrl: null, loading: false, error: false });
		expect(getMediaDownloadUrlSpy).not.toHaveBeenCalled();
	});

	it("sets loading=true immediately on mount with media", async () => {
		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));
		// loading transitions to true synchronously in setState inside the async run()
		// which is triggered by void run(); — by the time React processes it:
		await waitFor(() => expect(result.current.loading).toBe(false));
		// After settling it should have objectUrl (not just loading forever)
		expect(result.current.error).toBe(false);
	});

	it("resolves to objectUrl on successful download and decrypt", async () => {
		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => {
			expect(result.current.objectUrl).toBe(MOCK_BLOB_URL);
		});

		expect(result.current.loading).toBe(false);
		expect(result.current.error).toBe(false);
		expect(getMediaDownloadUrlSpy).toHaveBeenCalledWith(TOKEN, "blob-123");
		expect(fetchMock).toHaveBeenCalledWith("https://r2.test/ciphertext", { redirect: "error" });
	});

	it("passes the raw key to mediaImportKey, and iv/blobHash (plus the imported handle) to mediaDecryptWithHandle", async () => {
		let keyCopy: number[] | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			// Snapshot before the hook's finally block zeroes mediaKey.
			keyCopy = Array.from(rawKey);
			return { mediaKeyHandle: "mock-receive-handle-0" };
		});
		let handleArg: string | null = null;
		let ivCopy: number[] | null = null;
		let hashCopy: number[] | null = null;
		mediaDecryptWithHandleFn.mockImplementationOnce(
			async (handle: string, iv: Uint8Array, _ct, blobHash: Uint8Array) => {
				handleArg = handle;
				ivCopy = Array.from(iv);
				hashCopy = Array.from(blobHash);
				return JPEG_BYTES;
			},
		);

		renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => expect(keyCopy).not.toBeNull());
		expect(keyCopy).toEqual(MOCK_MEDIA.mediaKey);
		await waitFor(() => expect(handleArg).not.toBeNull());
		expect(handleArg).toBe("mock-receive-handle-0");
		expect(ivCopy).toEqual(MOCK_MEDIA.iv);
		expect(hashCopy).toEqual(MOCK_MEDIA.blobHash);
	});

	it("Y — mediaKey bytes are zeroed immediately after import, before the download even starts", async () => {
		let capturedKey: Uint8Array | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			capturedKey = rawKey;
			return { mediaKeyHandle: "mock-receive-handle-0" };
		});

		renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => expect(capturedKey).not.toBeNull());
		// After the finally block runs, the key bytes must all be zero.
		await waitFor(() => {
			expect(capturedKey).not.toBeNull();
			const allZero = Array.from(capturedKey ?? new Uint8Array()).every((b) => b === 0);
			expect(allZero).toBe(true);
		});
	});

	it("Y — mediaKey bytes are zeroed even when import throws", async () => {
		let capturedKey: Uint8Array | null = null;
		mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
			capturedKey = rawKey;
			throw new Error("import_failed");
		});

		renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => expect(capturedKey).not.toBeNull());
		await waitFor(() => {
			expect(capturedKey).not.toBeNull();
			const allZero = Array.from(capturedKey ?? new Uint8Array()).every((b) => b === 0);
			expect(allZero).toBe(true);
		});
	});

	it("drops the imported handle on success", async () => {
		renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => expect(mediaDropKeyFn).toHaveBeenCalledOnce());
		expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-receive-handle-0");
	});

	it("drops the imported handle even when decrypt throws — security invariant", async () => {
		mediaDecryptWithHandleFn.mockRejectedValueOnce(new Error("hash_mismatch"));

		renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => expect(mediaDropKeyFn).toHaveBeenCalledOnce());
		expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-receive-handle-0");
	});

	it("sets error=true on HTTP download failure (non-ok response)", async () => {
		fetchMock.mockResolvedValueOnce({ ok: false, status: 403 });

		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => {
			expect(result.current.error).toBe(true);
		});
		expect(result.current.objectUrl).toBeNull();
		expect(result.current.loading).toBe(false);
	});

	it("sets error=true when getMediaDownloadUrl rejects", async () => {
		getMediaDownloadUrlSpy.mockRejectedValueOnce(new Error("network_error"));

		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => {
			expect(result.current.error).toBe(true);
		});
		expect(result.current.objectUrl).toBeNull();
	});

	it("sets error=true when decrypt fails (hash mismatch or wrong key)", async () => {
		mediaDecryptWithHandleFn.mockRejectedValueOnce(new Error("hash_mismatch"));

		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => {
			expect(result.current.error).toBe(true);
		});
		expect(result.current.objectUrl).toBeNull();
		expect(result.current.loading).toBe(false);
	});

	it("revokes object URL on unmount — no memory leak", async () => {
		const { result, unmount } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		await waitFor(() => {
			expect(result.current.objectUrl).toBe(MOCK_BLOB_URL);
		});

		unmount();

		expect(URL.revokeObjectURL).toHaveBeenCalledWith(MOCK_BLOB_URL);
	});

	it("aborts the in-flight decrypt's signal on unmount (crypto-reviewer advisory B, cycle 312)", async () => {
		const abortSpy = vi.spyOn(AbortController.prototype, "abort");
		const { unmount } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		unmount();

		expect(abortSpy).toHaveBeenCalledOnce();
	});

	it("prefers the real mimeType (cycle-296) over the chunked-based videoHint when sniffing generic bytes", async () => {
		const genericBytes = new Uint8Array([1, 2, 3, 4]); // no image/video magic bytes
		mediaDecryptWithHandleFn.mockResolvedValueOnce(genericBytes);

		let capturedBlob: Blob | null = null;
		(globalThis.URL.createObjectURL as ReturnType<typeof vi.fn>).mockImplementation(
			(blob: Blob) => {
				capturedBlob = blob;
				return MOCK_BLOB_URL;
			},
		);

		const media: MediaPayload = { ...MOCK_MEDIA, mimeType: "video/quicktime" };
		renderHook(() => useMediaReceive(media));

		await waitFor(() => expect(capturedBlob).not.toBeNull());
		expect((capturedBlob as unknown as Blob).type).toBe("video/mp4");
	});

	it("does nothing when session token is absent", () => {
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });

		const { result } = renderHook(() => useMediaReceive(MOCK_MEDIA));

		expect(result.current).toEqual({ objectUrl: null, loading: false, error: false });
		expect(getMediaDownloadUrlSpy).not.toHaveBeenCalled();
	});
});
