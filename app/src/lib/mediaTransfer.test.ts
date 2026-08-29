/**
 * mediaTransfer — unit tests (prd.md §9.2 + §9.4.2).
 *
 * Security invariants verified:
 * - Files at or below MEDIA_CHUNK_THRESHOLD use the single-shot mediaEncrypt/
 *   mediaMessageCreate path (never the chunked variants).
 * - Files strictly larger than MEDIA_CHUNK_THRESHOLD use mediaEncryptChunked/
 *   mediaMessageCreateChunked (never the non-chunked variants).
 * - downloadAndDecryptMedia routes to mediaDecryptChunkedWithHandle when
 *   media.chunked === true, and to mediaDecryptWithHandle otherwise, after
 *   importing the raw key via mediaImportKey.
 * - The media key is always zeroed in both success and thrown-error cases,
 *   for both the chunked and non-chunked paths, and the imported handle is
 *   always dropped afterward.
 * - A thumbHandle passed on the chunked path is dropped, never leaked.
 * - ADR-0004: mediaExportKeyForStorage is opt-in (only called when the caller
 *   passes { exportKeyForPersistence: true }), is called AFTER sendMessage, and
 *   the transient Uint8Array it returns is zeroed once copied into the payload.
 */

import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as mediaApi from "../api/media";
import * as messagesApi from "../api/messages";
import { type MediaPayload, isValidMediaPayload } from "../hooks/useMessages";
import {
	MEDIA_CHUNK_THRESHOLD,
	downloadAndDecryptMedia,
	encryptAndSendMedia,
	sniffMimeType,
} from "./mediaTransfer";

const TOKEN = "test-token";
const IDENTITY_ID = "id-1";
const GROUP_ID = "group-1";

const mediaDropKeyFn = vi.fn(async (_handle: string) => true);
const mediaThumbnailDropFn = vi.fn(async (_handle: string) => true);

const mediaEncryptFn = vi.fn(async (_plaintext: Uint8Array) => ({
	ciphertext: new Uint8Array(48), // 32 bytes + 16-byte GCM tag
	mediaKeyHandle: "mock-media-key-handle-0",
	iv: new Uint8Array(12),
	blobHash: new Uint8Array(32),
}));

const mediaEncryptChunkedFn = vi.fn(async (bytes: Uint8Array) => ({
	ciphertext: new Uint8Array(bytes.length + 16), // padded chunk(s) + GCM tag(s), approximated
	mediaKeyHandle: "mock-chunked-key-handle-0",
	iv: new Uint8Array(12),
	blobHash: new Uint8Array(32),
	totalSize: bytes.length,
	chunkSize: 16 * 1024 * 1024,
}));

const mediaMessageCreateFn = vi.fn(
	async (
		_identityId: string,
		_groupId: string,
		_handle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_mimeType?: string,
	) => ({ ciphertext: new Uint8Array(64) }),
);

const mediaMessageCreateChunkedFn = vi.fn(
	async (
		_identityId: string,
		_groupId: string,
		_handle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_totalSize: number,
		_mimeType?: string,
	) => ({ ciphertext: new Uint8Array(96) }),
);

let importedKeyCounter = 0;
const mediaImportKeyFn = vi.fn(async (_rawKey: Uint8Array) => ({
	mediaKeyHandle: `mock-imported-handle-${importedKeyCounter++}`,
}));

// ADR-0004: mock the one-shot sender-path export. Returns a FRESH Uint8Array each
// call (never a shared buffer) so tests can retain a reference and assert it was
// zeroed by the caller after use, without cross-test contamination.
const mediaExportKeyForStorageFn = vi.fn(async (_handle: string) => ({
	mediaKey: new Uint8Array(32).fill(9),
}));

const mediaDecryptWithHandleFn = vi.fn(
	async (_handle: string, _iv: Uint8Array, _ciphertext: Uint8Array, _blobHash: Uint8Array) =>
		new Uint8Array(10),
);

const mediaDecryptChunkedWithHandleFn = vi.fn(
	async (
		_handle: string,
		_iv: Uint8Array,
		_ciphertext: Uint8Array,
		_blobHash: Uint8Array,
		_totalSize: number,
	) => new Uint8Array(20),
);

const mockWorker = {
	mediaEncrypt: mediaEncryptFn,
	mediaEncryptChunked: mediaEncryptChunkedFn,
	mediaMessageCreate: mediaMessageCreateFn,
	mediaMessageCreateChunked: mediaMessageCreateChunkedFn,
	mediaMessageCreateWithThumbnail: vi.fn(),
	mediaDropKey: mediaDropKeyFn,
	mediaThumbnailDrop: mediaThumbnailDropFn,
	mediaImportKey: mediaImportKeyFn,
	mediaDecryptWithHandle: mediaDecryptWithHandleFn,
	mediaDecryptChunkedWithHandle: mediaDecryptChunkedWithHandleFn,
	mediaExportKeyForStorage: mediaExportKeyForStorageFn,
};

describe("mediaTransfer (prd.md §9.2 + §9.4.2)", () => {
	let requestMediaUploadSpy: MockInstance<typeof mediaApi.requestMediaUpload>;
	let confirmMediaUploadSpy: MockInstance<typeof mediaApi.confirmMediaUpload>;
	let getMediaDownloadUrlSpy: MockInstance<typeof mediaApi.getMediaDownloadUrl>;
	let confirmMediaDownloadSpy: MockInstance<typeof mediaApi.confirmMediaDownload>;
	let sendMessageSpy: MockInstance<typeof messagesApi.sendMessage>;
	const fetchMock = vi.fn();

	beforeEach(() => {
		requestMediaUploadSpy = vi
			.spyOn(mediaApi, "requestMediaUpload")
			.mockResolvedValue({ mediaId: "test-media-id", uploadUrl: "https://r2.test/put" });
		confirmMediaUploadSpy = vi.spyOn(mediaApi, "confirmMediaUpload").mockResolvedValue(undefined);
		getMediaDownloadUrlSpy = vi
			.spyOn(mediaApi, "getMediaDownloadUrl")
			.mockResolvedValue({ downloadUrl: "https://r2.test/get" });
		confirmMediaDownloadSpy = vi
			.spyOn(mediaApi, "confirmMediaDownload")
			.mockResolvedValue(undefined);
		sendMessageSpy = vi.spyOn(messagesApi, "sendMessage").mockResolvedValue("envelope-id-1");

		fetchMock.mockResolvedValue({
			ok: true,
			status: 200,
			arrayBuffer: async () => new ArrayBuffer(8),
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		mediaEncryptFn.mockClear();
		mediaEncryptChunkedFn.mockClear();
		mediaMessageCreateFn.mockClear();
		mediaMessageCreateChunkedFn.mockClear();
		mediaDropKeyFn.mockClear();
		mediaThumbnailDropFn.mockClear();
		mediaImportKeyFn.mockClear();
		mediaDecryptWithHandleFn.mockClear();
		mediaDecryptChunkedWithHandleFn.mockClear();
		mediaExportKeyForStorageFn.mockClear();
		mediaExportKeyForStorageFn.mockImplementation(async (_handle: string) => ({
			mediaKey: new Uint8Array(32).fill(9),
		}));
	});

	afterEach(() => {
		vi.restoreAllMocks();
		fetchMock.mockReset();
	});

	describe("encryptAndSendMedia — routing", () => {
		it("uses mediaEncrypt/mediaMessageCreate (not chunked) for a file at MEDIA_CHUNK_THRESHOLD", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaEncryptFn).toHaveBeenCalledOnce();
			expect(mediaMessageCreateFn).toHaveBeenCalledOnce();
			expect(mediaEncryptChunkedFn).not.toHaveBeenCalled();
			expect(mediaMessageCreateChunkedFn).not.toHaveBeenCalled();
		});

		it("uses mediaEncrypt/mediaMessageCreate for a small file well under the threshold", async () => {
			const bytes = new Uint8Array(1024);
			await encryptAndSendMedia(
				bytes,
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaEncryptFn).toHaveBeenCalledOnce();
			expect(mediaEncryptChunkedFn).not.toHaveBeenCalled();
			expect(mediaMessageCreateChunkedFn).not.toHaveBeenCalled();
		});

		it("uses mediaEncryptChunked/mediaMessageCreateChunked (not the non-chunked variants) for a file strictly larger than the threshold", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaEncryptChunkedFn).toHaveBeenCalledOnce();
			expect(mediaMessageCreateChunkedFn).toHaveBeenCalledOnce();
			expect(mediaEncryptFn).not.toHaveBeenCalled();
			expect(mediaMessageCreateFn).not.toHaveBeenCalled();
		});

		it("passes totalSize from mediaEncryptChunked through to mediaMessageCreateChunked", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 5000);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaMessageCreateChunkedFn).toHaveBeenCalledWith(
				IDENTITY_ID,
				GROUP_ID,
				"mock-chunked-key-handle-0",
				"test-media-id",
				expect.any(Uint8Array),
				expect.any(Uint8Array),
				bytes.length,
				"video/mp4",
			);
		});

		it("passes the real mimeType through to mediaMessageCreateChunked (cycle-296 fix — no more size-bucket-only 'video' tag)", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/quicktime",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaMessageCreateChunkedFn).toHaveBeenCalledWith(
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				"video/quicktime",
			);
		});

		it("passes the real mimeType through to mediaMessageCreate on the non-chunked path (small video no longer silently loses its real type)", async () => {
			const bytes = new Uint8Array(1024);
			await encryptAndSendMedia(
				bytes,
				"video/quicktime",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaMessageCreateFn).toHaveBeenCalledWith(
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				expect.anything(),
				"video/quicktime",
			);
		});

		it("uploads the chunked ciphertext (not totalSize) as the R2 content length", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 5000);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			// mediaEncryptChunked mock returns ciphertext.length = bytes.length + 16.
			expect(requestMediaUploadSpy).toHaveBeenCalledWith(
				TOKEN,
				"video/mp4",
				bytes.length + 16,
				GROUP_ID,
			);
		});

		it("PUTs with a Content-Type matching the real mimeType, not a hardcoded value (chunked path) — R2 signs content-type into the presigned URL, so a mismatch fails the upload", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/quicktime",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(fetchMock).toHaveBeenCalledWith(
				"https://r2.test/put",
				expect.objectContaining({
					headers: { "Content-Type": "video/quicktime" },
				}),
			);
		});

		it("PUTs with a Content-Type matching the real mimeType, not a hardcoded value (non-chunked path)", async () => {
			const bytes = new Uint8Array(1024);
			await encryptAndSendMedia(
				bytes,
				"image/webp",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(fetchMock).toHaveBeenCalledWith(
				"https://r2.test/put",
				expect.objectContaining({
					headers: { "Content-Type": "image/webp" },
				}),
			);
		});

		it("drops a thumbHandle instead of using it on the chunked path", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				"leaked-thumb-handle",
			);

			expect(mediaThumbnailDropFn).toHaveBeenCalledWith("leaked-thumb-handle");
			expect(mockWorker.mediaMessageCreateWithThumbnail).not.toHaveBeenCalled();
		});

		it("confirms the upload and sends the message on the chunked path", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(confirmMediaUploadSpy).toHaveBeenCalledWith(TOKEN, "test-media-id");
			expect(sendMessageSpy).toHaveBeenCalledOnce();
		});

		it("returns the envelope id and base64 MLS ciphertext on the non-chunked path (for the caller's Dexie persist)", async () => {
			const bytes = new Uint8Array(1024);
			sendMessageSpy.mockResolvedValueOnce("envelope-single-1");

			const result = await encryptAndSendMedia(
				bytes,
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(result.envelopeId).toBe("envelope-single-1");
			// Mock mediaMessageCreate returns a 64-byte ciphertext — decode to verify it's the
			// same bytes, not something media-specific (blobId/key/iv never leak into this value).
			expect(atob(result.ciphertextB64)).toHaveLength(64);
		});

		it("returns the envelope id and base64 MLS ciphertext on the chunked path", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			sendMessageSpy.mockResolvedValueOnce("envelope-chunked-1");

			const result = await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(result.envelopeId).toBe("envelope-chunked-1");
			// Mock mediaMessageCreateChunked returns a 96-byte ciphertext.
			expect(atob(result.ciphertextB64)).toHaveLength(96);
		});
	});

	// ADR-0004 (docs/decisions/0004-media-key-local-persistence.md): the sender's own
	// copy of a sent attachment previously had no persistable key, so it rehydrated as a
	// permanent placeholder while every recipient's copy rehydrated fine. The fix is a
	// one-shot, opt-in, called-last key export whose JS exposure window is bounded by the
	// same zeroization discipline the receive path already uses.
	describe("encryptAndSendMedia — ADR-0004 key export for local persistence", () => {
		// Reads back the exact Uint8Array the mock handed to the caller, so "was it
		// zeroed after use?" can be asserted on the real buffer rather than a copy.
		const exportedBuffer = async (call = 0): Promise<Uint8Array> =>
			(await mediaExportKeyForStorageFn.mock.results[call].value).mediaKey;

		it("does NOT export the key when the caller did not opt in (non-chunked path)", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaExportKeyForStorageFn).not.toHaveBeenCalled();
			expect(result.media).toBeUndefined();
		});

		it("does NOT export the key when the caller did not opt in (chunked path)", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1),
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaExportKeyForStorageFn).not.toHaveBeenCalled();
			expect(result.media).toBeUndefined();
		});

		it("does NOT export the key when exportKeyForPersistence is explicitly false", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: false },
			);

			expect(mediaExportKeyForStorageFn).not.toHaveBeenCalled();
			expect(result.media).toBeUndefined();
		});

		it("exports exactly once, for the right handle, and returns a usable payload (non-chunked)", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect(mediaExportKeyForStorageFn).toHaveBeenCalledOnce();
			expect(mediaExportKeyForStorageFn).toHaveBeenCalledWith("mock-media-key-handle-0");

			expect(result.media).toBeDefined();
			const media = result.media as MediaPayload;
			expect(media.blobId).toBe("test-media-id");
			expect(media.blobHash).toHaveLength(32);
			expect(media.iv).toHaveLength(12);
			expect(media.mimeType).toBe("image/jpeg");
			expect(media.mediaKey).toHaveLength(32);
			// The payload captured the real key bytes, not an already-zeroed copy.
			expect(media.mediaKey.every((b) => b === 9)).toBe(true);
			// Single-shot path carries no chunk metadata and no inline thumbnail (the
			// §9.4.1 thumbnail key stays WASM-only — out of scope per ADR-0004).
			expect(media.chunked).toBeUndefined();
			expect(media.thumbnail).toBeUndefined();
		});

		it("exports exactly once and returns chunk metadata on the chunked path", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1),
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect(mediaExportKeyForStorageFn).toHaveBeenCalledOnce();
			expect(mediaExportKeyForStorageFn).toHaveBeenCalledWith("mock-chunked-key-handle-0");

			const media = result.media as MediaPayload;
			expect(media.chunked).toBe(true);
			expect(media.totalSize).toBe(MEDIA_CHUNK_THRESHOLD + 1);
			expect(media.chunkSize).toBe(16 * 1024 * 1024);
			expect(media.mimeType).toBe("video/mp4");
			expect(media.thumbnail).toBeUndefined();
		});

		// The exported payload is written straight into MessageRow.mediaJson and read back
		// through isValidMediaPayload on rehydration (ChatLayout.tsx). If it did not satisfy
		// that predicate the row would silently drop its attachment — the exact bug ADR-0004
		// exists to fix, just moved one layer down.
		it("produces a payload that passes isValidMediaPayload, before and after the JSON round trip (non-chunked)", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect(isValidMediaPayload(result.media)).toBe(true);
			expect(isValidMediaPayload(JSON.parse(JSON.stringify(result.media)))).toBe(true);
		});

		it("produces a payload that passes isValidMediaPayload, before and after the JSON round trip (chunked)", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1),
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect(isValidMediaPayload(result.media)).toBe(true);
			expect(isValidMediaPayload(JSON.parse(JSON.stringify(result.media)))).toBe(true);
		});

		// Key-hygiene invariant: the transport buffer that carried the raw key across the
		// worker boundary must be zeroed as soon as it is serialised, mirroring
		// downloadAndDecryptMedia's `mediaKey.fill(0)` after mediaImportKey.
		it("zeroes the exported key buffer immediately after serialising it", async () => {
			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			const buf = await exportedBuffer();
			expect(buf).toHaveLength(32);
			expect(buf.every((b) => b === 0)).toBe(true);
			// ...while the persisted copy still holds the real key.
			expect((result.media as MediaPayload).mediaKey.every((b) => b === 9)).toBe(true);
		});

		it("zeroes the exported key buffer on the chunked path too", async () => {
			await encryptAndSendMedia(
				new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1),
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect((await exportedBuffer()).every((b) => b === 0)).toBe(true);
		});

		// The message is already delivered by the time the export runs, so a failing export
		// must degrade to "no persisted payload", never to a thrown send.
		it("does not fail the send when the export rejects — media is simply undefined", async () => {
			mediaExportKeyForStorageFn.mockRejectedValueOnce(new Error("unknown media key handle"));
			sendMessageSpy.mockResolvedValueOnce("envelope-export-fail");

			const result = await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			expect(result.envelopeId).toBe("envelope-export-fail");
			expect(atob(result.ciphertextB64)).toHaveLength(64);
			expect(result.media).toBeUndefined();
		});

		// Ordering is a security property, not a style choice: exporting before the envelope
		// is accepted would hand raw key bytes to JS for a message that may never be
		// delivered, and would invalidate the handle mediaMessageCreate still needs.
		it("exports only AFTER mediaMessageCreate and sendMessage have completed", async () => {
			await encryptAndSendMedia(
				new Uint8Array(1024),
				"image/jpeg",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
				null,
				{ exportKeyForPersistence: true },
			);

			const createOrder = mediaMessageCreateFn.mock.invocationCallOrder[0];
			const sendOrder = sendMessageSpy.mock.invocationCallOrder[0];
			const exportOrder = mediaExportKeyForStorageFn.mock.invocationCallOrder[0];

			expect(exportOrder).toBeGreaterThan(createOrder);
			expect(exportOrder).toBeGreaterThan(sendOrder);
		});

		it("never exports when the send itself throws, but still releases the handle", async () => {
			sendMessageSpy.mockRejectedValueOnce(new Error("network error"));

			await expect(
				encryptAndSendMedia(
					new Uint8Array(1024),
					"image/jpeg",
					IDENTITY_ID,
					GROUP_ID,
					TOKEN,
					mockWorker as never,
					null,
					{ exportKeyForPersistence: true },
				),
			).rejects.toThrow("network error");

			expect(mediaExportKeyForStorageFn).not.toHaveBeenCalled();
			expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-media-key-handle-0");
		});
	});

	describe("encryptAndSendMedia — key hygiene (chunked path)", () => {
		it("calls mediaDropKey on success", async () => {
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);
			await encryptAndSendMedia(
				bytes,
				"video/mp4",
				IDENTITY_ID,
				GROUP_ID,
				TOKEN,
				mockWorker as never,
			);

			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
			expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-chunked-key-handle-0");
		});

		it("calls mediaDropKey even when sendMessage throws — security invariant", async () => {
			sendMessageSpy.mockRejectedValueOnce(new Error("network error"));
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);

			await expect(
				encryptAndSendMedia(bytes, "video/mp4", IDENTITY_ID, GROUP_ID, TOKEN, mockWorker as never),
			).rejects.toThrow("network error");

			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
			expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-chunked-key-handle-0");
		});

		it("calls mediaDropKey even when the R2 upload PUT throws", async () => {
			fetchMock.mockRejectedValueOnce(new Error("upload failed"));
			const bytes = new Uint8Array(MEDIA_CHUNK_THRESHOLD + 1);

			await expect(
				encryptAndSendMedia(bytes, "video/mp4", IDENTITY_ID, GROUP_ID, TOKEN, mockWorker as never),
			).rejects.toThrow("upload failed");

			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
		});
	});

	describe("downloadAndDecryptMedia — routing", () => {
		const nonChunkedMedia: MediaPayload = {
			blobId: "blob-1",
			blobHash: Array.from({ length: 32 }, () => 1),
			mediaKey: Array.from({ length: 32 }, () => 2),
			iv: Array.from({ length: 12 }, () => 3),
		};

		const chunkedMedia: MediaPayload = {
			blobId: "blob-2",
			blobHash: Array.from({ length: 32 }, () => 4),
			mediaKey: Array.from({ length: 32 }, () => 5),
			iv: Array.from({ length: 12 }, () => 6),
			chunked: true,
			totalSize: 33_554_432,
			chunkSize: 16 * 1024 * 1024,
		};

		it("imports the raw key via mediaImportKey before doing anything else", async () => {
			await downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never);

			expect(mediaImportKeyFn).toHaveBeenCalledOnce();
		});

		it("routes to mediaDecryptWithHandle (using the imported handle) when media.chunked is absent", async () => {
			await downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never);

			expect(mediaDecryptWithHandleFn).toHaveBeenCalledOnce();
			expect(mediaDecryptChunkedWithHandleFn).not.toHaveBeenCalled();
			const [handleArg] = mediaDecryptWithHandleFn.mock.calls[0];
			expect(handleArg).toBe((await mediaImportKeyFn.mock.results[0].value).mediaKeyHandle);
		});

		it("routes to mediaDecryptChunkedWithHandle (using the imported handle) when media.chunked === true", async () => {
			await downloadAndDecryptMedia(chunkedMedia, TOKEN, mockWorker as never);

			expect(mediaDecryptChunkedWithHandleFn).toHaveBeenCalledOnce();
			expect(mediaDecryptWithHandleFn).not.toHaveBeenCalled();
			expect(mediaDecryptChunkedWithHandleFn).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(Uint8Array),
				expect.any(Uint8Array),
				expect.any(Uint8Array),
				33_554_432,
			);
		});

		it("fetches the download URL for the given blobId regardless of chunked flag", async () => {
			await downloadAndDecryptMedia(chunkedMedia, TOKEN, mockWorker as never);
			expect(getMediaDownloadUrlSpy).toHaveBeenCalledWith(TOKEN, "blob-2");
		});

		it("zeroes the media key immediately after import, before the download even starts", async () => {
			let capturedKey: Uint8Array | null = null;
			mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
				capturedKey = rawKey;
				return { mediaKeyHandle: "mock-imported-handle-snapshot" };
			});
			const keyArray = [7, 7, 7];
			const media: MediaPayload = { ...chunkedMedia, mediaKey: keyArray };
			await downloadAndDecryptMedia(media, TOKEN, mockWorker as never);

			expect(capturedKey).not.toBeNull();
			expect(Array.from(capturedKey ?? new Uint8Array())).toEqual([0, 0, 0]);
		});

		it("zeroes the media key even when mediaImportKey throws — security invariant", async () => {
			let capturedKey: Uint8Array | null = null;
			mediaImportKeyFn.mockImplementationOnce(async (rawKey: Uint8Array) => {
				capturedKey = rawKey;
				throw new Error("import_failed");
			});
			const keyArray = [9, 9, 9];
			const media: MediaPayload = { ...chunkedMedia, mediaKey: keyArray };

			await expect(downloadAndDecryptMedia(media, TOKEN, mockWorker as never)).rejects.toThrow(
				"import_failed",
			);

			expect(capturedKey).not.toBeNull();
			expect(Array.from(capturedKey ?? new Uint8Array())).toEqual([0, 0, 0]);
		});

		it("drops the imported handle on success", async () => {
			await downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never);

			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
			const importedHandle = (await mediaImportKeyFn.mock.results[0].value).mediaKeyHandle;
			expect(mediaDropKeyFn).toHaveBeenCalledWith(importedHandle);
		});

		it("drops the imported handle even when the chunked decrypt throws — security invariant", async () => {
			mediaDecryptChunkedWithHandleFn.mockRejectedValueOnce(new Error("blob_hash_mismatch"));

			await expect(
				downloadAndDecryptMedia(chunkedMedia, TOKEN, mockWorker as never),
			).rejects.toThrow("blob_hash_mismatch");

			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
		});

		it("drops the imported handle even when the R2 fetch throws", async () => {
			fetchMock.mockRejectedValueOnce(new Error("network down"));

			await expect(
				downloadAndDecryptMedia(chunkedMedia, TOKEN, mockWorker as never),
			).rejects.toThrow("network down");

			// mediaDecryptChunkedWithHandle never got called (fetch failed first), but the
			// handle was already imported and must still be dropped.
			expect(mediaDecryptChunkedWithHandleFn).not.toHaveBeenCalled();
			expect(mediaDropKeyFn).toHaveBeenCalledOnce();
		});

		it("forwards an already-aborted signal to the shared limiter without importing a key", async () => {
			const controller = new AbortController();
			controller.abort();

			await expect(
				downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never, controller.signal),
			).rejects.toThrow(/aborted/i);

			expect(mediaImportKeyFn).not.toHaveBeenCalled();
			expect(getMediaDownloadUrlSpy).not.toHaveBeenCalled();
		});

		// cycle-289 ack-on-grant fix: the download-confirm ack must fire only once
		// the transfer is actually verified complete (blobHash + AES-GCM decrypt
		// both succeeded), not merely once a download URL was granted.
		it("confirms the download after a successful non-chunked decrypt", async () => {
			await downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never);

			expect(confirmMediaDownloadSpy).toHaveBeenCalledExactlyOnceWith(TOKEN, "blob-1");
		});

		it("confirms the download after a successful chunked decrypt", async () => {
			await downloadAndDecryptMedia(chunkedMedia, TOKEN, mockWorker as never);

			expect(confirmMediaDownloadSpy).toHaveBeenCalledExactlyOnceWith(TOKEN, "blob-2");
		});

		it("does not confirm the download when decryption fails", async () => {
			mediaDecryptWithHandleFn.mockRejectedValueOnce(new Error("blob_hash_mismatch"));

			await expect(
				downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never),
			).rejects.toThrow("blob_hash_mismatch");

			expect(confirmMediaDownloadSpy).not.toHaveBeenCalled();
		});

		it("does not fail the receive when the confirm-download call itself rejects — best-effort", async () => {
			confirmMediaDownloadSpy.mockRejectedValueOnce(new Error("http_500"));

			await expect(
				downloadAndDecryptMedia(nonChunkedMedia, TOKEN, mockWorker as never),
			).resolves.toEqual(new Uint8Array(10));
		});
	});

	describe("sniffMimeType — video detection (§9.4.2)", () => {
		it("detects an MP4/QuickTime `ftyp` box as video/mp4", () => {
			const bytes = new Uint8Array([0, 0, 0, 24, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]);
			expect(sniffMimeType(bytes)).toBe("video/mp4");
		});

		it("detects a WebM/Matroska EBML header as video/webm", () => {
			const bytes = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 1, 2, 3, 4]);
			expect(sniffMimeType(bytes)).toBe("video/webm");
		});

		it("falls back to video/mp4 (not image/jpeg) for unrecognized bytes when videoHint is set", () => {
			const bytes = new Uint8Array([1, 2, 3, 4]);
			expect(sniffMimeType(bytes, { videoHint: true })).toBe("video/mp4");
		});

		it("still falls back to image/jpeg for unrecognized bytes with no videoHint (prior behavior)", () => {
			const bytes = new Uint8Array([1, 2, 3, 4]);
			expect(sniffMimeType(bytes)).toBe("image/jpeg");
		});

		it("image magic bytes take precedence over videoHint", () => {
			const jpeg = new Uint8Array([0xff, 0xd8, 0xff, 0xe0]);
			expect(sniffMimeType(jpeg, { videoHint: true })).toBe("image/jpeg");
		});
	});
});
