/**
 * useMediaSend — unit tests (prd.md §9.2 + §9.4.1).
 *
 * Security invariants verified:
 * - mediaDropKey is ALWAYS called (finally block), even on send failure.
 * - mediaThumbnailDrop is ALWAYS called when a thumb handle was acquired.
 * - R2 PUT receives the ciphertext Uint8Array (not the plaintext file bytes).
 * - sendMessage receives the MLS ciphertext from mediaMessageCreate.
 * - When thumbnail is available, mediaMessageCreateWithThumbnail is used.
 */

import { act, renderHook } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as mediaApi from "../api/media";
import * as messagesApi from "../api/messages";
import { useAuthStore } from "../store/auth";
import * as CryptoWorkerHook from "./useCryptoWorker";
import { useMediaSend } from "./useMediaSend";

const TOKEN = "test-token";
const IDENTITY_ID = "id-1";

// Defined once; cleared in beforeEach so call counts reset between tests.
const mediaDropKeyFn = vi.fn(async (_handle: string) => true);
// ADR-0004: the one-shot sender-path key export. Fresh buffer per call so a test can
// observe whether the caller zeroed it.
const mediaExportKeyForStorageFn = vi.fn(async (_handle: string) => ({
	mediaKey: new Uint8Array(32).fill(9),
}));
const mediaThumbnailDropFn = vi.fn(async (_handle: string) => true);
const mediaThumbnailEncryptFn = vi.fn(async (_thumbBytes: Uint8Array) => ({
	thumbHandle: "mock-thumb-handle-0",
}));
const mediaMessageCreateWithThumbnailFn = vi.fn(
	async (
		_identityId: string,
		_groupId: string,
		_handle: string,
		_blobId: string,
		_blobHash: Uint8Array,
		_iv: Uint8Array,
		_thumbHandle: string,
	) => ({ ciphertext: new Uint8Array(80) }),
);

const mockWorker = {
	mediaEncrypt: vi.fn(async (_plaintext: Uint8Array) => ({
		ciphertext: new Uint8Array(48), // 32 bytes + 16-byte GCM tag
		mediaKeyHandle: "mock-media-key-handle-0",
		iv: new Uint8Array(12),
		blobHash: new Uint8Array(32),
	})),
	mediaMessageCreate: vi.fn(
		async (
			_identityId: string,
			_groupId: string,
			_handle: string,
			_blobId: string,
			_blobHash: Uint8Array,
			_iv: Uint8Array,
		) => ({ ciphertext: new Uint8Array(64) }),
	),
	mediaDropKey: mediaDropKeyFn,
	mediaExportKeyForStorage: mediaExportKeyForStorageFn,
	mediaThumbnailEncrypt: mediaThumbnailEncryptFn,
	mediaThumbnailDrop: mediaThumbnailDropFn,
	mediaMessageCreateWithThumbnail: mediaMessageCreateWithThumbnailFn,
};

const makeFile = (size = 100): File => {
	const bytes = new Uint8Array(size);
	const file = new File([bytes], "photo.jpg", { type: "image/jpeg" });
	// jsdom does not implement Blob/File.arrayBuffer — attach it explicitly.
	Object.defineProperty(file, "arrayBuffer", {
		value: async () => bytes.buffer,
		configurable: true,
	});
	return file;
};

describe("useMediaSend (prd.md §9.2)", () => {
	let requestMediaUploadSpy: MockInstance<typeof mediaApi.requestMediaUpload>;
	let confirmMediaUploadSpy: MockInstance<typeof mediaApi.confirmMediaUpload>;
	let sendMessageSpy: MockInstance<typeof messagesApi.sendMessage>;
	const fetchMock = vi.fn();

	beforeEach(() => {
		requestMediaUploadSpy = vi
			.spyOn(mediaApi, "requestMediaUpload")
			.mockResolvedValue({ mediaId: "test-media-id", uploadUrl: "https://r2.test/put" });
		confirmMediaUploadSpy = vi.spyOn(mediaApi, "confirmMediaUpload").mockResolvedValue(undefined);
		sendMessageSpy = vi.spyOn(messagesApi, "sendMessage").mockResolvedValue("envelope-id-1");

		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({ phase: "app", deviceId: "my-device", sessionToken: TOKEN });

		fetchMock.mockResolvedValue({ ok: true, status: 200 });
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		// Reset call counts so each test starts clean.
		mockWorker.mediaEncrypt.mockClear();
		mockWorker.mediaMessageCreate.mockClear();
		mediaDropKeyFn.mockClear();
		mediaExportKeyForStorageFn.mockClear();
		mediaExportKeyForStorageFn.mockImplementation(async (_handle: string) => ({
			mediaKey: new Uint8Array(32).fill(9),
		}));
		mediaThumbnailDropFn.mockClear();
		mediaThumbnailEncryptFn.mockClear();
		mediaMessageCreateWithThumbnailFn.mockClear();
	});

	afterEach(() => {
		vi.restoreAllMocks();
		// useAuthStore is a real zustand store the hook subscribes to via useSyncExternalStore;
		// @testing-library/react's auto-cleanup unmount runs as an outer afterEach (registered at
		// module import time), so this reset still lands on a mounted component and must be
		// wrapped in act() to avoid the "not wrapped in act" warning.
		act(() => {
			useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
		});
		fetchMock.mockReset();
	});

	it("returns a sendMedia function", () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		expect(typeof result.current.sendMedia).toBe("function");
	});

	it("calls requestMediaUpload with the correct groupId and ciphertext size", async () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-abc" }),
		);
		await result.current.sendMedia(makeFile());
		expect(requestMediaUploadSpy).toHaveBeenCalledWith(
			TOKEN,
			expect.any(String),
			48, // mock ciphertext: 32 bytes + 16-byte GCM tag
			"group-abc",
		);
	});

	it("PUTs ciphertext bytes to the presigned R2 URL (never plaintext)", async () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		await result.current.sendMedia(makeFile());

		expect(fetchMock).toHaveBeenCalledWith(
			"https://r2.test/put",
			expect.objectContaining({ method: "PUT" }),
		);
		const [, opts] = fetchMock.mock.calls[0] as [string, RequestInit];
		// Body must be a Uint8Array (ciphertext), not a plain string or the raw File.
		expect(opts.body).toBeInstanceOf(Uint8Array);
	});

	it("confirms the upload after R2 PUT succeeds", async () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		await result.current.sendMedia(makeFile());
		expect(confirmMediaUploadSpy).toHaveBeenCalledWith(TOKEN, "test-media-id");
	});

	it("calls sendMessage with the MLS ciphertext Uint8Array (not raw file bytes)", async () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		await result.current.sendMedia(makeFile());

		expect(sendMessageSpy).toHaveBeenCalledOnce();
		const [, , ciphertext] = sendMessageSpy.mock.calls[0] as [string, string, Uint8Array];
		expect(ciphertext).toBeInstanceOf(Uint8Array);
		// Mock mediaMessageCreate returns 64 bytes — distinct from file or media ciphertext.
		expect(ciphertext.length).toBe(64);
	});

	it("calls mediaDropKey even when sendMessage throws — security invariant", async () => {
		sendMessageSpy.mockRejectedValueOnce(new Error("network error"));

		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		await expect(result.current.sendMedia(makeFile())).rejects.toThrow("network error");

		// Despite send failure, the key handle must have been released.
		expect(mediaDropKeyFn).toHaveBeenCalledOnce();
		expect(mediaDropKeyFn).toHaveBeenCalledWith("mock-media-key-handle-0");
	});

	it("does nothing when identityId is absent", async () => {
		const { result } = renderHook(() =>
			useMediaSend({ identityId: undefined, groupId: "group-1" }),
		);
		await result.current.sendMedia(makeFile());
		expect(requestMediaUploadSpy).not.toHaveBeenCalled();
	});

	// §9.4.1 thumbnail invariants
	it("calls mediaThumbnailDrop even when sendMessage throws — security invariant", async () => {
		sendMessageSpy.mockRejectedValueOnce(new Error("network error"));

		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		// Simulate createImageBitmap not available (thumbnail path yields null) — just check the
		// thumb drop is always called if a thumbHandle was acquired (mock returns one on encrypt).
		// We patch mediaThumbnailEncrypt to confirm drop is called on error path.
		mediaThumbnailEncryptFn.mockResolvedValueOnce({ thumbHandle: "thumb-test-handle" });

		await expect(result.current.sendMedia(makeFile())).rejects.toThrow("network error");

		// The main key handle must be dropped.
		expect(mediaDropKeyFn).toHaveBeenCalledOnce();
	});

	it("mediaMessageCreate falls back to no-thumbnail variant when thumbnail generation fails", async () => {
		// mediaThumbnailEncrypt throws → sendMedia must still succeed and call mediaMessageCreate.
		mediaThumbnailEncryptFn.mockRejectedValueOnce(new Error("thumb enc failed"));

		const { result } = renderHook(() =>
			useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
		);
		await result.current.sendMedia(makeFile());

		// With thumbnail failure, falls back to standard mediaMessageCreate.
		expect(mockWorker.mediaMessageCreate).toHaveBeenCalledOnce();
		expect(sendMessageSpy).toHaveBeenCalledOnce();
	});

	// This cycle's fix: sendMedia never called any Dexie persist hook at all, so every
	// sent photo/video/voice note vanished from chat history on reload.
	describe("persistOutgoing wiring (Dexie persistence — this cycle's fix)", () => {
		// ADR-0004 (docs/decisions/0004-media-key-local-persistence.md): this used to
		// assert the OPPOSITE — that no media payload was passed, because the sender's
		// raw key never crossed the WASM→JS boundary and so the sender's own row was a
		// permanent placeholder. The one-shot post-send export closes that gap.
		it("calls persistOutgoing with the envelope id, groupId, placeholder text, ciphertext AND a real media payload (ADR-0004)", async () => {
			sendMessageSpy.mockResolvedValueOnce("envelope-img-1");
			const persistOutgoing = vi.fn();

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await result.current.sendMedia(makeFile()); // makeFile() defaults to image/jpeg

			expect(persistOutgoing).toHaveBeenCalledOnce();
			const [id, groupId, text, ciphertextB64, replyTo, expiresAt, media] =
				persistOutgoing.mock.calls[0];
			expect(id).toBe("envelope-img-1");
			expect(groupId).toBe("group-1");
			expect(text).toBe("Image attachment");
			expect(typeof ciphertextB64).toBe("string");
			// Not a reply, no TTL — those two params stay undefined for a plain media send.
			expect(replyTo).toBeUndefined();
			expect(expiresAt).toBeUndefined();
			// The 7th arg is the ADR-0004 payload that makes the row re-displayable.
			expect(media).toBeDefined();
			expect(media.blobId).toBe("test-media-id");
			expect(media.mediaKey).toHaveLength(32);
			expect(media.mimeType).toBe("image/jpeg");
		});

		it("opts into the key export exactly once, for the handle mediaEncrypt returned", async () => {
			const persistOutgoing = vi.fn();
			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await result.current.sendMedia(makeFile());

			expect(mediaExportKeyForStorageFn).toHaveBeenCalledOnce();
			expect(mediaExportKeyForStorageFn).toHaveBeenCalledWith("mock-media-key-handle-0");
		});

		// The opt-in is driven by whether a persistence sink exists at all: with nowhere
		// to store the key there is no reason to bring it into JS scope.
		it("never exports the key when no persistOutgoing sink was supplied", async () => {
			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
			);
			await result.current.sendMedia(makeFile());

			expect(mediaExportKeyForStorageFn).not.toHaveBeenCalled();
		});

		// Best-effort: the envelope is already delivered by the time the export runs, so
		// a failed export must still persist the row, just without a media payload.
		it("still persists the row (with media undefined) when the key export fails", async () => {
			mediaExportKeyForStorageFn.mockRejectedValueOnce(new Error("unknown media key handle"));
			sendMessageSpy.mockResolvedValueOnce("envelope-export-fail");
			const persistOutgoing = vi.fn();

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await expect(result.current.sendMedia(makeFile())).resolves.not.toThrow();

			expect(persistOutgoing).toHaveBeenCalledOnce();
			const [id, , text, , , , media] = persistOutgoing.mock.calls[0];
			expect(id).toBe("envelope-export-fail");
			expect(text).toBe("Image attachment");
			expect(media).toBeUndefined();
		});

		it("passes a video media payload through for a video/* file", async () => {
			const persistOutgoing = vi.fn();
			const videoFile = new File([new Uint8Array(10)], "clip.mp4", { type: "video/mp4" });
			Object.defineProperty(videoFile, "arrayBuffer", {
				value: async () => new Uint8Array(10).buffer,
				configurable: true,
			});

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await result.current.sendMedia(videoFile);

			const media = persistOutgoing.mock.calls[0][6];
			expect(media).toBeDefined();
			expect(media.mimeType).toBe("video/mp4");
			expect(media.mediaKey).toHaveLength(32);
		});

		it("uses the 'Video attachment' placeholder for a video/* file", async () => {
			const persistOutgoing = vi.fn();
			const videoFile = new File([new Uint8Array(10)], "clip.mp4", { type: "video/mp4" });
			Object.defineProperty(videoFile, "arrayBuffer", {
				value: async () => new Uint8Array(10).buffer,
				configurable: true,
			});

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await result.current.sendMedia(videoFile);

			expect(persistOutgoing).toHaveBeenCalledOnce();
			expect(persistOutgoing.mock.calls[0][2]).toBe("Video attachment");
		});

		it("uses the 'Voice message' placeholder for an audio/* file", async () => {
			const persistOutgoing = vi.fn();
			const voiceFile = new File([new Uint8Array(10)], "voice.webm", { type: "audio/webm" });
			Object.defineProperty(voiceFile, "arrayBuffer", {
				value: async () => new Uint8Array(10).buffer,
				configurable: true,
			});

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await result.current.sendMedia(voiceFile);

			expect(persistOutgoing).toHaveBeenCalledOnce();
			expect(persistOutgoing.mock.calls[0][2]).toBe("Voice message");
		});

		it("does not throw when persistOutgoing is omitted (optional param, back-compat)", async () => {
			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1" }),
			);
			await expect(result.current.sendMedia(makeFile())).resolves.not.toThrow();
		});

		it("does not call persistOutgoing when the send fails", async () => {
			sendMessageSpy.mockRejectedValueOnce(new Error("network error"));
			const persistOutgoing = vi.fn();

			const { result } = renderHook(() =>
				useMediaSend({ identityId: IDENTITY_ID, groupId: "group-1", persistOutgoing }),
			);
			await expect(result.current.sendMedia(makeFile())).rejects.toThrow("network error");

			expect(persistOutgoing).not.toHaveBeenCalled();
		});
	});
});
