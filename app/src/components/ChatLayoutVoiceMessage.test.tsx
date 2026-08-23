/**
 * Voice messages — record via mic button in Composer, send as a §9.2 media
 * attachment through the existing generic useMediaSend pipeline (mocked here
 * at the fetch/API boundary the same way useMediaSend.test.ts does).
 */
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as mediaApi from "../api/media";
import * as messagesApi from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => [
		{ leafIndex: 0, sigKeyHex: "aa".repeat(64) },
		{ leafIndex: 1, sigKeyHex: "bb".repeat(64) },
	]),
	mlsComputeSafetyNumber: vi.fn(async () => ({
		safetyNumber:
			"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986",
	})),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
	mediaEncrypt: vi.fn(async () => ({
		ciphertext: new Uint8Array(48),
		mediaKeyHandle: "mock-media-key-handle-0",
		iv: new Uint8Array(12),
		blobHash: new Uint8Array(32),
	})),
	mediaMessageCreate: vi.fn(async () => ({ ciphertext: new Uint8Array(64) })),
	mediaDropKey: vi.fn(async () => true),
	mediaThumbnailEncrypt: vi.fn(async () => ({ thumbHandle: "mock-thumb-handle-0" })),
	mediaThumbnailDrop: vi.fn(async () => true),
	mediaMessageCreateWithThumbnail: vi.fn(async () => ({ ciphertext: new Uint8Array(80) })),
};

class MockMediaStreamTrack {
	stop = vi.fn();
}

class MockMediaStream {
	private tracks: MockMediaStreamTrack[];
	constructor(tracks: MockMediaStreamTrack[]) {
		this.tracks = tracks;
	}
	getTracks() {
		return this.tracks;
	}
}

class MockMediaRecorder {
	static isTypeSupported = vi.fn((type: string) => type === "audio/webm;codecs=opus");
	stream: MockMediaStream;
	mimeType = "audio/webm;codecs=opus";
	state: "inactive" | "recording" = "inactive";
	ondataavailable: ((ev: { data: Blob }) => void) | null = null;
	onstop: (() => void) | null = null;
	start = vi.fn(() => {
		this.state = "recording";
	});
	stop = vi.fn(() => {
		this.state = "inactive";
		this.ondataavailable?.({ data: new Blob(["chunk"], { type: this.mimeType }) });
		this.onstop?.();
	});
	constructor(stream: MockMediaStream) {
		this.stream = stream;
	}
}

// jsdom does not implement Blob/File.arrayBuffer (see useMediaSend.test.ts) — sendMedia
// reads the recorded File via arrayBuffer(), so real File objects produced by
// useVoiceRecorder need this polyfilled once for this test file.
if (typeof Blob.prototype.arrayBuffer !== "function") {
	Blob.prototype.arrayBuffer = function (this: Blob) {
		return new Promise<ArrayBuffer>((resolve, reject) => {
			const reader = new FileReader();
			reader.onload = () => resolve(reader.result as ArrayBuffer);
			reader.onerror = () => reject(reader.error);
			reader.readAsArrayBuffer(this);
		});
	};
}

let lastTracks: MockMediaStreamTrack[];
let getUserMediaMock: ReturnType<typeof vi.fn>;

describe("ChatLayout — voice messages", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		// This cycle's fix wires sendMedia's persistOutgoing into the real Dexie
		// persistence path — a voice message sent in one test now durably lands in
		// db.messages (fake-indexeddb persists across tests within this file) and
		// would otherwise rehydrate into the next test's message list. Clear it,
		// same as ChatLayoutMediaGallery.test.tsx/ChatLayoutPoll.test.tsx already do.
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(mediaApi, "requestMediaUpload").mockResolvedValue({
			mediaId: "test-media-id",
			uploadUrl: "https://r2.test/put",
		});
		vi.spyOn(mediaApi, "confirmMediaUpload").mockResolvedValue(undefined);
		vi.spyOn(messagesApi, "sendMessage").mockResolvedValue("envelope-id-1");
		globalThis.fetch = vi.fn(async () => ({ ok: true, status: 200 })) as unknown as typeof fetch;
		useAuthStore.setState({ phase: "app", deviceId: "my-device", sessionToken: "test-token" });

		lastTracks = [new MockMediaStreamTrack()];
		getUserMediaMock = vi.fn(async () => new MockMediaStream(lastTracks));
		vi.stubGlobal("MediaRecorder", MockMediaRecorder);
		Object.defineProperty(global.navigator, "mediaDevices", {
			value: { getUserMedia: getUserMediaMock },
			configurable: true,
		});
	});

	afterEach(() => {
		cleanup();
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
	});

	it("shows a mic button when the composer is empty", () => {
		render(<ChatLayout />);
		expect(screen.getByRole("button", { name: "Voice" })).toBeInTheDocument();
	});

	it("clicking the mic button starts recording and shows the recording indicator", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: "Voice" }));

		await waitFor(() => {
			expect(screen.getByTestId("voice-recording-indicator")).toBeInTheDocument();
		});
		expect(screen.getByTestId("voice-elapsed")).toHaveTextContent("0:00");
		expect(screen.queryByRole("button", { name: "Voice" })).not.toBeInTheDocument();
	});

	it("clicking stop/send calls sendMedia (via onSendVoice) with a voice-message File", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: "Voice" }));
		await waitFor(() => screen.getByTestId("voice-recording-indicator"));

		await act(async () => {
			fireEvent.click(screen.getByRole("button", { name: "Send voice message" }));
		});

		// Recording UI is gone and the mic button is back.
		await waitFor(() => {
			expect(screen.getByRole("button", { name: "Voice" })).toBeInTheDocument();
		});
		// Every captured track was stopped (mic indicator clears).
		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalled();
		}
		// The optimistic placeholder bubble was posted (also mirrored in the sidebar preview).
		expect(screen.getAllByText("Voice message").length).toBeGreaterThan(0);
		// The generic send pipeline actually ran (R2 upload requested).
		await waitFor(() => {
			expect(mediaApi.requestMediaUpload).toHaveBeenCalled();
		});
	});

	it("clicking cancel discards the recording without sending", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: "Voice" }));
		await waitFor(() => screen.getByTestId("voice-recording-indicator"));

		fireEvent.click(screen.getByRole("button", { name: "Discard voice message" }));

		await waitFor(() => {
			expect(screen.getByRole("button", { name: "Voice" })).toBeInTheDocument();
		});
		expect(screen.queryAllByText("Voice message")).toHaveLength(0);
		expect(mediaApi.requestMediaUpload).not.toHaveBeenCalled();
		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalled();
		}
	});

	it("shows an inline error and does not crash when microphone permission is denied", async () => {
		getUserMediaMock.mockRejectedValueOnce(
			new DOMException("Permission denied", "NotAllowedError"),
		);
		render(<ChatLayout />);

		fireEvent.click(screen.getByRole("button", { name: "Voice" }));

		await waitFor(() => {
			expect(screen.getByTestId("voice-error-banner")).toBeInTheDocument();
		});
		// The composer is still usable — mic button is back, no crash.
		expect(screen.getByRole("button", { name: "Voice" })).toBeInTheDocument();
	});
});
