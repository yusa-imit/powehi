/**
 * useVoiceRecorder — unit tests.
 *
 * jsdom has no real MediaRecorder/getUserMedia, so both are stubbed here.
 * Covers: start→stop produces a File; cancel discards without producing a
 * File; permission-denied never throws and sets a content-free error;
 * captured track.stop() is always called; unmount mid-recording cleans up.
 */

import { act, renderHook, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useVoiceRecorder } from "./useVoiceRecorder";

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

type DataHandler = (ev: { data: Blob }) => void;
type StopHandler = () => void;

class MockMediaRecorder {
	static isTypeSupported = vi.fn((type: string) => type === "audio/webm;codecs=opus");
	static instances: MockMediaRecorder[] = [];
	static throwOnConstruct = false;

	stream: MockMediaStream;
	mimeType: string;
	state: "inactive" | "recording" = "inactive";
	ondataavailable: DataHandler | null = null;
	onstop: StopHandler | null = null;
	start = vi.fn(() => {
		this.state = "recording";
	});
	stop = vi.fn(() => {
		this.state = "inactive";
		// Real MediaRecorder fires a final dataavailable before stop.
		this.ondataavailable?.({ data: new Blob(["chunk"], { type: this.mimeType }) });
		this.onstop?.();
	});

	constructor(stream: MockMediaStream, options?: { mimeType?: string }) {
		if (MockMediaRecorder.throwOnConstruct) {
			// Real browsers can throw NotSupportedError even when isTypeSupported()
			// returned true for the chosen mimeType.
			throw new DOMException("mimeType not supported", "NotSupportedError");
		}
		this.stream = stream;
		this.mimeType = options?.mimeType ?? "";
		MockMediaRecorder.instances.push(this);
	}
}

let lastStream: MockMediaStream;
let lastTracks: MockMediaStreamTrack[];
let getUserMediaMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
	MockMediaRecorder.instances = [];
	MockMediaRecorder.throwOnConstruct = false;
	lastTracks = [new MockMediaStreamTrack(), new MockMediaStreamTrack()];
	lastStream = new MockMediaStream(lastTracks);
	getUserMediaMock = vi.fn(async () => lastStream);

	vi.stubGlobal("MediaRecorder", MockMediaRecorder);
	Object.defineProperty(global.navigator, "mediaDevices", {
		value: { getUserMedia: getUserMediaMock },
		configurable: true,
	});
});

afterEach(() => {
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
});

describe("useVoiceRecorder", () => {
	it("start then stop produces a File with the recorder's mimeType and a voice-message name", async () => {
		const { result } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await result.current.startRecording();
		});
		expect(result.current.recording).toBe(true);
		expect(getUserMediaMock).toHaveBeenCalledWith({ audio: true });

		let file: File | null = null;
		await act(async () => {
			file = await result.current.stopRecording();
		});

		expect(file).not.toBeNull();
		expect(file?.name).toBe("voice-message.webm");
		expect(file?.type).toBe("audio/webm;codecs=opus");
		expect(result.current.recording).toBe(false);
	});

	it("stop after start stops every captured track (mic indicator clears)", async () => {
		const { result } = renderHook(() => useVoiceRecorder());
		await act(async () => {
			await result.current.startRecording();
		});
		await act(async () => {
			await result.current.stopRecording();
		});
		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalledOnce();
		}
	});

	it("cancel discards the recording — no File produced, but tracks are stopped", async () => {
		const { result } = renderHook(() => useVoiceRecorder());
		await act(async () => {
			await result.current.startRecording();
		});

		act(() => {
			result.current.cancelRecording();
		});

		expect(result.current.recording).toBe(false);
		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalledOnce();
		}

		// Calling stopRecording afterwards (no active recorder) resolves null —
		// confirms cancel really discarded state rather than leaving it stoppable.
		let file: File | null = null;
		await act(async () => {
			file = await result.current.stopRecording();
		});
		expect(file).toBeNull();
	});

	it("permission-denied getUserMedia rejection never throws and sets a content-free error", async () => {
		getUserMediaMock.mockRejectedValueOnce(
			new DOMException("Permission denied", "NotAllowedError"),
		);
		const { result } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await expect(result.current.startRecording()).resolves.toBeUndefined();
		});

		expect(result.current.recording).toBe(false);
		expect(result.current.error).toBeTruthy();
		expect(result.current.error).not.toMatch(/NotAllowedError|Permission denied/);
	});

	it("stopRecording with nothing recorded resolves null", async () => {
		const { result } = renderHook(() => useVoiceRecorder());
		let file: File | null = null;
		await act(async () => {
			file = await result.current.stopRecording();
		});
		expect(file).toBeNull();
	});

	it("unmount mid-recording stops the interval and the captured stream", async () => {
		vi.useFakeTimers({ shouldAdvanceTime: true });
		const { result, unmount } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await result.current.startRecording();
		});

		unmount();

		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalledOnce();
		}

		// Advancing timers after unmount must not throw or resurrect state —
		// the interval was cleared as part of unmount cleanup.
		await act(async () => {
			vi.advanceTimersByTime(5000);
		});

		vi.useRealTimers();
	});

	it("stops the mic stream if MediaRecorder construction throws", async () => {
		MockMediaRecorder.throwOnConstruct = true;
		const { result } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await result.current.startRecording();
		});

		expect(result.current.recording).toBe(false);
		expect(result.current.error).toBeTruthy();
		for (const track of lastTracks) {
			expect(track.stop).toHaveBeenCalledOnce();
		}
	});

	it("falls back to browser-default MediaRecorder when no candidate mimeType is supported", async () => {
		MockMediaRecorder.isTypeSupported = vi.fn(() => false);
		const { result } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await result.current.startRecording();
		});

		expect(result.current.error).toBeNull();
		expect(MockMediaRecorder.instances).toHaveLength(1);
	});

	it("elapsedSec ticks upward once per second while recording", async () => {
		vi.useFakeTimers({ shouldAdvanceTime: true });
		const { result } = renderHook(() => useVoiceRecorder());

		await act(async () => {
			await result.current.startRecording();
		});
		expect(result.current.elapsedSec).toBe(0);

		await act(async () => {
			vi.advanceTimersByTime(2500);
		});

		await waitFor(() => expect(result.current.elapsedSec).toBeGreaterThanOrEqual(2));

		vi.useRealTimers();
	});
});
