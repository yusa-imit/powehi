/**
 * useVoiceRecorder — capture a short voice message via the browser's
 * MediaRecorder API and hand back a plaintext `File` for the caller to
 * encrypt/send (e.g. via `useMediaSend`'s `sendMedia`).
 *
 * This hook does NOT touch crypto, IndexedDB, or the network — it is pure
 * Web Audio/MediaRecorder plumbing. The resulting File is handed to the
 * existing generic media-send pipeline exactly like a picked image/video.
 *
 * Privacy invariants:
 * - The captured MediaStream's tracks are ALWAYS stopped (`track.stop()`) on
 *   stop/cancel/unmount, so the browser's mic-in-use indicator reliably
 *   clears — never left dangling on an abandoned recording.
 * - No plaintext logging: audio bytes/blob contents are never logged, and
 *   caught errors are never logged with raw detail — `error` is set to a
 *   static, content-free category string only (no-plaintext-logging.md).
 */

import { useCallback, useEffect, useRef, useState } from "react";

// Preference order: opus-in-webm (best size/quality) → webm default →
// mp4 (Safari) → browser default (empty string tells MediaRecorder to pick).
const CANDIDATE_MIME_TYPES = ["audio/webm;codecs=opus", "audio/webm", "audio/mp4"];

function pickMimeType(): string {
	if (typeof MediaRecorder === "undefined" || typeof MediaRecorder.isTypeSupported !== "function") {
		return "";
	}
	for (const candidate of CANDIDATE_MIME_TYPES) {
		if (MediaRecorder.isTypeSupported(candidate)) return candidate;
	}
	return "";
}

function extFromMimeType(mimeType: string): string {
	if (mimeType.startsWith("audio/mp4")) return "mp4";
	return "webm";
}

export interface VoiceRecorderHook {
	/** True while a recording is in progress. */
	recording: boolean;
	/** Seconds elapsed since `startRecording` resolved; ticks once per second. */
	elapsedSec: number;
	/** Content-free error category (permission denied / unsupported), or null. */
	error: string | null;
	/** Request mic access and begin recording. Sets `error` instead of throwing. */
	startRecording: () => Promise<void>;
	/** Stop recording and resolve the captured audio as a File (null if nothing was captured). */
	stopRecording: () => Promise<File | null>;
	/** Stop recording and discard whatever was captured — no File is produced. */
	cancelRecording: () => void;
}

export function useVoiceRecorder(): VoiceRecorderHook {
	const [recording, setRecording] = useState(false);
	const [elapsedSec, setElapsedSec] = useState(0);
	const [error, setError] = useState<string | null>(null);

	const recorderRef = useRef<MediaRecorder | null>(null);
	const streamRef = useRef<MediaStream | null>(null);
	const chunksRef = useRef<BlobPart[]>([]);
	const mimeTypeRef = useRef<string>("");
	const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

	const clearTimer = useCallback(() => {
		if (intervalRef.current !== null) {
			clearInterval(intervalRef.current);
			intervalRef.current = null;
		}
	}, []);

	const stopStream = useCallback(() => {
		const tracks = streamRef.current?.getTracks() ?? [];
		for (const track of tracks) {
			track.stop();
		}
		streamRef.current = null;
	}, []);

	const startRecording = useCallback(async () => {
		setError(null);
		if (typeof navigator === "undefined" || !navigator.mediaDevices?.getUserMedia) {
			setError("Voice recording isn't supported in this browser.");
			return;
		}
		if (typeof MediaRecorder === "undefined") {
			setError("Voice recording isn't supported in this browser.");
			return;
		}
		let stream: MediaStream;
		try {
			stream = await navigator.mediaDevices.getUserMedia({ audio: true });
		} catch {
			// Permission denial / device-unavailable — category only, never the raw error.
			setError("Microphone access was denied.");
			return;
		}
		// Assigned before MediaRecorder construction so stopStream() in the catch
		// below can always release the mic (a construction throw, e.g. an
		// unsupported mimeType despite isTypeSupported() saying otherwise, must
		// not leave the browser's mic-in-use indicator on).
		streamRef.current = stream;
		try {
			const mimeType = pickMimeType();
			const recorder = mimeType
				? new MediaRecorder(stream, { mimeType })
				: new MediaRecorder(stream);
			mimeTypeRef.current = recorder.mimeType || mimeType || "audio/webm";
			chunksRef.current = [];
			recorder.ondataavailable = (ev: BlobEvent) => {
				if (ev.data && ev.data.size > 0) chunksRef.current.push(ev.data);
			};
			recorderRef.current = recorder;
			recorder.start();
			setElapsedSec(0);
			setRecording(true);
			clearTimer();
			intervalRef.current = setInterval(() => {
				setElapsedSec((s) => s + 1);
			}, 1000);
		} catch {
			setError("Voice recording isn't supported in this browser.");
			stopStream();
		}
	}, [clearTimer, stopStream]);

	const stopRecording = useCallback(async (): Promise<File | null> => {
		const recorder = recorderRef.current;
		clearTimer();
		setRecording(false);
		if (!recorder) {
			stopStream();
			return null;
		}
		if (recorder.state !== "inactive") {
			const stopped = new Promise<void>((resolve) => {
				recorder.onstop = () => resolve();
			});
			recorder.stop();
			await stopped;
		}
		stopStream();
		recorderRef.current = null;
		const chunks = chunksRef.current;
		chunksRef.current = [];
		if (chunks.length === 0) return null;
		const mimeType = mimeTypeRef.current || "audio/webm";
		const blob = new Blob(chunks, { type: mimeType });
		if (blob.size === 0) return null;
		const ext = extFromMimeType(mimeType);
		return new File([blob], `voice-message.${ext}`, { type: mimeType });
	}, [clearTimer, stopStream]);

	const cancelRecording = useCallback(() => {
		const recorder = recorderRef.current;
		clearTimer();
		setRecording(false);
		if (recorder) {
			// Discard: drop the handlers first so no late dataavailable/stop event
			// can resurrect the recording into a File after cancellation.
			recorder.ondataavailable = null;
			recorder.onstop = null;
			if (recorder.state !== "inactive") {
				recorder.stop();
			}
		}
		recorderRef.current = null;
		chunksRef.current = [];
		stopStream();
	}, [clearTimer, stopStream]);

	// Clean up a lingering recorder/stream/timer if the component unmounts
	// mid-recording (e.g. user navigates away without stopping/cancelling).
	useEffect(() => {
		return () => {
			clearTimer();
			const recorder = recorderRef.current;
			if (recorder) {
				recorder.ondataavailable = null;
				recorder.onstop = null;
				if (recorder.state !== "inactive") {
					recorder.stop();
				}
			}
			stopStream();
		};
	}, [clearTimer, stopStream]);

	return { recording, elapsedSec, error, startRecording, stopRecording, cancelRecording };
}
