/**
 * Per-chat notification sound synthesis — pure Web Audio API, no binary assets.
 *
 * Each sound is a short tone (or short note sequence) synthesized on demand via
 * OscillatorNode + GainNode with a quick attack/decay envelope (avoids clicks/
 * pops). No fetch, no bundled audio files, no third-party audio library.
 *
 * Callers only ever pass an opaque `NotificationSoundId` — never message
 * content or sender identity (no-plaintext-logging.md applies to this call
 * site too, even though it isn't logging: nothing content-bearing crosses in).
 */

/** Fixed catalog of selectable notification sounds. "none" is a silent no-op. */
export const NOTIFICATION_SOUNDS = ["default", "chime", "pop", "none"] as const;

export type NotificationSoundId = (typeof NOTIFICATION_SOUNDS)[number];

/** Human-readable labels for the sound picker UI. */
export const NOTIFICATION_SOUND_LABELS: Record<NotificationSoundId, string> = {
	default: "Default",
	chime: "Chime",
	pop: "Pop",
	none: "None",
};

/** A single synthesized note: frequency (Hz), start offset (s), duration (s), waveform. */
interface Note {
	freq: number;
	start: number;
	duration: number;
	type: OscillatorType;
}

/** Note sequences per sound id (excluding "none", which never synthesizes anything). */
const SOUND_NOTES: Record<Exclude<NotificationSoundId, "none">, Note[]> = {
	// Clean two-note rising blip.
	default: [
		{ freq: 660, start: 0, duration: 0.09, type: "sine" },
		{ freq: 880, start: 0.09, duration: 0.12, type: "sine" },
	],
	// Soft three-note bell-like arpeggio.
	chime: [
		{ freq: 523.25, start: 0, duration: 0.14, type: "triangle" },
		{ freq: 659.25, start: 0.08, duration: 0.14, type: "triangle" },
		{ freq: 783.99, start: 0.16, duration: 0.2, type: "triangle" },
	],
	// Single short, low percussive blip.
	pop: [{ freq: 220, start: 0, duration: 0.06, type: "square" }],
};

// Lazily created, reused AudioContext. Created on first playback attempt (not at
// import time) so we never trigger a browser autoplay-policy warning on load,
// and so environments without Web Audio (SSR, jsdom, older browsers) never pay
// for — or fail on — construction until a sound actually needs to play.
let sharedCtx: AudioContext | null = null;

function getAudioContext(): AudioContext | null {
	if (typeof window === "undefined") return null;
	const Ctor =
		window.AudioContext ??
		(window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
	if (!Ctor) return null;
	if (sharedCtx && sharedCtx.state !== "closed") return sharedCtx;
	try {
		sharedCtx = new Ctor();
		return sharedCtx;
	} catch {
		return null;
	}
}

/**
 * Play a short synthesized tone for `soundId`. No-op for `"none"` and in any
 * environment without Web Audio support. Never throws — a failed or unavailable
 * playback must never interrupt message handling.
 */
export function playNotificationSound(soundId: NotificationSoundId): void {
	if (soundId === "none") return;
	const ctx = getAudioContext();
	if (!ctx) return;

	try {
		if (ctx.state === "suspended") {
			void ctx.resume().catch(() => {});
		}
		const now = ctx.currentTime;
		for (const note of SOUND_NOTES[soundId]) {
			const osc = ctx.createOscillator();
			const gain = ctx.createGain();
			osc.type = note.type;
			osc.frequency.setValueAtTime(note.freq, now + note.start);

			// Quick attack/decay envelope — avoids the click/pop of a hard on/off edge.
			const attackEnd = now + note.start + Math.min(0.01, note.duration / 4);
			const noteEnd = now + note.start + note.duration;
			gain.gain.setValueAtTime(0, now + note.start);
			gain.gain.linearRampToValueAtTime(0.2, attackEnd);
			gain.gain.exponentialRampToValueAtTime(0.0001, noteEnd);

			osc.connect(gain);
			gain.connect(ctx.destination);
			osc.start(now + note.start);
			osc.stop(noteEnd + 0.02);
			osc.onended = () => {
				osc.disconnect();
				gain.disconnect();
			};
		}
	} catch {
		// Synthesis failure must never propagate into the message-handling path.
	}
}
