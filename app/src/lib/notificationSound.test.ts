/**
 * Notification sound synthesis — Web Audio API, no binary assets.
 * jsdom has no native AudioContext, so most environments here exercise the
 * "unavailable" no-op path by default; a handful of tests install a minimal
 * mock AudioContext to verify the synthesis path calls the expected nodes.
 *
 * The module keeps a lazily-created, reused AudioContext at module scope, so
 * tests that need to observe fresh node-creation calls per mock install use
 * `vi.resetModules()` + a dynamic re-import to get an isolated module instance
 * instead of reusing a cached context from a previous test.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	NOTIFICATION_SOUNDS,
	NOTIFICATION_SOUND_LABELS,
	type NotificationSoundId,
	playNotificationSound,
} from "./notificationSound";

/** Minimal mock AudioContext — records node creation without producing real audio. */
function installMockAudioContext() {
	const oscillators: Array<{
		type: string;
		frequency: { setValueAtTime: ReturnType<typeof vi.fn> };
		connect: ReturnType<typeof vi.fn>;
		disconnect: ReturnType<typeof vi.fn>;
		start: ReturnType<typeof vi.fn>;
		stop: ReturnType<typeof vi.fn>;
		onended: (() => void) | null;
	}> = [];

	const createOscillator = vi.fn(() => {
		const osc = {
			type: "sine",
			frequency: { setValueAtTime: vi.fn() },
			connect: vi.fn(),
			disconnect: vi.fn(),
			start: vi.fn(),
			stop: vi.fn(),
			onended: null as (() => void) | null,
		};
		oscillators.push(osc);
		return osc;
	});
	const createGain = vi.fn(() => ({
		gain: {
			setValueAtTime: vi.fn(),
			linearRampToValueAtTime: vi.fn(),
			exponentialRampToValueAtTime: vi.fn(),
		},
		connect: vi.fn(),
		disconnect: vi.fn(),
	}));

	class MockAudioContext {
		state = "running";
		currentTime = 0;
		destination = {};
		createOscillator = createOscillator;
		createGain = createGain;
		resume = vi.fn(async () => {});
	}

	// biome-ignore lint/suspicious/noExplicitAny: test-only global patch
	(window as any).AudioContext = MockAudioContext;
	return { createOscillator, createGain, oscillators };
}

function uninstallMockAudioContext() {
	// biome-ignore lint/suspicious/noExplicitAny: test-only global patch
	(window as any).AudioContext = undefined;
}

/** Re-imports notificationSound.ts as a fresh module instance (isolated `sharedCtx`). */
async function freshModule() {
	vi.resetModules();
	return import("./notificationSound");
}

describe("notification sound catalog", () => {
	it("includes exactly the expected sound ids", () => {
		expect(NOTIFICATION_SOUNDS).toEqual(["default", "chime", "pop", "none"]);
	});

	it("includes a 'none' silent option", () => {
		expect(NOTIFICATION_SOUNDS).toContain("none");
	});

	it("has a human-readable label for every catalog entry", () => {
		for (const id of NOTIFICATION_SOUNDS) {
			expect(NOTIFICATION_SOUND_LABELS[id]).toBeTruthy();
			expect(typeof NOTIFICATION_SOUND_LABELS[id]).toBe("string");
		}
	});
});

describe("playNotificationSound — no AudioContext available", () => {
	afterEach(() => {
		uninstallMockAudioContext();
	});

	it("does not throw for any catalog entry when Web Audio is unavailable", () => {
		uninstallMockAudioContext();
		for (const id of NOTIFICATION_SOUNDS) {
			expect(() => playNotificationSound(id)).not.toThrow();
		}
	});

	it("'none' does not throw and is a no-op with no AudioContext", () => {
		uninstallMockAudioContext();
		expect(() => playNotificationSound("none")).not.toThrow();
	});
});

describe("playNotificationSound — AudioContext available", () => {
	afterEach(() => {
		uninstallMockAudioContext();
		vi.restoreAllMocks();
		vi.resetModules();
	});

	it("'none' never constructs oscillator/gain nodes", async () => {
		const mod = await freshModule();
		const { createOscillator, createGain } = installMockAudioContext();
		mod.playNotificationSound("none");
		expect(createOscillator).not.toHaveBeenCalled();
		expect(createGain).not.toHaveBeenCalled();
	});

	it.each(["default", "chime", "pop"] as NotificationSoundId[])(
		"'%s' creates at least one oscillator + gain node and starts playback",
		async (id) => {
			const mod = await freshModule();
			const { createOscillator, createGain, oscillators } = installMockAudioContext();
			mod.playNotificationSound(id);
			expect(createOscillator).toHaveBeenCalled();
			expect(createGain).toHaveBeenCalled();
			for (const osc of oscillators) {
				expect(osc.start).toHaveBeenCalled();
				expect(osc.connect).toHaveBeenCalled();
			}
		},
	);

	it("distinct sound ids produce distinct note counts (each sound is audibly distinct)", async () => {
		const noteCountFor = async (id: NotificationSoundId) => {
			const mod = await freshModule();
			const { oscillators } = installMockAudioContext();
			mod.playNotificationSound(id);
			return oscillators.length;
		};
		expect(await noteCountFor("default")).toBe(2);
		expect(await noteCountFor("chime")).toBe(3);
		expect(await noteCountFor("pop")).toBe(1);
	});

	it("does not throw when AudioContext construction fails", async () => {
		const mod = await freshModule();
		class ThrowingAudioContext {
			constructor() {
				throw new Error("denied");
			}
		}
		// biome-ignore lint/suspicious/noExplicitAny: test-only global patch
		(window as any).AudioContext = ThrowingAudioContext;
		expect(() => mod.playNotificationSound("default")).not.toThrow();
	});
});
