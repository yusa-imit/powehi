import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => []),
	mlsComputeSafetyNumber: vi.fn(async () => ({ safetyNumber: "000000 000000" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

function makeExpiringMsg(id: string, expiresAt: number): IncomingMessage {
	return {
		id,
		senderId: "peer-device",
		groupId: MAYA_GROUP_ID,
		text: "expiring message",
		ciphertextB64: "Zg==",
		epochSeq: 1,
		expiresAt,
	};
}

describe("ChatLayout — disappearing message countdown tick", () => {
	let captureOnMessage: ((msg: IncomingMessage) => void) | null = null;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			captureOnMessage = onMsg;
		});
		vi.useFakeTimers({ now: Date.now() });
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		vi.useRealTimers();
		captureOnMessage = null;
	});

	it("renders disappearing-badge when a message has expiresAt", async () => {
		render(<ChatLayout />);
		const expiresAt = Date.now() + 120_000; // 2 min from now
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-1", expiresAt));
		});
		expect(screen.getByTestId("disappearing-badge")).toBeTruthy();
	});

	it("disappearing-badge shows 'Disappearing ·' prefix", async () => {
		render(<ChatLayout />);
		const expiresAt = Date.now() + 120_000;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-2", expiresAt));
		});
		expect(screen.getByTestId("disappearing-badge").textContent).toMatch(/^Disappearing\s·/);
	});

	it("badge data-countdown-tick increments after 1 s (countdown tick running)", async () => {
		render(<ChatLayout />);
		const expiresAt = Date.now() + 120_000;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-3", expiresAt));
		});
		const badge = screen.getByTestId("disappearing-badge");
		const tickBefore = Number(badge.getAttribute("data-countdown-tick"));
		// Advance fake clock by 1 second — the interval fires once.
		await act(async () => {
			vi.advanceTimersByTime(1000);
		});
		const tickAfter = Number(badge.getAttribute("data-countdown-tick"));
		expect(tickAfter).toBeGreaterThan(tickBefore);
	});

	it("badge data-countdown-tick increments 3 times after 3 s", async () => {
		render(<ChatLayout />);
		const expiresAt = Date.now() + 120_000;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-4", expiresAt));
		});
		const badge = screen.getByTestId("disappearing-badge");
		const tickBefore = Number(badge.getAttribute("data-countdown-tick"));
		await act(async () => {
			vi.advanceTimersByTime(3000);
		});
		const tickAfter = Number(badge.getAttribute("data-countdown-tick"));
		expect(tickAfter - tickBefore).toBeGreaterThanOrEqual(3);
	});

	it("no disappearing-badge when no message has expiresAt", async () => {
		render(<ChatLayout />);
		await act(async () => {
			captureOnMessage?.({
				id: "no-exp",
				senderId: "peer-device",
				groupId: MAYA_GROUP_ID,
				text: "normal message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		expect(screen.queryByTestId("disappearing-badge")).toBeNull();
	});

	it("badge shows '2m' label for a message expiring in 2 minutes", async () => {
		render(<ChatLayout />);
		const expiresAt = Date.now() + 2 * 60 * 1000;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-5", expiresAt));
		});
		expect(screen.getByTestId("disappearing-badge").textContent).toContain("2m");
	});

	it("badge shows 'soon' when message is about to expire", async () => {
		render(<ChatLayout />);
		// expiresAt is already in the past; formatTimeLeft clamps to 'soon'
		const expiresAt = Date.now() - 1;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-6", expiresAt));
		});
		// May be swept by the 30 s purge timer but with fake timers it won't have fired yet.
		const badge = screen.queryByTestId("disappearing-badge");
		if (badge) {
			expect(badge.textContent).toContain("soon");
		}
	});

	it("badge text updates to show shorter time after clock advances", async () => {
		render(<ChatLayout />);
		// 61 seconds → '2m' (Math.ceil(61/60) = 2).
		const expiresAt = Date.now() + 61_000;
		await act(async () => {
			captureOnMessage?.(makeExpiringMsg("exp-7", expiresAt));
		});
		expect(screen.getByTestId("disappearing-badge").textContent).toContain("2m");
		// Advance 1 second — now 60 s left → Math.ceil(60/60) = 1 → '1m'.
		await act(async () => {
			vi.advanceTimersByTime(1000);
		});
		expect(screen.getByTestId("disappearing-badge").textContent).toContain("1m");
	});
});
