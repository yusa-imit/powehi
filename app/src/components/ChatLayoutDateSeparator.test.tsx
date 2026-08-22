import { act, cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { ChatLayout, getDayLabel } from "./ChatLayout";

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
};

// Maya's chat mlsGroupId — used for incoming message tests.
const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

// ── getDayLabel unit tests ────────────────────────────────────────────────────

describe("getDayLabel", () => {
	it("returns 'Today' for current timestamp", () => {
		expect(getDayLabel(Date.now())).toBe("Today");
	});

	it("returns 'Yesterday' for yesterday's timestamp", () => {
		const yesterday = Date.now() - 86_400_000;
		expect(getDayLabel(yesterday)).toBe("Yesterday");
	});

	it("returns a formatted date string for older timestamps", () => {
		const twoDaysAgo = Date.now() - 2 * 86_400_000;
		const label = getDayLabel(twoDaysAgo);
		// Should NOT be "Today" or "Yesterday"
		expect(label).not.toBe("Today");
		expect(label).not.toBe("Yesterday");
		// Should be a non-empty string
		expect(label.length).toBeGreaterThan(0);
	});

	it("two calls with the same date return the same label", () => {
		const ts = Date.now() - 5 * 86_400_000;
		expect(getDayLabel(ts)).toBe(getDayLabel(ts));
	});
});

// ── Integration tests ─────────────────────────────────────────────────────────

describe("ChatLayout — date separators", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("seed data shows 'Today' date separator in Maya's chat", async () => {
		render(<ChatLayout />);
		// Maya's chat is the first and is selected by default.
		const separators = screen.getAllByTestId("date-separator");
		const labels = separators.map((el) => el.textContent?.toLowerCase() ?? "");
		expect(labels.some((l) => l.includes("today"))).toBe(true);
	});

	it("seed data shows 'Yesterday' date separator in Maya's chat", () => {
		render(<ChatLayout />);
		const separators = screen.getAllByTestId("date-separator");
		const labels = separators.map((el) => el.textContent?.toLowerCase() ?? "");
		expect(labels.some((l) => l.includes("yesterday"))).toBe(true);
	});

	it("each day label appears at most once per distinct day in the list", () => {
		render(<ChatLayout />);
		const separators = screen.getAllByTestId("date-separator");
		const labels = separators.map((el) => el.textContent ?? "");
		const unique = new Set(labels);
		expect(labels.length).toBe(unique.size);
	});

	it("incoming message on same day as last message does not add a new date separator", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		const beforeCount = screen.getAllByTestId("date-separator").length;

		// Deliver a message to Maya's chat (active chat, mlsGroupId matches).
		await act(async () => {
			capturedOnMessage?.({
				id: "ds-uuid-same-day",
				senderId: "peer-device-ds",
				groupId: MAYA_GROUP_ID,
				text: "Hello same day",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		// The last seed message in Maya's chat already has day: "Today".
		// A new incoming message today should NOT add another "Today" separator.
		const afterCount = screen.getAllByTestId("date-separator").length;
		expect(afterCount).toBe(beforeCount);
	});

	it("date-separator elements have text content (not empty)", () => {
		render(<ChatLayout />);
		const separators = screen.getAllByTestId("date-separator");
		for (const sep of separators) {
			expect((sep.textContent ?? "").trim().length).toBeGreaterThan(0);
		}
	});

	it("date separators are ordered: Yesterday before Today", () => {
		render(<ChatLayout />);
		const separators = screen.getAllByTestId("date-separator");
		const labels = separators.map((el) => el.textContent?.toLowerCase() ?? "");
		const yIdx = labels.findIndex((l) => l.includes("yesterday"));
		const tIdx = labels.findIndex((l) => l.includes("today"));
		// Both should be present and Yesterday should come before Today.
		expect(yIdx).toBeGreaterThanOrEqual(0);
		expect(tIdx).toBeGreaterThanOrEqual(0);
		expect(yIdx).toBeLessThan(tIdx);
	});
});
