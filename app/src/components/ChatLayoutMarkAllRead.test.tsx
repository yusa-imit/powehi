import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
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
};

// Jordan's chat has unread: 2 in SEED_CHATS — the button should be visible on load.
// Design Team has mentionCount: 2 in SEED_CHATS.
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — mark all as read", () => {
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

	it("mark-all-read button is visible on load because Jordan has unread: 2", () => {
		render(<ChatLayout />);
		expect(screen.getByRole("button", { name: /mark all as read/i })).toBeInTheDocument();
	});

	it("mark-all-read button has aria-label 'Mark all as read'", () => {
		render(<ChatLayout />);
		const btn = screen.getByRole("button", { name: /mark all as read/i });
		expect(btn).toHaveAttribute("aria-label", "Mark all as read");
	});

	it("clicking mark-all-read clears the Jordan unread badge", () => {
		render(<ChatLayout />);
		// Jordan starts with unread: 2 — its badge should be visible.
		const unreadBadges = screen.getAllByTestId("unread-badge");
		expect(unreadBadges.length).toBeGreaterThan(0);

		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		expect(screen.queryAllByTestId("unread-badge")).toHaveLength(0);
	});

	it("clicking mark-all-read hides the button itself (no more unread)", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		expect(screen.queryByRole("button", { name: /mark all as read/i })).not.toBeInTheDocument();
	});

	it("clicking mark-all-read clears mention badges", () => {
		render(<ChatLayout />);
		// Design Team has mentionCount: 2 — its @ badge should be visible.
		const mentionBadges = screen.getAllByTestId("mention-badge");
		expect(mentionBadges.length).toBeGreaterThan(0);

		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		expect(screen.queryAllByTestId("mention-badge")).toHaveLength(0);
	});

	it("mark-all-read button reappears after a new incoming message", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		// Clear all unread first.
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		expect(screen.queryByRole("button", { name: /mark all as read/i })).not.toBeInTheDocument();

		// Select Maya (the active chat with mlsGroupId matching incoming below).
		// We need to deliver to a BACKGROUND chat (Jordan) so unread increments.
		await act(async () => {
			capturedOnMessage?.({
				id: "mar-uuid-1001",
				senderId: "peer-device-mar",
				groupId: JORDAN_GROUP_ID,
				text: "New message after clearing",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		// Button should be visible again since Jordan now has unread: 1.
		expect(screen.getByRole("button", { name: /mark all as read/i })).toBeInTheDocument();
	});

	it("mark-all-read does not affect the active chat's messages", () => {
		render(<ChatLayout />);
		// Select Maya (active chat) — her conversation is rendered.
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));

		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		// Maya's messages should still be visible in the message list area.
		const bubbles = screen.getAllByTestId("message-bubble");
		expect(bubbles.length).toBeGreaterThan(0);
	});

	it("mark-all-read is a no-op when there are no unread messages", () => {
		render(<ChatLayout />);
		// Clear once — button disappears.
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		expect(screen.queryByRole("button", { name: /mark all as read/i })).not.toBeInTheDocument();
		// No crash or error — test simply passes.
	});

	it("Chats tab unread badge is cleared by mark-all-read", () => {
		render(<ChatLayout />);
		// Switch to the DMs (Chats) tab and verify Jordan's unread badge is visible.
		fireEvent.click(screen.getByTestId("filter-tab-dms"));
		expect(screen.getAllByTestId("unread-badge").length).toBeGreaterThan(0);

		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		expect(screen.queryAllByTestId("unread-badge")).toHaveLength(0);
	});

	it("Groups tab mention badge is cleared by mark-all-read", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-groups"));
		expect(screen.getAllByTestId("mention-badge").length).toBeGreaterThan(0);

		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		expect(screen.queryAllByTestId("mention-badge")).toHaveLength(0);
	});

	it("selecting a chat individually still works after mark-all-read", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));

		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.getByTestId("conversation-header-name")).toHaveTextContent("Jordan");
	});
});
