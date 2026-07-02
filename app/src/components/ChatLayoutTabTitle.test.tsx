import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
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

// Jordan's chat has unread: 2 in SEED_CHATS; Maya is active on load.
const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — browser tab title unread badge", () => {
	let captureOnMessage: ((msg: IncomingMessage) => void) | null = null;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			captureOnMessage = onMsg;
		});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		captureOnMessage = null;
		document.title = "Powehi";
	});

	it("shows unread count in tab title on initial render when Jordan has unread: 2", () => {
		render(<ChatLayout />);
		expect(document.title).toBe("(2) Powehi");
	});

	it("tab title reflects only numeric unread count from seed", () => {
		render(<ChatLayout />);
		expect(document.title).toMatch(/^\(\d+\) Powehi$/);
	});

	it("increments tab title when a background chat receives a new message", async () => {
		render(<ChatLayout />);
		// Maya is active; Jordan starts with unread:2 → title (2).
		// Switch to Jordan so Maya becomes background.
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		// Now send a message to Maya (background).
		await act(async () => {
			captureOnMessage?.({
				id: "tab-title-bg",
				senderId: "device-tt-1",
				groupId: MAYA_GROUP_ID,
				text: "background msg",
				ciphertextB64: "dGVzdA==",
				epochSeq: 1,
			});
		});
		// Jordan unread cleared on first visit (→0); Maya gets +1 → total 1.
		expect(document.title).toBe("(1) Powehi");
	});

	it("resets tab title to 'Powehi' when mark-all-read is clicked", () => {
		render(<ChatLayout />);
		expect(document.title).toBe("(2) Powehi");
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		expect(document.title).toBe("Powehi");
	});

	it("resets tab title when switching to the unread chat clears its badge", () => {
		render(<ChatLayout />);
		// Jordan has unread:2 → (2) Powehi
		expect(document.title).toBe("(2) Powehi");
		// First visit to Jordan: badge is cleared (but divider may stay).
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		// Jordan's unread becomes 0 → title resets
		expect(document.title).toBe("Powehi");
	});

	it("stays 'Powehi' when active chat receives a message (no badge increment)", async () => {
		render(<ChatLayout />);
		// Clear Jordan's badge first.
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		expect(document.title).toBe("Powehi");
		// Send a message to Maya (active) — no unread increment.
		await act(async () => {
			captureOnMessage?.({
				id: "tab-title-active",
				senderId: "device-tt-2",
				groupId: MAYA_GROUP_ID,
				text: "active msg",
				ciphertextB64: "dGVzdA==",
				epochSeq: 2,
			});
		});
		expect(document.title).toBe("Powehi");
	});

	it("tab title is restored to 'Powehi' on component unmount", () => {
		const { unmount } = render(<ChatLayout />);
		expect(document.title).toBe("(2) Powehi");
		unmount();
		expect(document.title).toBe("Powehi");
	});

	it("accumulates badge from multiple background chats", async () => {
		render(<ChatLayout />);
		// Maya active. Jordan unread:2 already. Send message to Jordan (background).
		await act(async () => {
			captureOnMessage?.({
				id: "tab-title-multi",
				senderId: "device-tt-3",
				groupId: JORDAN_GROUP_ID,
				text: "extra msg to Jordan",
				ciphertextB64: "dGVzdA==",
				epochSeq: 3,
			});
		});
		// Jordan: 2 + 1 = 3; title = (3)
		expect(document.title).toBe("(3) Powehi");
	});

	it("title reverts to plain count after clearing individual chat unread", () => {
		render(<ChatLayout />);
		expect(document.title).toBe("(2) Powehi");
		// Simulate Jordan is already active (default active is Maya).
		// Switch to Jordan → first visit clears badge.
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		expect(document.title).toBe("Powehi");
		// Switch back to Maya — nothing unread left.
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		expect(document.title).toBe("Powehi");
	});
});
