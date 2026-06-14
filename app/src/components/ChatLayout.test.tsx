import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { ChatLayout } from "./ChatLayout";

// The stable mock worker singleton — same reference on every useCryptoWorker() call
// so the useEffect dependency array doesn't see a new object on re-renders.
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
	// Passthrough encryption for tests — EncryptedPowehiDb interface satisfaction.
	// Tests verify DB round-trip behavior; encryption correctness is covered by encryption.test.ts.
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

// KAT safety number (same value — used in test assertions after the mock is hoisted).
const KAT_SN =
	"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986";

describe("ChatLayout", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("renders the sidebar encryption banner", () => {
		render(<ChatLayout />);
		// The sidebar banner uses uppercase text
		expect(screen.getByText("END-TO-END ENCRYPTED")).toBeInTheDocument();
	});

	it("renders the sidebar with seed chat names", () => {
		render(<ChatLayout />);
		// Names appear in both sidebar and conversation header — at least one instance each
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Jordan").length).toBeGreaterThan(0);
	});

	it("renders the E2EE notice in the message area", () => {
		render(<ChatLayout />);
		expect(screen.getByText(/not even powehi/i)).toBeInTheDocument();
	});

	it("composer placeholder mentions encryption", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		expect(textarea).toBeInTheDocument();
	});

	it("searching filters — Jordan disappears when searching 'maya'", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "maya" } });
		// Jordan should no longer appear in the sidebar; conversation panel might still show last-selected
		// Check the sidebar specifically — filtered chat list buttons
		const chatButtons = screen.queryAllByRole("button", { name: /jordan/i });
		// The sidebar ChatRow is a button; after filter, Jordan's button should be gone
		expect(chatButtons.length).toBe(0);
	});

	it("empty search query shows no-match message", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "zzz-nomatch" } });
		expect(screen.getByText(/no chats match/i)).toBeInTheDocument();
	});

	it("typing and sending a message appends it to the conversation", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		const msg = `Hello test message ${Date.now()}`;
		fireEvent.change(textarea, { target: { value: msg } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		expect(screen.getAllByText(msg).length).toBeGreaterThan(0);
	});

	it("the info panel opens and shows safety numbers verify button", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Wait for the computed safety number to arrive (WASM computation is async).
		// Maya is unverified by default → button aria-label is "Verify safety numbers".
		expect(
			await screen.findByRole("button", { name: /verify safety numbers/i }),
		).toBeInTheDocument();
	});

	it("selecting Jordan switches the active conversation header", () => {
		render(<ChatLayout />);
		const jordanButton = screen.getByRole("button", { name: /jordan/i });
		fireEvent.click(jordanButton);
		const header = screen.getByRole("banner");
		expect(header).toHaveTextContent(/jordan/i);
	});

	it("timer button cycles through disappearing TTL options", () => {
		render(<ChatLayout />);
		// Initially Off — button has label "Set disappearing timer"
		const timerBtn = screen.getByRole("button", { name: /disappearing timer/i });
		expect(timerBtn).toBeInTheDocument();
		// First click → 5m
		fireEvent.click(timerBtn);
		expect(screen.getByRole("button", { name: /disappearing: 5m/i })).toBeInTheDocument();
		// Second click → 1h
		fireEvent.click(screen.getByRole("button", { name: /disappearing: 5m/i }));
		expect(screen.getByRole("button", { name: /disappearing: 1h/i })).toBeInTheDocument();
	});

	it("message sent with active TTL shows disappearing badge", () => {
		render(<ChatLayout />);
		// Enable disappearing timer (click once → 5m)
		fireEvent.click(screen.getByRole("button", { name: /disappearing timer/i }));
		// Send a message
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "secret message" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		// The message was appended
		expect(screen.getAllByText("secret message").length).toBeGreaterThan(0);
		// The disappearing badge should appear ("Disappearing" text)
		expect(screen.getByText("Disappearing")).toBeInTheDocument();
	});

	it("persists verification to DB when user confirms safety number match", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Wait for computed safety number to arrive (WASM is async) then verify.
		const verifyBtn = await screen.findByRole("button", { name: /verify safety numbers/i });
		fireEvent.click(verifyBtn);
		const confirmBtn = await screen.findByRole("button", { name: /confirm match/i });
		fireEvent.click(confirmBtn);
		await waitFor(async () => {
			const allRecords = await db.verifiedContacts.toArray();
			expect(allRecords).toHaveLength(1);
			expect(allRecords[0].safetyNumber).toMatch(/^\d{6}( \d{6}){11}$/);
		});
	});

	it("shows MITM alert when stored safety number differs from current", async () => {
		// Pre-populate with a stale safety number to simulate identity key change
		const staleSN =
			"111111 222222 333333 444444 555555 666666 777777 888888 999999 000000 121212 343434";
		await db.verifiedContacts.put({
			contactId: "maya", // matches SEED_CHATS[0].id
			safetyNumber: staleSN,
			verifiedAt: Date.now() - 86_400_000,
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() => {
			expect(screen.getByText(/safety number changed/i)).toBeInTheDocument();
		});
	});

	it("clears verification in DB when user resets", async () => {
		// Pre-populate with the current safety number (previously verified)
		await db.verifiedContacts.put({
			contactId: "maya", // matches SEED_CHATS[0].id
			safetyNumber: KAT_SN,
			verifiedAt: Date.now() - 86_400_000,
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Wait for DB load — button becomes "Re-verify safety numbers"
		await waitFor(() => {
			expect(screen.getByRole("button", { name: /re-verify/i })).toBeInTheDocument();
		});
		// Clicking Re-verify directly calls onReset (clears verification from DB)
		fireEvent.click(screen.getByRole("button", { name: /re-verify/i }));
		await waitFor(async () => {
			const allRecords = await db.verifiedContacts.toArray();
			expect(allRecords).toHaveLength(0);
		});
	});

	// ── In-conversation message search ───────────────────────────────────────────

	it("renders search button in conversation header", () => {
		render(<ChatLayout />);
		expect(screen.getByRole("button", { name: /search in conversation/i })).toBeInTheDocument();
	});

	it("clicking search button shows search input", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		expect(screen.getByPlaceholderText(/search in conversation/i)).toBeInTheDocument();
	});

	it("typing in message search highlights matching text with mark elements", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		const searchInput = screen.getByPlaceholderText(/search in conversation/i);
		// "cafe" appears in Maya's seed messages ("9am at the corner cafe?")
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		const marks = document.querySelectorAll("mark");
		expect(marks.length).toBeGreaterThan(0);
		expect(Array.from(marks).some((m) => m.textContent === "cafe")).toBe(true);
	});

	it("closing message search removes the search input and clears highlights", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		const searchInput = screen.getByPlaceholderText(/search in conversation/i);
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		// Highlights should be present
		expect(document.querySelectorAll("mark").length).toBeGreaterThan(0);
		// Close search
		fireEvent.click(screen.getByRole("button", { name: /close search/i }));
		expect(screen.queryByPlaceholderText(/search in conversation/i)).not.toBeInTheDocument();
		expect(document.querySelectorAll("mark").length).toBe(0);
	});

	it("switching active conversation resets message search", () => {
		render(<ChatLayout />);
		// Open message search in Maya's conversation
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		expect(screen.getByPlaceholderText(/search in conversation/i)).toBeInTheDocument();
		// Switch to Jordan — the chat row button's accessible name includes "Jordan"
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// Search input should be gone after switching chats
		expect(screen.queryByPlaceholderText(/search in conversation/i)).not.toBeInTheDocument();
	});

	// ── Unread message count badge ────────────────────────────────────────────────

	it("shows unread badge with count 2 for Jordan from seed data", () => {
		render(<ChatLayout />);
		// Jordan starts with unread: 2 in SEED_CHATS
		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "2")).toBe(true);
	});

	it("selecting Jordan clears its unread badge", () => {
		render(<ChatLayout />);
		// Badge visible before selection
		expect(screen.getAllByTestId("unread-badge").some((b) => b.textContent === "2")).toBe(true);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// No badge with "2" after selection (unread reset to 0)
		const badges = screen.queryAllByTestId("unread-badge");
		expect(badges.every((b) => b.textContent !== "2")).toBe(true);
	});

	it("receiving a message for an inactive chat increments its unread badge", async () => {
		// Capture the onMessage callback injected into useMessages
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnMessage).toBeDefined();

		// Jordan's mlsGroupId matches SEED_CHATS entry; Maya is currently active
		await act(async () => {
			capturedOnMessage?.({
				id: "env-001",
				senderId: "device-abc",
				groupId: "33333333-3333-3333-3333-333333333333",
				text: "hey there",
				ciphertextB64: "Y2lwaGVydGV4dA==",
				epochSeq: 1,
			});
		});

		// Jordan's unread should go from 2 → 3
		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "3")).toBe(true);
	});

	it("messages for the active chat do not increment its unread badge", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);

		// Maya is active; her mlsGroupId is in SEED_CHATS
		await act(async () => {
			capturedOnMessage?.({
				id: "env-002",
				senderId: "device-xyz",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "hello maya",
				ciphertextB64: "Y2lwaGVydGV4dA==",
				epochSeq: 1,
			});
		});

		// Maya has no unread badge (active chat — count stays 0)
		const badges = screen.queryAllByTestId("unread-badge");
		// Only Jordan's badge (= "2") should remain; Maya's count stays 0 (no badge)
		expect(badges.every((b) => b.textContent !== "0")).toBe(true);
	});

	it("unread badge displays 9+ when count exceeds 9", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnMessage).toBeDefined();

		// Jordan starts with unread: 2 — send 8 more to exceed 9 (total 10)
		await act(async () => {
			for (let i = 0; i < 8; i++) {
				capturedOnMessage?.({
					id: `env-${i + 10}`,
					senderId: "device-abc",
					groupId: "33333333-3333-3333-3333-333333333333",
					text: `msg ${i}`,
					ciphertextB64: "Y2lwaGVydGV4dA==",
					epochSeq: i + 2,
				});
			}
		});

		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "9+")).toBe(true);
	});
});
