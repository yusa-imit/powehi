import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
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
});
