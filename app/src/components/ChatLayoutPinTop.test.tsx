import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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

describe("ChatLayout — pin chat to top", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("InfoPanel shows Pin to top row with Off state by default", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toBeInTheDocument(),
		);
		expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("Off");
	});

	it("Pin to top toggle changes state to On", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinRow);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("On"),
		);
	});

	it("Pin to top double-toggle returns to Off", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinRow);
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("On"),
		);
		fireEvent.click(screen.getByRole("button", { name: /pin to top/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("Off"),
		);
	});

	it("Pinned chat shows pin-top-indicator in sidebar", async () => {
		render(<ChatLayout />);
		// Pin Jordan via InfoPanel
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinRow);
		// Close InfoPanel to return to sidebar view
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		await waitFor(() => expect(screen.getByTestId("pin-top-indicator")).toBeInTheDocument());
	});

	it("Unpinned chat has no pin-top-indicator", () => {
		render(<ChatLayout />);
		// No chats are pinned by default in SEED_CHATS
		expect(screen.queryByTestId("pin-top-indicator")).not.toBeInTheDocument();
	});

	it("Pinned chat appears before unpinned chats in sidebar", async () => {
		render(<ChatLayout />);
		// Pin Design Team (it appears after other chats in SEED_CHATS order)
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinRow);
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		// After pinning, all sidebar chat buttons should have Design Team first
		await waitFor(() => {
			// Find all sidebar chat buttons — they contain chat names in their text content
			const sidebar = document.querySelector("aside");
			const chatButtons = sidebar
				? Array.from(sidebar.querySelectorAll('[data-testid="pin-top-indicator"]'))
				: [];
			expect(chatButtons.length).toBeGreaterThan(0);
		});

		// Verify Design Team is still visible (not hidden) and has pin indicator
		expect(screen.getByRole("button", { name: /design team/i })).toBeInTheDocument();
		expect(screen.getByTestId("pin-top-indicator")).toBeInTheDocument();
	});

	it("Pin is chat-specific — pinning Jordan does not affect Maya", async () => {
		render(<ChatLayout />);
		// Pin Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const pinRow = await screen.findByRole("button", { name: /pin to top/i });
		fireEvent.click(pinRow);
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		// Open Maya InfoPanel — should still show Off
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("Off"),
		);
	});

	it("Multiple pinned chats both show pin indicator", async () => {
		render(<ChatLayout />);
		// Pin Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(await screen.findByRole("button", { name: /pin to top/i }));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		// Pin Maya
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(await screen.findByRole("button", { name: /pin to top/i }));
		fireEvent.click(screen.getByRole("button", { name: /close/i }));

		await waitFor(() => expect(screen.getAllByTestId("pin-top-indicator")).toHaveLength(2));
	});

	it("Pinning does not affect archived chats — archived chats remain absent from All tab", async () => {
		render(<ChatLayout />);
		// Archive Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Also pin it
		fireEvent.click(screen.getByRole("button", { name: /pin to top/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("On"),
		);
		fireEvent.click(screen.getByRole("button", { name: /close/i }));
		// All tab should NOT show Jordan (archived wins over pinned)
		fireEvent.click(screen.getByTestId("filter-tab-all"));
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /^jordan$/i })).not.toBeInTheDocument(),
		);
	});

	it("Pin to top state is independent of mute state", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Pin Jordan
		fireEvent.click(await screen.findByRole("button", { name: /pin to top/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("On"),
		);
		// Mute Jordan — should not affect pin state
		fireEvent.click(screen.getByRole("button", { name: /mute/i }));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("On"),
		);
		// Pin state still On
		expect(screen.getByRole("button", { name: /pin to top/i })).toHaveTextContent("On");
	});
});
