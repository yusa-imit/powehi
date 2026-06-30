import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

function openInfoPanel(chatName: RegExp | string) {
	const chatBtn = screen.getAllByRole("button", { name: chatName })[0];
	fireEvent.click(chatBtn);
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
}

describe("ChatLayout — clear chat history", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("Clear messages button is visible in InfoPanel", () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		expect(screen.getByTestId("clear-messages-button")).toBeInTheDocument();
	});

	it("Clear messages button has correct text", () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		expect(screen.getByTestId("clear-messages-button")).toHaveTextContent("Clear messages");
	});

	it("Clicking Clear messages shows inline confirmation prompt", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		expect(screen.getByTestId("clear-messages-cancel")).toBeInTheDocument();
		expect(screen.getByTestId("clear-messages-confirm-btn")).toBeInTheDocument();
	});

	it("Confirmation prompt shows warning text", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		expect(screen.getByTestId("clear-messages-confirm")).toHaveTextContent(
			"Clear all messages?",
		);
	});

	it("Cancel button hides the confirmation prompt", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-cancel"));
		await waitFor(() =>
			expect(screen.queryByTestId("clear-messages-confirm")).not.toBeInTheDocument(),
		);
		// Original button should be back
		expect(screen.getByTestId("clear-messages-button")).toBeInTheDocument();
	});

	it("Cancel keeps chat messages intact", async () => {
		render(<ChatLayout />);
		// Jordan's seed messages should be visible
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.getByText("split for last night")).toBeInTheDocument();
		// Open InfoPanel and start clearing
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		// Cancel — messages must remain
		fireEvent.click(screen.getByTestId("clear-messages-cancel"));
		await waitFor(() =>
			expect(screen.queryByTestId("clear-messages-confirm")).not.toBeInTheDocument(),
		);
		expect(screen.getByText("split for last night")).toBeInTheDocument();
	});

	it("Confirming Clear removes all messages from the message list", async () => {
		render(<ChatLayout />);
		// Verify Jordan's messages are there
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.getByText("split for last night")).toBeInTheDocument();
		// Open InfoPanel, clear messages
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		await waitFor(() =>
			expect(screen.queryByText("split for last night")).not.toBeInTheDocument(),
		);
		expect(screen.queryByText("receipt.pdf")).not.toBeInTheDocument();
	});

	it("Unread badge is cleared after clearing messages", async () => {
		render(<ChatLayout />);
		// Jordan has 2 unread in seed data — badge should be visible
		const unreadBadge = () =>
			screen.queryByTestId("chat-unread-jordan") ??
			document.querySelector('[data-testid="chat-row-jordan"] [data-testid*="unread"]');
		// Open InfoPanel and clear
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		// After clearing, unread should be 0 — badge gone
		await waitFor(() =>
			expect(screen.queryByText("2")).not.toBeInTheDocument(),
		);
		expect(unreadBadge()).toBeNull();
	});

	it("Confirmation prompt closes after confirming", async () => {
		render(<ChatLayout />);
		openInfoPanel(/jordan/i);
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		await waitFor(() =>
			expect(screen.queryByTestId("clear-messages-confirm")).not.toBeInTheDocument(),
		);
	});

	it("Other chats messages are unaffected by clear", async () => {
		render(<ChatLayout />);
		// First open Maya's chat to verify her messages exist
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		expect(screen.getByText("9am at the corner cafe?")).toBeInTheDocument();
		// Now clear Jordan's chat
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		// Switch back to Maya — her messages must still be there
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await waitFor(() =>
			expect(screen.getByText("9am at the corner cafe?")).toBeInTheDocument(),
		);
	});

	it("Starred message from cleared chat is removed from starred panel", async () => {
		render(<ChatLayout />);
		// Star Jordan's message first
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// Hover to show star button (simulate via fireEvent.mouseEnter on the message)
		const message = screen.getByText("split for last night").closest(
			'[data-testid="message-bubble"]',
		);
		if (message) fireEvent.mouseEnter(message);
		const starBtn = screen.queryByRole("button", { name: /star message/i });
		if (starBtn) fireEvent.click(starBtn);
		// Open starred panel
		const starsBtn = screen.queryByRole("button", { name: /starred/i });
		if (starsBtn) fireEvent.click(starsBtn);
		// Now clear Jordan's chat
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		await waitFor(() =>
			expect(screen.getByTestId("clear-messages-confirm")).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		// The starred message from Jordan should be gone
		await waitFor(() =>
			expect(screen.queryByTestId("starred-item")).not.toBeInTheDocument(),
		);
	});
});
