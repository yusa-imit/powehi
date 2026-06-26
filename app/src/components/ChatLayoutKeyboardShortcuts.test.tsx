import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { useAuthStore } from "../store/auth";
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

const SEED_GROUP_ID = "11111111-1111-1111-1111-111111111111";

describe("ChatLayout — keyboard shortcuts (↑ to edit last, Escape to cancel)", () => {
	let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({
			sessionToken: "tok-kbd",
			identityId: "id-kbd",
			deviceId: "dev-kbd",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
	});

	afterEach(async () => {
		await act(async () => {});
		vi.restoreAllMocks();
		capturedOnMessage = undefined;
	});

	it("↑ in empty composer activates edit mode (edit-preview is shown)", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "My own message" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		await waitFor(() => {
			expect(screen.getByTestId("edit-preview")).toBeInTheDocument();
		});
	});

	it("↑ populates the composer with the last own message text", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Edit me please" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		await waitFor(() => {
			expect(screen.getByTestId("edit-preview")).toHaveTextContent("Edit me please");
		});
	});

	it("↑ is a no-op when the composer has partial draft text", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "First sent" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		await act(async () => {
			fireEvent.change(composer, { target: { value: "partial draft" } });
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
	});

	it("↑ is a no-op in Jordan chat which has no own messages", async () => {
		render(<ChatLayout />);

		// Switch to Jordan's chat which contains only peer messages in seed data.
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
	});

	it("↑ is a no-op when already in edit mode", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Message A" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});
		await act(async () => {
			fireEvent.change(composer, { target: { value: "Message B" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		// Enter edit mode on first ↑
		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});
		await waitFor(() => expect(screen.getByTestId("edit-preview")).toBeInTheDocument());

		// Second ↑ should not change what's being edited
		const previewTextBefore = screen.getByTestId("edit-preview").textContent;
		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});
		expect(screen.getByTestId("edit-preview").textContent).toBe(previewTextBefore);
	});

	it("↑ skips deleted own messages and targets the most recent non-deleted one", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Kept message" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});
		await act(async () => {
			fireEvent.change(composer, { target: { value: "To be deleted" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		// Delete the last own message via bubble delete button
		const bubbles = screen.getAllByTestId("message-bubble");
		const lastBubble = bubbles[bubbles.length - 1];
		fireEvent.mouseEnter(lastBubble);
		await act(async () => {
			fireEvent.click(screen.getByTestId("delete-button"));
		});

		// ↑ should now edit "Kept message"
		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		await waitFor(() => {
			expect(screen.getByTestId("edit-preview")).toHaveTextContent("Kept message");
		});
	});

	it("Escape cancels active edit mode", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Escape this edit" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});
		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});
		await waitFor(() => expect(screen.getByTestId("edit-preview")).toBeInTheDocument());

		await act(async () => {
			fireEvent.keyDown(composer, { key: "Escape" });
		});

		await waitFor(() => {
			expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
		});
	});

	it("Escape cancels active reply mode (reply-preview disappears)", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "reply-cancel-uuid-0001",
				senderId: "peer-device-kbd",
				groupId: SEED_GROUP_ID,
				text: "Reply to this",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("reply-button"));
		});

		await waitFor(() => expect(screen.getByTestId("reply-preview")).toBeInTheDocument());

		const composer = screen.getByPlaceholderText(/encrypted/i);
		await act(async () => {
			fireEvent.keyDown(composer, { key: "Escape" });
		});

		await waitFor(() => {
			expect(screen.queryByTestId("reply-preview")).not.toBeInTheDocument();
		});
	});

	it("Escape is a no-op when neither editing nor replying", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await expect(
			act(async () => {
				fireEvent.keyDown(composer, { key: "Escape" });
			}),
		).resolves.not.toThrow();

		expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
		expect(screen.queryByTestId("reply-preview")).not.toBeInTheDocument();
	});

	it("edit mode entered via ↑ lets the user confirm an edit (edited badge appears)", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Original text" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});
		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});
		await waitFor(() => expect(screen.getByTestId("edit-preview")).toBeInTheDocument());

		await act(async () => {
			fireEvent.change(composer, { target: { value: "Edited text" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		await waitFor(() => {
			expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
			expect(screen.getByTestId("edited-badge")).toBeInTheDocument();
		});
	});

	it("↑ selects the very last own message when two own messages exist", async () => {
		render(<ChatLayout />);
		const composer = screen.getByPlaceholderText(/encrypted/i);

		await act(async () => {
			fireEvent.change(composer, { target: { value: "First own" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});
		await act(async () => {
			fireEvent.change(composer, { target: { value: "Second own" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		await act(async () => {
			fireEvent.keyDown(composer, { key: "ArrowUp" });
		});

		await waitFor(() => {
			expect(screen.getByTestId("edit-preview")).toHaveTextContent("Second own");
		});
	});
});
