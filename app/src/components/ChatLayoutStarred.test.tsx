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

const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

describe("ChatLayout — starred messages", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("star button appears on hover for a seed message", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		expect(screen.getByTestId("star-button")).toBeInTheDocument();
	});

	it("star button aria-label is 'Star message' for an unstarred message", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		expect(screen.getByTestId("star-button")).toHaveAttribute("aria-label", "Star message");
	});

	it("starred messages button opens the starred panel", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getByTestId("starred-panel")).toBeInTheDocument();
	});

	it("starred panel shows empty state when nothing is starred", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getByText(/no starred messages yet/i)).toBeInTheDocument();
	});

	it("close button dismisses the starred panel", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getByTestId("starred-panel")).toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: /close starred/i }));
		expect(screen.queryByTestId("starred-panel")).not.toBeInTheDocument();
	});

	it("starring a seed message adds it to the starred panel", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getAllByTestId("starred-item")).toHaveLength(1);
	});

	it("starred item shows the message text", () => {
		render(<ChatLayout />);
		// First seed bubble in Maya's chat: "Hey — are you free tomorrow morning?"
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getAllByTestId("starred-item")[0]).toHaveTextContent(
			"Hey — are you free tomorrow morning?",
		);
	});

	it("starred item shows the chat name", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getAllByTestId("starred-item")[0]).toHaveTextContent("Maya Akana");
	});

	it("clicking a starred item closes the starred panel", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[0]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		fireEvent.click(screen.getAllByTestId("starred-item")[0]);
		expect(screen.queryByTestId("starred-panel")).not.toBeInTheDocument();
	});

	it("unstarring a message removes it from the starred panel", () => {
		render(<ChatLayout />);
		const bubbles = screen.getAllByTestId("message-bubble");
		// Star the first message
		fireEvent.mouseEnter(bubbles[0]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		// Verify it is in the panel
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getAllByTestId("starred-item")).toHaveLength(1);
		// Close panel and unstar
		fireEvent.click(screen.getByRole("button", { name: /close starred/i }));
		fireEvent.mouseEnter(bubbles[0]);
		expect(screen.getByTestId("star-button")).toHaveAttribute("aria-label", "Unstar message");
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[0]);
		// Panel should now show empty state
		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		expect(screen.getByText(/no starred messages yet/i)).toBeInTheDocument();
	});

	it("star button is absent for deleted incoming messages", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnDelete: ((groupId: string, targetMessageId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(
				_id,
				_gid,
				onMsg,
				_onPq,
				_onTyping,
				_onReaction,
				_onReactionRemove,
				_onRead,
				_onDelivery,
				_onEdit,
				onDelete,
			) => {
				capturedOnMessage = onMsg;
				capturedOnDelete = onDelete;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "star-del-uuid-0001";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				senderId: "peer-device-star",
				groupId: MAYA_GROUP_ID,
				text: "This will be deleted in star test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		await act(async () => {
			capturedOnDelete?.(MAYA_GROUP_ID, MSG_ID);
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		expect(screen.queryByTestId("star-button")).not.toBeInTheDocument();
	});

	it("starring an incoming message with a stable id shows it in the panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "star-incoming-uuid-0002",
				senderId: "peer-device-star",
				groupId: MAYA_GROUP_ID,
				text: "Star this incoming message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("star-button"));
		fireEvent.mouseLeave(bubbles[bubbles.length - 1]);

		fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
		const items = screen.getAllByTestId("starred-item");
		expect(items.some((el) => el.textContent?.includes("Star this incoming message"))).toBe(true);
	});
});
