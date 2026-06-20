import { act, fireEvent, render, screen } from "@testing-library/react";
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

describe("ChatLayout — message forwarding", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("forward button appears on hover for an incoming message with a stable envelope id", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-msg-uuid-0001",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Message to forward",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.getByTestId("forward-button")).toBeInTheDocument();
	});

	it("forward button does NOT appear on deleted messages", async () => {
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

		const MSG_ID = "fwd-del-uuid-0002";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Will be deleted",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		await act(async () => {
			capturedOnDelete?.("11111111-1111-1111-1111-111111111111", MSG_ID);
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("forward-button")).not.toBeInTheDocument();
	});

	it("clicking forward button opens the forward modal", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-modal-uuid-0003",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Forward this",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));

		expect(screen.getByTestId("forward-modal")).toBeInTheDocument();
	});

	it("close button dismisses the forward modal", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-close-uuid-0004",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Close the modal",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));
		expect(screen.getByTestId("forward-modal")).toBeInTheDocument();

		fireEvent.click(screen.getByTestId("forward-modal-close"));
		expect(screen.queryByTestId("forward-modal")).not.toBeInTheDocument();
	});

	it("forward modal shows 'No other conversations' when no other chat has an MLS session", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-empty-uuid-0005",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "No targets",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));

		expect(screen.getByText(/no other conversations/i)).toBeInTheDocument();
	});
});
