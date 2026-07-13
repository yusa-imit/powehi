import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import * as WelcomePollerModule from "../hooks/useWelcomePoller";
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

describe("ChatLayout — message forwarding", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
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

	it("clicking a forward target toggles its selection instead of sending immediately", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnNewGroup:
			| ((event: { groupId: string; senderDeviceId: string }) => void)
			| undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		vi.spyOn(WelcomePollerModule, "useWelcomePoller").mockImplementation(
			(_identityId, onNewGroup) => {
				capturedOnNewGroup = onNewGroup;
			},
		);
		useAuthStore.setState({
			sessionToken: "tok-fwd-1",
			identityId: "id-fwd-1",
			deviceId: "dev-fwd-1",
		});
		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-toggle-target", senderDeviceId: "peer-device-toggle" });
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-toggle-uuid-0006",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Toggle me",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));

		const target = screen.getByTestId("forward-target-fwd-toggle-target");
		expect(target).toHaveAttribute("aria-pressed", "false");

		fireEvent.click(target);
		expect(target).toHaveAttribute("aria-pressed", "true");
		// The modal stays open and no send happened yet — selection only.
		expect(screen.getByTestId("forward-modal")).toBeInTheDocument();

		fireEvent.click(target);
		expect(target).toHaveAttribute("aria-pressed", "false");
	});

	it("forwards to every selected target in one send and closes the modal", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnNewGroup:
			| ((event: { groupId: string; senderDeviceId: string }) => void)
			| undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		vi.spyOn(WelcomePollerModule, "useWelcomePoller").mockImplementation(
			(_identityId, onNewGroup) => {
				capturedOnNewGroup = onNewGroup;
			},
		);
		useAuthStore.setState({
			sessionToken: "tok-fwd-2",
			identityId: "id-fwd-2",
			deviceId: "dev-fwd-2",
		});
		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-target-a", senderDeviceId: "peer-device-aaaa" });
		});
		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-target-b", senderDeviceId: "peer-device-bbbb" });
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-multi-uuid-0007",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Forward to both",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));

		const targetA = screen.getByTestId("forward-target-fwd-target-a");
		const targetB = screen.getByTestId("forward-target-fwd-target-b");
		fireEvent.click(targetA);
		fireEvent.click(targetB);

		expect(screen.getByText("Forward to (2)")).toBeInTheDocument();
		expect(screen.getByTestId("forward-send-button")).not.toBeDisabled();

		const encryptCallsBefore = MOCK_WORKER.mlsEncrypt.mock.calls.length;

		await act(async () => {
			fireEvent.click(screen.getByTestId("forward-send-button"));
		});

		expect(MOCK_WORKER.mlsEncrypt.mock.calls.length).toBe(encryptCallsBefore + 2);
		expect(screen.queryByTestId("forward-modal")).not.toBeInTheDocument();
	});

	it("the send button is disabled until at least one target is selected", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnNewGroup:
			| ((event: { groupId: string; senderDeviceId: string }) => void)
			| undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		vi.spyOn(WelcomePollerModule, "useWelcomePoller").mockImplementation(
			(_identityId, onNewGroup) => {
				capturedOnNewGroup = onNewGroup;
			},
		);
		useAuthStore.setState({
			sessionToken: "tok-fwd-3",
			identityId: "id-fwd-3",
			deviceId: "dev-fwd-3",
		});
		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-disabled-target", senderDeviceId: "peer-device-dddd" });
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-disabled-uuid-0008",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "No selection yet",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));

		expect(screen.getByTestId("forward-send-button")).toBeDisabled();
	});

	it("does not carry a stale selection into a freshly reopened forward modal", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnNewGroup:
			| ((event: { groupId: string; senderDeviceId: string }) => void)
			| undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		vi.spyOn(WelcomePollerModule, "useWelcomePoller").mockImplementation(
			(_identityId, onNewGroup) => {
				capturedOnNewGroup = onNewGroup;
			},
		);
		useAuthStore.setState({
			sessionToken: "tok-fwd-4",
			identityId: "id-fwd-4",
			deviceId: "dev-fwd-4",
		});
		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-reopen-target", senderDeviceId: "peer-device-eeee" });
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-reopen-uuid-0009",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "First message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-reopen-uuid-0010",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Second message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		let bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 2]);
		fireEvent.click(screen.getAllByTestId("forward-button")[0]);
		fireEvent.click(screen.getByTestId("forward-target-fwd-reopen-target"));
		expect(screen.getByText("Forward to (1)")).toBeInTheDocument();

		// Dismiss via the backdrop (not the explicit close button) to mimic every
		// real dismiss path, then reopen the modal for a different message.
		fireEvent.click(screen.getByTestId("forward-modal-backdrop"));
		expect(screen.queryByTestId("forward-modal")).not.toBeInTheDocument();

		bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getAllByTestId("forward-button")[0]);

		expect(screen.getByText("Forward to")).toBeInTheDocument();
		expect(screen.getByTestId("forward-target-fwd-reopen-target")).toHaveAttribute(
			"aria-pressed",
			"false",
		);
		expect(screen.getByTestId("forward-send-button")).toBeDisabled();
	});
});
