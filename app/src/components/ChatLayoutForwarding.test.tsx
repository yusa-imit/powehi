import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MediaApi from "../api/media";
import * as MessagesApi from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage, MediaPayload } from "../hooks/useMessages";
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
	// Receiver-side opaque-handle pattern (cycle 309): import then decrypt via handle.
	mediaImportKey: vi.fn(async () => ({ mediaKeyHandle: "mock-fwd-import-handle" })),
	// JPEG magic bytes so sniffMimeType resolves to image/jpeg during forward re-encrypt.
	mediaDecryptWithHandle: vi.fn(async () => new Uint8Array([0xff, 0xd8, 0xff, 0xe0, 1, 2, 3, 4])),
	mediaEncrypt: vi.fn(async () => ({
		ciphertext: new Uint8Array(48),
		mediaKeyHandle: "mock-fwd-media-key-handle",
		iv: new Uint8Array(12),
		blobHash: new Uint8Array(32),
	})),
	mediaMessageCreate: vi.fn(async () => ({ ciphertext: new Uint8Array(64) })),
	mediaDropKey: vi.fn(async () => true),
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

	it("forwards a media message by decrypting once and re-encrypting fresh for the target group", async () => {
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
			sessionToken: "tok-fwd-media",
			identityId: "id-fwd-media",
			deviceId: "dev-fwd-media",
		});

		const getMediaDownloadUrlSpy = vi
			.spyOn(MediaApi, "getMediaDownloadUrl")
			.mockResolvedValue({ downloadUrl: "https://r2.test/original-ciphertext" });
		const requestMediaUploadSpy = vi
			.spyOn(MediaApi, "requestMediaUpload")
			.mockResolvedValue({ mediaId: "fwd-new-media-id", uploadUrl: "https://r2.test/put" });
		const confirmMediaUploadSpy = vi
			.spyOn(MediaApi, "confirmMediaUpload")
			.mockResolvedValue(undefined);
		const sendMessageSpy = vi.spyOn(MessagesApi, "sendMessage").mockResolvedValue("env-id-media");

		const fetchMock = vi.fn().mockResolvedValue({
			ok: true,
			arrayBuffer: async () => new ArrayBuffer(64),
		});
		globalThis.fetch = fetchMock as unknown as typeof globalThis.fetch;

		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-media-target", senderDeviceId: "peer-device-media" });
		});

		const media: MediaPayload = {
			blobId: "original-blob-id",
			blobHash: Array.from<number>({ length: 32 }).fill(7),
			mediaKey: Array.from<number>({ length: 32 }).fill(9),
			iv: Array.from<number>({ length: 12 }).fill(3),
		};

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-media-uuid-0011",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "[image]",
				media,
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));
		fireEvent.click(screen.getByTestId("forward-target-fwd-media-target"));

		await act(async () => {
			fireEvent.click(screen.getByTestId("forward-send-button"));
		});

		// Decrypts the ORIGINAL blob (the source message's own blobId), not a re-derived one.
		await waitFor(() =>
			expect(getMediaDownloadUrlSpy).toHaveBeenCalledWith("tok-fwd-media", "original-blob-id"),
		);
		// Re-encrypts fresh (new key, new blob) rather than reusing the source ciphertext/key.
		await waitFor(() => expect(MOCK_WORKER.mediaEncrypt).toHaveBeenCalledOnce());
		expect(requestMediaUploadSpy).toHaveBeenCalledWith(
			"tok-fwd-media",
			"image/jpeg",
			48,
			"fwd-media-target",
		);
		await waitFor(() =>
			expect(confirmMediaUploadSpy).toHaveBeenCalledWith("tok-fwd-media", "fwd-new-media-id"),
		);
		await waitFor(() =>
			expect(MOCK_WORKER.mediaMessageCreate).toHaveBeenCalledWith(
				"id-fwd-media",
				"fwd-media-target",
				"mock-fwd-media-key-handle",
				"fwd-new-media-id",
				expect.any(Uint8Array),
				expect.any(Uint8Array),
				"image/jpeg",
			),
		);
		await waitFor(() =>
			expect(sendMessageSpy).toHaveBeenCalledWith(
				"tok-fwd-media",
				"fwd-media-target",
				expect.any(Uint8Array),
			),
		);
		// The opaque media key handle is always dropped after use.
		await waitFor(() =>
			expect(MOCK_WORKER.mediaDropKey).toHaveBeenCalledWith("mock-fwd-media-key-handle"),
		);
		expect(screen.queryByTestId("forward-modal")).not.toBeInTheDocument();
	});

	it("persists the forwarded text message to Dexie under the target group so it survives a reload", async () => {
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
			sessionToken: "tok-fwd-persist",
			identityId: "id-fwd-persist",
			deviceId: "dev-fwd-persist",
		});
		const sendMessageSpy = vi
			.spyOn(MessagesApi, "sendMessage")
			.mockResolvedValue("env-fwd-persist-id");

		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({
				groupId: "fwd-persist-target",
				senderDeviceId: "peer-device-persist",
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-persist-uuid-0012",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Persist me",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));
		fireEvent.click(screen.getByTestId("forward-target-fwd-persist-target"));

		await act(async () => {
			fireEvent.click(screen.getByTestId("forward-send-button"));
		});

		await waitFor(() => expect(sendMessageSpy).toHaveBeenCalled());

		await waitFor(async () => {
			const row = await db.messages.get("env-fwd-persist-id");
			expect(row).toBeDefined();
			expect(row?.groupId).toBe("fwd-persist-target");
			expect(row?.senderDeviceId).toBe("dev-fwd-persist");
			expect(row?.plaintextB64).toBe(btoa("Persist me"));
			// Pins the actual re-encrypted ciphertext from THIS forward's mlsEncrypt call
			// (MOCK_WORKER.mlsEncrypt always resolves [0xde, 0xad]) — must NOT be the source
			// message's own ciphertextB64 ("Zg=="), which would mean the wrong bytes (or the
			// wrong group's ciphertext) got persisted.
			expect(row?.ciphertextB64).toBe("3q0=");
			expect(row?.ciphertextB64).not.toBe("Zg==");
			// Forwards carry no reply context and (pre-existing, unchanged by this fix) no TTL.
			expect(row?.expiresAt).toBeUndefined();
			expect(row?.replyToJson).toBeUndefined();
		});
	});

	it("does not persist a forwarded message when the send fails (optimistic bubble stays, Dexie stays empty)", async () => {
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
			sessionToken: "tok-fwd-fail",
			identityId: "id-fwd-fail",
			deviceId: "dev-fwd-fail",
		});
		const sendMessageSpy = vi
			.spyOn(MessagesApi, "sendMessage")
			.mockRejectedValue(new Error("network down"));

		render(<ChatLayout />);
		await waitFor(() => expect(capturedOnNewGroup).toBeTypeOf("function"));

		act(() => {
			capturedOnNewGroup?.({ groupId: "fwd-fail-target", senderDeviceId: "peer-device-fail" });
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "fwd-fail-uuid-0013",
				senderId: "peer-device-fwd",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "Never lands",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		fireEvent.click(screen.getByTestId("forward-button"));
		fireEvent.click(screen.getByTestId("forward-target-fwd-fail-target"));

		await act(async () => {
			fireEvent.click(screen.getByTestId("forward-send-button"));
		});

		await waitFor(() => expect(sendMessageSpy).toHaveBeenCalled());
		// Give the rejected promise chain a tick to settle before asserting the negative.
		await act(async () => {
			await Promise.resolve();
		});
		expect(await db.messages.where("groupId").equals("fwd-fail-target").count()).toBe(0);
	});
});
