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

const SEED_GROUP_ID = "11111111-1111-1111-1111-111111111111";

describe("ChatLayout — Web Share API (navigator.share)", () => {
	let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
	let shareMock: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		shareMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "share", {
			value: shareMock,
			configurable: true,
			writable: true,
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

	it("share button appears on hover for an incoming text message with a stable envelope id", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-uuid-0001",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Hello from peer",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.getByTestId("share-button")).toBeInTheDocument();
	});

	it("share button does NOT appear for deleted messages", async () => {
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

		const MSG_ID = "share-del-uuid-0002";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Will be deleted",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		await act(async () => {
			capturedOnDelete?.(SEED_GROUP_ID, MSG_ID);
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("share-button")).not.toBeInTheDocument();
	});

	it("share button does NOT appear for media-only [image] messages", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-img-uuid-0003",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "[image]",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("share-button")).not.toBeInTheDocument();
	});

	it("share button does NOT appear for media-only [video] messages (§9.4.2)", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-video-uuid-0004",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "[video]",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("share-button")).not.toBeInTheDocument();
	});

	it("clicking share button calls navigator.share", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-click-uuid-0004",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Share this text",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("share-button"));
		});

		expect(shareMock).toHaveBeenCalledOnce();
	});

	it("navigator.share is called with { text } only — no title or url to minimise metadata exposure", async () => {
		render(<ChatLayout />);

		const MSG_TEXT = "Sensitive text to share";
		await act(async () => {
			capturedOnMessage?.({
				id: "share-meta-uuid-0005",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: MSG_TEXT,
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("share-button"));
		});

		expect(shareMock).toHaveBeenCalledWith({ text: MSG_TEXT });
		const call = shareMock.mock.calls[0][0] as Record<string, unknown>;
		expect(call.title).toBeUndefined();
		expect(call.url).toBeUndefined();
	});

	it("share button appears for own (sent) messages too", async () => {
		render(<ChatLayout />);

		const composer = screen.getByPlaceholderText(/encrypted/i);
		await act(async () => {
			fireEvent.change(composer, { target: { value: "My own message" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		const lastBubble = bubbles[bubbles.length - 1];
		fireEvent.mouseEnter(lastBubble);

		expect(screen.getByTestId("share-button")).toBeInTheDocument();
	});

	it("navigator.share cancellation (AbortError) is handled silently without crashing", async () => {
		shareMock.mockRejectedValue(new DOMException("Aborted", "AbortError"));
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-abort-uuid-0007",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Aborted share",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		await expect(
			act(async () => {
				fireEvent.click(screen.getByTestId("share-button"));
			}),
		).resolves.not.toThrow();
	});

	it("share button aria-label is 'Share message'", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-aria-uuid-0008",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Aria label test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.getByTestId("share-button")).toHaveAttribute("aria-label", "Share message");
	});

	it("navigator.share is NOT called when message text is empty", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-empty-uuid-0009",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("share-button")).not.toBeInTheDocument();
		expect(shareMock).not.toHaveBeenCalled();
	});

	it("share button uses the correct text when multiple messages are present", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "share-multi-uuid-0010a",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "First message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
			capturedOnMessage?.({
				id: "share-multi-uuid-0010b",
				senderId: "peer-device-share",
				groupId: SEED_GROUP_ID,
				text: "Second message to share",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("share-button"));
		});

		expect(shareMock).toHaveBeenCalledWith({ text: "Second message to share" });
	});
});
