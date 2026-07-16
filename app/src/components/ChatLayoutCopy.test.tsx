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

describe("ChatLayout — copy message to clipboard", () => {
	let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
	let clipboardWriteMock: ReturnType<typeof vi.fn>;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		clipboardWriteMock = vi.fn().mockResolvedValue(undefined);
		Object.defineProperty(navigator, "clipboard", {
			value: { writeText: clipboardWriteMock },
			configurable: true,
			writable: true,
		});

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
	});

	afterEach(async () => {
		vi.useRealTimers(); // restore before any async teardown — fake timers would hang db.clear()
		await act(async () => {});
		vi.restoreAllMocks();
		capturedOnMessage = undefined;
	});

	it("copy button appears on hover for an incoming text message", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-uuid-0001",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Hello, copy me",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.getByTestId("copy-button")).toBeInTheDocument();
	});

	it("copy button does NOT appear for deleted messages", async () => {
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

		const MSG_ID = "copy-del-uuid-0002";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				senderId: "peer-device-copy",
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

		expect(screen.queryByTestId("copy-button")).not.toBeInTheDocument();
	});

	it("copy button does NOT appear for media-only [image] messages", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-img-uuid-0003",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "[image]",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("copy-button")).not.toBeInTheDocument();
	});

	it("copy button does NOT appear for media-only [video] messages (§9.4.2)", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-video-uuid-0012",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "[video]",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("copy-button")).not.toBeInTheDocument();
	});

	it("clicking copy button calls navigator.clipboard.writeText with the message text", async () => {
		render(<ChatLayout />);

		const MSG_TEXT = "Copy this text please";
		await act(async () => {
			capturedOnMessage?.({
				id: "copy-click-uuid-0004",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: MSG_TEXT,
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("copy-button"));
		});

		expect(clipboardWriteMock).toHaveBeenCalledWith(MSG_TEXT);
	});

	it("copy button appears for own (sent) messages too", async () => {
		render(<ChatLayout />);

		const composer = screen.getByPlaceholderText(/encrypted/i);
		await act(async () => {
			fireEvent.change(composer, { target: { value: "My own message to copy" } });
			fireEvent.keyDown(composer, { key: "Enter" });
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		const lastBubble = bubbles[bubbles.length - 1];
		fireEvent.mouseEnter(lastBubble);

		expect(screen.getByTestId("copy-button")).toBeInTheDocument();
	});

	it("copy button has aria-label 'Copy message'", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-aria-uuid-0006",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Aria label test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.getByTestId("copy-button")).toHaveAttribute("aria-label", "Copy message");
	});

	it("copy button icon changes to check after click (copied state)", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-feedback-uuid-0007",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Feedback test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		const btn = screen.getByTestId("copy-button");
		// Before click: copy icon (aria-label stays "Copy message" since it's the button)
		expect(btn).toHaveAttribute("aria-label", "Copy message");
		// data-testid present = button is there
		await act(async () => {
			fireEvent.click(btn);
		});
		// After click: button still present (copied state visible for 1.5 s)
		expect(screen.getByTestId("copy-button")).toBeInTheDocument();
	});

	it("clipboard failure (.catch) does not throw or crash the component", async () => {
		clipboardWriteMock.mockRejectedValue(new Error("Clipboard denied"));
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-fail-uuid-0008",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Clipboard denied",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		await expect(
			act(async () => {
				fireEvent.click(screen.getByTestId("copy-button"));
			}),
		).resolves.not.toThrow();
	});

	it("copy uses the correct text when multiple messages are present", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-multi-uuid-0009a",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "First message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
			capturedOnMessage?.({
				id: "copy-multi-uuid-0009b",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Second message to copy",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
		await act(async () => {
			fireEvent.click(screen.getByTestId("copy-button"));
		});

		expect(clipboardWriteMock).toHaveBeenCalledWith("Second message to copy");
	});

	it("copy button copied state is present immediately after click and clears after 1500ms", async () => {
		// Receive the message with real timers, THEN switch to fake timers for the timeout assertion.
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-timer-uuid-0010",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "Timer test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		// Now switch to fake timers before the click so setTimeout(…, 1500) is captured.
		vi.useFakeTimers();

		act(() => {
			fireEvent.click(screen.getByTestId("copy-button"));
		});

		// Immediately after click: button still present in "copied" state.
		expect(screen.getByTestId("copy-button")).toBeInTheDocument();

		// Advance past the 1.5 s reset — still in DOM (hover keeps it visible, state reverts).
		act(() => {
			vi.advanceTimersByTime(1600);
		});

		expect(screen.getByTestId("copy-button")).toBeInTheDocument();
	});

	it("copy button is NOT shown when message text is empty", async () => {
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "copy-empty-uuid-0011",
				senderId: "peer-device-copy",
				groupId: SEED_GROUP_ID,
				text: "",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		const bubbles = screen.getAllByTestId("message-bubble");
		fireEvent.mouseEnter(bubbles[bubbles.length - 1]);

		expect(screen.queryByTestId("copy-button")).not.toBeInTheDocument();
		expect(clipboardWriteMock).not.toHaveBeenCalled();
	});
});
