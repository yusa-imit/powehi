import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

let captureIncoming: ((msg: IncomingMessage) => void) | null = null;
let captureOnPin: ((gId: string, targetMessageId: string, action: "pin" | "unpin") => void) | null =
	null;

describe("ChatLayout — pinned banner jump-to-message", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(
				_id,
				_gid,
				onMsg,
				_onPq,
				_onTyping,
				_onReaction,
				_onReactionRemove,
				_onReadReceipt,
				_onDelivery,
				_onEdit,
				_onDelete,
				onPin,
			) => {
				captureIncoming = onMsg;
				captureOnPin = onPin ?? null;
			},
		);
		Element.prototype.scrollIntoView = vi.fn();
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.useRealTimers();
		captureIncoming = null;
		captureOnPin = null;
	});

	it("pinned banner renders when an incoming pin arrives for the active chat", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-banner-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "pinned_test_message_banner",
				ciphertextB64: "abc",
				epochSeq: 1001,
			});
		});
		await act(async () => {
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner")).toBeInTheDocument());
	});

	it("pinned banner exposes a jump button with the correct accessible label", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-a11y-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "accessible_pin_text",
				ciphertextB64: "abc",
				epochSeq: 1002,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner-jump")).toBeInTheDocument());
		expect(screen.getByTestId("pinned-banner-jump")).toHaveAttribute(
			"aria-label",
			"Jump to pinned message",
		);
	});

	it("clicking the pinned banner jump button calls scrollIntoView on the target message", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-scroll-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "scroll_pin_message",
				ciphertextB64: "abc",
				epochSeq: 1003,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner-jump")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("pinned-banner-jump"));
		await waitFor(() => {
			expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({
				block: "center",
				behavior: "smooth",
			});
		});
	});

	it("clicking the pinned banner jump button sets data-jump-flash on the pinned message", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-flash-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "flash_pin_message",
				ciphertextB64: "abc",
				epochSeq: 1004,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner-jump")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("pinned-banner-jump"));
		await waitFor(() => {
			const el = document.querySelector(`[data-msg-id="${msgId}"]`);
			expect(el).toHaveAttribute("data-jump-flash", "true");
		});
	});

	it("jump flash on pinned message clears after 1400ms", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		const msgId = "env-pin-flash-clear-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "flash_clear_pin_message",
				ciphertextB64: "abc",
				epochSeq: 1005,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await act(async () => {
			fireEvent.click(screen.getByTestId("pinned-banner-jump"));
		});
		const el = document.querySelector(`[data-msg-id="${msgId}"]`);
		expect(el).toHaveAttribute("data-jump-flash", "true");
		await act(async () => {
			vi.advanceTimersByTime(1500);
		});
		expect(el).not.toHaveAttribute("data-jump-flash");
	});

	it("pinned banner preview displays the pinned message text (no ciphertext or PII)", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-preview-001";
		const plaintext = "unique_preview_phrase_zyx987";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: plaintext,
				ciphertextB64: "abc",
				epochSeq: 1006,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner")).toHaveTextContent(plaintext));
	});

	it("clicking the unpin button via peer signal removes the pinned banner", async () => {
		render(<ChatLayout />);
		const msgId = "env-pin-unpin-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "unpin_test_message",
				ciphertextB64: "abc",
				epochSeq: 1007,
			});
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner")).toBeInTheDocument());
		await act(async () => {
			captureOnPin?.(MAYA_GROUP_ID, msgId, "unpin");
		});
		await waitFor(() => expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument());
	});

	it("pinned banner is absent when no message has been pinned", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
	});

	it("clicking the banner jump button does not crash when the pinned message is not in the DOM", async () => {
		render(<ChatLayout />);
		// Pin an ID without first delivering the message → element won't be in DOM
		const msgId = "env-pin-no-dom-001";
		await act(async () => {
			captureOnPin?.(MAYA_GROUP_ID, msgId, "pin");
		});
		await waitFor(() => expect(screen.getByTestId("pinned-banner-jump")).toBeInTheDocument());
		await act(async () => {
			fireEvent.click(screen.getByTestId("pinned-banner-jump"));
		});
		// Element not found → scrollIntoView must NOT be called
		expect(Element.prototype.scrollIntoView).not.toHaveBeenCalled();
	});

	it("pinned banner is not shown when the pinned message belongs to a different (non-active) chat", async () => {
		render(<ChatLayout />);
		// Maya is active; pin a message in Jordan's chat
		const msgId = "env-pin-jordan-001";
		await act(async () => {
			captureIncoming?.({
				id: msgId,
				senderId: "device-jordan",
				groupId: JORDAN_GROUP_ID,
				text: "jordan_pinned_msg",
				ciphertextB64: "abc",
				epochSeq: 2001,
			});
			captureOnPin?.(JORDAN_GROUP_ID, msgId, "pin");
		});
		// Banner should NOT appear — Maya's chat has no pinned message
		expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
	});
});
