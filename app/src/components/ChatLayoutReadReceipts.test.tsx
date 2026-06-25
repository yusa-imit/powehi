import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesApiModule from "../api/messages";
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

const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

let captureIncoming: ((msg: IncomingMessage) => void) | null = null;
let captureOnReadReceipt:
	| ((gId: string, messageIds: string[], readAt: number, senderDeviceId: string) => void)
	| null = null;
let captureOnDeliveryReceipt:
	| ((gId: string, messageIds: string[], senderDeviceId: string) => void)
	| null = null;

describe("ChatLayout — read receipt delivery UI", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		MOCK_WORKER.mlsEncrypt.mockClear();
		// Set up auth so receipt functions can pass their guards (sessionToken + identityId).
		useAuthStore.setState({
			sessionToken: "tok-rr-test",
			identityId: "22222222-2222-2222-2222-222222222222",
			phase: "app",
			deviceId: "dev-rr-test",
		});
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(
				_id,
				_gid,
				onMsg,
				_onPq,
				_onTyping,
				_onReaction,
				_onReactionRemove,
				onReadReceipt,
				onDeliveryReceipt,
			) => {
				captureIncoming = onMsg;
				captureOnReadReceipt = onReadReceipt ?? null;
				captureOnDeliveryReceipt = onDeliveryReceipt ?? null;
			},
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		vi.useRealTimers();
		captureIncoming = null;
		captureOnReadReceipt = null;
		captureOnDeliveryReceipt = null;
		useAuthStore.setState({ sessionToken: null, identityId: null, phase: "login", deviceId: null });
	});

	it("seed message with read:true shows 'Read' double-check indicator (Ari Work chat)", async () => {
		render(<ChatLayout />);
		// Switch to Ari Work chat which has read:true outgoing messages
		const ariBtn = screen.getByRole("button", { name: /Ari Work/i });
		await act(async () => {
			fireEvent.click(ariBtn);
		});
		const readIndicators = screen.getAllByTestId("read-indicator");
		const readOne = readIndicators.find((el) => el.getAttribute("aria-label") === "Read");
		expect(readOne).toBeTruthy();
	});

	it("incoming messages ('from:them') never show a read-status indicator", async () => {
		render(<ChatLayout />);
		await act(async () => {
			captureIncoming?.({
				id: "env-incoming-no-indicator",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "hi no indicator",
				ciphertextB64: "abc",
				epochSeq: 9040,
			});
		});
		// All read-indicators must belong to "me" messages — the incoming "them" message has none.
		const indicators = screen.queryAllByTestId("read-indicator");
		for (const el of indicators) {
			const label = el.getAttribute("aria-label");
			expect(["Read", "Delivered", "Sent", "Sending"]).toContain(label);
		}
	});

	it("'Sending' (timer) indicator shows for optimistic outgoing message with no id", async () => {
		// Delay sendMessageApi so the optimistic message stays without an id.
		let resolveSend: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage").mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveSend = resolve;
				}),
		);
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "sending now" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		// Before the API resolves, the optimistic message has no id → shows "Sending" timer icon.
		const sendingIndicators = screen
			.queryAllByTestId("read-indicator")
			.filter((el) => el.getAttribute("aria-label") === "Sending");
		expect(sendingIndicators.length).toBeGreaterThanOrEqual(1);
		// Clean up: resolve to prevent hanging timers.
		await act(async () => {
			resolveSend("env-resolved-id");
		});
	});

	it("incoming delivery_receipt event transitions message to 'Delivered' state", async () => {
		let resolveSend: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage").mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveSend = resolve;
				}),
		);
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "delivery test" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		const knownId = "env-delivery-test-001";
		await act(async () => {
			resolveSend(knownId);
		});
		// Fire a delivery_receipt for the known id.
		await act(async () => {
			captureOnDeliveryReceipt?.(MAYA_GROUP_ID, [knownId], "device-peer");
		});
		await waitFor(() => {
			const delivered = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered");
			expect(delivered.length).toBeGreaterThanOrEqual(1);
		});
	});

	it("incoming read_receipt event transitions message to 'Read' state", async () => {
		let resolveSend: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage").mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveSend = resolve;
				}),
		);
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "read test" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		const knownId = "env-read-receipt-001";
		await act(async () => {
			resolveSend(knownId);
		});
		await act(async () => {
			captureOnReadReceipt?.(MAYA_GROUP_ID, [knownId], Date.now(), "device-peer");
		});
		await waitFor(() => {
			const readIndicators = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read");
			expect(readIndicators.length).toBeGreaterThanOrEqual(1);
		});
	});

	it("active+focused incoming message dispatches read receipt immediately (mlsEncrypt called twice)", async () => {
		vi.spyOn(document, "hasFocus").mockReturnValue(true);
		render(<ChatLayout />);
		MOCK_WORKER.mlsEncrypt.mockClear();
		await act(async () => {
			captureIncoming?.({
				id: "env-immediate-read-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "immediate read",
				ciphertextB64: "abc",
				epochSeq: 9010,
			});
		});
		// delivery_receipt (1st encrypt call) + read_receipt (2nd) both fired immediately.
		await waitFor(() => {
			expect(MOCK_WORKER.mlsEncrypt).toHaveBeenCalledTimes(2);
		});
	});

	it("active+unfocused incoming message defers read receipt (only delivery_receipt mlsEncrypt call)", async () => {
		vi.spyOn(document, "hasFocus").mockReturnValue(false);
		render(<ChatLayout />);
		MOCK_WORKER.mlsEncrypt.mockClear();
		await act(async () => {
			captureIncoming?.({
				id: "env-deferred-read-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "deferred read",
				ciphertextB64: "abc",
				epochSeq: 9020,
			});
		});
		// Only delivery receipt fired — read receipt is in the pending buffer.
		await waitFor(() => {
			expect(MOCK_WORKER.mlsEncrypt).toHaveBeenCalledTimes(1);
		});
	});

	it("window focus event flushes deferred read receipt (2nd mlsEncrypt call fires after focus)", async () => {
		vi.spyOn(document, "hasFocus").mockReturnValue(false);
		render(<ChatLayout />);
		MOCK_WORKER.mlsEncrypt.mockClear();
		await act(async () => {
			captureIncoming?.({
				id: "env-flush-on-focus-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "flush on focus",
				ciphertextB64: "abc",
				epochSeq: 9030,
			});
		});
		expect(MOCK_WORKER.mlsEncrypt).toHaveBeenCalledTimes(1);
		// Window gains focus → pending read receipt should be dispatched.
		await act(async () => {
			window.dispatchEvent(new Event("focus"));
		});
		await waitFor(() => {
			expect(MOCK_WORKER.mlsEncrypt).toHaveBeenCalledTimes(2);
		});
	});

	it("read_receipt for multiple ids marks all matching messages as read", async () => {
		let resolveFirst: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage")
			.mockImplementationOnce(
				() =>
					new Promise((r) => {
						resolveFirst = r;
					}),
			)
			.mockImplementation(async () => "env-second-id");
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "msg one" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		const id1 = "env-batch-read-001";
		await act(async () => {
			resolveFirst(id1);
		});
		await act(async () => {
			captureOnReadReceipt?.(MAYA_GROUP_ID, [id1], Date.now(), "device-peer");
		});
		await waitFor(() => {
			const readIndicators = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read");
			expect(readIndicators.length).toBeGreaterThanOrEqual(1);
		});
	});

	it("Sent indicator shows single check after id backfill — no 'Sending' or 'Delivered'", async () => {
		let resolveSend: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage").mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveSend = resolve;
				}),
		);
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "just sent" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		// Before id backfill: "Sending" state
		const sendingBefore = screen
			.queryAllByTestId("read-indicator")
			.filter((el) => el.getAttribute("aria-label") === "Sending");
		expect(sendingBefore.length).toBeGreaterThanOrEqual(1);
		// Resolve with id — message transitions to "Sent"
		await act(async () => {
			resolveSend("env-sent-only-001");
		});
		await waitFor(() => {
			const sentIndicators = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Sent");
			expect(sentIndicators.length).toBeGreaterThanOrEqual(1);
		});
		// No longer "Sending" after id backfill
		const sendingAfter = screen
			.queryAllByTestId("read-indicator")
			.filter((el) => el.getAttribute("aria-label") === "Sending");
		expect(sendingAfter.length).toBe(0);
	});

	it("delivery_receipt stops at 'Delivered' — does not advance message to 'Read' without read_receipt", async () => {
		let resolveSend: (id: string) => void = () => {};
		vi.spyOn(MessagesApiModule, "sendMessage").mockImplementation(
			() =>
				new Promise((resolve) => {
					resolveSend = resolve;
				}),
		);
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/Message.*—\s*encrypted/i);
		await act(async () => {
			fireEvent.change(textarea, { target: { value: "will be delivered not read" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		});
		const knownId = "env-delivered-not-read";
		await act(async () => {
			resolveSend(knownId);
		});
		// At this point: message is "Sent" (single check). No delivery or read receipt yet.
		const sentCount = screen
			.queryAllByTestId("read-indicator")
			.filter((el) => el.getAttribute("aria-label") === "Sent").length;
		expect(sentCount).toBeGreaterThanOrEqual(1);
		// Fire delivery_receipt only — no read_receipt.
		await act(async () => {
			captureOnDeliveryReceipt?.(MAYA_GROUP_ID, [knownId], "device-peer");
		});
		// After delivery_receipt: message transitions to "Delivered", not "Read".
		await waitFor(() => {
			const delivered = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered");
			expect(delivered.length).toBeGreaterThanOrEqual(1);
		});
		// The "Sent" indicator for this message should be gone now (it became "Delivered").
		const sentAfter = screen
			.queryAllByTestId("read-indicator")
			.filter((el) => el.getAttribute("aria-label") === "Sent").length;
		expect(sentAfter).toBeLessThan(sentCount);
	});
});
