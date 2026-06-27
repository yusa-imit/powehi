import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

let captureIncoming: ((msg: IncomingMessage) => void) | null = null;

/** Simulate scrolling up in the message list scroll container.
 * scrollTop=0, scrollHeight=1000, clientHeight=600 → 0+600 < 920 → not at bottom.
 * Uses getter/setter so subsequent writes to scrollTop don't throw.
 */
function simulateScrollUp(el: HTMLElement) {
	Object.defineProperty(el, "scrollHeight", { configurable: true, value: 1000 });
	Object.defineProperty(el, "clientHeight", { configurable: true, value: 600 });
	Object.defineProperty(el, "scrollTop", { configurable: true, get: () => 0, set: vi.fn() });
	fireEvent.scroll(el);
}

/** Simulate scrolling to the bottom of the message list scroll container.
 * scrollTop=400, scrollHeight=1000, clientHeight=600 → 1000 >= 920 → at bottom.
 * Uses getter/setter so subsequent writes to scrollTop don't throw.
 */
function simulateScrollToBottom(el: HTMLElement) {
	Object.defineProperty(el, "scrollHeight", { configurable: true, value: 1000 });
	Object.defineProperty(el, "clientHeight", { configurable: true, value: 600 });
	Object.defineProperty(el, "scrollTop", { configurable: true, get: () => 400, set: vi.fn() });
	fireEvent.scroll(el);
}

describe("ChatLayout — jump-to-bottom FAB", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			captureIncoming = onMsg;
		});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		captureIncoming = null;
	});

	it("FAB is absent at initial render (user is considered at bottom)", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("jump-to-bottom-btn")).not.toBeInTheDocument();
	});

	it("FAB appears when the user scrolls up in the message list", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
	});

	it("FAB has aria-label 'Jump to bottom'", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() =>
			expect(screen.getByTestId("jump-to-bottom-btn")).toHaveAttribute(
				"aria-label",
				"Jump to bottom",
			),
		);
	});

	it("clicking the FAB hides it (restores at-bottom state)", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("jump-to-bottom-btn"));
		await waitFor(() => expect(screen.queryByTestId("jump-to-bottom-btn")).not.toBeInTheDocument());
	});

	it("clicking the FAB sets scrollTop to scrollHeight on the scroll container", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		const scrollSetSpy = vi.fn();
		Object.defineProperty(scrollEl, "scrollTop", {
			configurable: true,
			set: scrollSetSpy,
			get: () => 0,
		});
		fireEvent.click(screen.getByTestId("jump-to-bottom-btn"));
		expect(scrollSetSpy).toHaveBeenCalled();
	});

	it("badge is absent when FAB is shown but no new messages have arrived", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		expect(screen.queryByTestId("jump-to-bottom-badge")).not.toBeInTheDocument();
	});

	it("badge shows count 1 when one new message arrives while scrolled up", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		await act(async () => {
			captureIncoming?.({
				id: "env-jtb-msg-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "new_message_while_scrolled_up",
				ciphertextB64: "abc",
				epochSeq: 5001,
			});
		});
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-badge")).toHaveTextContent("1"));
	});

	it("badge count increments for each new message while scrolled up", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		await act(async () => {
			captureIncoming?.({
				id: "env-jtb-msg-002",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "first_new_msg",
				ciphertextB64: "abc",
				epochSeq: 5002,
			});
		});
		await act(async () => {
			captureIncoming?.({
				id: "env-jtb-msg-003",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "second_new_msg",
				ciphertextB64: "abc",
				epochSeq: 5003,
			});
		});
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-badge")).toHaveTextContent("2"));
	});

	it("scrolling back to the bottom clears the badge", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		await act(async () => {
			captureIncoming?.({
				id: "env-jtb-msg-004",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "badge_reset_test_msg",
				ciphertextB64: "abc",
				epochSeq: 5004,
			});
		});
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-badge")).toBeInTheDocument());
		simulateScrollToBottom(scrollEl);
		await waitFor(() =>
			expect(screen.queryByTestId("jump-to-bottom-badge")).not.toBeInTheDocument(),
		);
	});

	it("scrolling back to the bottom hides the FAB", async () => {
		render(<ChatLayout />);
		const scrollEl = screen.getByTestId("message-list-scroll");
		simulateScrollUp(scrollEl);
		await waitFor(() => expect(screen.getByTestId("jump-to-bottom-btn")).toBeInTheDocument());
		simulateScrollToBottom(scrollEl);
		await waitFor(() => expect(screen.queryByTestId("jump-to-bottom-btn")).not.toBeInTheDocument());
	});

	it("badge never shows when new messages arrive while at bottom (no scroll needed)", async () => {
		render(<ChatLayout />);
		// Do NOT scroll up — stay at bottom (initial state)
		await act(async () => {
			captureIncoming?.({
				id: "env-jtb-msg-005",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "at_bottom_new_msg",
				ciphertextB64: "abc",
				epochSeq: 5005,
			});
		});
		// Neither FAB nor badge should appear
		expect(screen.queryByTestId("jump-to-bottom-btn")).not.toBeInTheDocument();
		expect(screen.queryByTestId("jump-to-bottom-badge")).not.toBeInTheDocument();
	});
});
