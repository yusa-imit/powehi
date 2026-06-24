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

// Maya's mlsGroupId from SEED_CHATS
const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";

let captureIncoming: ((msg: IncomingMessage) => void) | null = null;

describe("ChatLayout — jump-to-message from sidebar search", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_, __, onMessage) => {
			captureIncoming = onMessage;
		});
		// scrollIntoView is not implemented in jsdom
		Element.prototype.scrollIntoView = vi.fn();
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.useRealTimers();
		captureIncoming = null;
	});

	it("section header shows result count when messages match", async () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		await waitFor(() =>
			expect(screen.getByTestId("msg-search-section-header")).toBeInTheDocument(),
		);
		// "9am at the corner cafe?" matches — header should show "Messages (1)"
		expect(screen.getByTestId("msg-search-section-header")).toHaveTextContent("Messages (1)");
	});

	it("section header count increments when multiple messages match", async () => {
		render(<ChatLayout />);
		// Deliver two messages that both contain the same keyword
		await act(async () => {
			captureIncoming?.({
				id: "env-count-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "uniqueword_alpha first match",
				ciphertextB64: "abc",
				epochSeq: 9100,
			});
			captureIncoming?.({
				id: "env-count-002",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "uniqueword_alpha second match",
				ciphertextB64: "abc",
				epochSeq: 9101,
			});
		});
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "uniqueword_alpha" } });
		await waitFor(() =>
			expect(screen.getByTestId("msg-search-section-header")).toBeInTheDocument(),
		);
		expect(screen.getByTestId("msg-search-section-header")).toHaveTextContent("Messages (2)");
	});

	it("message wrapper has data-msg-id attribute after incoming message with ID", async () => {
		render(<ChatLayout />);
		const uniqueId = "env-jump-target-001";
		await act(async () => {
			captureIncoming?.({
				id: uniqueId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "jump_target_phrase_xyz",
				ciphertextB64: "abc",
				epochSeq: 9200,
			});
		});
		// The active chat is Maya by default — message should appear in DOM
		const el = document.querySelector(`[data-msg-id="${uniqueId}"]`);
		expect(el).toBeInTheDocument();
	});

	it("clicking search result for a message with ID sets data-jump-flash on the target", async () => {
		render(<ChatLayout />);
		const uniqueId = "env-jump-flash-001";
		await act(async () => {
			captureIncoming?.({
				id: uniqueId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "flashable_phrase_abc123",
				ciphertextB64: "abc",
				epochSeq: 9300,
			});
		});
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "flashable_phrase_abc123" } });
		await waitFor(() => expect(screen.getByTestId("msg-search-result")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("msg-search-result"));
		await waitFor(() => {
			const el = document.querySelector(`[data-msg-id="${uniqueId}"]`);
			expect(el).toHaveAttribute("data-jump-flash", "true");
		});
	});

	it("scrollIntoView is called on the target element when jumping", async () => {
		render(<ChatLayout />);
		const uniqueId = "env-scroll-001";
		await act(async () => {
			captureIncoming?.({
				id: uniqueId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "scrollable_phrase_xyz789",
				ciphertextB64: "abc",
				epochSeq: 9400,
			});
		});
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "scrollable_phrase_xyz789" } });
		await waitFor(() => expect(screen.getByTestId("msg-search-result")).toBeInTheDocument());
		fireEvent.click(screen.getByTestId("msg-search-result"));
		await waitFor(() => {
			expect(Element.prototype.scrollIntoView).toHaveBeenCalledWith({
				block: "center",
				behavior: "smooth",
			});
		});
	});

	it("flash clears and jump state resets after timeout", async () => {
		vi.useFakeTimers();
		render(<ChatLayout />);
		const uniqueId = "env-flash-clear-001";
		// Deliver a message with a server ID
		await act(async () => {
			captureIncoming?.({
				id: uniqueId,
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "clearable_flash_phrase_q1w2",
				ciphertextB64: "abc",
				epochSeq: 9500,
			});
		});
		// Search and click the result — use act wrapping to avoid waitFor deadlock with fake timers
		await act(async () => {
			fireEvent.change(screen.getByPlaceholderText("Search chats"), {
				target: { value: "clearable_flash_phrase_q1w2" },
			});
		});
		const result = screen.getByTestId("msg-search-result");
		await act(async () => {
			fireEvent.click(result);
		});
		// Flash should be active immediately
		const el = document.querySelector(`[data-msg-id="${uniqueId}"]`);
		expect(el).toHaveAttribute("data-jump-flash", "true");
		// Advance past the 1400ms flash duration; act flushes React state updates
		await act(async () => {
			vi.advanceTimersByTime(1500);
		});
		expect(el).not.toHaveAttribute("data-jump-flash");
	});

	it("clicking result for message without server ID still switches chat without crashing", async () => {
		render(<ChatLayout />);
		// Start on Jordan's chat
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		expect(screen.getByRole("banner")).toHaveTextContent(/jordan/i);
		// "9am at the corner cafe?" is a seed message in Maya's chat (no server ID)
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		await waitFor(() => expect(screen.getByTestId("msg-search-result")).toBeInTheDocument());
		// Click should not throw — just switches chat
		fireEvent.click(screen.getByTestId("msg-search-result"));
		await waitFor(() => expect(screen.getByRole("banner")).toHaveTextContent(/maya/i));
	});

	it("section header count is 0-free when search is empty (section not rendered)", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("msg-search-section-header")).not.toBeInTheDocument();
	});

	it("result count caps at 10 total across chats", async () => {
		render(<ChatLayout />);
		// Deliver 12 matching messages to exceed the 10-result cap
		await act(async () => {
			for (let i = 0; i < 12; i++) {
				captureIncoming?.({
					id: `env-cap-${i}`,
					senderId: "device-maya",
					groupId: MAYA_GROUP_ID,
					text: `captest_phrase_unique message ${i}`,
					ciphertextB64: "abc",
					epochSeq: 9600 + i,
				});
			}
		});
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "captest_phrase_unique" } });
		await waitFor(() =>
			expect(screen.getByTestId("msg-search-section-header")).toBeInTheDocument(),
		);
		// Should show at most 10 due to the .slice(0, 10) cap
		const results = screen.getAllByTestId("msg-search-result");
		expect(results.length).toBeLessThanOrEqual(10);
		// Header count matches actual rendered count
		expect(screen.getByTestId("msg-search-section-header")).toHaveTextContent(
			`Messages (${results.length})`,
		);
	});

	it("each message result button has a unique key (no duplicate key warnings)", async () => {
		render(<ChatLayout />);
		// Deliver two messages with same text but different IDs — previously would share key
		await act(async () => {
			captureIncoming?.({
				id: "env-key-001",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "duplicate_text_phrase_abc",
				ciphertextB64: "abc",
				epochSeq: 9700,
			});
			captureIncoming?.({
				id: "env-key-002",
				senderId: "device-maya",
				groupId: MAYA_GROUP_ID,
				text: "duplicate_text_phrase_abc",
				ciphertextB64: "abc",
				epochSeq: 9701,
			});
		});
		const searchInput = screen.getByPlaceholderText("Search chats");
		fireEvent.change(searchInput, { target: { value: "duplicate_text_phrase_abc" } });
		await waitFor(() => {
			const results = screen.getAllByTestId("msg-search-result");
			// Both results rendered (no key collision dropping one)
			expect(results.length).toBe(2);
		});
	});
});
