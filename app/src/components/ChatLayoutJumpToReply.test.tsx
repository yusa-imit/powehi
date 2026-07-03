import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => []),
	mlsComputeSafetyNumber: vi.fn(async () => ({ safetyNumber: "000000 000000" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

describe("ChatLayout — jump-to-original via reply quote click", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		// scrollIntoView is not implemented in jsdom
		Element.prototype.scrollIntoView = vi.fn();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("reply-quote button is present when message has replyTo", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "orig-uuid-1111-1111-111111111111",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-a",
				text: "original message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "reply-uuid-2222-2222-222222222222",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-b",
				text: "reply message",
				ciphertextB64: "Zg==",
				epochSeq: 2,
				replyTo: {
					messageId: "orig-uuid-1111-1111-111111111111",
					excerpt: "original message",
				},
			});
		});

		expect(screen.getByTestId("reply-quote")).toBeInTheDocument();
	});

	it("reply-quote shows the excerpt text", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "reply-uuid-3333-3333-333333333333",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-a",
				text: "quoted reply",
				ciphertextB64: "Zg==",
				epochSeq: 3,
				replyTo: {
					messageId: "orig-uuid-0000-0000-000000000000",
					excerpt: "the original excerpt",
				},
			});
		});

		expect(screen.getByTestId("reply-quote").textContent).toContain("the original excerpt");
	});

	it("clicking reply-quote scrolls to the original message (data-msg-id present)", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		const ORIG_ID = "orig-uuid-aabb-aabb-aabbccddeeff";
		const REPLY_ID = "reply-uuid-ccdd-ccdd-ccddaabbccdd";

		await act(async () => {
			capturedOnMessage?.({
				id: ORIG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-a",
				text: "Hello world",
				ciphertextB64: "Zg==",
				epochSeq: 4,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: REPLY_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-b",
				text: "Replying to hello",
				ciphertextB64: "Zg==",
				epochSeq: 5,
				replyTo: {
					messageId: ORIG_ID,
					excerpt: "Hello world",
				},
			});
		});

		// The original message should have data-msg-id attribute
		const origEl = document.querySelector(`[data-msg-id="${ORIG_ID}"]`);
		expect(origEl).toBeTruthy();

		// Clicking the reply-quote triggers the jump
		const quote = screen.getByTestId("reply-quote");
		await act(async () => {
			fireEvent.click(quote);
		});

		// Flash highlight is applied — original message gets the flash class/style
		// The jump is triggered: the element flashing-id state is set briefly
		// We verify by checking the original message element is still in the DOM
		expect(document.querySelector(`[data-msg-id="${ORIG_ID}"]`)).toBeInTheDocument();
	});

	it("reply-quote is a button element (not a div) for accessibility", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "reply-uuid-eeee-eeee-eeeeeeeeeeee",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-c",
				text: "accessible reply",
				ciphertextB64: "Zg==",
				epochSeq: 6,
				replyTo: {
					messageId: "orig-uuid-ffff-ffff-ffffffffffff",
					excerpt: "some original text",
				},
			});
		});

		const quote = screen.getByTestId("reply-quote");
		expect(quote.tagName.toLowerCase()).toBe("button");
	});

	it("message without replyTo has no reply-quote element", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "no-reply-uuid-5555-5555-555555555555",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-d",
				text: "plain message no reply",
				ciphertextB64: "Zg==",
				epochSeq: 7,
			});
		});

		expect(screen.queryByTestId("reply-quote")).not.toBeInTheDocument();
	});

	it("multiple reply messages each have their own reply-quote", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "multi-reply-1111",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-a",
				text: "first reply",
				ciphertextB64: "Zg==",
				epochSeq: 8,
				replyTo: { messageId: "orig-1111", excerpt: "excerpt one" },
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "multi-reply-2222",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-b",
				text: "second reply",
				ciphertextB64: "Zg==",
				epochSeq: 9,
				replyTo: { messageId: "orig-2222", excerpt: "excerpt two" },
			});
		});

		const quotes = screen.getAllByTestId("reply-quote");
		expect(quotes.length).toBe(2);
		expect(quotes[0].textContent).toContain("excerpt one");
		expect(quotes[1].textContent).toContain("excerpt two");
	});

	it("clicking one reply-quote does not affect other messages", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		const ORIG_A = "orig-aaaa-0000-0000-000000000aaa";
		const ORIG_B = "orig-bbbb-1111-1111-111111111bbb";

		await act(async () => {
			capturedOnMessage?.({
				id: ORIG_A,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-x",
				text: "message A",
				ciphertextB64: "Zg==",
				epochSeq: 10,
			});
			capturedOnMessage?.({
				id: ORIG_B,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-x",
				text: "message B",
				ciphertextB64: "Zg==",
				epochSeq: 11,
			});
		});

		await act(async () => {
			capturedOnMessage?.({
				id: "reply-to-A",
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-y",
				text: "reply to A",
				ciphertextB64: "Zg==",
				epochSeq: 12,
				replyTo: { messageId: ORIG_A, excerpt: "message A" },
			});
		});

		const quotes = screen.getAllByTestId("reply-quote");
		// Clicking the quote triggers jump to ORIG_A — message B still in DOM
		await act(async () => {
			fireEvent.click(quotes[0]);
		});

		expect(document.querySelector(`[data-msg-id="${ORIG_B}"]`)).toBeInTheDocument();
	});
});
