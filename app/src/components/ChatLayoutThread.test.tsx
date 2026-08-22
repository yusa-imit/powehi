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

const MAYA_GROUP = "11111111-1111-1111-1111-111111111111";

describe("ChatLayout — message thread panel", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		Element.prototype.scrollIntoView = vi.fn();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("no 'replies' button when message has no replies", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "root-no-reply",
				groupId: MAYA_GROUP,
				senderId: "sender-1",
				text: "a standalone message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		expect(screen.queryByTestId("thread-replies-btn")).not.toBeInTheDocument();
	});

	it("'1 reply' button shown when message has 1 reply", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "root-with-one-reply",
				groupId: MAYA_GROUP,
				senderId: "sender-1",
				text: "root message",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "reply-1",
				groupId: MAYA_GROUP,
				senderId: "sender-2",
				text: "first reply",
				ciphertextB64: "Zg==",
				epochSeq: 3,
				replyTo: { messageId: "root-with-one-reply", excerpt: "root message" },
			});
		});

		const btn = screen.getByTestId("thread-replies-btn");
		expect(btn).toBeInTheDocument();
		expect(btn.textContent).toContain("1 reply");
	});

	it("'2 replies' button shown when message has 2 replies", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "root-two-replies",
				groupId: MAYA_GROUP,
				senderId: "sender-1",
				text: "two reply root",
				ciphertextB64: "Zg==",
				epochSeq: 4,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "reply-a",
				groupId: MAYA_GROUP,
				senderId: "sender-2",
				text: "reply A",
				ciphertextB64: "Zg==",
				epochSeq: 5,
				replyTo: { messageId: "root-two-replies", excerpt: "two reply root" },
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "reply-b",
				groupId: MAYA_GROUP,
				senderId: "sender-3",
				text: "reply B",
				ciphertextB64: "Zg==",
				epochSeq: 6,
				replyTo: { messageId: "root-two-replies", excerpt: "two reply root" },
			});
		});

		const btn = screen.getByTestId("thread-replies-btn");
		expect(btn).toBeInTheDocument();
		expect(btn.textContent).toContain("2 replies");
	});

	it("clicking 'replies' button opens thread panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "open-thread-root",
				groupId: MAYA_GROUP,
				senderId: "sender-1",
				text: "open this thread",
				ciphertextB64: "Zg==",
				epochSeq: 7,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "open-thread-reply",
				groupId: MAYA_GROUP,
				senderId: "sender-2",
				text: "thread reply",
				ciphertextB64: "Zg==",
				epochSeq: 8,
				replyTo: { messageId: "open-thread-root", excerpt: "open this thread" },
			});
		});

		expect(screen.queryByTestId("thread-panel")).not.toBeInTheDocument();
		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		expect(screen.getByTestId("thread-panel")).toBeInTheDocument();
	});

	it("thread panel shows correct testid", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "panel-testid-root",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "panel root",
				ciphertextB64: "Zg==",
				epochSeq: 9,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "panel-testid-reply",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "panel reply",
				ciphertextB64: "Zg==",
				epochSeq: 10,
				replyTo: { messageId: "panel-testid-root", excerpt: "panel root" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		expect(screen.getByTestId("thread-panel")).toBeInTheDocument();
	});

	it("thread panel shows root message text", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "root-text-check",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "this is the root message",
				ciphertextB64: "Zg==",
				epochSeq: 11,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "reply-text-check",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "a reply",
				ciphertextB64: "Zg==",
				epochSeq: 12,
				replyTo: { messageId: "root-text-check", excerpt: "this is the root message" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		const rootEl = screen.getByTestId("thread-root-text");
		expect(rootEl.textContent).toBe("this is the root message");
	});

	it("thread panel shows reply text", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "root-reply-text",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "some root text",
				ciphertextB64: "Zg==",
				epochSeq: 13,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "the-reply-text",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "the actual reply content",
				ciphertextB64: "Zg==",
				epochSeq: 14,
				replyTo: { messageId: "root-reply-text", excerpt: "some root text" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		const replyEl = screen.getByTestId("thread-reply-text");
		expect(replyEl.textContent).toBe("the actual reply content");
	});

	it("thread panel close button closes panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "close-root",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "close test root",
				ciphertextB64: "Zg==",
				epochSeq: 15,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "close-reply",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "close test reply",
				ciphertextB64: "Zg==",
				epochSeq: 16,
				replyTo: { messageId: "close-root", excerpt: "close test root" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		expect(screen.getByTestId("thread-panel")).toBeInTheDocument();
		fireEvent.click(screen.getByTestId("thread-panel-close"));
		expect(screen.queryByTestId("thread-panel")).not.toBeInTheDocument();
	});

	it("thread panel shows reply count", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "count-root",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "count root",
				ciphertextB64: "Zg==",
				epochSeq: 17,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "count-reply-1",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "count reply 1",
				ciphertextB64: "Zg==",
				epochSeq: 18,
				replyTo: { messageId: "count-root", excerpt: "count root" },
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "count-reply-2",
				groupId: MAYA_GROUP,
				senderId: "s3",
				text: "count reply 2",
				ciphertextB64: "Zg==",
				epochSeq: 19,
				replyTo: { messageId: "count-root", excerpt: "count root" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		const countEl = screen.getByTestId("thread-reply-count");
		expect(countEl.textContent).toContain("2 replies");
	});

	it("thread panel has composer (textarea + send button)", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "composer-root",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "composer root",
				ciphertextB64: "Zg==",
				epochSeq: 20,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "composer-reply",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "composer reply",
				ciphertextB64: "Zg==",
				epochSeq: 21,
				replyTo: { messageId: "composer-root", excerpt: "composer root" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		expect(screen.getByTestId("thread-compose")).toBeInTheDocument();
		expect(screen.getByTestId("thread-send")).toBeInTheDocument();
	});

	it("sending in thread panel adds reply with replyTo pointing to root", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await act(async () => {
			capturedOnMessage?.({
				id: "send-root-id",
				groupId: MAYA_GROUP,
				senderId: "s1",
				text: "send root",
				ciphertextB64: "Zg==",
				epochSeq: 22,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: "send-reply-seed",
				groupId: MAYA_GROUP,
				senderId: "s2",
				text: "seed reply",
				ciphertextB64: "Zg==",
				epochSeq: 23,
				replyTo: { messageId: "send-root-id", excerpt: "send root" },
			});
		});

		fireEvent.click(screen.getByTestId("thread-replies-btn"));
		const textarea = screen.getByTestId("thread-compose") as HTMLTextAreaElement;
		fireEvent.change(textarea, { target: { value: "my new thread reply" } });
		fireEvent.click(screen.getByTestId("thread-send"));

		// After sending, "2 replies" button should appear (was 1, now 2)
		const btn = screen.getByTestId("thread-replies-btn");
		expect(btn.textContent).toContain("2 replies");
	});
});
