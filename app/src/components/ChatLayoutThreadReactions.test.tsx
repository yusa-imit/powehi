import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
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

// Maya's chat is the default active chat (id="maya").
const MAYA_GROUP = "11111111-1111-1111-1111-111111111111";

describe("ChatLayout — thread panel emoji reactions", () => {
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

	/** Helper: set up root + reply injection, then open the thread panel. */
	async function setupAndOpenPanel(opts: {
		capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		rootId?: string;
		replyId?: string;
		rootText?: string;
		replyText?: string;
	}) {
		const {
			capturedOnMessage,
			rootId = "tr-root-1",
			replyId = "tr-reply-1",
			rootText = "thread root message",
			replyText = "a reply in thread",
		} = opts;

		await act(async () => {
			capturedOnMessage?.({
				id: rootId,
				groupId: MAYA_GROUP,
				senderId: "peer-s1",
				text: rootText,
				ciphertextB64: "Zg==",
				epochSeq: 50,
			});
		});
		await act(async () => {
			capturedOnMessage?.({
				id: replyId,
				groupId: MAYA_GROUP,
				senderId: "peer-s2",
				text: replyText,
				ciphertextB64: "Zg==",
				epochSeq: 51,
				replyTo: { messageId: rootId, excerpt: rootText },
			});
		});

		const replyBtn = screen.getByTestId("thread-replies-btn");
		fireEvent.click(replyBtn);
	}

	it("root message with peer reaction shows reaction chip in thread panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((gId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		await act(async () => {
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "👍", "peer-s1");
		});

		expect(screen.getByTestId("thread-reaction-chip-👍")).toBeInTheDocument();
	});

	it("reply message with peer reaction shows reaction chip in thread panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((gId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		await act(async () => {
			capturedOnReaction?.(MAYA_GROUP, "tr-reply-1", "❤️", "peer-s2");
		});

		expect(screen.getByTestId("thread-reaction-chip-❤️")).toBeInTheDocument();
	});

	it("reaction chip shows correct sender count", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((gId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		await act(async () => {
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "😂", "peer-s1");
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "😂", "peer-s2");
		});

		const chip = screen.getByTestId("thread-reaction-chip-😂");
		expect(chip).toHaveTextContent("2");
	});

	it("hovering root message card shows emoji react row", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		fireEvent.mouseEnter(cards[0]); // root is first card

		expect(screen.getByTestId("thread-react-row")).toBeInTheDocument();
	});

	it("hovering reply card shows emoji react row", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		// cards[0] = root (isRoot), cards[1] = reply
		fireEvent.mouseEnter(cards[1]);

		expect(screen.getByTestId("thread-react-row")).toBeInTheDocument();
	});

	it("react row contains all 6 allowed emoji buttons", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		fireEvent.mouseEnter(cards[0]);

		for (const emoji of ["👍", "❤️", "😂", "😮", "😢", "😡"]) {
			expect(screen.getByTestId(`thread-react-btn-${emoji}`)).toBeInTheDocument();
		}
	});

	it("clicking emoji react button triggers mlsEncrypt", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-dev", sessionToken: "tok-tr" });

		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		MOCK_WORKER.mlsEncrypt.mockClear();
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		fireEvent.mouseEnter(cards[0]);

		await act(async () => {
			fireEvent.click(screen.getByTestId("thread-react-btn-👍"));
		});

		expect(MOCK_WORKER.mlsEncrypt).toHaveBeenCalled();
	});

	it("no reaction chips when thread message has no reactions", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		expect(screen.queryByTestId("thread-reaction-chips")).not.toBeInTheDocument();
	});

	it("mouse leave removes react row", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		fireEvent.mouseEnter(cards[0]);
		expect(screen.getByTestId("thread-react-row")).toBeInTheDocument();

		fireEvent.mouseLeave(cards[0]);
		expect(screen.queryByTestId("thread-react-row")).not.toBeInTheDocument();
	});

	it("multiple different emojis each show separate chips", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((gId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		await act(async () => {
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "👍", "peer-s1");
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "❤️", "peer-s2");
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "😂", "peer-s3");
		});

		expect(screen.getByTestId("thread-reaction-chip-👍")).toBeInTheDocument();
		expect(screen.getByTestId("thread-reaction-chip-❤️")).toBeInTheDocument();
		expect(screen.getByTestId("thread-reaction-chip-😂")).toBeInTheDocument();
	});

	it("react row absent for deleted reply in thread panel", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnDelete: ((gId: string, msgId: string) => void) | undefined;

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

		await setupAndOpenPanel({
			capturedOnMessage: capturedOnMessage,
			replyId: "tr-del-reply",
		});

		// Mark the reply deleted (only "them" messages can be deleted via handleIncomingDelete)
		await act(async () => {
			capturedOnDelete?.(MAYA_GROUP, "tr-del-reply");
		});

		const cards = screen.getAllByTestId("thread-msg-card");
		// Hover reply card (index 1)
		fireEvent.mouseEnter(cards[1]);

		expect(screen.queryByTestId("thread-react-row")).not.toBeInTheDocument();
	});

	it("react button aria-labels contain the emoji name", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		const cards = screen.getAllByTestId("thread-msg-card");
		fireEvent.mouseEnter(cards[0]);

		expect(screen.getByRole("button", { name: /React with 👍/i })).toBeInTheDocument();
	});

	it("thread panel shows reaction chips container when reactions exist", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((gId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		await setupAndOpenPanel({ capturedOnMessage: capturedOnMessage });

		await act(async () => {
			capturedOnReaction?.(MAYA_GROUP, "tr-root-1", "😮", "peer-s1");
		});

		expect(screen.getByTestId("thread-reaction-chips")).toBeInTheDocument();
	});
});
