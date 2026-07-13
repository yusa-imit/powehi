import { act, render, screen } from "@testing-library/react";
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

describe("ChatLayout — emoji reaction toggle & reaction_remove", () => {
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

	it("peer reaction_remove removes the emoji chip when senders list becomes empty", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;
		let capturedOnReactionRemove:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction, onReactionRemove) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
				capturedOnReactionRemove = onReactionRemove;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "rr-msg-uuid-1111-111111111111";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-1",
				text: "reaction remove test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		// Add a reaction first
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "👍", "peer-dev-1");
		});
		expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();

		// Remove that reaction
		await act(async () => {
			capturedOnReactionRemove?.(
				"11111111-1111-1111-1111-111111111111",
				MSG_ID,
				"👍",
				"peer-dev-1",
			);
		});
		expect(screen.queryByTestId("reaction-chip-👍")).not.toBeInTheDocument();
	});

	it("peer reaction_remove reduces count but keeps chip when other senders remain", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;
		let capturedOnReactionRemove:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction, onReactionRemove) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
				capturedOnReactionRemove = onReactionRemove;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "rr-multi-uuid-2222-222222222222";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-a",
				text: "multi sender reaction",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});

		// Two senders react with ❤️
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "peer-dev-a");
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "peer-dev-b");
		});
		const chip = screen.getByTestId("reaction-chip-❤️");
		expect(chip).toHaveTextContent("2");

		// peer-dev-a removes their ❤️ — chip stays with count 1
		await act(async () => {
			capturedOnReactionRemove?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "peer-dev-a");
		});
		expect(screen.getByTestId("reaction-chip-❤️")).toHaveTextContent("1");
	});

	it("reaction_remove is a no-op when sender is not in the senders list", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;
		let capturedOnReactionRemove:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction, onReactionRemove) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
				capturedOnReactionRemove = onReactionRemove;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "rr-noop-uuid-3333-333333333333";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-c",
				text: "noop remove test",
				ciphertextB64: "Zg==",
				epochSeq: 3,
			});
		});

		// One sender reacts
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "😂", "peer-dev-c");
		});
		expect(screen.getByTestId("reaction-chip-😂")).toHaveTextContent("1");

		// A different device tries to remove — count stays at 1
		await act(async () => {
			capturedOnReactionRemove?.(
				"11111111-1111-1111-1111-111111111111",
				MSG_ID,
				"😂",
				"unknown-dev",
			);
		});
		expect(screen.getByTestId("reaction-chip-😂")).toHaveTextContent("1");
	});

	it("own reaction chip shows aria-pressed=true when myDeviceId matches", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-own-device", sessionToken: "tok-r" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "own-react-uuid-4444-444444444444";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-d",
				text: "own reaction highlight",
				ciphertextB64: "Zg==",
				epochSeq: 4,
			});
		});

		// myDeviceId reacts with 😮
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "😮", "my-own-device");
		});

		const chip = screen.getByTestId("reaction-chip-😮");
		expect(chip).toHaveAttribute("aria-pressed", "true");
	});

	it("peer-only reaction chip shows aria-pressed=false", async () => {
		useAuthStore.setState({ phase: "app", deviceId: "my-own-device", sessionToken: "tok-r2" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "peer-react-uuid-5555-555555555555";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-e",
				text: "peer-only reaction",
				ciphertextB64: "Zg==",
				epochSeq: 5,
			});
		});

		// A different device reacts
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "😢", "other-dev");
		});

		const chip = screen.getByTestId("reaction-chip-😢");
		expect(chip).toHaveAttribute("aria-pressed", "false");
	});

	it("reaction_remove from wrong groupId is a no-op", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		let capturedOnReaction:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;
		let capturedOnReactionRemove:
			| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
			| undefined;

		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_id, _gid, onMsg, _onPq, _onTyping, onReaction, onReactionRemove) => {
				capturedOnMessage = onMsg;
				capturedOnReaction = onReaction;
				capturedOnReactionRemove = onReactionRemove;
			},
		);
		render(<ChatLayout />);

		const MSG_ID = "rr-wronggid-uuid-6666-666666666666";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-f",
				text: "wrong gid remove",
				ciphertextB64: "Zg==",
				epochSeq: 6,
			});
		});

		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "👍", "peer-dev-f");
		});
		expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();

		// Remove from a different groupId — chip must survive
		await act(async () => {
			capturedOnReactionRemove?.(
				"99999999-9999-9999-9999-999999999999",
				MSG_ID,
				"👍",
				"peer-dev-f",
			);
		});
		expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();
	});
});
