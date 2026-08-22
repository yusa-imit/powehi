import { act, fireEvent, render, screen, within } from "@testing-library/react";
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

const DESIGN_TEAM_GROUP_ID = "44444444-4444-4444-4444-444444444444";

describe("ChatLayout — @mention highlighting in message bubbles", () => {
	beforeEach(async () => {
		useAuthStore.setState({ myHandle: null });
		await db.verifiedContacts.clear();
		await db.messages.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("@all in seed message renders as self-mention chip", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		// The seed has "@you can you review the final mockup? @all feedback welcome"
		// @all is always treated as self-mention regardless of myHandle
		const selfChips = screen.getAllByTestId("mention-self");
		expect(selfChips.length).toBeGreaterThanOrEqual(1);
		const allChip = selfChips.find((el) => el.textContent === "@all");
		expect(allChip).toBeTruthy();
	});

	it("@handle that is not myHandle renders as other-mention chip", () => {
		useAuthStore.setState({ myHandle: "alice" });
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		// @you in the seed message — myHandle is "alice", so @you is other-mention
		const otherChips = screen.getAllByTestId("mention-other");
		const youChip = otherChips.find((el) => el.textContent === "@you");
		expect(youChip).toBeTruthy();
	});

	it("@myHandle in an incoming message renders as self-mention chip", async () => {
		useAuthStore.setState({ myHandle: "alice" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0001",
				senderId: "peer-a",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "hey @alice can you review this?",
				ciphertextB64: "Zg==",
				epochSeq: 10,
			});
		});
		const selfChips = screen.getAllByTestId("mention-self");
		const aliceChip = selfChips.find((el) => el.textContent === "@alice");
		expect(aliceChip).toBeTruthy();
	});

	it("self-mention chip has orange color style", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		const selfChips = screen.getAllByTestId("mention-self");
		const allChip = selfChips.find((el) => el.textContent === "@all");
		expect(allChip).toHaveStyle({ color: "#FF8A3D" });
	});

	it("other-mention chip has a muted color distinct from self-mention", () => {
		useAuthStore.setState({ myHandle: "alice" });
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		const otherChips = screen.getAllByTestId("mention-other");
		expect(otherChips.length).toBeGreaterThanOrEqual(1);
		// Other-mention chip must NOT have the orange self-mention color
		for (const chip of otherChips) {
			expect(chip).not.toHaveStyle({ color: "#FF8A3D" });
		}
	});

	it("messages without @mention have no mention chips", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0002",
				senderId: "peer-a",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "this is a plain message with no at-signs",
				ciphertextB64: "Zg==",
				epochSeq: 11,
			});
		});
		// The plain incoming message itself should not add any mention chips
		// (seed messages may have some — we just verify the plain text doesn't add any)
		const bubbles = screen.getAllByTestId("message-bubble");
		const plainBubble = bubbles.find((b) =>
			within(b).queryByText(/plain message with no at-signs/),
		);
		expect(plainBubble).toBeTruthy();
		if (plainBubble) {
			expect(within(plainBubble).queryByTestId("mention-self")).toBeNull();
			expect(within(plainBubble).queryByTestId("mention-other")).toBeNull();
		}
	});

	it("message with both @myHandle and @all shows two self-mention chips", async () => {
		useAuthStore.setState({ myHandle: "alice" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0003",
				senderId: "peer-a",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "@alice and @all please check the mockup",
				ciphertextB64: "Zg==",
				epochSeq: 12,
			});
		});
		const bubbles = screen.getAllByTestId("message-bubble");
		const targetBubble = bubbles.find((b) => within(b).queryByText(/please check the mockup/));
		expect(targetBubble).toBeTruthy();
		if (targetBubble) {
			const selfChips = within(targetBubble).getAllByTestId("mention-self");
			expect(selfChips.length).toBe(2);
		}
	});

	it("@mention and @otherHandle in same message shows both chip types", async () => {
		useAuthStore.setState({ myHandle: "alice" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0004",
				senderId: "peer-a",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "hey @alice see what @jordan said",
				ciphertextB64: "Zg==",
				epochSeq: 13,
			});
		});
		const bubbles = screen.getAllByTestId("message-bubble");
		const targetBubble = bubbles.find((b) => within(b).queryByText(/see what/));
		expect(targetBubble).toBeTruthy();
		if (targetBubble) {
			expect(within(targetBubble).getByTestId("mention-self")).toHaveTextContent("@alice");
			expect(within(targetBubble).getByTestId("mention-other")).toHaveTextContent("@jordan");
		}
	});

	it("@mention matching is case-insensitive for self-mention", async () => {
		useAuthStore.setState({ myHandle: "Alice" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0005",
				senderId: "peer-a",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "pinging @alice lowercase version",
				ciphertextB64: "Zg==",
				epochSeq: 14,
			});
		});
		const bubbles = screen.getAllByTestId("message-bubble");
		const targetBubble = bubbles.find((b) => within(b).queryByText(/lowercase version/));
		expect(targetBubble).toBeTruthy();
		if (targetBubble) {
			// myHandle is "Alice" (capital A), mention is @alice (lowercase) — should still be self-mention
			const selfChips = within(targetBubble).getAllByTestId("mention-self");
			expect(selfChips.find((el) => el.textContent === "@alice")).toBeTruthy();
		}
	});

	it("mention chips render in DM chats when text contains @handle", async () => {
		useAuthStore.setState({ myHandle: "alice" });
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Open the first DM (Maya Akana)
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		await act(async () => {
			capturedOnMessage?.({
				id: "mh-test-0006",
				senderId: "peer-maya",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "I sent the link to @alice",
				ciphertextB64: "Zg==",
				epochSeq: 20,
			});
		});
		const selfChips = screen.getAllByTestId("mention-self");
		expect(selfChips.find((el) => el.textContent === "@alice")).toBeTruthy();
	});
});
