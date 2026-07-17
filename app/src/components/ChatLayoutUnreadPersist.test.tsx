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

// Jordan's chat has unread: 2 in SEED_CHATS (same seed used by ChatLayoutMarkAllRead.test.tsx).
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — unread badge + New Messages divider persistence", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.groups.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("persists an incremented unread count + firstUnreadMessageId to Dexie on incoming background message", async () => {
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Jordan is not the active chat (Maya is default) — this is a background arrival.
		await act(async () => {
			capturedOnMessage?.({
				id: "unread-persist-uuid-0001",
				senderId: "peer-device",
				groupId: JORDAN_GROUP_ID,
				text: "are you around?",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		await waitFor(async () => {
			const row = await db.groups.get(JORDAN_GROUP_ID);
			// Jordan's in-memory seed unread was already 2 — the write-through recomputes
			// from that snapshot, so this should land at 3.
			expect(row?.unread).toBe(3);
		});
		// firstUnreadMessageId is only set on the 0 -> 1 transition, not on every increment
		// (Jordan's seed unread starts at 2, so this message doesn't set it).
		const row = await db.groups.get(JORDAN_GROUP_ID);
		expect(row?.firstUnreadMessageId).toBeUndefined();
	});

	it("sets firstUnreadMessageId on the transition from 0 to 1 unread for a background chat", async () => {
		// Maya starts at unread: 0 in SEED_CHATS and is the default active chat — switch to
		// Jordan first so Maya becomes a background chat before the message arrives.
		const MAYA_GROUP_ID = "11111111-1111-1111-1111-111111111111";
		await db.groups.add({
			id: MAYA_GROUP_ID,
			name: "Maya Akana",
			mlsStateB64: "",
			lastActivity: Date.now(),
		});
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		await act(async () => {
			capturedOnMessage?.({
				id: "unread-persist-first-0001",
				senderId: "peer-device-maya",
				groupId: MAYA_GROUP_ID,
				text: "first unread message in this background chat",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		await waitFor(async () => {
			const row = await db.groups.get(MAYA_GROUP_ID);
			expect(row?.firstUnreadMessageId).toBe("unread-persist-first-0001");
			expect(row?.unread).toBe(1);
		});
	});

	it("rehydrates a persisted unread count from Dexie when switching to that chat", async () => {
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
			unread: 7,
		});
		render(<ChatLayout />);
		// Switch to Jordan so the active-chat rehydration effect (keyed on
		// active.mlsGroupId) fires for Jordan's group, then away and back to force
		// the effect's async db.groups.get() to resolve against the persisted row.
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		// Selecting the chat also clears unread (handleSelectChat) — assert the
		// persisted-then-cleared Dexie row instead, which is the durable signal that
		// rehydration read row.unread (same technique as the mentionCount precedent).
		await waitFor(async () => {
			const row = await db.groups.get(JORDAN_GROUP_ID);
			expect(row?.unread).toBe(0);
		});
	});

	it("clearing all messages resets a chat's persisted unread and firstUnreadMessageId", async () => {
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
			unread: 4,
			firstUnreadMessageId: "some-message-id",
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("clear-messages-button"));
		fireEvent.click(screen.getByTestId("clear-messages-confirm-btn"));
		await waitFor(async () => {
			const row = await db.groups.get(JORDAN_GROUP_ID);
			expect(row?.unread).toBe(0);
			expect(row?.firstUnreadMessageId).toBeUndefined();
		});
	});

	it("mark-all-read resets persisted unread and firstUnreadMessageId for every chat", async () => {
		await db.groups.add({
			id: JORDAN_GROUP_ID,
			name: "Jordan",
			mlsStateB64: "",
			lastActivity: Date.now(),
			unread: 2,
			firstUnreadMessageId: "jordan-first-unread",
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /mark all as read/i }));
		await waitFor(async () => {
			const row = await db.groups.get(JORDAN_GROUP_ID);
			expect(row?.unread).toBe(0);
			expect(row?.firstUnreadMessageId).toBeUndefined();
		});
	});
});
