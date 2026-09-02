/**
 * ChatLayout — client-local "block contact" feature.
 *
 * Closes a real gap: the "Block · Report" button in the InfoPanel has rendered
 * with zero handler since the very first mock-UI commit (786cf6f, May 2026).
 * Follows the exact same per-chat local-only boolean preference pattern as
 * muted (schema v12, ChatLayoutMute.test.tsx) and archived (schema v18,
 * ChatLayoutArchive.test.tsx) — persisted to Dexie GroupRow.blocked (schema
 * v28). Unlike muting, a blocked chat's incoming message must not be appended
 * to the visible message list or update the sidebar preview — see the
 * "incoming message to blocked chat" suite below.
 */
import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesApi from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import * as NotificationSoundModule from "../lib/notificationSound";
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

// Jordan's mlsGroupId from SEED_CHATS
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

function openInfoPanel(chatName: RegExp | string) {
	const chatBtn = screen.getAllByRole("button", { name: chatName })[0];
	fireEvent.click(chatBtn);
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
}

describe("ChatLayout — block contact", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		// Several tests below seed/mutate Jordan's GroupRow (block/unblock persistence,
		// rehydration) without always resetting it — clear defensively so no test's
		// leftover `blocked`/`muted` row leaks into a later test's hydration (a race
		// between this async Dexie read and the synchronous test assertions otherwise
		// makes failures order-dependent/flaky).
		await db.groups.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	describe("button confirm/cancel flow", () => {
		it("Block button is visible in InfoPanel, unblocked state", () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			expect(screen.getByTestId("block-button")).toBeInTheDocument();
			expect(screen.getByTestId("block-button")).toHaveTextContent("Block");
			expect(screen.queryByTestId("unblock-button")).not.toBeInTheDocument();
		});

		it("Clicking Block shows an inline confirmation prompt", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			expect(screen.getByTestId("block-cancel")).toBeInTheDocument();
			expect(screen.getByTestId("block-confirm-btn")).toBeInTheDocument();
			expect(screen.getByTestId("block-confirm")).toHaveTextContent("Block this contact?");
		});

		it("Cancel hides the confirmation prompt and leaves the chat unblocked", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-cancel"));
			await waitFor(() => expect(screen.queryByTestId("block-confirm")).not.toBeInTheDocument());
			expect(screen.getByTestId("block-button")).toBeInTheDocument();
			expect(screen.queryByTestId("unblock-button")).not.toBeInTheDocument();
		});

		it("Confirming Block switches the InfoPanel to a single-click Unblock button", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			expect(screen.queryByTestId("block-button")).not.toBeInTheDocument();
			expect(screen.queryByTestId("block-confirm")).not.toBeInTheDocument();
		});

		it("Unblock is a single click — no confirmation prompt", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("unblock-button"));
			await waitFor(() => expect(screen.getByTestId("block-button")).toBeInTheDocument());
			expect(screen.queryByTestId("block-confirm")).not.toBeInTheDocument();
		});

		it("blocked chat shows the blocked indicator in the sidebar", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getAllByTestId("blocked-icon")).toHaveLength(1));
		});

		it("blocked chat shows the Blocked badge in the InfoPanel header", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			expect(screen.queryByTestId("info-panel-blocked-badge")).not.toBeInTheDocument();
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() =>
				expect(screen.getByTestId("info-panel-blocked-badge")).toBeInTheDocument(),
			);
		});
	});

	describe("handleToggleBlock persistence", () => {
		it("persists the blocked flag to Dexie GroupRow so it survives a reload", async () => {
			await db.groups.clear();
			await db.groups.add({
				id: JORDAN_GROUP_ID,
				name: "Jordan",
				mlsStateB64: "",
				lastActivity: Date.now(),
			});
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(async () => {
				const row = await db.groups.get(JORDAN_GROUP_ID);
				expect(row?.blocked).toBe(true);
			});
		});

		it("persists false back to Dexie GroupRow when unblocked", async () => {
			await db.groups.clear();
			await db.groups.add({
				id: JORDAN_GROUP_ID,
				name: "Jordan",
				mlsStateB64: "",
				lastActivity: Date.now(),
				blocked: true,
			});
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("unblock-button"));
			await waitFor(async () => {
				const row = await db.groups.get(JORDAN_GROUP_ID);
				expect(row?.blocked).toBe(false);
			});
		});

		it("rehydrates a persisted blocked flag from Dexie when switching to that chat", async () => {
			await db.groups.clear();
			await db.groups.add({
				id: JORDAN_GROUP_ID,
				name: "Jordan",
				mlsStateB64: "",
				lastActivity: Date.now(),
				blocked: true,
			});
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
		});

		it("block is chat-specific — blocking Jordan leaves Maya unblocked", async () => {
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			// Switch to Maya — InfoPanel stays open and now shows Maya's data
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			await waitFor(() => expect(screen.getByTestId("block-button")).toBeInTheDocument());
		});
	});

	describe("incoming message to a blocked chat", () => {
		it("does NOT increment the unread badge", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);
			// Select Jordan to clear its existing 2-unread count, then block it
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			// Switch to Maya — Jordan becomes a blocked background chat
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			await act(async () => {
				capturedOnMessage?.({
					id: "block-suppress-uuid-0001",
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "This should be silent and hidden",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});
			expect(screen.queryByTestId("unread-badge")).not.toBeInTheDocument();
		});

		it("does NOT trigger vibration", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			const vibrateSpy = vi.fn();
			Object.defineProperty(navigator, "vibrate", { value: vibrateSpy, configurable: true });
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			vibrateSpy.mockClear();
			await act(async () => {
				capturedOnMessage?.({
					id: "block-suppress-uuid-0002",
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Silent message",
					ciphertextB64: "Zg==",
					epochSeq: 2,
				});
			});
			expect(vibrateSpy).not.toHaveBeenCalled();
		});

		it("does NOT trigger a notification sound", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			const soundSpy = vi.spyOn(NotificationSoundModule, "playNotificationSound");
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			soundSpy.mockClear();
			await act(async () => {
				capturedOnMessage?.({
					id: "block-suppress-uuid-0002b",
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Silent message",
					ciphertextB64: "Zg==",
					epochSeq: 2,
				});
			});
			expect(soundSpy).not.toHaveBeenCalled();
		});

		it("blocking and unblocking never send anything over the wire — no MLS encrypt, no API call", async () => {
			const sendMessageSpy = vi.spyOn(MessagesApi, "sendMessage");
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			MOCK_WORKER.mlsEncrypt.mockClear();
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("unblock-button"));
			await waitFor(() => expect(screen.getByTestId("block-button")).toBeInTheDocument());
			expect(MOCK_WORKER.mlsEncrypt).not.toHaveBeenCalled();
			expect(sendMessageSpy).not.toHaveBeenCalled();
		});

		it("is NOT appended to the visible message list or sidebar preview, but IS persisted to Dexie", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			// Switch to Maya — Jordan becomes a blocked background chat. (A blocked chat
			// that's still the *open/active* conversation is a separate, pre-existing Dexie
			// live-rehydration path — out of scope here; see handleIncoming's doc comment.)
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);

			const knownId = "block-persist-uuid-0003";
			await act(async () => {
				capturedOnMessage?.({
					id: knownId,
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Hidden from the UI but kept in Dexie",
					ciphertextB64: "Zg==",
					epochSeq: 3,
				});
			});

			// Not appended anywhere in the DOM — neither as a message bubble (Jordan's
			// conversation isn't even rendered while Maya is active) nor as the Jordan
			// sidebar row's preview text (that row stays mounted regardless of which
			// chat is active, so a `last` update would surface here).
			expect(screen.queryByText("Hidden from the UI but kept in Dexie")).not.toBeInTheDocument();

			// But it IS persisted to Dexie so history survives an eventual unblock.
			await waitFor(async () => {
				const row = await db.messages.get(knownId);
				expect(row).toBeTruthy();
			});
		});

		it("mirrors muted behavior when the chat is BOTH muted and blocked (independent flags)", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);
			openInfoPanel(/jordan/i);
			// Mute Jordan
			fireEvent.click(screen.getByRole("button", { name: /mute/i }));
			await waitFor(() =>
				expect(screen.getByRole("button", { name: /mute/i })).toHaveTextContent("On"),
			);
			// Block Jordan too
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
			// Switch to Maya — Jordan becomes a muted+blocked background chat.
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			await act(async () => {
				capturedOnMessage?.({
					id: "block-and-mute-uuid-0004",
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Silent either way",
					ciphertextB64: "Zg==",
					epochSeq: 4,
				});
			});
			expect(screen.queryByTestId("unread-badge")).not.toBeInTheDocument();
			await waitFor(async () => {
				const row = await db.messages.get("block-and-mute-uuid-0004");
				expect(row).toBeTruthy();
			});
		});

		it("incoming message to an unblocked background chat DOES increment unread and IS appended", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			await act(async () => {
				capturedOnMessage?.({
					id: "unblocked-allow-uuid-0005",
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "This should count",
					ciphertextB64: "Zg==",
					epochSeq: 5,
				});
			});
			await waitFor(() => expect(screen.getByTestId("unread-badge")).toBeInTheDocument());
		});
	});

	// Regression coverage for security-auditor findings (this cycle): `useMessages` only
	// polls the ACTIVE group, so every one of these signals can only ever arrive while the
	// blocked chat is also the open/active conversation — the exact scenario the "incoming
	// message" suite above documents as out of scope for the plain-message path. A blocked
	// contact must not be able to inject visible content or state changes through any of
	// these side channels either.
	describe("peer-driven signals suppressed while the blocked chat is open/active", () => {
		function mockUseMessages() {
			const captured: {
				onMessage?: (msg: IncomingMessage) => void;
				onTyping?: (groupId: string) => void;
				onReaction?: (groupId: string, targetId: string, emoji: string, senderId: string) => void;
				onEdit?: (
					groupId: string,
					targetMessageId: string,
					newText: string,
					senderDeviceId: string,
				) => void;
				onPin?: (groupId: string, targetMessageId: string, action: "pin" | "unpin") => void;
				onPresence?: (groupId: string, status: "online" | "offline") => void;
			} = {};
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					onMessage,
					_onPqBinding,
					onTyping,
					onReaction,
					_onReactionRemove,
					_onReadReceipt,
					_onDeliveryReceipt,
					onEdit,
					_onDelete,
					onPin,
					onPresence,
				) => {
					captured.onMessage = onMessage;
					captured.onTyping = onTyping;
					captured.onReaction = onReaction;
					captured.onEdit = onEdit;
					captured.onPin = onPin;
					captured.onPresence = onPresence;
				},
			);
			return captured;
		}

		async function blockActiveJordan() {
			openInfoPanel(/jordan/i);
			fireEvent.click(screen.getByTestId("block-button"));
			await waitFor(() => expect(screen.getByTestId("block-confirm")).toBeInTheDocument());
			fireEvent.click(screen.getByTestId("block-confirm-btn"));
			await waitFor(() => expect(screen.getByTestId("unblock-button")).toBeInTheDocument());
		}

		it("an incoming edit does not rewrite an already-visible bubble's text", async () => {
			const captured = mockUseMessages();
			render(<ChatLayout />);
			const knownId = "block-edit-target-uuid-0006";
			// Deliver the original message before blocking so it's a real, already-rendered
			// bubble (not a seed message with no `id`, which an edit can't target by id).
			// Select Jordan (without opening InfoPanel yet — blockActiveJordan does that,
			// and InfoPanel's "info" button toggles closed on a second click).
			fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
			await act(async () => {
				captured.onMessage?.({
					id: knownId,
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Original text",
					ciphertextB64: "Zg==",
					epochSeq: 6,
				});
			});
			// "Original text" renders both in the message bubble and the sidebar preview —
			// use getAllByText throughout rather than getByText.
			await waitFor(() => expect(screen.getAllByText("Original text").length).toBeGreaterThan(0));
			await blockActiveJordan();
			await act(async () => {
				captured.onEdit?.(JORDAN_GROUP_ID, knownId, "injected while blocked", "peer-device-block");
			});
			expect(screen.queryByText("injected while blocked")).not.toBeInTheDocument();
			expect(screen.getAllByText("Original text").length).toBeGreaterThan(0);
		});

		it("an incoming typing signal does not show the typing indicator", async () => {
			const captured = mockUseMessages();
			render(<ChatLayout />);
			await blockActiveJordan();
			await act(async () => {
				captured.onTyping?.(JORDAN_GROUP_ID);
			});
			expect(screen.queryByTestId("typing-bubble")).not.toBeInTheDocument();
		});

		it("an incoming reaction does not render on the target message", async () => {
			const captured = mockUseMessages();
			render(<ChatLayout />);
			const knownId = "block-reaction-target-uuid-0007";
			fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
			await act(async () => {
				captured.onMessage?.({
					id: knownId,
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "React to this",
					ciphertextB64: "Zg==",
					epochSeq: 7,
				});
			});
			await waitFor(() => expect(screen.getAllByText("React to this").length).toBeGreaterThan(0));
			await blockActiveJordan();
			await act(async () => {
				captured.onReaction?.(JORDAN_GROUP_ID, knownId, "👍", "peer-device-block");
			});
			expect(screen.queryByTestId("reaction-chip-👍")).not.toBeInTheDocument();
		});

		it("an incoming pin does not show the pinned-message banner", async () => {
			const captured = mockUseMessages();
			render(<ChatLayout />);
			const knownId = "block-pin-target-uuid-0008";
			fireEvent.click(screen.getAllByRole("button", { name: /jordan/i })[0]);
			await act(async () => {
				captured.onMessage?.({
					id: knownId,
					senderId: "peer-device-block",
					groupId: JORDAN_GROUP_ID,
					text: "Pin candidate",
					ciphertextB64: "Zg==",
					epochSeq: 8,
				});
			});
			await waitFor(() => expect(screen.getAllByText("Pin candidate").length).toBeGreaterThan(0));
			await blockActiveJordan();
			await act(async () => {
				captured.onPin?.(JORDAN_GROUP_ID, knownId, "pin");
			});
			expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
		});

		it("an incoming presence update does not mark the chat online", async () => {
			const captured = mockUseMessages();
			render(<ChatLayout />);
			await blockActiveJordan();
			expect(screen.queryByText("online")).not.toBeInTheDocument();
			await act(async () => {
				captured.onPresence?.(JORDAN_GROUP_ID, "online");
			});
			expect(screen.queryByText("online")).not.toBeInTheDocument();
			await waitFor(async () => {
				const row = await db.groups.get(JORDAN_GROUP_ID);
				expect(row?.lastSeenAt).toBeUndefined();
			});
		});
	});
});
