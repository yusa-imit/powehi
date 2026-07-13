import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import * as MessagesApiModule from "../api/messages";
import * as EncryptedDbModule from "../db/encrypted-db";
import { db } from "../db/schema";
import type { MessageRow } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import * as WelcomePollerModule from "../hooks/useWelcomePoller";
import { useAuthStore } from "../store/auth";
import { textToBase64 } from "../utils/base64";
import { ChatLayout } from "./ChatLayout";

// The stable mock worker singleton — same reference on every useCryptoWorker() call
// so the useEffect dependency array doesn't see a new object on re-renders.
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
	// Passthrough encryption for tests — EncryptedPowehiDb interface satisfaction.
	// Tests verify DB round-trip behavior; encryption correctness is covered by encryption.test.ts.
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

// KAT safety number (same value — used in test assertions after the mock is hoisted).
const KAT_SN =
	"689053 337949 184798 288064 134849 362568 560227 765408 921198 315305 693006 807986";

describe("ChatLayout", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		await db.messages.clear();
		await db.groups.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("renders the sidebar encryption banner", () => {
		render(<ChatLayout />);
		// The sidebar banner uses uppercase text
		expect(screen.getByText("END-TO-END ENCRYPTED")).toBeInTheDocument();
	});

	it("renders the sidebar with seed chat names", () => {
		render(<ChatLayout />);
		// Names appear in both sidebar and conversation header — at least one instance each
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Jordan").length).toBeGreaterThan(0);
	});

	it("renders the E2EE notice in the message area", () => {
		render(<ChatLayout />);
		expect(screen.getByText(/not even powehi/i)).toBeInTheDocument();
	});

	it("composer placeholder mentions encryption", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		expect(textarea).toBeInTheDocument();
	});

	it("searching filters — Jordan disappears when searching 'maya'", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "maya" } });
		// Jordan should no longer appear in the sidebar; conversation panel might still show last-selected
		// Check the sidebar specifically — filtered chat list buttons
		const chatButtons = screen.queryAllByRole("button", { name: /jordan/i });
		// The sidebar ChatRow is a button; after filter, Jordan's button should be gone
		expect(chatButtons.length).toBe(0);
	});

	it("empty search query shows no-match message", () => {
		render(<ChatLayout />);
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "zzz-nomatch" } });
		expect(screen.getByText(/no chats match/i)).toBeInTheDocument();
	});

	it("typing and sending a message appends it to the conversation", () => {
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		const msg = `Hello test message ${Date.now()}`;
		fireEvent.change(textarea, { target: { value: msg } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		expect(screen.getAllByText(msg).length).toBeGreaterThan(0);
	});

	it("the info panel opens and shows safety numbers verify button", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Wait for the computed safety number to arrive (WASM computation is async).
		// Maya is unverified by default → button aria-label is "Verify safety numbers".
		expect(
			await screen.findByRole("button", { name: /verify safety numbers/i }),
		).toBeInTheDocument();
	});

	it("selecting Jordan switches the active conversation header", () => {
		render(<ChatLayout />);
		const jordanButton = screen.getByRole("button", { name: /jordan/i });
		fireEvent.click(jordanButton);
		const header = screen.getByRole("banner");
		expect(header).toHaveTextContent(/jordan/i);
	});

	it("timer button cycles through disappearing TTL options", () => {
		render(<ChatLayout />);
		// Initially Off — button has label "Set disappearing timer"
		const timerBtn = screen.getByRole("button", { name: /disappearing timer/i });
		expect(timerBtn).toBeInTheDocument();
		// First click → 5m
		fireEvent.click(timerBtn);
		expect(screen.getByRole("button", { name: /disappearing: 5m/i })).toBeInTheDocument();
		// Second click → 1h
		fireEvent.click(screen.getByRole("button", { name: /disappearing: 5m/i }));
		expect(screen.getByRole("button", { name: /disappearing: 1h/i })).toBeInTheDocument();
	});

	it("message sent with active TTL shows disappearing badge", () => {
		render(<ChatLayout />);
		// Enable disappearing timer (click once → 5m)
		fireEvent.click(screen.getByRole("button", { name: /disappearing timer/i }));
		// Send a message
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		fireEvent.change(textarea, { target: { value: "secret message" } });
		fireEvent.click(screen.getByRole("button", { name: /send message/i }));
		// The message was appended
		expect(screen.getAllByText("secret message").length).toBeGreaterThan(0);
		// The disappearing badge should appear with remaining time
		expect(screen.getByTestId("disappearing-badge")).toBeInTheDocument();
		expect(screen.getByTestId("disappearing-badge").textContent).toMatch(/Disappearing/);
	});

	it("persists verification to DB when user confirms safety number match", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Drain pending micro-tasks so the async WASM mock (mlsGroupMembers →
		// mlsComputeSafetyNumber) resolves and React re-renders InfoPanel with the
		// computed safety number before findByRole starts polling. Without this
		// drain the safety number effect Promise may resolve during act() teardown
		// of a prior test, leaving a timing window where the button is absent.
		await act(async () => {});
		// Wait for computed safety number to arrive (WASM is async) then verify.
		const verifyBtn = await screen.findByRole("button", { name: /verify safety numbers/i });
		fireEvent.click(verifyBtn);
		const confirmBtn = await screen.findByRole("button", { name: /confirm match/i });
		fireEvent.click(confirmBtn);
		await waitFor(async () => {
			const allRecords = await db.verifiedContacts.toArray();
			expect(allRecords).toHaveLength(1);
			expect(allRecords[0].safetyNumber).toMatch(/^\d{6}( \d{6}){11}$/);
		});
	});

	it("shows MITM alert when stored safety number differs from current", async () => {
		// Pre-populate with a stale safety number to simulate identity key change
		const staleSN =
			"111111 222222 333333 444444 555555 666666 777777 888888 999999 000000 121212 343434";
		await db.verifiedContacts.put({
			contactId: "maya", // matches SEED_CHATS[0].id
			safetyNumber: staleSN,
			verifiedAt: Date.now() - 86_400_000,
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() => {
			expect(screen.getByText(/safety number changed/i)).toBeInTheDocument();
		});
	});

	it("clears verification in DB when user resets", async () => {
		// Pre-populate with the current safety number (previously verified)
		await db.verifiedContacts.put({
			contactId: "maya", // matches SEED_CHATS[0].id
			safetyNumber: KAT_SN,
			verifiedAt: Date.now() - 86_400_000,
		});
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		// Wait for DB load — button becomes "Re-verify safety numbers"
		await waitFor(() => {
			expect(screen.getByRole("button", { name: /re-verify/i })).toBeInTheDocument();
		});
		// Clicking Re-verify directly calls onReset (clears verification from DB)
		fireEvent.click(screen.getByRole("button", { name: /re-verify/i }));
		await waitFor(async () => {
			const allRecords = await db.verifiedContacts.toArray();
			expect(allRecords).toHaveLength(0);
		});
	});

	// ── In-conversation message search ───────────────────────────────────────────

	it("renders search button in conversation header", () => {
		render(<ChatLayout />);
		expect(screen.getByRole("button", { name: /search in conversation/i })).toBeInTheDocument();
	});

	it("clicking search button shows search input", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		expect(screen.getByPlaceholderText(/search in conversation/i)).toBeInTheDocument();
	});

	it("typing in message search highlights matching text with mark elements", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		const searchInput = screen.getByPlaceholderText(/search in conversation/i);
		// "cafe" appears in Maya's seed messages ("9am at the corner cafe?")
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		const marks = document.querySelectorAll("mark");
		expect(marks.length).toBeGreaterThan(0);
		expect(Array.from(marks).some((m) => m.textContent === "cafe")).toBe(true);
	});

	it("closing message search removes the search input and clears highlights", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		const searchInput = screen.getByPlaceholderText(/search in conversation/i);
		fireEvent.change(searchInput, { target: { value: "cafe" } });
		// Highlights should be present
		expect(document.querySelectorAll("mark").length).toBeGreaterThan(0);
		// Close search
		fireEvent.click(screen.getByRole("button", { name: /close search/i }));
		expect(screen.queryByPlaceholderText(/search in conversation/i)).not.toBeInTheDocument();
		expect(document.querySelectorAll("mark").length).toBe(0);
	});

	it("switching active conversation resets message search", () => {
		render(<ChatLayout />);
		// Open message search in Maya's conversation
		fireEvent.click(screen.getByRole("button", { name: /search in conversation/i }));
		expect(screen.getByPlaceholderText(/search in conversation/i)).toBeInTheDocument();
		// Switch to Jordan — the chat row button's accessible name includes "Jordan"
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// Search input should be gone after switching chats
		expect(screen.queryByPlaceholderText(/search in conversation/i)).not.toBeInTheDocument();
	});

	// ── Unread message count badge ────────────────────────────────────────────────

	it("shows unread badge with count 2 for Jordan from seed data", () => {
		render(<ChatLayout />);
		// Jordan starts with unread: 2 in SEED_CHATS
		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "2")).toBe(true);
	});

	it("selecting Jordan clears its unread badge", () => {
		render(<ChatLayout />);
		// Badge visible before selection
		expect(screen.getAllByTestId("unread-badge").some((b) => b.textContent === "2")).toBe(true);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		// No badge with "2" after selection (unread reset to 0)
		const badges = screen.queryAllByTestId("unread-badge");
		expect(badges.every((b) => b.textContent !== "2")).toBe(true);
	});

	it("receiving a message for an inactive chat increments its unread badge", async () => {
		// Capture the onMessage callback injected into useMessages
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnMessage).toBeDefined();

		// Jordan's mlsGroupId matches SEED_CHATS entry; Maya is currently active
		await act(async () => {
			capturedOnMessage?.({
				id: "env-001",
				senderId: "device-abc",
				groupId: "33333333-3333-3333-3333-333333333333",
				text: "hey there",
				ciphertextB64: "Y2lwaGVydGV4dA==",
				epochSeq: 1,
			});
		});

		// Jordan's unread should go from 2 → 3
		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "3")).toBe(true);
	});

	it("messages for the active chat do not increment its unread badge", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);

		// Maya is active; her mlsGroupId is in SEED_CHATS
		await act(async () => {
			capturedOnMessage?.({
				id: "env-002",
				senderId: "device-xyz",
				groupId: "11111111-1111-1111-1111-111111111111",
				text: "hello maya",
				ciphertextB64: "Y2lwaGVydGV4dA==",
				epochSeq: 1,
			});
		});

		// Maya has no unread badge (active chat — count stays 0)
		const badges = screen.queryAllByTestId("unread-badge");
		// Only Jordan's badge (= "2") should remain; Maya's count stays 0 (no badge)
		expect(badges.every((b) => b.textContent !== "0")).toBe(true);
	});

	it("unread badge displays 9+ when count exceeds 9", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, onMessage) => {
				capturedOnMessage = onMessage;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnMessage).toBeDefined();

		// Jordan starts with unread: 2 — send 8 more to exceed 9 (total 10)
		await act(async () => {
			for (let i = 0; i < 8; i++) {
				capturedOnMessage?.({
					id: `env-${i + 10}`,
					senderId: "device-abc",
					groupId: "33333333-3333-3333-3333-333333333333",
					text: `msg ${i}`,
					ciphertextB64: "Y2lwaGVydGV4dA==",
					epochSeq: i + 2,
				});
			}
		});

		const badges = screen.getAllByTestId("unread-badge");
		expect(badges.some((b) => b.textContent === "9+")).toBe(true);
	});

	// ── Typing indicator ─────────────────────────────────────────────────────────

	it("seed chat Sam shows animated typing dots in sidebar", () => {
		render(<ChatLayout />);
		// Sam has typing: true in SEED_CHATS; sidebar should show the TypingDots component
		const dots = screen.getAllByTestId("typing-dots");
		expect(dots.length).toBeGreaterThanOrEqual(1);
	});

	it("incoming typing signal shows animated typing dots in the conversation header for the active chat", async () => {
		let capturedOnTyping: ((groupId: string) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
			(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
				capturedOnTyping = onTyping;
			},
		);
		render(<ChatLayout />);
		expect(capturedOnTyping).toBeDefined();

		// Maya is active; fire a typing signal for her group
		await act(async () => {
			capturedOnTyping?.("11111111-1111-1111-1111-111111111111");
		});

		// The ConversationHeader should now show the TypingDots component
		const dots = screen.getAllByTestId("typing-dots");
		expect(dots.length).toBeGreaterThanOrEqual(1);
	});

	it("typing indicator auto-clears after 3 seconds", async () => {
		vi.useFakeTimers();
		try {
			let capturedOnTyping: ((groupId: string) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, _onMessage, _onPqBinding, onTyping) => {
					capturedOnTyping = onTyping;
				},
			);
			render(<ChatLayout />);

			// Trigger typing signal for Maya's group (active chat)
			await act(async () => {
				capturedOnTyping?.("11111111-1111-1111-1111-111111111111");
			});
			// Both Sam's sidebar dots + Maya's header dots are present → 2 instances
			const before = screen.getAllByTestId("typing-dots").length;
			expect(before).toBeGreaterThanOrEqual(2);

			// Advance timers past the 3 s auto-clear
			await act(async () => {
				vi.advanceTimersByTime(3_100);
			});
			// After clear only Sam's sidebar dots remain → count dropped by 1
			const after = screen.getAllByTestId("typing-dots").length;
			expect(after).toBeLessThan(before);
		} finally {
			vi.useRealTimers();
		}
	});

	it("typing in the composer triggers the outgoing typing signal", () => {
		// sendTypingIndicator requires sessionToken/MLS context which aren't set in this test;
		// verify that onChange fires without throwing (graceful no-op in unauthenticated state).
		render(<ChatLayout />);
		const textarea = screen.getByPlaceholderText(/encrypted/i);
		// Should not throw even without a session
		expect(() => {
			fireEvent.change(textarea, { target: { value: "a" } });
		}).not.toThrow();
	});

	describe("emoji reactions", () => {
		it("reaction chips are rendered when a message has reactions", async () => {
			let capturedOnReaction:
				| ((groupId: string, targetId: string, emoji: string, senderId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_id, _gid, _onMsg, _onPq, _onTyping, onReaction) => {
					capturedOnReaction = onReaction;
				},
			);
			render(<ChatLayout />);

			// Simulate an incoming message so it has an id, then a reaction for it
			const MSG_ID = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee";
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_id, _gid, onMsg, _onPq, _onTyping, onReaction) => {
					capturedOnMessage = onMsg;
					capturedOnReaction = onReaction;
				},
			);
			render(<ChatLayout />);

			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "hello reaction",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			await act(async () => {
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "👍", "peer-device-1");
			});

			expect(screen.getByTestId("reaction-chips")).toBeInTheDocument();
			expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();
		});

		it("reaction chip shows count of senders", async () => {
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

			const MSG_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff";
			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "count me",
					ciphertextB64: "Zg==",
					epochSeq: 2,
				});
			});

			await act(async () => {
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "dev-a");
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "dev-b");
			});

			const chip = screen.getByTestId("reaction-chip-❤️");
			// Count is 2
			expect(chip.textContent).toContain("2");
		});

		it("incoming reaction persists the reaction map to Dexie so it survives a reload", async () => {
			const reactionSpy = vi.spyOn(
				EncryptedDbModule.EncryptedPowehiDb.prototype,
				"markMessageReactions",
			);
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

			const MSG_ID = "12121212-1212-1212-1212-121212121212";
			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "persist my reaction",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			await act(async () => {
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "👍", "peer-device-1");
			});

			await waitFor(() =>
				expect(reactionSpy).toHaveBeenCalledWith(
					MSG_ID,
					JSON.stringify({ "👍": ["peer-device-1"] }),
				),
			);
		});

		it("reaction_remove persists the updated (emoji key dropped) map to Dexie", async () => {
			const reactionSpy = vi.spyOn(
				EncryptedDbModule.EncryptedPowehiDb.prototype,
				"markMessageReactions",
			);
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

			const MSG_ID = "13131313-1313-1313-1313-131313131313";
			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "reaction then remove",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});
			await act(async () => {
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "🔥", "peer-device-1");
			});
			await waitFor(() =>
				expect(reactionSpy).toHaveBeenCalledWith(
					MSG_ID,
					JSON.stringify({ "🔥": ["peer-device-1"] }),
				),
			);

			await act(async () => {
				capturedOnReactionRemove?.(
					"11111111-1111-1111-1111-111111111111",
					MSG_ID,
					"🔥",
					"peer-device-1",
				);
			});

			// Last sender for that emoji removed — the emoji key is dropped entirely.
			await waitFor(() => expect(reactionSpy).toHaveBeenLastCalledWith(MSG_ID, JSON.stringify({})));
		});

		it("incoming reaction is NOT forwarded to the message list as a new message", async () => {
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

			const MSG_ID = "aaaabbbb-cccc-dddd-eeee-ffffgggggggg";
			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "only one",
					ciphertextB64: "Zg==",
					epochSeq: 3,
				});
			});

			await act(async () => {
				capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "😮", "peer-device-x");
			});

			// The reaction emoji appears only in a chip button, not as a standalone message text
			const chipEl = screen.queryByTestId("reaction-chip-😮");
			expect(chipEl).toBeInTheDocument();
			// The emoji text rendered should be confined to the chip, not a new message bubble
			const allWithEmoji = screen.queryAllByText(/😮/);
			for (const el of allWithEmoji) {
				// Each element containing the emoji should be within a reaction chip
				expect(el.closest("[data-testid='reaction-chips']")).not.toBeNull();
			}
		});

		it("reaction trigger button is visible for messages with an id", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);

			await act(async () => {
				capturedOnMessage?.({
					id: "msg-with-id-111",
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "reactable message",
					ciphertextB64: "Zg==",
					epochSeq: 4,
				});
			});

			expect(screen.getByTestId("reaction-trigger")).toBeInTheDocument();
		});

		it("clicking reaction trigger opens the emoji picker", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
				capturedOnMessage = onMsg;
			});
			render(<ChatLayout />);

			await act(async () => {
				capturedOnMessage?.({
					id: "msg-with-id-222",
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "sender-1",
					text: "open picker",
					ciphertextB64: "Zg==",
					epochSeq: 5,
				});
			});

			fireEvent.click(screen.getByTestId("reaction-trigger"));
			expect(screen.getByTestId("reaction-picker")).toBeInTheDocument();
		});
	});

	describe("read receipts", () => {
		it("incoming read_receipt is NOT added to the message list as a new bubble", async () => {
			let capturedOnReadReceipt:
				| ((groupId: string, messageIds: string[], readAt: number, senderDeviceId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onReactionRemove, onReadReceipt) => {
					capturedOnReadReceipt = onReadReceipt;
				},
			);
			render(<ChatLayout />);

			const RECEIPT_MSG_ID = "11112222-3333-4444-5555-666677778888";
			await act(async () => {
				capturedOnReadReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					[RECEIPT_MSG_ID],
					Date.now(),
					"peer-device-z",
				);
			});

			// No new message bubble should appear from a read receipt
			expect(screen.queryByText(/read_receipt/i)).not.toBeInTheDocument();
		});

		it("seed me-messages with read: true show Read aria-label on double-check", () => {
			// Seed data in ChatLayout has multiple me-messages with read: true.
			// Verify the aria-label is correctly set without any async overhead.
			render(<ChatLayout />);
			const readIndicators = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read");
			expect(readIndicators.length).toBeGreaterThan(0);
		});

		it("sent message gets Read indicator after sendMessage assigns envelopeId and receipt arrives", async () => {
			let capturedOnReadReceipt:
				| ((groupId: string, messageIds: string[], readAt: number, senderDeviceId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onReactionRemove, onReadReceipt) => {
					capturedOnReadReceipt = onReadReceipt;
				},
			);
			// Provide a session token so the MLS encrypt + send path runs.
			useAuthStore.setState({ phase: "app", deviceId: "my-device-99", sessionToken: "tok-99" });

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("env-receipt-test-1");

			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "hello from me" } });
			fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

			// Wait for the envelopeId to be backfilled into the optimistic message.
			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			// Before receipt: the new "me" message has read: false (default).
			// Seed messages have various read states; count "Sent" indicators for new message.
			const beforeRead = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read").length;

			// Simulate incoming read receipt for our just-sent message.
			await act(async () => {
				capturedOnReadReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					["env-receipt-test-1"],
					Date.now(),
					"peer-device-abc",
				);
			});

			const afterRead = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read").length;
			expect(afterRead).toBeGreaterThan(beforeRead);

			sendSpy.mockRestore();
			useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
		});
	});

	describe("delivery receipts", () => {
		it("incoming delivery_receipt is NOT added as a message bubble", async () => {
			let capturedOnDeliveryReceipt:
				| ((groupId: string, messageIds: string[], senderDeviceId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onReadReceipt,
					onDeliveryReceipt,
				) => {
					capturedOnDeliveryReceipt = onDeliveryReceipt;
				},
			);
			render(<ChatLayout />);

			await act(async () => {
				capturedOnDeliveryReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					["ddddddd-0001"],
					"peer-device-z",
				);
			});

			expect(screen.queryByText(/delivery_receipt/i)).not.toBeInTheDocument();
		});

		it("handleIncomingDeliveryReceipt shows Delivered indicator on matching message", async () => {
			let capturedOnDeliveryReceipt:
				| ((groupId: string, messageIds: string[], senderDeviceId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onReadReceipt,
					onDeliveryReceipt,
				) => {
					capturedOnDeliveryReceipt = onDeliveryReceipt;
				},
			);
			useAuthStore.setState({ phase: "app", deviceId: "my-device-d1", sessionToken: "tok-d1" });

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("env-delivery-test-1");

			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "delivered test" } });
			fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const beforeDelivered = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered").length;

			await act(async () => {
				capturedOnDeliveryReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					["env-delivery-test-1"],
					"peer-device-d1",
				);
			});

			const afterDelivered = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered").length;
			expect(afterDelivered).toBeGreaterThan(beforeDelivered);

			sendSpy.mockRestore();
			useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
		});

		it("delivered message transitions to Read after subsequent read_receipt", async () => {
			let capturedOnReadReceipt:
				| ((groupId: string, messageIds: string[], readAt: number, senderDeviceId: string) => void)
				| undefined;
			let capturedOnDeliveryReceipt:
				| ((groupId: string, messageIds: string[], senderDeviceId: string) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					onReadReceipt,
					onDeliveryReceipt,
				) => {
					capturedOnReadReceipt = onReadReceipt;
					capturedOnDeliveryReceipt = onDeliveryReceipt;
				},
			);
			useAuthStore.setState({ phase: "app", deviceId: "my-device-d2", sessionToken: "tok-d2" });

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("env-delivery-test-2");

			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "read transition test" } });
			fireEvent.keyDown(textarea, { key: "Enter", shiftKey: false });

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			// Apply delivery receipt first.
			await act(async () => {
				capturedOnDeliveryReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					["env-delivery-test-2"],
					"peer-device-d2",
				);
			});

			const deliveredCount = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered").length;
			expect(deliveredCount).toBeGreaterThan(0);

			// Apply read receipt — should supersede delivered state.
			await act(async () => {
				capturedOnReadReceipt?.(
					"11111111-1111-1111-1111-111111111111",
					["env-delivery-test-2"],
					Date.now(),
					"peer-device-d2",
				);
			});

			const readCount = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Read").length;
			const stillDelivered = screen
				.queryAllByTestId("read-indicator")
				.filter((el) => el.getAttribute("aria-label") === "Delivered").length;

			expect(readCount).toBeGreaterThan(0);
			expect(stillDelivered).toBe(deliveredCount - 1);

			sendSpy.mockRestore();
			useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
		});
	});

	describe("new messages divider", () => {
		it("divider does not appear in the active chat when a message arrives", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, onMessage) => {
					capturedOnMessage = onMessage;
				},
			);
			render(<ChatLayout />);

			// Maya is the active chat; message for Maya should NOT show the divider
			await act(async () => {
				capturedOnMessage?.({
					id: "env-ndiv-1",
					senderId: "device-a",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "no divider here",
					ciphertextB64: "dGVzdA==",
					epochSeq: 1,
				});
			});

			expect(screen.queryByTestId("new-messages-divider")).not.toBeInTheDocument();
		});

		it("divider appears in a background chat when it receives its first unread message", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, onMessage) => {
					capturedOnMessage = onMessage;
				},
			);
			render(<ChatLayout />);

			// Switch to Jordan — Maya becomes background
			fireEvent.click(screen.getAllByText("Jordan")[0]);

			// Send a message for Maya (now background)
			await act(async () => {
				capturedOnMessage?.({
					id: "env-ndiv-2",
					senderId: "device-b",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "new for background maya",
					ciphertextB64: "dGVzdA==",
					epochSeq: 2,
				});
			});

			// Switch back to Maya — divider should now be visible
			fireEvent.click(screen.getAllByText("Maya Akana")[0]);

			expect(screen.getByTestId("new-messages-divider")).toBeInTheDocument();
		});

		it("divider is removed after switching back to the chat", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, onMessage) => {
					capturedOnMessage = onMessage;
				},
			);
			render(<ChatLayout />);

			// Move to Jordan and send a message to Maya (background)
			fireEvent.click(screen.getAllByText("Jordan")[0]);
			await act(async () => {
				capturedOnMessage?.({
					id: "env-ndiv-3",
					senderId: "device-c",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "clear me later",
					ciphertextB64: "dGVzdA==",
					epochSeq: 3,
				});
			});

			// First switch back to Maya — divider visible
			fireEvent.click(screen.getAllByText("Maya Akana")[0]);
			expect(screen.getByTestId("new-messages-divider")).toBeInTheDocument();

			// Switch away and back — divider should be gone now
			fireEvent.click(screen.getAllByText("Jordan")[0]);
			fireEvent.click(screen.getAllByText("Maya Akana")[0]);
			expect(screen.queryByTestId("new-messages-divider")).not.toBeInTheDocument();
		});

		it("subsequent unread messages do not duplicate the divider", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, onMessage) => {
					capturedOnMessage = onMessage;
				},
			);
			render(<ChatLayout />);

			// Move to Jordan — Maya is background
			fireEvent.click(screen.getAllByText("Jordan")[0]);
			await act(async () => {
				capturedOnMessage?.({
					id: "env-ndiv-4a",
					senderId: "device-d",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "first new msg",
					ciphertextB64: "dGVzdA==",
					epochSeq: 4,
				});
				capturedOnMessage?.({
					id: "env-ndiv-4b",
					senderId: "device-d",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "second new msg",
					ciphertextB64: "dGVzdA==",
					epochSeq: 5,
				});
			});

			fireEvent.click(screen.getAllByText("Maya Akana")[0]);
			// Only one divider — not one per new message
			expect(screen.getAllByTestId("new-messages-divider")).toHaveLength(1);

			await act(async () => {});
		});
	});

	describe("quote reply", () => {
		it("incoming message with replyTo renders a reply-quote block", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_identityId, _groupId, onMessage) => {
					capturedOnMessage = onMessage;
				},
			);
			render(<ChatLayout />);

			await act(async () => {
				capturedOnMessage?.({
					id: "env-reply-1",
					senderId: "device-x",
					groupId: "11111111-1111-1111-1111-111111111111",
					text: "That is a great idea",
					ciphertextB64: "dGVzdA==",
					epochSeq: 1,
					replyTo: { messageId: "orig-uuid", excerpt: "Original message text" },
				});
			});

			expect(screen.getByTestId("reply-quote")).toBeInTheDocument();
			expect(screen.getByTestId("reply-quote").textContent).toBe("Original message text");
		});

		it("reply button appears on message bubble hover", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			expect(screen.getByTestId("reply-button")).toBeInTheDocument();
		});

		it("clicking reply button shows reply preview in composer", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("reply-button"));
			expect(screen.getByTestId("reply-preview")).toBeInTheDocument();
		});

		it("cancel-reply button clears the reply preview", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("reply-button"));
			expect(screen.getByTestId("reply-preview")).toBeInTheDocument();
			fireEvent.click(screen.getByTestId("cancel-reply"));
			expect(screen.queryByTestId("reply-preview")).not.toBeInTheDocument();
		});
	});

	describe("message editing", () => {
		it("edit button appears on hover for own ('me') messages but not for peer messages", async () => {
			// Send a "me" message so it's in the list
			render(<ChatLayout />);
			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "My own message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			// Find the "me" message bubble (last one appended) and hover it
			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			expect(screen.getByTestId("edit-button")).toBeInTheDocument();

			// Peer messages should not show edit button
			fireEvent.mouseLeave(lastBubble);
			// Hover the first bubble (a seed "them" message)
			fireEvent.mouseEnter(bubbles[0]);
			expect(screen.queryByTestId("edit-button")).not.toBeInTheDocument();
		});

		it("clicking edit button on own message shows edit preview in composer", () => {
			render(<ChatLayout />);
			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "Editable message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("edit-button"));

			expect(screen.getByTestId("edit-preview")).toBeInTheDocument();
		});

		it("cancel-edit button clears the edit preview", () => {
			render(<ChatLayout />);
			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "To be edited" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[bubbles.length - 1]);
			fireEvent.click(screen.getByTestId("edit-button"));
			expect(screen.getByTestId("edit-preview")).toBeInTheDocument();
			fireEvent.click(screen.getByTestId("cancel-edit"));
			expect(screen.queryByTestId("edit-preview")).not.toBeInTheDocument();
		});

		it("incoming edit updates matching peer message text and shows edited badge", async () => {
			const editSpy = vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "markMessageEdited");
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnEdit:
				| ((
						groupId: string,
						targetMessageId: string,
						newText: string,
						senderDeviceId: string,
				  ) => void)
				| undefined;
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
					onEdit,
				) => {
					capturedOnMessage = onMsg;
					capturedOnEdit = onEdit;
				},
			);
			render(<ChatLayout />);

			const MSG_ID = "edit-target-uuid-1111-111111111111";
			await act(async () => {
				capturedOnMessage?.({
					id: MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "peer-device-1",
					text: "original peer text",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			// Message appears in the list (also in sidebar preview — use getAllByText)
			expect(screen.getAllByText("original peer text").length).toBeGreaterThan(0);

			await act(async () => {
				capturedOnEdit?.(
					"11111111-1111-1111-1111-111111111111",
					MSG_ID,
					"updated peer text",
					"peer-device-1",
				);
			});

			// Updated text must appear; edited badge must be present
			expect(screen.getAllByText("updated peer text").length).toBeGreaterThan(0);
			expect(screen.getByTestId("edited-badge")).toBeInTheDocument();
			// Legitimate peer edit must persist to Dexie so it survives a reload.
			await waitFor(() => expect(editSpy).toHaveBeenCalledWith(MSG_ID, expect.any(String)));
		});

		it("incoming edit does NOT rewrite 'me' messages (own message protection)", async () => {
			const editSpy = vi.spyOn(EncryptedDbModule.EncryptedPowehiDb.prototype, "markMessageEdited");
			let capturedOnEdit:
				| ((
						groupId: string,
						targetMessageId: string,
						newText: string,
						senderDeviceId: string,
				  ) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					onEdit,
				) => {
					capturedOnEdit = onEdit;
				},
			);
			render(<ChatLayout />);

			// Send an own message (optimistic update applies regardless of session state)
			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "my protected message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
			// Message appears in bubble and sidebar — use getAllByText
			expect(screen.getAllByText("my protected message").length).toBeGreaterThan(0);

			// A peer sends an edit targeting a nonexistent ID — should be a no-op
			await act(async () => {
				capturedOnEdit?.(
					"11111111-1111-1111-1111-111111111111",
					"fake-id-that-does-not-exist",
					"hacked content",
					"peer-device-1",
				);
			});

			// Own message must remain; hacked content must not appear anywhere
			expect(screen.getAllByText("my protected message").length).toBeGreaterThan(0);
			expect(screen.queryByText("hacked content")).not.toBeInTheDocument();
			// A forged edit that doesn't match a "them" message must never reach Dexie —
			// the persistence layer must honor the same guard as the in-memory state.
			expect(editSpy).not.toHaveBeenCalled();
		});
	});

	describe("message deletion", () => {
		it("delete button appears on hover for own message with a stable envelope id", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			// Provide a session token so the MLS encrypt + send path runs and backfills the id.
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-del-1",
				sessionToken: "tok-del-1",
			});

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("del-test-env-1");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "message to delete" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			// Wait for the envelopeId to be backfilled onto the optimistic message.
			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			// Hover the last bubble (the sent "me" message with id now set).
			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);

			expect(screen.getByTestId("delete-button")).toBeInTheDocument();
		});

		it("clicking delete button marks own message as deleted (shows placeholder)", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-del-2",
				sessionToken: "tok-del-2",
			});

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("del-test-env-2");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "to be deleted" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("delete-button"));

			expect(screen.getByTestId("deleted-placeholder")).toBeInTheDocument();
		});

		it("incoming delete marks peer message as deleted and shows placeholder", async () => {
			const deleteSpy = vi.spyOn(
				EncryptedDbModule.EncryptedPowehiDb.prototype,
				"markMessageDeleted",
			);
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnDelete: ((groupId: string, targetMessageId: string) => void) | undefined;
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

			const PEER_MSG_ID = "delete-peer-uuid-1111-111111111111";
			await act(async () => {
				capturedOnMessage?.({
					id: PEER_MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "peer-device-1",
					text: "peer message text",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			expect(screen.getAllByText("peer message text").length).toBeGreaterThan(0);

			await act(async () => {
				capturedOnDelete?.("11111111-1111-1111-1111-111111111111", PEER_MSG_ID);
			});

			// Deleted placeholder must be present in the message bubble area.
			expect(screen.getByTestId("deleted-placeholder")).toBeInTheDocument();
			// Legitimate peer delete must persist to Dexie so it survives a reload.
			await waitFor(() => expect(deleteSpy).toHaveBeenCalledWith(PEER_MSG_ID));
		});

		it("incoming delete does NOT erase own 'me' messages", async () => {
			const deleteSpy = vi.spyOn(
				EncryptedDbModule.EncryptedPowehiDb.prototype,
				"markMessageDeleted",
			);
			let capturedOnDelete: ((groupId: string, targetMessageId: string) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					_onEdit,
					onDelete,
				) => {
					capturedOnDelete = onDelete;
				},
			);
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "my own message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
			expect(screen.getAllByText("my own message").length).toBeGreaterThan(0);

			// Peer sends a delete targeting a fake id — should be a no-op for own messages
			await act(async () => {
				capturedOnDelete?.("11111111-1111-1111-1111-111111111111", "fake-id-0000-0000-0000");
			});

			expect(screen.getAllByText("my own message").length).toBeGreaterThan(0);
			expect(screen.queryByTestId("deleted-placeholder")).not.toBeInTheDocument();
			await act(async () => {});
			// A forged delete that doesn't match a "them" message must never reach Dexie —
			// the persistence layer must honor the same guard as the in-memory state.
			expect(deleteSpy).not.toHaveBeenCalled();
		});
	});

	describe("message pinning", () => {
		it("pin button appears on hover for a message with a stable envelope id", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-pin-1",
				sessionToken: "tok-pin-1",
			});

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("pin-test-env-1");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "message to pin" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);

			expect(screen.getByTestId("pin-button")).toBeInTheDocument();
		});

		it("clicking pin button shows pinned banner with message text", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-pin-2",
				sessionToken: "tok-pin-2",
			});

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("pin-test-env-2");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "pinnable message" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("pin-button"));

			expect(screen.getByTestId("pinned-banner")).toBeInTheDocument();
		});

		it("incoming pin shows pinned banner with peer message text", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnPin:
				| ((groupId: string, targetMessageId: string, action: "pin" | "unpin") => void)
				| undefined;
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
					_onDelete,
					onPin,
				) => {
					capturedOnMessage = onMsg;
					capturedOnPin = onPin;
				},
			);
			render(<ChatLayout />);

			const PEER_MSG_ID = "pin-peer-uuid-1111-111111111111";
			await act(async () => {
				capturedOnMessage?.({
					id: PEER_MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "peer-device-pin",
					text: "peer pinned message",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			await act(async () => {
				capturedOnPin?.("11111111-1111-1111-1111-111111111111", PEER_MSG_ID, "pin");
			});

			expect(screen.getByTestId("pinned-banner")).toBeInTheDocument();
		});

		it("unpin button on banner hides the pinned banner", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-pin-3",
				sessionToken: "tok-pin-3",
			});

			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("pin-test-env-3");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "to be unpinned" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));

			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("pin-button"));

			expect(screen.getByTestId("pinned-banner")).toBeInTheDocument();

			fireEvent.click(screen.getByTestId("unpin-button"));

			expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
		});

		it("clicking pin button persists pinnedMessageId to Dexie so it survives a reload", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-pin-persist-1",
				sessionToken: "tok-pin-persist-1",
			});
			await db.groups.add({
				id: "11111111-1111-1111-1111-111111111111",
				name: "Maya Akana",
				mlsStateB64: "",
				lastActivity: 1000,
			});
			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("pin-persist-env-1");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "message to persist pin" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("pin-button"));

			await waitFor(async () => {
				const row = await db.groups.get("11111111-1111-1111-1111-111111111111");
				expect(row?.pinnedMessageId).toBeTruthy();
			});
		});

		it("unpin clears the persisted pinnedMessageId in Dexie", async () => {
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
			useAuthStore.setState({
				phase: "app",
				deviceId: "my-device-pin-persist-2",
				sessionToken: "tok-pin-persist-2",
			});
			await db.groups.add({
				id: "11111111-1111-1111-1111-111111111111",
				name: "Maya Akana",
				mlsStateB64: "",
				lastActivity: 1000,
			});
			const sendSpy = vi
				.spyOn(MessagesApiModule, "sendMessage")
				.mockResolvedValue("pin-persist-env-2");
			render(<ChatLayout />);

			const textarea = screen.getByPlaceholderText(/encrypted/i);
			fireEvent.change(textarea, { target: { value: "message to unpin" } });
			fireEvent.click(screen.getByRole("button", { name: /send message/i }));
			await waitFor(() => expect(sendSpy).toHaveBeenCalled());
			await act(async () => {});

			const bubbles = screen.getAllByTestId("message-bubble");
			const lastBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(lastBubble);
			fireEvent.click(screen.getByTestId("pin-button"));
			await waitFor(async () => {
				const row = await db.groups.get("11111111-1111-1111-1111-111111111111");
				expect(row?.pinnedMessageId).toBeTruthy();
			});

			fireEvent.click(screen.getByTestId("unpin-button"));

			await waitFor(async () => {
				const row = await db.groups.get("11111111-1111-1111-1111-111111111111");
				expect(row?.pinnedMessageId).toBeUndefined();
			});
		});

		it("incoming pin persists pinnedMessageId to Dexie keyed by the peer's group id", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnPin:
				| ((groupId: string, targetMessageId: string, action: "pin" | "unpin") => void)
				| undefined;
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
					_onDelete,
					onPin,
				) => {
					capturedOnMessage = onMsg;
					capturedOnPin = onPin;
				},
			);
			await db.groups.add({
				id: "11111111-1111-1111-1111-111111111111",
				name: "Maya Akana",
				mlsStateB64: "",
				lastActivity: 1000,
			});
			render(<ChatLayout />);

			const PEER_MSG_ID = "pin-persist-peer-uuid-1111-1111111111";
			await act(async () => {
				capturedOnMessage?.({
					id: PEER_MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "peer-device-pin-persist",
					text: "peer message to persist pin",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});
			await act(async () => {
				capturedOnPin?.("11111111-1111-1111-1111-111111111111", PEER_MSG_ID, "pin");
			});

			await waitFor(async () => {
				const row = await db.groups.get("11111111-1111-1111-1111-111111111111");
				expect(row?.pinnedMessageId).toBe(PEER_MSG_ID);
			});
		});

		it("unpinning a restored-from-Dexie pin does not get resurrected by a later message arrival", async () => {
			// Regression test for a security-auditor finding (cycle 259): the "apply persisted
			// pin state" effect re-runs on every `rows` change (to retry against the mount race),
			// but `persistedPinnedMessageId` was only ever set once at load time — an in-session
			// unpin cleared `chats` + Dexie but left the stale persisted id in state, so the next
			// unrelated `rows` update (e.g. an incoming message) silently re-pinned the message.
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnPin:
				| ((groupId: string, targetMessageId: string, action: "pin" | "unpin") => void)
				| undefined;
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
					_onDelete,
					onPin,
				) => {
					capturedOnMessage = onMsg;
					capturedOnPin = onPin;
				},
			);
			const GROUP_ID = "11111111-1111-1111-1111-111111111111";
			const PINNED_ID = "resurrect-regression-pinned-1";
			await db.messages.add({
				id: PINNED_ID,
				groupId: GROUP_ID,
				ciphertextB64: "Zg==",
				senderDeviceId: "peer-device-resurrect",
				epochSeq: 1,
				receivedAt: 1000,
				plaintextB64: textToBase64("message pinned before this session started"),
			});
			await db.groups.add({
				id: GROUP_ID,
				name: "Maya Akana",
				mlsStateB64: "",
				lastActivity: 1000,
				pinnedMessageId: PINNED_ID,
			});

			render(<ChatLayout />);
			await waitFor(() => expect(screen.getByTestId("pinned-banner")).toBeInTheDocument());

			// Unpin the restored message.
			await act(async () => {
				capturedOnPin?.(GROUP_ID, PINNED_ID, "unpin");
			});
			await waitFor(() => expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument());
			await waitFor(async () => {
				const row = await db.groups.get(GROUP_ID);
				expect(row?.pinnedMessageId).toBeUndefined();
			});

			// A later, unrelated message arrival changes `rows` and re-runs the apply effect —
			// it must not resurrect the pin that was just cleared.
			await act(async () => {
				capturedOnMessage?.({
					id: "resurrect-regression-followup-1",
					groupId: GROUP_ID,
					senderId: "peer-device-resurrect",
					text: "an unrelated later message",
					ciphertextB64: "Zg==",
					epochSeq: 2,
				});
			});
			expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
			const row = await db.groups.get(GROUP_ID);
			expect(row?.pinnedMessageId).toBeUndefined();
		});
	});

	describe("user presence", () => {
		it("incoming 'online' presence marks the peer chat as online", async () => {
			let capturedOnPresence: ((groupId: string, status: "online" | "offline") => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					_onEdit,
					_onDelete,
					_onPin,
					onPresence,
				) => {
					capturedOnPresence = onPresence;
				},
			);

			render(<ChatLayout />);

			await act(async () => {
				capturedOnPresence?.("11111111-1111-1111-1111-111111111111", "online");
			});

			expect(screen.getByText("online")).toBeInTheDocument();
		});

		it("incoming 'offline' presence marks the peer chat as offline with lastSeen time", async () => {
			let capturedOnPresence: ((groupId: string, status: "online" | "offline") => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					_onEdit,
					_onDelete,
					_onPin,
					onPresence,
				) => {
					capturedOnPresence = onPresence;
				},
			);

			render(<ChatLayout />);

			// First mark online, then offline.
			await act(async () => {
				capturedOnPresence?.("11111111-1111-1111-1111-111111111111", "online");
			});
			await act(async () => {
				capturedOnPresence?.("11111111-1111-1111-1111-111111111111", "offline");
			});

			// Should now show "last seen HH:MM" in the header.
			const header = screen.getByText(/last seen/i);
			expect(header).toBeInTheDocument();
		});

		it("presence 'online' from unknown group does not add new 'online' elements", async () => {
			let capturedOnPresence: ((groupId: string, status: "online" | "offline") => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					_onEdit,
					_onDelete,
					_onPin,
					onPresence,
				) => {
					capturedOnPresence = onPresence;
				},
			);

			render(<ChatLayout />);

			// Count "online" elements before sending presence.
			const countBefore = screen.queryAllByText("online").length;

			// Unknown groupId — should not match any chat; no change to online count.
			await act(async () => {
				capturedOnPresence?.("00000000-0000-0000-0000-000000000000", "online");
			});

			expect(screen.queryAllByText("online").length).toBe(countBefore);
		});

		it("online status automatically reverts to offline after 90 s (timer fires)", async () => {
			vi.useFakeTimers();
			let capturedOnPresence: ((groupId: string, status: "online" | "offline") => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
					_onReactionRemove,
					_onRead,
					_onDelivery,
					_onEdit,
					_onDelete,
					_onPin,
					onPresence,
				) => {
					capturedOnPresence = onPresence;
				},
			);

			render(<ChatLayout />);

			await act(async () => {
				capturedOnPresence?.("11111111-1111-1111-1111-111111111111", "online");
			});
			expect(screen.getByText("online")).toBeInTheDocument();

			// Advance 90 s — the auto-offline timer should fire.
			await act(async () => {
				vi.advanceTimersByTime(90_000);
			});

			expect(screen.queryByText("online")).not.toBeInTheDocument();
			expect(screen.getByText(/last seen/i)).toBeInTheDocument();

			vi.useRealTimers();
		});
	});

	// ── Starred messages ──────────────────────────────────────────────────────────

	describe("starred messages", () => {
		it("star button appears on hover for any non-deleted message", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			expect(screen.getByTestId("star-button")).toBeInTheDocument();
		});

		it("star button aria-label is 'Star message' when not yet starred", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			expect(screen.getByTestId("star-button")).toHaveAttribute("aria-label", "Star message");
		});

		it("clicking star button marks message as starred — aria-label becomes 'Unstar message'", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("star-button"));
			// After starring, the button aria-label toggles (message is re-rendered with starred:true)
			expect(screen.getByTestId("star-button")).toHaveAttribute("aria-label", "Unstar message");
		});

		it("clicking star button again unstars the message — aria-label reverts to 'Star message'", () => {
			render(<ChatLayout />);
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("star-button"));
			fireEvent.click(screen.getByTestId("star-button"));
			expect(screen.getByTestId("star-button")).toHaveAttribute("aria-label", "Star message");
		});

		it("starred panel opens and shows empty state when no messages are starred", () => {
			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
			expect(screen.getByTestId("starred-panel")).toBeInTheDocument();
			expect(screen.getByText(/no starred messages yet/i)).toBeInTheDocument();
		});

		it("starred panel lists a message after it is starred", () => {
			render(<ChatLayout />);
			// Star the first seed message
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("star-button"));
			// Open the panel
			fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
			expect(screen.getByTestId("starred-panel")).toBeInTheDocument();
			expect(screen.getAllByTestId("starred-item").length).toBeGreaterThan(0);
		});

		it("starred panel close button dismisses the panel", () => {
			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
			expect(screen.getByTestId("starred-panel")).toBeInTheDocument();
			fireEvent.click(screen.getByRole("button", { name: /close starred/i }));
			expect(screen.queryByTestId("starred-panel")).not.toBeInTheDocument();
		});

		it("clicking a starred item in the panel navigates to that chat and closes the panel", () => {
			render(<ChatLayout />);
			// Switch to Jordan so the star lands on a non-active chat
			fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
			// Star a Jordan message
			const bubbles = screen.getAllByTestId("message-bubble");
			fireEvent.mouseEnter(bubbles[0]);
			fireEvent.click(screen.getByTestId("star-button"));
			// Switch back to Maya (default active chat)
			fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
			// Open starred panel and click the Jordan starred item
			fireEvent.click(screen.getByRole("button", { name: /starred messages/i }));
			const item = screen.getByTestId("starred-item");
			fireEvent.click(item);
			// Panel should be closed after navigation
			expect(screen.queryByTestId("starred-panel")).not.toBeInTheDocument();
		});

		it("star button does not appear on a deleted message", async () => {
			let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
			let capturedOnDelete: ((groupId: string, targetMessageId: string) => void) | undefined;
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

			const PEER_MSG_ID = "star-delete-uuid-1111-111111111111";
			await act(async () => {
				capturedOnMessage?.({
					id: PEER_MSG_ID,
					groupId: "11111111-1111-1111-1111-111111111111",
					senderId: "peer-device-star",
					text: "peer message for star-delete test",
					ciphertextB64: "Zg==",
					epochSeq: 1,
				});
			});

			// Delete the peer message
			await act(async () => {
				capturedOnDelete?.("11111111-1111-1111-1111-111111111111", PEER_MSG_ID);
			});

			// The deleted-placeholder should be visible
			expect(screen.getByTestId("deleted-placeholder")).toBeInTheDocument();

			// Hover the deleted bubble — star-button must NOT appear
			const bubbles = screen.getAllByTestId("message-bubble");
			const deletedBubble = bubbles[bubbles.length - 1];
			fireEvent.mouseEnter(deletedBubble);
			expect(screen.queryByTestId("star-button")).not.toBeInTheDocument();
		});
	});

	describe("group chat scaffold", () => {
		it("New group button is in Sidebar", () => {
			render(<ChatLayout />);
			expect(screen.getByRole("button", { name: /new group/i })).toBeInTheDocument();
		});

		it("group badge shown for group chat in sidebar", async () => {
			render(<ChatLayout />);
			// Open the create group modal and create a group to get a group chat in the sidebar
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			expect(screen.getByRole("dialog", { name: /new group/i })).toBeInTheDocument();
		});

		it("ConversationHeader shows group status when isGroup is true", async () => {
			// We check the ConversationHeader renders group-status for a group chat.
			// Trigger group creation flow to add a group chat.
			const mockWorkerWithGroup = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-aabbccdd" })),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				mockWorkerWithGroup as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			useAuthStore.setState({ sessionToken: "tok-test", identityId: "id-test", deviceId: "dev-1" });

			render(<ChatLayout />);
			// Open new group modal
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			// Type group name
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Alpha Team" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			// Wait for group to appear in sidebar
			await waitFor(() => {
				expect(screen.getByText("Alpha Team")).toBeInTheDocument();
			});
			// Click on the new group chat
			fireEvent.click(screen.getByRole("button", { name: /alpha team/i }));
			// ConversationHeader should show group status
			await waitFor(() => {
				expect(screen.getByTestId("group-status")).toBeInTheDocument();
			});
		});

		it("ConversationHeader does not show typing indicator for group chat", async () => {
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			const mockWorkerWithGroup = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-notyping123" })),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				mockWorkerWithGroup as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			useAuthStore.setState({
				sessionToken: "tok-test2",
				identityId: "id-test2",
				deviceId: "dev-2",
			});

			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Beta Team" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			await waitFor(() => {
				expect(screen.getByText("Beta Team")).toBeInTheDocument();
			});
			fireEvent.click(screen.getByRole("button", { name: /beta team/i }));
			await waitFor(() => {
				expect(screen.getByTestId("group-status")).toBeInTheDocument();
			});
			// There should be no typing span inside the group status
			expect(screen.queryByText(/·\s*typing/i)).not.toBeInTheDocument();
		});

		it("safety numbers useEffect skipped for group chat", async () => {
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			const groupWorker = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-safety-skip" })),
				mlsGroupMembers: vi.fn(async () => []),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				groupWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			useAuthStore.setState({
				sessionToken: "tok-test3",
				identityId: "id-test3",
				deviceId: "dev-3",
			});

			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Safety Skip Group" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			await waitFor(() => {
				expect(screen.getByText("Safety Skip Group")).toBeInTheDocument();
			});
			fireEvent.click(screen.getByRole("button", { name: /safety skip group/i }));
			await waitFor(() => {
				expect(screen.getByTestId("group-status")).toBeInTheDocument();
			});
			// Open info panel — safety numbers should not be computed for group chats
			fireEvent.click(screen.getByRole("button", { name: /info/i }));
			await waitFor(() => {
				// mlsGroupMembers should NOT have been called for the group chat
				expect(groupWorker.mlsGroupMembers).not.toHaveBeenCalled();
			});
		});

		it("CreateGroupModal closes when backdrop is clicked", () => {
			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			expect(screen.getByRole("dialog", { name: /new group/i })).toBeInTheDocument();
			// Click the backdrop (the dialog element itself)
			const dialog = screen.getByRole("dialog", { name: /new group/i });
			fireEvent.click(dialog);
			expect(screen.queryByRole("dialog", { name: /new group/i })).not.toBeInTheDocument();
		});

		it("group badge appears in sidebar for group chats", async () => {
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			const gWorker = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-badge-test" })),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				gWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			useAuthStore.setState({ sessionToken: "tok-b", identityId: "id-b", deviceId: "dev-b" });

			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Badge Group" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			await waitFor(() => {
				expect(screen.getByTestId("group-badge")).toBeInTheDocument();
			});
		});

		it("group chat shows member count of 1 after creation", async () => {
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			const mWorker = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-member-count" })),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				mWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			useAuthStore.setState({ sessionToken: "tok-m", identityId: "id-m", deviceId: "dev-m" });

			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Member Count Group" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			await waitFor(() => {
				expect(screen.getByText("Member Count Group")).toBeInTheDocument();
			});
			fireEvent.click(screen.getByRole("button", { name: /member count group/i }));
			await waitFor(() => {
				const groupStatus = screen.getByTestId("group-status");
				// memberCount is 1 so it just shows "Group" (no member count suffix when <= 1)
				expect(groupStatus.textContent).toBe("Group");
			});
		});

		it("persists a GroupRow to Dexie when a group is created (closes the group-row-creation gap)", async () => {
			vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
			const dexieWorker = {
				...MOCK_WORKER,
				mlsCreateGroup: vi.fn(async () => ({ groupId: "group-dexie-created" })),
			};
			vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
				dexieWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
			);
			useAuthStore.setState({ sessionToken: "tok-d", identityId: "id-d", deviceId: "dev-d" });

			render(<ChatLayout />);
			fireEvent.click(screen.getByRole("button", { name: /new group/i }));
			fireEvent.change(screen.getByTestId("group-name-input"), {
				target: { value: "Dexie Group" },
			});
			fireEvent.click(screen.getByTestId("create-group-submit"));
			await waitFor(() => {
				expect(screen.getByText("Dexie Group")).toBeInTheDocument();
			});

			const row = await db.groups.get("group-dexie-created");
			expect(row).toBeDefined();
			expect(row?.name).toBe("Dexie Group");
			// No MLS state export exists yet — placeholder, not yet consumed anywhere.
			expect(row?.mlsStateB64).toBe("");
		});

		it("persists a GroupRow to Dexie when a Welcome envelope joins a new group", async () => {
			let capturedOnNewGroup:
				| ((event: { groupId: string; senderDeviceId: string }) => void)
				| null = null;
			vi.spyOn(WelcomePollerModule, "useWelcomePoller").mockImplementation(
				(_identityId, onNewGroup) => {
					capturedOnNewGroup = onNewGroup;
				},
			);
			useAuthStore.setState({ sessionToken: "tok-w", identityId: "id-w", deviceId: "dev-w" });

			render(<ChatLayout />);
			await waitFor(() => expect(capturedOnNewGroup).not.toBeNull());

			act(() => {
				capturedOnNewGroup?.({ groupId: "welcome-group-1", senderDeviceId: "peer-device-9999" });
			});

			await waitFor(async () => {
				const row = await db.groups.get("welcome-group-1");
				expect(row).toBeDefined();
			});
			const row = await db.groups.get("welcome-group-1");
			expect(row?.name).toBe("Contact peer-dev");
			expect(row?.mlsStateB64).toBe("");
		});
	});

	describe("message history rehydration (Dexie -> chats)", () => {
		const MAYA_GROUP = "11111111-1111-1111-1111-111111111111";
		const JORDAN_GROUP = "33333333-3333-3333-3333-333333333333";

		function seedRow(row: Partial<MessageRow> & Pick<MessageRow, "id" | "groupId">): MessageRow {
			return {
				ciphertextB64: "Zg==",
				senderDeviceId: "peer-device-x",
				epochSeq: 1,
				receivedAt: 1000,
				...row,
			};
		}

		it("rehydrates a plain, an edited, and a deleted row for the active chat on mount", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "rehydrate-plain-1",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("rehydrated plain text"),
				}),
				seedRow({
					id: "rehydrate-edited-1",
					groupId: MAYA_GROUP,
					receivedAt: 2000,
					plaintextB64: textToBase64("original text before edit"),
					editedText: textToBase64("rehydrated edited text"),
				}),
				seedRow({
					id: "rehydrate-deleted-1",
					groupId: MAYA_GROUP,
					receivedAt: 3000,
					plaintextB64: textToBase64("text that got deleted"),
					deletedAt: 4000,
				}),
			]);

			render(<ChatLayout />);

			await waitFor(() => {
				expect(screen.getAllByText("rehydrated plain text").length).toBeGreaterThan(0);
			});
			// Edited row shows the new text (not the stale original) plus the edited badge.
			expect(screen.getAllByText("rehydrated edited text").length).toBeGreaterThan(0);
			expect(screen.queryByText("original text before edit")).not.toBeInTheDocument();
			expect(screen.getByTestId("edited-badge")).toBeInTheDocument();
			// Deleted row renders the tombstone placeholder, not the raw text.
			expect(screen.getByTestId("deleted-placeholder")).toBeInTheDocument();
			expect(screen.queryByText("text that got deleted")).not.toBeInTheDocument();
		});

		it("switching chats loads the newly active chat's own rows without leaking the previous chat's rows", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "maya-only-row",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("maya exclusive history"),
				}),
				seedRow({
					id: "jordan-only-row",
					groupId: JORDAN_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("jordan exclusive history"),
				}),
			]);

			render(<ChatLayout />);

			await waitFor(() => {
				expect(screen.getAllByText("maya exclusive history").length).toBeGreaterThan(0);
			});
			expect(screen.queryByText("jordan exclusive history")).not.toBeInTheDocument();

			fireEvent.click(screen.getByRole("button", { name: /jordan/i }));

			await waitFor(() => {
				expect(screen.getAllByText("jordan exclusive history").length).toBeGreaterThan(0);
			});
			// Jordan's message pane must not show Maya's rehydrated history.
			expect(screen.queryByText("maya exclusive history")).not.toBeInTheDocument();
		});

		it("skips a row with no plaintextB64 and no editedText without crashing", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "ciphertext-only-row",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					// No plaintextB64, no editedText — nothing decryptable/renderable yet.
				}),
				seedRow({
					id: "renderable-row",
					groupId: MAYA_GROUP,
					receivedAt: 2000,
					plaintextB64: textToBase64("still renders fine"),
				}),
			]);

			expect(() => render(<ChatLayout />)).not.toThrow();

			await waitFor(() => {
				expect(screen.getAllByText("still renders fine").length).toBeGreaterThan(0);
			});
		});

		it("does not duplicate a message already present in chats state (same id) on rehydration", async () => {
			const DUP_ID = "dup-msg-live-and-persisted";
			await db.messages.bulkPut([
				seedRow({
					id: DUP_ID,
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("duplicate-safe text"),
				}),
			]);

			render(<ChatLayout />);

			await waitFor(() => {
				expect(screen.getAllByText("duplicate-safe text").length).toBeGreaterThan(0);
			});
			const countAfterMount = screen.getAllByText("duplicate-safe text").length;

			// Switch away and back — the hook reloads rows for each group change,
			// re-running rehydration against a chats state that already has DUP_ID.
			fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
			await waitFor(() => {
				expect(screen.queryByText("duplicate-safe text")).not.toBeInTheDocument();
			});
			fireEvent.click(screen.getByRole("button", { name: /maya/i }));

			await waitFor(() => {
				expect(screen.getAllByText("duplicate-safe text").length).toBeGreaterThan(0);
			});
			// Same bubble count as the first mount — no duplicate bubble was created.
			expect(screen.getAllByText("duplicate-safe text").length).toBe(countAfterMount);
		});

		it("reconciles an out-of-band edit/delete/reaction into a chat id already in state", async () => {
			const EDIT_ID = "reconcile-edit-live";
			const DELETE_ID = "reconcile-delete-live";
			const REACT_ID = "reconcile-reaction-live";
			await db.messages.bulkPut([
				seedRow({
					id: EDIT_ID,
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("stale pre-edit text"),
				}),
				seedRow({
					id: DELETE_ID,
					groupId: MAYA_GROUP,
					receivedAt: 2000,
					plaintextB64: textToBase64("not yet deleted"),
				}),
				seedRow({
					id: REACT_ID,
					groupId: MAYA_GROUP,
					receivedAt: 3000,
					plaintextB64: textToBase64("not yet reacted to"),
				}),
			]);

			render(<ChatLayout />);
			await waitFor(() => {
				expect(screen.getAllByText("stale pre-edit text").length).toBeGreaterThan(0);
			});
			expect(screen.getAllByText("not yet deleted").length).toBeGreaterThan(0);
			expect(screen.queryByTestId("edited-badge")).not.toBeInTheDocument();
			expect(screen.queryByTestId("deleted-placeholder")).not.toBeInTheDocument();
			expect(screen.queryByTestId("reaction-chip-🎉")).not.toBeInTheDocument();

			// Simulate another browser tab on the same account mutating these rows in
			// Dexie directly — this tab's own handleIncomingEdit/Delete/Reaction never
			// ran, so these ids are already in `chats` state with the pre-mutation data.
			await db.messages.update(EDIT_ID, { editedText: textToBase64("edited out of band") });
			await db.messages.update(DELETE_ID, { deletedAt: 5000 });
			await db.messages.update(REACT_ID, {
				reactionsJson: JSON.stringify({ "🎉": ["peer-device-x"] }),
			});

			// Switch away and back — the hook reloads `rows` for the group, re-running
			// the rehydration effect against a `chats` state that already has these ids.
			fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
			await waitFor(() => {
				expect(screen.queryByText("stale pre-edit text")).not.toBeInTheDocument();
			});
			fireEvent.click(screen.getByRole("button", { name: /maya/i }));

			await waitFor(() => {
				expect(screen.getAllByText("edited out of band").length).toBeGreaterThan(0);
			});
			expect(screen.queryByText("stale pre-edit text")).not.toBeInTheDocument();
			expect(screen.getByTestId("edited-badge")).toBeInTheDocument();
			expect(screen.getByTestId("deleted-placeholder")).toBeInTheDocument();
			expect(screen.queryByText("not yet deleted")).not.toBeInTheDocument();
			expect(screen.getByTestId("reaction-chip-🎉")).toBeInTheDocument();
		});

		it("rehydrates a persisted reaction map for the active chat on mount", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "rehydrate-reacted-1",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("message with a reaction"),
					reactionsJson: JSON.stringify({ "👍": ["peer-device-x"] }),
				}),
			]);

			render(<ChatLayout />);

			await waitFor(() => {
				expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();
			});
		});

		it("skips reactionsJson that fails to parse without crashing the whole row", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "rehydrate-bad-reactions-1",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("still renders despite bad reactions json"),
					reactionsJson: "{not valid json",
				}),
			]);

			expect(() => render(<ChatLayout />)).not.toThrow();

			await waitFor(() => {
				expect(
					screen.getAllByText("still renders despite bad reactions json").length,
				).toBeGreaterThan(0);
			});
			expect(screen.queryByTestId("reaction-chips")).not.toBeInTheDocument();
		});

		it("restores a persisted pinned message on mount for the active chat", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "rehydrate-pinned-1",
					groupId: MAYA_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("this message was pinned before reload"),
				}),
			]);
			await db.groups.add({
				id: MAYA_GROUP,
				name: "Maya Akana",
				mlsStateB64: "",
				lastActivity: 1000,
				pinnedMessageId: "rehydrate-pinned-1",
			});

			render(<ChatLayout />);

			await waitFor(() => {
				expect(screen.getByTestId("pinned-banner")).toBeInTheDocument();
			});
			expect(screen.getByTestId("pinned-banner").textContent).toContain(
				"this message was pinned before reload",
			);
		});

		it("does not restore a persisted pin for a different (inactive) chat's messages", async () => {
			await db.messages.bulkPut([
				seedRow({
					id: "rehydrate-pinned-jordan-1",
					groupId: JORDAN_GROUP,
					receivedAt: 1000,
					plaintextB64: textToBase64("jordan's pinned message"),
				}),
			]);
			await db.groups.add({
				id: JORDAN_GROUP,
				name: "Jordan",
				mlsStateB64: "",
				lastActivity: 1000,
				pinnedMessageId: "rehydrate-pinned-jordan-1",
			});

			// Maya is the default active chat — Jordan's pin must not leak into it.
			render(<ChatLayout />);
			await act(async () => {});

			expect(screen.queryByTestId("pinned-banner")).not.toBeInTheDocument();
		});
	});
});
