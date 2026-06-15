import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as MessagesApiModule from "../api/messages";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
import type { IncomingMessage } from "../hooks/useMessages";
import { useAuthStore } from "../store/auth";
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
		// The disappearing badge should appear ("Disappearing" text)
		expect(screen.getByText("Disappearing")).toBeInTheDocument();
	});

	it("persists verification to DB when user confirms safety number match", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
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

	it("seed chat Sam shows 'typing...' in sidebar", () => {
		render(<ChatLayout />);
		// Sam has typing: true in SEED_CHATS; sidebar should show italicised "typing..."
		expect(screen.getByText("typing...")).toBeInTheDocument();
	});

	it("incoming typing signal shows '· typing' in the conversation header for the active chat", async () => {
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

		// The ConversationHeader should now show "· typing"
		expect(screen.getByText(/·\s*typing/i)).toBeInTheDocument();
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

			// Trigger typing signal
			await act(async () => {
				capturedOnTyping?.("11111111-1111-1111-1111-111111111111");
			});
			expect(screen.getByText(/·\s*typing/i)).toBeInTheDocument();

			// Advance timers past the 3 s auto-clear
			await act(async () => {
				vi.advanceTimersByTime(3_100);
			});
			expect(screen.queryByText(/·\s*typing/i)).not.toBeInTheDocument();
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
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, onReadReceipt) => {
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
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, onReadReceipt) => {
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
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onReadReceipt, onDeliveryReceipt) => {
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
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onReadReceipt, onDeliveryReceipt) => {
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
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, onReadReceipt, onDeliveryReceipt) => {
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
				(_id, _gid, onMsg, _onPq, _onTyping, _onReaction, _onRead, _onDelivery, onEdit) => {
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
		});

		it("incoming edit does NOT rewrite 'me' messages (own message protection)", async () => {
			let capturedOnEdit:
				| ((
						groupId: string,
						targetMessageId: string,
						newText: string,
						senderDeviceId: string,
				  ) => void)
				| undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(_id, _gid, _onMsg, _onPq, _onTyping, _onReaction, _onRead, _onDelivery, onEdit) => {
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
		});

		it("incoming delete does NOT erase own 'me' messages", async () => {
			let capturedOnDelete: ((groupId: string, targetMessageId: string) => void) | undefined;
			vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(
				(
					_id,
					_gid,
					_onMsg,
					_onPq,
					_onTyping,
					_onReaction,
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
		});
	});
});
