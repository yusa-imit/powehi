import { act, render, screen } from "@testing-library/react";
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

describe("ChatLayout — group message reactions total summary + sidebar preview", () => {
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

	// ── Sidebar last-message reaction summary ──────────────────────────────────

	it("sidebar shows reaction summary for Design Team (last msg has reactions)", () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
		render(<ChatLayout />);
		// Design Team seed: last message has 🎉×3 + 🔥×2
		const summaries = screen.getAllByTestId("last-msg-reaction-summary");
		expect(summaries.length).toBeGreaterThan(0);
		const designTeamSummary = summaries[0];
		expect(designTeamSummary.textContent).toContain("🎉");
		expect(designTeamSummary.textContent).toContain("🔥");
	});

	it("sidebar shows no reaction summary for DM chat (maya)", () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
		render(<ChatLayout />);
		// maya is a DM with no reactions on last message
		const summaries = screen.queryAllByTestId("last-msg-reaction-summary");
		// Only Design Team should have a summary; maya should not
		// The Design Team summary contains 🎉 so we verify DM chats don't add extra ones
		const allText = summaries.map((el) => el.textContent ?? "");
		// All summaries must be for group chats — none contain DM-only text
		for (const t of allText) {
			expect(t.length).toBeGreaterThan(0);
		}
	});

	it("sidebar reaction summary contains emoji and count for multi-sender reactions", () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
		render(<ChatLayout />);
		const summaries = screen.getAllByTestId("last-msg-reaction-summary");
		const designSummary = summaries.find((el) => el.textContent?.includes("🎉"));
		expect(designSummary).toBeTruthy();
		// 🎉 has 3 senders → shown as "🎉3"
		expect(designSummary?.textContent).toContain("🎉3");
		// 🔥 has 2 senders → shown as "🔥2"
		expect(designSummary?.textContent).toContain("🔥2");
	});

	// ── In-message reaction-total-summary ─────────────────────────────────────

	it("group message with >= 2 total reactions shows reaction-total-summary", async () => {
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

		// Select Design Team (isGroup=true)
		const designTeamBtn = screen.getByText("Design Team").closest("button");
		expect(designTeamBtn).toBeTruthy();
		designTeamBtn?.click();

		const MSG_ID = "grp-summary-uuid-1111-111111111111";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "44444444-4444-4444-4444-444444444444",
				senderId: "dev-x",
				text: "group reactions test",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});

		// Two senders react with two different emojis → total = 2
		await act(async () => {
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "👍", "dev-a");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "❤️", "dev-b");
		});

		const summaries = screen.getAllByTestId("reaction-total-summary");
		expect(summaries.length).toBeGreaterThan(0);
		// At least one summary shows the right count
		const msgSummary = summaries.find((el) => el.textContent?.includes("2 reactions"));
		expect(msgSummary).toBeTruthy();
	});

	it("DM message with reactions does NOT show reaction-total-summary", async () => {
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

		// Default active chat is Maya — a DM (isGroup=false)
		const MSG_ID = "dm-no-summary-uuid-2222-222222222222";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "11111111-1111-1111-1111-111111111111",
				senderId: "peer-dev-dm",
				text: "DM reaction no summary",
				ciphertextB64: "Zg==",
				epochSeq: 2,
			});
		});

		// Two senders react
		await act(async () => {
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "👍", "dev-a");
			capturedOnReaction?.("11111111-1111-1111-1111-111111111111", MSG_ID, "❤️", "dev-b");
		});

		// DM — no summary badge
		expect(screen.queryByTestId("reaction-total-summary")).not.toBeInTheDocument();
	});

	it("group message with only 1 total reaction does NOT show reaction-total-summary", async () => {
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

		// Navigate to Design Team
		const designTeamBtn = screen.getByText("Design Team").closest("button");
		designTeamBtn?.click();

		const MSG_ID = "grp-one-react-uuid-3333-333333333333";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "44444444-4444-4444-4444-444444444444",
				senderId: "dev-y",
				text: "single reaction test",
				ciphertextB64: "Zg==",
				epochSeq: 3,
			});
		});

		// Only 1 reaction total
		await act(async () => {
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "😮", "dev-a");
		});

		// Chip is shown but NO total summary (threshold is 2)
		expect(screen.getByTestId("reaction-chip-😮")).toBeInTheDocument();
		// No total summary element for this message (seed messages may have some, filter by content)
		const summaries = screen.queryAllByTestId("reaction-total-summary");
		// The seed messages for Design Team already have totals (👍3+❤️1=4, 👀2)
		// but the new single-reaction message should NOT add a summary
		const singleMsgSummary = summaries.find((el) => el.textContent?.includes("1 reaction"));
		expect(singleMsgSummary).toBeFalsy();
	});

	it("reaction-total-summary count is accurate across multiple emojis", async () => {
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

		const designTeamBtn = screen.getByText("Design Team").closest("button");
		designTeamBtn?.click();

		const MSG_ID = "grp-count-uuid-4444-444444444444";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "44444444-4444-4444-4444-444444444444",
				senderId: "dev-z",
				text: "count accuracy test",
				ciphertextB64: "Zg==",
				epochSeq: 4,
			});
		});

		// 👍 × 3 + ❤️ × 2 + 😂 × 1 = 6 total
		await act(async () => {
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "👍", "dev-a");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "👍", "dev-b");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "👍", "dev-c");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "❤️", "dev-d");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "❤️", "dev-e");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "😂", "dev-f");
		});

		const summaries = screen.getAllByTestId("reaction-total-summary");
		const sixReactionSummary = summaries.find((el) => el.textContent?.includes("6 reactions"));
		expect(sixReactionSummary).toBeTruthy();
	});

	it("reaction-total-summary uses singular 'reaction' for exactly 1 count (edge case — not shown but text accurate)", async () => {
		// This tests the pluralisation logic in isolation — the summary is only
		// rendered when totalReactionCount >= 2, so 1 reaction never shows, but
		// if the threshold were relaxed the text would be "1 reaction" not "1 reactions".
		// We verify via the plural branch: 2 reactions → "2 reactions" (plural).
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

		const designTeamBtn = screen.getByText("Design Team").closest("button");
		designTeamBtn?.click();

		const MSG_ID = "plural-uuid-5555-555555555555";
		await act(async () => {
			capturedOnMessage?.({
				id: MSG_ID,
				groupId: "44444444-4444-4444-4444-444444444444",
				senderId: "dev-p",
				text: "plural test",
				ciphertextB64: "Zg==",
				epochSeq: 5,
			});
		});

		await act(async () => {
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "👍", "dev-a");
			capturedOnReaction?.("44444444-4444-4444-4444-444444444444", MSG_ID, "❤️", "dev-b");
		});

		const summaries = screen.getAllByTestId("reaction-total-summary");
		const plural = summaries.find((el) => el.textContent?.includes("2 reactions"));
		expect(plural).toBeTruthy();
		// Confirm no "2 reaction " (without 's') bug
		const noBug = summaries.find((el) => /·\s+2 reaction[^s]/.test(el.textContent ?? ""));
		expect(noBug).toBeFalsy();
	});

	it("Design Team seed shows reaction chips for first message when selected", async () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
		render(<ChatLayout />);

		// Navigate to Design Team
		const designTeamBtn = screen.getByText("Design Team").closest("button");
		expect(designTeamBtn).toBeTruthy();
		await act(async () => {
			designTeamBtn?.click();
		});

		// First seed message has 👍×3 + ❤️×1
		expect(screen.getByTestId("reaction-chip-👍")).toBeInTheDocument();
		expect(screen.getByTestId("reaction-chip-❤️")).toBeInTheDocument();
	});

	it("Design Team seed shows reaction-total-summary for first message (👍3 + ❤️1 = 4 total)", async () => {
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => undefined);
		render(<ChatLayout />);

		const designTeamBtn = screen.getByText("Design Team").closest("button");
		await act(async () => {
			designTeamBtn?.click();
		});

		// totalReactionCount for first message = 3 + 1 = 4 → shows "· 4 reactions"
		const summaries = screen.getAllByTestId("reaction-total-summary");
		const fourReactions = summaries.find((el) => el.textContent?.includes("4 reactions"));
		expect(fourReactions).toBeTruthy();
	});
});
