import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

// From SEED_CHATS
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";
const DESIGN_TEAM_GROUP_ID = "44444444-4444-4444-4444-444444444444";

describe("ChatLayout — sidebar chat filter tabs", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("All, Chats, and Groups tabs are rendered", () => {
		render(<ChatLayout />);
		expect(screen.getByTestId("filter-tab-all")).toBeInTheDocument();
		expect(screen.getByTestId("filter-tab-dms")).toBeInTheDocument();
		expect(screen.getByTestId("filter-tab-groups")).toBeInTheDocument();
	});

	it("All tab shows both DM and group chats", () => {
		render(<ChatLayout />);
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Jordan").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Design Team").length).toBeGreaterThan(0);
	});

	it("Chats tab hides group chats and shows only DMs", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-dms"));
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getAllByText("Jordan").length).toBeGreaterThan(0);
		expect(screen.queryByRole("button", { name: /design team/i })).not.toBeInTheDocument();
	});

	it("Groups tab hides DMs and shows only group chats", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-groups"));
		expect(screen.getByRole("button", { name: /design team/i })).toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /maya akana/i })).not.toBeInTheDocument();
		expect(screen.queryByRole("button", { name: /^jordan$/i })).not.toBeInTheDocument();
	});

	it("All tab is restored after switching back from Groups", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-groups"));
		expect(screen.queryByRole("button", { name: /maya akana/i })).not.toBeInTheDocument();
		fireEvent.click(screen.getByTestId("filter-tab-all"));
		expect(screen.getAllByText("Maya Akana").length).toBeGreaterThan(0);
		expect(screen.getByRole("button", { name: /design team/i })).toBeInTheDocument();
	});

	it("Chats tab shows DM unread badge (Jordan has 2 unread)", () => {
		render(<ChatLayout />);
		expect(screen.getByTestId("filter-tab-dms-badge")).toHaveTextContent("2");
	});

	it("Groups tab does not show badge when no group has unread messages", () => {
		render(<ChatLayout />);
		// Design Team starts with unread: 0 → no badge on Groups tab
		expect(screen.queryByTestId("filter-tab-groups-badge")).not.toBeInTheDocument();
	});

	it("Groups tab badge appears after an incoming group message", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Select Design Team then switch away so it becomes a background chat
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// Dispatch an incoming message for the Design Team MLS group
		await act(async () => {
			capturedOnMessage?.({
				id: "filter-group-uuid-0001",
				senderId: "peer-group-member",
				groupId: DESIGN_TEAM_GROUP_ID,
				text: "New group message",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		// Groups tab badge must now show "1"
		await waitFor(() =>
			expect(screen.getByTestId("filter-tab-groups-badge")).toHaveTextContent("1"),
		);
	});

	it("Chats tab badge updates when DM unread increments", async () => {
		let capturedOnMessage: ((msg: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		// Select Jordan to clear its 2-unread badge, then switch to Maya
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		// DM badge now shows 0 — no badge
		expect(screen.queryByTestId("filter-tab-dms-badge")).not.toBeInTheDocument();
		// Incoming message for Jordan
		await act(async () => {
			capturedOnMessage?.({
				id: "filter-dm-uuid-0001",
				senderId: "peer-jordan",
				groupId: JORDAN_GROUP_ID,
				text: "DM incoming",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		// Chats tab badge now shows "1"
		await waitFor(() => expect(screen.getByTestId("filter-tab-dms-badge")).toHaveTextContent("1"));
	});

	it("Groups tab: message search is scoped to group chats only", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-groups"));
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		fireEvent.change(searchInput, { target: { value: "palette" } });
		// "I pushed the color palette revisions." is in Design Team messages
		expect(screen.getByTestId("msg-search-section-header")).toBeInTheDocument();
		const results = screen.getAllByTestId("msg-search-result");
		for (const result of results) {
			expect(result).toHaveTextContent(/design team/i);
		}
	});

	it("Chats tab: message search excludes group chat messages", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByTestId("filter-tab-dms"));
		const searchInput = screen.getByPlaceholderText(/search chats/i);
		// "color palette" only exists in Design Team — should yield no message results on Chats tab
		fireEvent.change(searchInput, { target: { value: "color palette" } });
		expect(screen.queryByTestId("msg-search-section-header")).not.toBeInTheDocument();
	});
});
