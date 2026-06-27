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

// mlsGroupId from SEED_CHATS (Jordan's group, used for auto-unarchive test)
const JORDAN_GROUP_ID = "33333333-3333-3333-3333-333333333333";

describe("ChatLayout — chat archive", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	function setup() {
		let capturedOnMessage: ((m: IncomingMessage) => void) | undefined;
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation((_id, _gid, onMsg) => {
			if (onMsg) capturedOnMessage = onMsg;
		});
		render(<ChatLayout />);
		return {
			triggerIncoming: (m: IncomingMessage) => capturedOnMessage?.(m),
		};
	}

	it("Archived tab renders", () => {
		render(<ChatLayout />);
		expect(screen.getByTestId("filter-tab-archived")).toBeInTheDocument();
	});

	it("Archived tab shows only archived chats", async () => {
		render(<ChatLayout />);
		// Open Jordan's InfoPanel and archive it
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Switch to archived tab
		fireEvent.click(screen.getByTestId("filter-tab-archived"));
		// Jordan should appear in the archived tab
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /jordan/i })).toBeInTheDocument(),
		);
		// Maya should NOT appear
		expect(screen.queryByRole("button", { name: /maya akana/i })).not.toBeInTheDocument();
	});

	it("All tab excludes archived chats", async () => {
		render(<ChatLayout />);
		// Archive Jordan via InfoPanel
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Go back to All tab
		fireEvent.click(screen.getByTestId("filter-tab-all"));
		// Jordan should NOT appear in All tab
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /^jordan$/i })).not.toBeInTheDocument(),
		);
	});

	it("Archive button in InfoPanel toggles to Unarchive Chat", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const archiveBtn = screen.getByTestId("archive-button");
		expect(archiveBtn).toHaveTextContent("Archive Chat");
		fireEvent.click(archiveBtn);
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
	});

	it("Unarchive button in InfoPanel toggles back to Archive Chat", async () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		const btn = () => screen.getByTestId("archive-button");
		// Archive
		fireEvent.click(btn());
		await waitFor(() => expect(btn()).toHaveTextContent("Unarchive Chat"));
		// Unarchive
		fireEvent.click(btn());
		await waitFor(() => expect(btn()).toHaveTextContent("Archive Chat"));
	});

	it("Archived chat auto-unarchives on new message", async () => {
		const { triggerIncoming } = setup();
		// Archive Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Switch to archived tab to confirm Jordan is there
		fireEvent.click(screen.getByTestId("filter-tab-archived"));
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /jordan/i })).toBeInTheDocument(),
		);
		// Switch to All tab — Jordan not there yet
		fireEvent.click(screen.getByTestId("filter-tab-all"));
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /^jordan$/i })).not.toBeInTheDocument(),
		);
		// Simulate incoming message on Jordan's MLS group
		await act(async () => {
			triggerIncoming({
				id: "archive-auto-unarchive-0001",
				senderId: "peer-device",
				groupId: JORDAN_GROUP_ID,
				text: "New message auto-unarchives",
				ciphertextB64: "Zg==",
				epochSeq: 1,
			});
		});
		// Jordan should now appear in All tab (auto-unarchived)
		await waitFor(() =>
			expect(screen.getByRole("button", { name: /jordan/i })).toBeInTheDocument(),
		);
	});

	it("Archived tab badge is absent", () => {
		render(<ChatLayout />);
		// The archived tab never shows an unread badge
		const archivedTab = screen.getByTestId("filter-tab-archived");
		expect(archivedTab).not.toContainElement(screen.queryByTestId("filter-tab-archived-badge"));
	});

	it("Chat archived via InfoPanel disappears from All tab", async () => {
		render(<ChatLayout />);
		// Verify Jordan is in All tab
		expect(screen.getByRole("button", { name: /jordan/i })).toBeInTheDocument();
		// Archive Jordan
		fireEvent.click(screen.getByRole("button", { name: /jordan/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// All tab is still active — Jordan must be gone
		fireEvent.click(screen.getByTestId("filter-tab-all"));
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /^jordan$/i })).not.toBeInTheDocument(),
		);
	});

	it("DMs tab also excludes archived chat", async () => {
		render(<ChatLayout />);
		// Archive Maya (a DM)
		fireEvent.click(screen.getAllByRole("button", { name: /maya akana/i })[0]);
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Switch to Chats (DMs) tab
		fireEvent.click(screen.getByTestId("filter-tab-dms"));
		// Maya should not appear in DMs tab
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /maya akana/i })).not.toBeInTheDocument(),
		);
	});

	it("Groups tab also excludes archived group", async () => {
		render(<ChatLayout />);
		// Archive Design Team (a group)
		fireEvent.click(screen.getByRole("button", { name: /design team/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		fireEvent.click(screen.getByTestId("archive-button"));
		await waitFor(() =>
			expect(screen.getByTestId("archive-button")).toHaveTextContent("Unarchive Chat"),
		);
		// Switch to Groups tab
		fireEvent.click(screen.getByTestId("filter-tab-groups"));
		// Design Team should not appear in Groups tab
		await waitFor(() =>
			expect(screen.queryByRole("button", { name: /design team/i })).not.toBeInTheDocument(),
		);
	});
});
