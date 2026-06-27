import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import * as UseMessagesModule from "../hooks/useMessages";
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

function openGroupInfoPanel() {
	// Click "Design Team" in the sidebar (Groups tab)
	fireEvent.click(screen.getByTestId("filter-tab-groups"));
	fireEvent.click(screen.getByRole("button", { name: /design team/i }));
	fireEvent.click(screen.getByRole("button", { name: /info/i }));
}

describe("ChatLayout — group member list", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		useAuthStore.setState({
			sessionToken: null,
			identityId: null,
			deviceId: null,
			myHandle: null,
		});
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		vi.spyOn(UseMessagesModule, "useMessages").mockImplementation(() => {});
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
	});

	it("group member list renders when InfoPanel opens for a group chat", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => expect(screen.getByTestId("group-member-list")).toBeInTheDocument());
	});

	it("group member list is NOT rendered for DM chats", async () => {
		render(<ChatLayout />);
		// Open Maya's DM InfoPanel
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() => expect(screen.queryByTestId("group-member-list")).not.toBeInTheDocument());
	});

	it("members section title shows correct member count", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		// Design Team has 4 members
		await waitFor(() => expect(screen.getByText("Members (4)")).toBeInTheDocument());
	});

	it("each member row renders with data-testid", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			const rows = screen.getAllByTestId("group-member-row");
			expect(rows).toHaveLength(4);
		});
	});

	it("member names are displayed", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			expect(screen.getByText("Finn")).toBeInTheDocument();
			expect(screen.getByText("Maya")).toBeInTheDocument();
			expect(screen.getByText("Jordan")).toBeInTheDocument();
			expect(screen.getByText("Noa")).toBeInTheDocument();
		});
	});

	it("member handles are displayed with @ prefix", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			expect(screen.getByText("@finn")).toBeInTheDocument();
			expect(screen.getByText("@maya")).toBeInTheDocument();
			expect(screen.getByText("@jordan")).toBeInTheDocument();
			expect(screen.getByText("@noa")).toBeInTheDocument();
		});
	});

	it("admin badge shown for admin member", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		// Finn is admin in the Design Team seed
		await waitFor(() => {
			const adminBadges = screen.getAllByTestId("member-admin-badge");
			expect(adminBadges).toHaveLength(1);
			expect(adminBadges[0]).toHaveTextContent("Admin");
		});
	});

	it("non-admin members do not have admin badge", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			// Only 1 admin badge total
			const adminBadges = screen.getAllByTestId("member-admin-badge");
			expect(adminBadges).toHaveLength(1);
		});
	});

	it("You badge shown on own member entry when myHandle matches", async () => {
		useAuthStore.setState({
			sessionToken: null,
			identityId: null,
			deviceId: null,
			myHandle: "finn",
		});
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			const youBadges = screen.getAllByTestId("member-you-badge");
			expect(youBadges).toHaveLength(1);
			expect(youBadges[0]).toHaveTextContent("You");
		});
	});

	it("You badge is absent when myHandle is not in the member list", async () => {
		useAuthStore.setState({
			sessionToken: null,
			identityId: null,
			deviceId: null,
			myHandle: "unknown-user",
		});
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => expect(screen.queryByTestId("member-you-badge")).not.toBeInTheDocument());
	});

	it("Safety number card does NOT appear for group chats", async () => {
		render(<ChatLayout />);
		openGroupInfoPanel();
		await waitFor(() => {
			expect(screen.queryByText("Safety Numbers")).not.toBeInTheDocument();
		});
	});

	it("Safety number card appears for DM chats (not group)", async () => {
		render(<ChatLayout />);
		// Open Maya's DM InfoPanel
		fireEvent.click(screen.getByRole("button", { name: /maya akana/i }));
		fireEvent.click(screen.getByRole("button", { name: /info/i }));
		await waitFor(() => expect(screen.getByText("Safety Numbers")).toBeInTheDocument());
	});
});
