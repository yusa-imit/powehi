import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
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

async function openDmInfoPanel() {
	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	render(<ChatLayout />);
	// Click the first DM seed chat — Maya
	fireEvent.click(screen.getAllByRole("button", { name: /maya/i })[0]);
	// Open InfoPanel
	fireEvent.click(screen.getByRole("button", { name: /info|conversation info/i }));
	await waitFor(() => expect(screen.getByTestId("nickname-display")).toBeInTheDocument());
}

async function createGroupAndOpenInfo(groupName: string) {
	vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
	const worker = {
		...MOCK_WORKER,
		mlsCreateGroup: vi.fn(async () => ({
			groupId: `grp-${groupName.toLowerCase().replace(/\s/g, "-")}`,
		})),
	};
	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		worker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	useAuthStore.setState({ sessionToken: "tok-nn", identityId: "id-nn", deviceId: "dev-nn" });

	render(<ChatLayout />);
	fireEvent.click(screen.getByRole("button", { name: /new group/i }));
	fireEvent.change(screen.getByTestId("group-name-input"), { target: { value: groupName } });
	fireEvent.click(screen.getByTestId("create-group-submit"));
	await waitFor(() => expect(screen.getByText(groupName)).toBeInTheDocument());
	fireEvent.click(screen.getByRole("button", { name: new RegExp(groupName, "i") }));
	await waitFor(() => expect(screen.getByTestId("group-status")).toBeInTheDocument());
	fireEvent.click(screen.getByRole("button", { name: /info|conversation info/i }));
	await waitFor(() => expect(screen.getByTestId("group-description-text")).toBeInTheDocument());
}

describe("ChatLayout — chat nickname", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("nickname section is shown in DM InfoPanel", async () => {
		await openDmInfoPanel();
		expect(screen.getByTestId("nickname-display")).toBeInTheDocument();
	});

	it("nickname section is NOT shown in group InfoPanel", async () => {
		await createGroupAndOpenInfo("Nickname Test Group");
		expect(screen.queryByTestId("nickname-display")).not.toBeInTheDocument();
		expect(screen.queryByTestId("nickname-edit-btn")).not.toBeInTheDocument();
	});

	it("shows 'No nickname set' placeholder when no nickname", async () => {
		await openDmInfoPanel();
		expect(screen.getByTestId("nickname-display")).toHaveTextContent("No nickname set");
	});

	it("edit button opens the nickname input", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		expect(screen.getByTestId("nickname-input")).toBeInTheDocument();
	});

	it("nickname input has maxLength 50", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		expect(screen.getByTestId("nickname-input")).toHaveAttribute("maxLength", "50");
	});

	it("Save button saves the nickname and hides input", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "My Maya" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("My Maya"),
		);
		expect(screen.queryByTestId("nickname-input")).not.toBeInTheDocument();
	});

	it("pressing Enter saves the nickname", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Enter Nick" } });
		fireEvent.keyDown(screen.getByTestId("nickname-input"), { key: "Enter" });
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("Enter Nick"),
		);
	});

	it("Cancel button discards the draft without saving", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Discard Me" } });
		fireEvent.click(screen.getByTestId("nickname-cancel"));
		expect(screen.queryByTestId("nickname-input")).not.toBeInTheDocument();
		expect(screen.getByTestId("nickname-display")).toHaveTextContent("No nickname set");
	});

	it("Escape key cancels without saving", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Esc Nick" } });
		fireEvent.keyDown(screen.getByTestId("nickname-input"), { key: "Escape" });
		expect(screen.queryByTestId("nickname-input")).not.toBeInTheDocument();
		expect(screen.getByTestId("nickname-display")).toHaveTextContent("No nickname set");
	});

	it("saved nickname appears in the ConversationHeader", async () => {
		await openDmInfoPanel();
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Header Nick" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("conversation-header-name")).toHaveTextContent("Header Nick"),
		);
	});

	it("clearing nickname (empty string) restores original name in ConversationHeader", async () => {
		await openDmInfoPanel();
		// First set a nickname
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Temp Nick" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("Temp Nick"),
		);
		// Now clear it
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("No nickname set"),
		);
		// Header reverts to real name
		expect(screen.getByTestId("conversation-header-name")).toHaveTextContent("Maya");
	});

	it("nickname is searchable in the QuickSwitcher", async () => {
		await openDmInfoPanel();
		// Set nickname
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "SearchMe" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("SearchMe"),
		);
		// Open quick switcher and type the nickname
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		fireEvent.change(screen.getByTestId("quick-switcher-input"), {
			target: { value: "SearchMe" },
		});
		await waitFor(() => {
			const items = screen.queryAllByTestId(/^quick-switcher-item-/);
			expect(items.length).toBeGreaterThan(0);
		});
	});

	it("QuickSwitcher displays nickname instead of real name when set", async () => {
		await openDmInfoPanel();
		// Set nickname
		fireEvent.click(screen.getByTestId("nickname-edit-btn"));
		fireEvent.change(screen.getByTestId("nickname-input"), { target: { value: "Display Nick" } });
		fireEvent.click(screen.getByTestId("nickname-save"));
		await waitFor(() =>
			expect(screen.getByTestId("nickname-display")).toHaveTextContent("Display Nick"),
		);
		// Open quick switcher — find Maya's item and check it shows the nickname
		await act(async () => {
			fireEvent.keyDown(window, { key: "k", ctrlKey: true });
		});
		await waitFor(() => expect(screen.getAllByText("Display Nick").length).toBeGreaterThan(0));
	});
});
