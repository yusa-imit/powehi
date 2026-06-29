import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
	useAuthStore.setState({ sessionToken: "tok-gd", identityId: "id-gd", deviceId: "dev-gd" });

	render(<ChatLayout />);
	fireEvent.click(screen.getByRole("button", { name: /new group/i }));
	fireEvent.change(screen.getByTestId("group-name-input"), { target: { value: groupName } });
	fireEvent.click(screen.getByTestId("create-group-submit"));
	await waitFor(() => expect(screen.getByText(groupName)).toBeInTheDocument());
	fireEvent.click(screen.getByRole("button", { name: new RegExp(groupName, "i") }));
	await waitFor(() => expect(screen.getByTestId("group-status")).toBeInTheDocument());

	// Open InfoPanel
	fireEvent.click(screen.getByRole("button", { name: /info|conversation info/i }));
	await waitFor(() => expect(screen.getByTestId("group-description-text")).toBeInTheDocument());
}

describe("ChatLayout — group description", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("seed Design Team shows its description in InfoPanel", async () => {
		render(<ChatLayout />);
		// Select Design Team (4th seed chat)
		const designTeam = screen.getByRole("button", { name: /design team/i });
		fireEvent.click(designTeam);
		await waitFor(() => expect(screen.getByTestId("group-status")).toBeInTheDocument());
		fireEvent.click(screen.getByRole("button", { name: /info|conversation info/i }));
		await waitFor(() =>
			expect(screen.getByTestId("group-description-text")).toHaveTextContent(
				"Where design meets code",
			),
		);
	});

	it("new group shows 'No description set' placeholder", async () => {
		await createGroupAndOpenInfo("Empty Desc Group");
		expect(screen.getByTestId("group-description-text")).toHaveTextContent("No description set");
	});

	it("edit button is present for group InfoPanel", async () => {
		await createGroupAndOpenInfo("Edit Btn Group");
		expect(screen.getByTestId("group-description-edit-btn")).toBeInTheDocument();
	});

	it("clicking edit button shows textarea with current description", async () => {
		await createGroupAndOpenInfo("Edit Open Group");
		fireEvent.click(screen.getByTestId("group-description-edit-btn"));
		expect(screen.getByTestId("group-description-input")).toBeInTheDocument();
	});

	it("Save button saves the new description", async () => {
		await createGroupAndOpenInfo("Save Desc Group");
		fireEvent.click(screen.getByTestId("group-description-edit-btn"));
		fireEvent.change(screen.getByTestId("group-description-input"), {
			target: { value: "My new description" },
		});
		fireEvent.click(screen.getByTestId("group-description-save"));
		await waitFor(() =>
			expect(screen.getByTestId("group-description-text")).toHaveTextContent("My new description"),
		);
	});

	it("pressing Enter saves the description and hides textarea", async () => {
		await createGroupAndOpenInfo("Enter Save Group");
		fireEvent.click(screen.getByTestId("group-description-edit-btn"));
		fireEvent.change(screen.getByTestId("group-description-input"), {
			target: { value: "Enter key saved" },
		});
		fireEvent.keyDown(screen.getByTestId("group-description-input"), { key: "Enter" });
		await waitFor(() =>
			expect(screen.getByTestId("group-description-text")).toHaveTextContent("Enter key saved"),
		);
		expect(screen.queryByTestId("group-description-input")).not.toBeInTheDocument();
	});

	it("pressing Escape cancels editing without saving", async () => {
		await createGroupAndOpenInfo("Escape Cancel Group");
		fireEvent.click(screen.getByTestId("group-description-edit-btn"));
		fireEvent.change(screen.getByTestId("group-description-input"), {
			target: { value: "Should not save" },
		});
		fireEvent.keyDown(screen.getByTestId("group-description-input"), { key: "Escape" });
		expect(screen.queryByTestId("group-description-input")).not.toBeInTheDocument();
		expect(screen.getByTestId("group-description-text")).toHaveTextContent("No description set");
	});

	it("Cancel button dismisses textarea without saving", async () => {
		await createGroupAndOpenInfo("Cancel Btn Group");
		fireEvent.click(screen.getByTestId("group-description-edit-btn"));
		fireEvent.change(screen.getByTestId("group-description-input"), {
			target: { value: "Draft discard" },
		});
		fireEvent.click(screen.getByTestId("group-description-cancel"));
		expect(screen.queryByTestId("group-description-input")).not.toBeInTheDocument();
		expect(screen.getByTestId("group-description-text")).toHaveTextContent("No description set");
	});

	it("description section is absent in the InfoPanel for DM chats", async () => {
		render(<ChatLayout />);
		// Sam (seed DM chat) — click to open, then open InfoPanel
		fireEvent.click(screen.getByRole("button", { name: /sam/i }));
		fireEvent.click(screen.getByRole("button", { name: /info|conversation info/i }));
		// DM InfoPanel shows Safety Numbers, not group-description-text
		await waitFor(() =>
			expect(screen.queryByTestId("group-description-text")).not.toBeInTheDocument(),
		);
	});
});
