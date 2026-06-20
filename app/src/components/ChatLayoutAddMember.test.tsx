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

async function createGroupAndSelect(groupName: string) {
	vi.spyOn(GroupsApiModule, "createGroup").mockResolvedValue(undefined);
	const amWorker = {
		...MOCK_WORKER,
		mlsCreateGroup: vi.fn(async () => ({
			groupId: `grp-${groupName.toLowerCase().replace(/\s/g, "-")}`,
		})),
	};
	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		amWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	useAuthStore.setState({ sessionToken: "tok-am", identityId: "id-am", deviceId: "dev-am" });

	render(<ChatLayout />);
	fireEvent.click(screen.getByRole("button", { name: /new group/i }));
	fireEvent.change(screen.getByTestId("group-name-input"), { target: { value: groupName } });
	fireEvent.click(screen.getByTestId("create-group-submit"));
	await waitFor(() => expect(screen.getByText(groupName)).toBeInTheDocument());
	fireEvent.click(screen.getByRole("button", { name: new RegExp(groupName, "i") }));
	await waitFor(() => expect(screen.getByTestId("group-status")).toBeInTheDocument());
}

describe("ChatLayout — add member to group", () => {
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("Add member button is visible in header for group chats", async () => {
		await createGroupAndSelect("Add Btn Group");
		expect(screen.getByRole("button", { name: /add member/i })).toBeInTheDocument();
	});

	it("Add member button is NOT present for 1:1 chats", () => {
		useAuthStore.setState({ sessionToken: "tok-am", identityId: "id-am", deviceId: "dev-am" });
		render(<ChatLayout />);
		expect(screen.queryByRole("button", { name: /add member/i })).not.toBeInTheDocument();
	});

	it("clicking Add member opens AddMemberModal", async () => {
		await createGroupAndSelect("Modal Open Group");
		fireEvent.click(screen.getByRole("button", { name: /add member/i }));
		expect(screen.getByRole("dialog", { name: /add member/i })).toBeInTheDocument();
	});

	it("successful add increments member count in group status", async () => {
		vi.spyOn(GroupsApiModule, "addMember").mockResolvedValue(undefined);
		await createGroupAndSelect("Count Group");
		fireEvent.click(screen.getByRole("button", { name: /add member/i }));
		await waitFor(() => screen.getByRole("dialog", { name: /add member/i }));
		const options = screen.getAllByTestId("contact-option");
		fireEvent.click(options[0]);
		await waitFor(() => {
			const groupStatus = screen.getByTestId("group-status");
			expect(groupStatus.textContent).toMatch(/2 members/);
		});
	});
});
