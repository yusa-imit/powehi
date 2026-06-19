import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApi from "../api/groups";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { CreateGroupModal } from "./CreateGroupModal";

const MOCK_WORKER = {
	mlsCreateGroup: vi.fn(async (_identityId: string) => ({ groupId: "test-group-id" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

describe("CreateGroupModal", () => {
	beforeEach(() => {
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
		useAuthStore.setState({ sessionToken: "tok-abc", identityId: "id-xyz", deviceId: "dev-1" });
		vi.spyOn(GroupsApi, "createGroup").mockResolvedValue(undefined);
		MOCK_WORKER.mlsCreateGroup.mockResolvedValue({ groupId: "test-group-id" });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("renders when open", () => {
		render(<CreateGroupModal open={true} onClose={() => {}} onGroupCreated={() => {}} />);
		expect(screen.getByRole("dialog", { name: /new group/i })).toBeInTheDocument();
	});

	it("does not render when closed", () => {
		render(<CreateGroupModal open={false} onClose={() => {}} onGroupCreated={() => {}} />);
		expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
	});

	it("shows group name input and submit button", () => {
		render(<CreateGroupModal open={true} onClose={() => {}} onGroupCreated={() => {}} />);
		expect(screen.getByTestId("group-name-input")).toBeInTheDocument();
		expect(screen.getByTestId("create-group-submit")).toBeInTheDocument();
	});

	it("shows validation error when name is empty and submit clicked", async () => {
		render(<CreateGroupModal open={true} onClose={() => {}} onGroupCreated={() => {}} />);
		// Input is empty — the button is disabled, so we trigger submit directly
		// by typing a space (which trims to empty) then clicking
		const input = screen.getByTestId("group-name-input");
		fireEvent.change(input, { target: { value: "   " } });
		fireEvent.click(screen.getByTestId("create-group-submit"));
		await waitFor(() => {
			expect(screen.getByTestId("group-name-error")).toBeInTheDocument();
		});
	});

	it("calls onGroupCreated with groupId and name on success", async () => {
		const onGroupCreated = vi.fn();
		render(<CreateGroupModal open={true} onClose={() => {}} onGroupCreated={onGroupCreated} />);
		fireEvent.change(screen.getByTestId("group-name-input"), {
			target: { value: "My Cool Group" },
		});
		fireEvent.click(screen.getByTestId("create-group-submit"));
		await waitFor(() => {
			expect(onGroupCreated).toHaveBeenCalledWith("test-group-id", "My Cool Group");
		});
	});

	it("shows error message when API fails", async () => {
		vi.spyOn(GroupsApi, "createGroup").mockRejectedValue(new Error("network_error"));
		render(<CreateGroupModal open={true} onClose={() => {}} onGroupCreated={() => {}} />);
		fireEvent.change(screen.getByTestId("group-name-input"), {
			target: { value: "Group With Error" },
		});
		fireEvent.click(screen.getByTestId("create-group-submit"));
		await waitFor(() => {
			expect(screen.getByTestId("create-group-error")).toBeInTheDocument();
		});
	});

	it("closes on backdrop click", () => {
		const onClose = vi.fn();
		render(<CreateGroupModal open={true} onClose={onClose} onGroupCreated={() => {}} />);
		const dialog = screen.getByRole("dialog");
		fireEvent.click(dialog);
		expect(onClose).toHaveBeenCalled();
	});
});
