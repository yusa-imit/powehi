import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as GroupsApiModule from "../api/groups";
import { useAuthStore } from "../store/auth";
import { PendingRemovalBanner } from "./PendingRemovalBanner";

const GROUP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const DEVICE_A = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const DEVICE_B = "cccccccc-cccc-cccc-cccc-cccccccccccc";

describe("PendingRemovalBanner", () => {
	beforeEach(() => {
		useAuthStore.setState({ sessionToken: "tok-pending", identityId: "id", deviceId: "dev" });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("renders nothing while loading and nothing when the list is empty", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockResolvedValue([]);
		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		expect(screen.queryByTestId("pending-removal-banner")).not.toBeInTheDocument();
		await waitFor(() => {
			expect(GroupsApiModule.listPendingRemovals).toHaveBeenCalledWith("tok-pending", GROUP_ID);
		});
		expect(screen.queryByTestId("pending-removal-banner")).not.toBeInTheDocument();
	});

	it("renders nothing when the fetch fails (fail closed)", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockRejectedValue(new Error("http_500"));
		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		await waitFor(() => {
			expect(GroupsApiModule.listPendingRemovals).toHaveBeenCalled();
		});
		expect(screen.queryByTestId("pending-removal-banner")).not.toBeInTheDocument();
	});

	it("renders one row per pending device, short-labeled, with no auto-removal", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockResolvedValue([DEVICE_A, DEVICE_B]);
		const removeSpy = vi.spyOn(GroupsApiModule, "removeMember").mockResolvedValue(undefined);

		render(<PendingRemovalBanner groupId={GROUP_ID} />);

		await waitFor(() => {
			expect(screen.getByTestId("pending-removal-banner")).toBeInTheDocument();
		});
		expect(screen.getByTestId(`pending-removal-label-${DEVICE_A}`)).toHaveTextContent(
			`Device ${DEVICE_A.slice(0, 8)}`,
		);
		expect(screen.getByTestId(`pending-removal-row-${DEVICE_B}`)).toBeInTheDocument();

		// The API must never be called just from fetching/rendering the list.
		expect(removeSpy).not.toHaveBeenCalled();
		// The signal is server-reported and unverified — the UI must say so.
		expect(screen.getByTestId("pending-removal-warning")).toBeInTheDocument();
	});

	it("requires a confirm step before calling removeMember", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockResolvedValue([DEVICE_A]);
		const removeSpy = vi.spyOn(GroupsApiModule, "removeMember").mockResolvedValue(undefined);

		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`)).toBeInTheDocument();
		});

		// First click only arms confirmation — must not call the API yet.
		fireEvent.click(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`));
		expect(removeSpy).not.toHaveBeenCalled();
		expect(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`)).toBeInTheDocument();

		// Cancel backs out without calling the API.
		fireEvent.click(screen.getByTestId(`pending-removal-cancel-${DEVICE_A}`));
		expect(removeSpy).not.toHaveBeenCalled();
		expect(screen.queryByTestId(`pending-removal-confirm-${DEVICE_A}`)).not.toBeInTheDocument();

		// Re-arm and confirm — now the API is called (after the arm delay elapses).
		fireEvent.click(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`));
		fireEvent.click(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`));
		expect(removeSpy).not.toHaveBeenCalled();

		await waitFor(
			() => {
				expect(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`)).toBeEnabled();
			},
			{ timeout: 1000 },
		);
		fireEvent.click(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`));

		await waitFor(() => {
			expect(removeSpy).toHaveBeenCalledWith("tok-pending", GROUP_ID, DEVICE_A);
		});
	});

	it("does not act on a confirm click within the arm delay (guards accidental double-click)", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockResolvedValue([DEVICE_A]);
		const removeSpy = vi.spyOn(GroupsApiModule, "removeMember").mockResolvedValue(undefined);

		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`)).toBeInTheDocument();
		});

		fireEvent.click(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`));
		// Simulate a stray double-click landing on the confirm control's
		// coordinates immediately after arming — must be disabled/no-op.
		const confirmBtn = screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`);
		expect(confirmBtn).toBeDisabled();
		fireEvent.click(confirmBtn);
		expect(removeSpy).not.toHaveBeenCalled();
	});

	it("drops the device from the list after a successful remove, without refetching", async () => {
		const listSpy = vi
			.spyOn(GroupsApiModule, "listPendingRemovals")
			.mockResolvedValue([DEVICE_A, DEVICE_B]);
		vi.spyOn(GroupsApiModule, "removeMember").mockResolvedValue(undefined);

		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-row-${DEVICE_A}`)).toBeInTheDocument();
		});

		fireEvent.click(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`));
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`)).toBeEnabled();
		});
		fireEvent.click(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`));

		await waitFor(() => {
			expect(screen.queryByTestId(`pending-removal-row-${DEVICE_A}`)).not.toBeInTheDocument();
		});
		expect(screen.getByTestId(`pending-removal-row-${DEVICE_B}`)).toBeInTheDocument();
		expect(listSpy).toHaveBeenCalledTimes(1);
	});

	it("shows a scoped per-row error and keeps the device listed on failure", async () => {
		vi.spyOn(GroupsApiModule, "listPendingRemovals").mockResolvedValue([DEVICE_A]);
		vi.spyOn(GroupsApiModule, "removeMember").mockRejectedValue(new Error("http_500"));

		render(<PendingRemovalBanner groupId={GROUP_ID} />);
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`)).toBeInTheDocument();
		});

		fireEvent.click(screen.getByTestId(`pending-removal-btn-${DEVICE_A}`));
		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`)).toBeEnabled();
		});
		fireEvent.click(screen.getByTestId(`pending-removal-confirm-${DEVICE_A}`));

		await waitFor(() => {
			expect(screen.getByTestId(`pending-removal-error-${DEVICE_A}`)).toBeInTheDocument();
		});
		// Error must be category-only — never the raw thrown message/body.
		expect(screen.getByTestId(`pending-removal-error-${DEVICE_A}`)).not.toHaveTextContent(
			"http_500",
		);
		expect(screen.getByTestId(`pending-removal-row-${DEVICE_A}`)).toBeInTheDocument();
	});
});
