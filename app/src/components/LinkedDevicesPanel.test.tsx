import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as AuthApi from "../api/auth";
import { useAuthStore } from "../store/auth";
import { LinkedDevicesPanel } from "./LinkedDevicesPanel";

const DEVICE_A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const DEVICE_B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const SESSION = "tok-test";

const MOCK_DEVICES: AuthApi.DeviceInfo[] = [
	{
		device_id: DEVICE_A,
		created_at: "2026-01-01T00:00:00Z",
		last_seen_at: "2026-06-30T12:00:00Z",
	},
	{
		device_id: DEVICE_B,
		created_at: "2026-03-15T00:00:00Z",
		last_seen_at: null,
	},
];

describe("LinkedDevicesPanel", () => {
	beforeEach(() => {
		useAuthStore.setState({ sessionToken: SESSION, deviceId: DEVICE_A, phase: "app" });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		useAuthStore.setState({ sessionToken: null, deviceId: null, phase: "login" });
	});

	it("shows loading state initially", async () => {
		// listDevices never resolves during this tick — loading state is visible.
		vi.spyOn(AuthApi, "listDevices").mockReturnValue(new Promise(() => {}));
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		expect(screen.getByTestId("linked-devices-loading")).toBeInTheDocument();
	});

	it("renders device list after fetch resolves", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() => {
			expect(screen.getByTestId(`device-row-${DEVICE_A}`)).toBeInTheDocument();
			expect(screen.getByTestId(`device-row-${DEVICE_B}`)).toBeInTheDocument();
		});
	});

	it("marks current device with badge", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() => {
			expect(
				screen.getByTestId(`device-current-badge-${DEVICE_A}`),
			).toBeInTheDocument();
		});
		// Non-current device must NOT have the badge.
		expect(
			screen.queryByTestId(`device-current-badge-${DEVICE_B}`),
		).not.toBeInTheDocument();
	});

	it("current device has no revoke button", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() =>
			expect(screen.getByTestId(`device-row-${DEVICE_A}`)).toBeInTheDocument(),
		);
		expect(screen.queryByTestId(`device-revoke-btn-${DEVICE_A}`)).not.toBeInTheDocument();
	});

	it("non-current device shows revoke button", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() =>
			expect(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`)).toBeInTheDocument(),
		);
	});

	it("revoke shows confirmation step before calling API", async () => {
		const revokeSpy = vi.spyOn(AuthApi, "revokeDevice").mockResolvedValue(undefined);
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() =>
			expect(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`)).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`));
		expect(screen.getByTestId(`device-revoke-confirm-${DEVICE_B}`)).toBeInTheDocument();
		expect(revokeSpy).not.toHaveBeenCalled();
	});

	it("cancels revoke confirmation and returns to revoke button", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() =>
			expect(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`)).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`));
		expect(screen.getByTestId(`device-revoke-confirm-${DEVICE_B}`)).toBeInTheDocument();
		fireEvent.click(screen.getByTestId(`device-revoke-cancel-${DEVICE_B}`));
		await waitFor(() =>
			expect(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`)).toBeInTheDocument(),
		);
		expect(
			screen.queryByTestId(`device-revoke-confirm-${DEVICE_B}`),
		).not.toBeInTheDocument();
	});

	it("calls revokeDevice API and removes device from list on confirm", async () => {
		const revokeSpy = vi.spyOn(AuthApi, "revokeDevice").mockResolvedValue(undefined);
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() =>
			expect(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`)).toBeInTheDocument(),
		);
		fireEvent.click(screen.getByTestId(`device-revoke-btn-${DEVICE_B}`));
		await act(async () => {
			fireEvent.click(screen.getByTestId(`device-revoke-confirm-${DEVICE_B}`));
		});
		expect(revokeSpy).toHaveBeenCalledWith(SESSION, DEVICE_B);
		await waitFor(() => {
			expect(
				screen.queryByTestId(`device-row-${DEVICE_B}`),
			).not.toBeInTheDocument();
		});
		// Current device still present.
		expect(screen.getByTestId(`device-row-${DEVICE_A}`)).toBeInTheDocument();
	});

	it("shows error state when listDevices API fails", async () => {
		vi.spyOn(AuthApi, "listDevices").mockRejectedValue(new Error("network"));
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() => {
			expect(screen.getByTestId("linked-devices-error")).toBeInTheDocument();
		});
	});

	it("shows empty state when no devices are returned", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue([]);
		render(<LinkedDevicesPanel onClose={vi.fn()} />);
		await waitFor(() => {
			expect(screen.getByTestId("linked-devices-empty")).toBeInTheDocument();
		});
	});

	it("close button fires onClose callback", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue(MOCK_DEVICES);
		const onClose = vi.fn();
		render(<LinkedDevicesPanel onClose={onClose} />);
		fireEvent.click(screen.getByTestId("linked-devices-close"));
		expect(onClose).toHaveBeenCalledTimes(1);
	});
});
