import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as AuthApi from "../api/auth";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { ChatLayout } from "./ChatLayout";

const MOCK_WORKER = {
	mlsGroupMembers: vi.fn(async () => []),
	mlsComputeSafetyNumber: vi.fn(async () => ({ safetyNumber: "000000 000000" })),
	mlsEncrypt: vi.fn(async () => ({ ciphertext: new Uint8Array([0xde, 0xad]) })),
	mlsDecrypt: vi.fn(async () => ({ plaintext: new Uint8Array() })),
	encryptDbField: vi.fn(async (v: string) => v),
	decryptDbField: vi.fn(async (v: string) => v),
};

describe("ChatLayout — settings panel", () => {
	// Several tests below overwrite `logout` on the store (it's not a mockable
	// module export, just store state) — capture the real implementation once
	// so afterEach can restore it. Without this, a rejecting spy from one test
	// silently leaks into every later test in the file.
	const originalLogout = useAuthStore.getState().logout;

	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		useAuthStore.setState({
			phase: "login",
			deviceId: null,
			sessionToken: null,
			logout: originalLogout,
		});
	});

	it("settings icon opens the settings panel", () => {
		render(<ChatLayout />);
		expect(screen.queryByTestId("settings-panel")).not.toBeInTheDocument();
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
	});

	it("close button dismisses the settings panel", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
		fireEvent.click(screen.getByTestId("settings-close"));
		expect(screen.queryByTestId("settings-panel")).not.toBeInTheDocument();
	});

	it("log out button calls useAuthStore's logout action", async () => {
		const logoutSpy = vi.fn().mockResolvedValue(undefined);
		useAuthStore.setState({ logout: logoutSpy });

		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		await act(async () => {
			fireEvent.click(screen.getByTestId("settings-logout-btn"));
		});

		expect(logoutSpy).toHaveBeenCalledOnce();
	});

	it("shows a failure message and does not silently re-idle if logout() rejects", async () => {
		const logoutSpy = vi.fn().mockRejectedValue(new Error("worker unreachable"));
		useAuthStore.setState({ logout: logoutSpy });

		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		await act(async () => {
			fireEvent.click(screen.getByTestId("settings-logout-btn"));
		});

		expect(logoutSpy).toHaveBeenCalledOnce();
		expect(screen.getByTestId("settings-logout-error")).toBeInTheDocument();
	});

	it("linked devices row navigates into the LinkedDevicesPanel", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue([]);
		useAuthStore.setState({ sessionToken: "tok-settings-test", deviceId: "dev-settings-test" });

		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		await act(async () => {
			fireEvent.click(screen.getByTestId("settings-linked-devices-row"));
		});

		expect(screen.getByTestId("linked-devices-panel")).toBeInTheDocument();
		await waitFor(() => {
			expect(screen.getByTestId("linked-devices-empty")).toBeInTheDocument();
		});
	});

	it("Escape key dismisses the settings panel", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
		// Dispatch from inside the panel content, not the overlay directly — a
		// real Escape keypress originates wherever focus is (always somewhere
		// inside "settings-panel", since nothing ever focuses the bare overlay
		// <dialog> itself) and must bubble up to the overlay's handler.
		fireEvent.keyDown(screen.getByTestId("settings-panel"), { key: "Escape" });
		expect(screen.queryByTestId("settings-panel")).not.toBeInTheDocument();
	});

	it("clicking the backdrop dismisses the settings panel", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
		// Click the overlay itself (currentTarget), not the inner panel — the
		// panel's own onClick stops propagation so only a genuine backdrop hit
		// should close it.
		fireEvent.click(screen.getByTestId("settings-overlay"));
		expect(screen.queryByTestId("settings-panel")).not.toBeInTheDocument();
	});

	it("clicking inside the panel content does not dismiss it", () => {
		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		fireEvent.click(screen.getByTestId("settings-panel"));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
	});

	it("dismissing from the linked-devices view resets back to the main view on reopen", async () => {
		vi.spyOn(AuthApi, "listDevices").mockResolvedValue([]);
		useAuthStore.setState({ sessionToken: "tok-settings-test-2", deviceId: "dev-settings-test-2" });

		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		await act(async () => {
			fireEvent.click(screen.getByTestId("settings-linked-devices-row"));
		});
		expect(screen.getByTestId("linked-devices-panel")).toBeInTheDocument();

		// Exit the whole overlay from the devices sub-view via Escape — the
		// devices panel's own close button only pops back to Settings' main
		// view, so this is the only way to reach handleClose() while `view`
		// is still "devices". Dispatched from inside the devices content,
		// matching where a real keypress would originate.
		fireEvent.keyDown(screen.getByTestId("linked-devices-panel"), { key: "Escape" });
		expect(screen.queryByTestId("settings-panel")).not.toBeInTheDocument();

		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		expect(screen.getByTestId("settings-panel")).toBeInTheDocument();
		expect(screen.queryByTestId("linked-devices-panel")).not.toBeInTheDocument();
		expect(screen.getByTestId("settings-logout-btn")).toBeInTheDocument();
	});

	it("disables the logout and linked-devices rows while logging out", async () => {
		let resolveLogout!: () => void;
		const logoutSpy = vi.fn(
			() =>
				new Promise<void>((resolve) => {
					resolveLogout = resolve;
				}),
		);
		useAuthStore.setState({ logout: logoutSpy });

		render(<ChatLayout />);
		fireEvent.click(screen.getByRole("button", { name: /^settings$/i }));
		fireEvent.click(screen.getByTestId("settings-logout-btn"));

		expect(screen.getByTestId("settings-logout-btn")).toBeDisabled();
		expect(screen.getByTestId("settings-linked-devices-row")).toBeDisabled();
		expect(screen.getByText("Logging out…")).toBeInTheDocument();
		expect(logoutSpy).toHaveBeenCalledOnce();

		// A second click while disabled must not re-enter logout() — a disabled
		// HTML button suppresses the click event entirely, so this proves the
		// gate holds, not just that it looks disabled.
		fireEvent.click(screen.getByTestId("settings-logout-btn"));
		expect(logoutSpy).toHaveBeenCalledOnce();

		await act(async () => {
			resolveLogout();
		});
	});
});
