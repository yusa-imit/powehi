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
	beforeEach(async () => {
		await db.verifiedContacts.clear();
		vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
			MOCK_WORKER as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
		);
	});

	afterEach(() => {
		cleanup();
		vi.restoreAllMocks();
		useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null });
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
});
