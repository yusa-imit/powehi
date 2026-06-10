import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as AuthModule from "../api/auth";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { Login } from "./Login";

// vi.fn() stubs — implementations set in beforeEach so they survive vi.restoreAllMocks().
const opaqueRegistrationStart = vi.fn();
const opaqueRegistrationFinish = vi.fn();
const opaqueLoginStart = vi.fn();
const opaqueLoginFinish = vi.fn();
const generateRecoveryPhrase = vi.fn();
const mlsInitIdentityFromPhrase = vi.fn();

const mockWorker = {
	opaqueRegistrationStart,
	opaqueRegistrationFinish,
	opaqueLoginStart,
	opaqueLoginFinish,
	generateRecoveryPhrase,
	mlsInitIdentityFromPhrase,
};

beforeEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null, identityId: null });

	// Re-apply return values after vi.restoreAllMocks() may have cleared them.
	opaqueRegistrationStart.mockResolvedValue({
		sessionId: "mock-reg-session",
		message: new Uint8Array(32),
	});
	opaqueRegistrationFinish.mockResolvedValue({ upload: new Uint8Array(64) });
	opaqueLoginStart.mockResolvedValue({
		sessionId: "mock-login-session",
		message: new Uint8Array(32),
	});
	opaqueLoginFinish.mockResolvedValue({ finalization: new Uint8Array(64) });
	generateRecoveryPhrase.mockResolvedValue({
		words: Array.from({ length: 24 }, (_, i) => `word${i + 1}`),
	});
	mlsInitIdentityFromPhrase.mockResolvedValue({
		identityId: "mock-identity-id",
		keyPackage: new Uint8Array([1, 2, 3]),
	});

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	vi.spyOn(AuthModule, "hashHandle").mockResolvedValue(new Uint8Array(32));
	vi.spyOn(AuthModule, "regInit").mockResolvedValue({
		user_id: "user-uuid-0001",
		opaque_response: Array(32).fill(0),
	});
	vi.spyOn(AuthModule, "regFinish").mockResolvedValue({
		user_id: "user-uuid-0001",
		device_id: "device-uuid-0001",
	});
	vi.spyOn(AuthModule, "loginInit").mockResolvedValue({
		user_id: "user-uuid-0001",
		opaque_ke2: Array(32).fill(0),
		login_nonce: "nonce-mock-0001",
	});
	vi.spyOn(AuthModule, "loginFinish").mockResolvedValue("session-token-mock");
	vi.spyOn(AuthModule, "uploadKeyPackage").mockResolvedValue(undefined);
});

afterEach(() => {
	cleanup();
	vi.restoreAllMocks();
});

describe("Login — BIP-39 registration flow (§8.5)", () => {
	async function fillAndSubmitRegistration() {
		fireEvent.click(screen.getByText(/new to powehi/i));
		fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
		fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "S3cret!pw" } });
		fireEvent.click(screen.getByRole("button", { name: /create account/i }));
	}

	it("shows RecoveryPhraseModal after successful registration", async () => {
		render(<Login />);
		await fillAndSubmitRegistration();

		await waitFor(() => {
			expect(screen.getByRole("dialog")).toBeInTheDocument();
		});
		expect(screen.getByText("Your recovery phrase")).toBeInTheDocument();
	});

	it("renders all 24 words in the modal", async () => {
		render(<Login />);
		await fillAndSubmitRegistration();

		await waitFor(() => {
			expect(screen.getByRole("dialog")).toBeInTheDocument();
		});
		// The mock generateRecoveryPhrase returns word1..word24.
		expect(screen.getByText("word1")).toBeInTheDocument();
		expect(screen.getByText("word24")).toBeInTheDocument();
	});

	it("auth phase stays at login until modal is confirmed", async () => {
		render(<Login />);
		await fillAndSubmitRegistration();

		await waitFor(() => {
			expect(screen.getByRole("dialog")).toBeInTheDocument();
		});
		// Phase must NOT advance to "app" before confirmation.
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("advances to app phase after confirming recovery phrase", async () => {
		render(<Login />);
		await fillAndSubmitRegistration();

		const dialog = await screen.findByRole("dialog");

		// Click the confirmation button inside the RecoveryPhraseModal.
		const confirmBtn = within(dialog).getByRole("button", {
			name: /I have saved my recovery phrase/i,
		});
		fireEvent.click(confirmBtn);

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});
	});

	it("security: recovery words must not appear in any console output", async () => {
		const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});

		render(<Login />);
		await fillAndSubmitRegistration();

		await waitFor(() => {
			expect(screen.getByRole("dialog")).toBeInTheDocument();
		});

		// No console output should contain any of the 24 mock recovery words.
		const allCalls = [...consoleSpy.mock.calls, ...warnSpy.mock.calls, ...infoSpy.mock.calls].map(
			(args) => JSON.stringify(args),
		);

		for (const call of allCalls) {
			expect(call).not.toMatch(/word\d+/);
		}
	});

	it("calls regInit with handle_hash (Uint8Array, not plaintext handle)", async () => {
		render(<Login />);
		await fillAndSubmitRegistration();

		await waitFor(() => {
			expect(vi.mocked(AuthModule.regInit)).toHaveBeenCalled();
		});
		const [calledWithHash] = vi.mocked(AuthModule.regInit).mock.calls[0] as [
			Uint8Array,
			...unknown[],
		];
		// First argument must be a Uint8Array hash, not the raw handle string.
		expect(calledWithHash).toBeInstanceOf(Uint8Array);
		expect(JSON.stringify([...calledWithHash])).not.toContain("alice");
	});
});
