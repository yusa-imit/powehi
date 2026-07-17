import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as AuthModule from "../api/auth";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { Login } from "./Login";

// §8.5 account restore — signs in from a brand-new device (no local IndexedDB
// identity row) with password + 24-word BIP-39 recovery phrase. Covers the
// "restore-account" Mode added to Login.tsx: doRestoreAccount re-derives the
// phrase-locked MLS identity, signs the server's login nonce, and sends it as
// loginFinish's optional 4th `recovery_proof` argument.

const opaqueLoginStart = vi.fn();
const opaqueLoginFinish = vi.fn();
const mlsInitIdentityFromPhrase = vi.fn();
const mlsSignRecoveryChallenge = vi.fn();

const mockWorker = {
	opaqueLoginStart,
	opaqueLoginFinish,
	mlsInitIdentityFromPhrase,
	mlsSignRecoveryChallenge,
};

const RECOVERY_PHRASE = Array.from({ length: 24 }, (_, i) => `word${i + 1}`).join(" ");

async function switchToRestoreMode() {
	fireEvent.click(screen.getByText(/lost your device/i));
}

async function fillAndSubmitRestore(phrase = RECOVERY_PHRASE) {
	await switchToRestoreMode();
	fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
	fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "S3cret!pw" } });
	fireEvent.change(screen.getByLabelText(/recovery phrase/i), { target: { value: phrase } });
	fireEvent.click(screen.getByRole("button", { name: /restore account/i }));
}

beforeEach(async () => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null, identityId: null });
	// The whole point of restore mode is that this browser has NO local device row.
	await db.identity.clear();

	opaqueLoginStart.mockResolvedValue({
		sessionId: "mock-login-session",
		message: new Uint8Array(32),
	});
	opaqueLoginFinish.mockResolvedValue({ finalization: new Uint8Array(64) });
	mlsInitIdentityFromPhrase.mockResolvedValue({
		identityId: "restored-phrase-identity-id",
		keyPackage: new Uint8Array([1, 2, 3]),
		pqDecapKeyHandle: "mock-pq-decap-handle-phrase-0",
		recoveryPubkey: new Uint8Array(32),
	});
	mlsSignRecoveryChallenge.mockResolvedValue({ signature: new Uint8Array(64) });

	vi.spyOn(CryptoWorkerHook, "useCryptoWorker").mockReturnValue(
		mockWorker as unknown as ReturnType<typeof CryptoWorkerHook.useCryptoWorker>,
	);
	vi.spyOn(AuthModule, "hashHandle").mockResolvedValue(new Uint8Array(32));
	vi.spyOn(AuthModule, "loginInit").mockResolvedValue({
		user_id: "user-uuid-0001",
		opaque_ke2: Array(32).fill(0),
		login_nonce: "nonce-mock-0001",
	});
	vi.spyOn(AuthModule, "loginFinish").mockResolvedValue("session-token-mock");
	vi.spyOn(AuthModule, "uploadKeyPackage").mockResolvedValue(undefined);
});

afterEach(async () => {
	cleanup();
	vi.restoreAllMocks();
	await db.identity.clear();
});

describe("Login — restore account flow (§8.5)", () => {
	it("shows the restore-account form when 'Lost your device?' is clicked", async () => {
		render(<Login />);
		await switchToRestoreMode();

		expect(screen.getByLabelText(/recovery phrase/i)).toBeInTheDocument();
		expect(screen.getByRole("button", { name: /restore account/i })).toBeInTheDocument();
	});

	it("happy path: submits recovery_proof (mls_credential + signature) as loginFinish's 4th arg and reaches the app", async () => {
		render(<Login />);
		await fillAndSubmitRestore();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect(mlsSignRecoveryChallenge).toHaveBeenCalledTimes(1);
		const [signedPhrase, signedNonce] = mlsSignRecoveryChallenge.mock.calls[0] as [
			string,
			Uint8Array,
		];
		expect(signedPhrase).toBe(RECOVERY_PHRASE);
		// NOTE: jsdom's TextEncoder returns a Uint8Array constructed in a separate vm
		// realm from this test file's global Uint8Array, so a direct `instanceof`
		// check is unreliable here (unrelated pre-existing jsdom quirk — verified via
		// a standalone repro). ArrayBuffer.isView is realm-agnostic per spec.
		expect(ArrayBuffer.isView(signedNonce)).toBe(true);
		expect(Array.from(signedNonce as unknown as ArrayLike<number>)).toEqual(
			Array.from(new TextEncoder().encode("nonce-mock-0001")),
		);

		expect(vi.mocked(AuthModule.loginFinish)).toHaveBeenCalledTimes(1);
		const loginFinishCall = vi.mocked(AuthModule.loginFinish).mock.calls[0];
		expect(loginFinishCall).toHaveLength(4);
		const recoveryProof = loginFinishCall[3] as
			| { mls_credential: Uint8Array; signature: Uint8Array }
			| undefined;
		expect(recoveryProof).toBeDefined();
		expect(recoveryProof?.mls_credential).toBeInstanceOf(Uint8Array);
		expect(recoveryProof?.mls_credential).toHaveLength(16);
		expect(recoveryProof?.signature).toBeInstanceOf(Uint8Array);
		expect(recoveryProof?.signature).toHaveLength(64);

		// A brand-new device row was minted locally with the phrase-derived identity.
		const stored = await db.identity.get(1);
		expect(stored?.mlsIdentityId).toBe("restored-phrase-identity-id");

		expect(useAuthStore.getState().identityId).toBe("restored-phrase-identity-id");
		expect(useAuthStore.getState().pqDecapKeyHandle).toBe("mock-pq-decap-handle-phrase-0");
	});

	it("collapses ANY restore failure into one generic message (never reveals which factor failed)", async () => {
		vi.spyOn(AuthModule, "loginFinish").mockRejectedValueOnce(new Error("unauthorized"));

		render(<Login />);
		await fillAndSubmitRestore();

		await waitFor(() => {
			expect(
				screen.getByText(/restore failed.*check your handle, password, and recovery phrase/i),
			).toBeInTheDocument();
		});
		// Must NOT advance to the app on failure.
		expect(useAuthStore.getState().phase).toBe("login");
	});

	it("clears the recovery-phrase textarea from component state immediately after a submit attempt", async () => {
		render(<Login />);
		await fillAndSubmitRestore();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect((screen.getByLabelText(/recovery phrase/i) as HTMLTextAreaElement).value).toBe("");
	});

	it("clears the recovery-phrase textarea even when the restore attempt fails", async () => {
		vi.spyOn(AuthModule, "loginFinish").mockRejectedValueOnce(new Error("unauthorized"));

		render(<Login />);
		await fillAndSubmitRestore();

		await waitFor(() => {
			expect(screen.getByText(/restore failed/i)).toBeInTheDocument();
		});

		expect((screen.getByLabelText(/recovery phrase/i) as HTMLTextAreaElement).value).toBe("");
	});
});
