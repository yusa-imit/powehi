import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as AuthModule from "../api/auth";
import { EncryptedPowehiDb } from "../db/encrypted-db";
import { db } from "../db/schema";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "../store/auth";
import { Login } from "./Login";

// Sign-in path MLS state rehydration (closes: MLS_CTX thread_local starts empty
// on every fresh worker instance, so a page reload/re-login wiped all MLS group
// state until a group was somehow rejoined). Covers the three branches added to
// Login.tsx's handleSubmit sign-in path:
//   1. stored provider-state blob present → mlsImportState + mlsGetKeyPackage
//   2. no stored blob → falls back to mlsInitIdentity (must not regress)
//   3. mlsImportState throws (stale/corrupt/wrong-version) → falls back to
//      mlsInitIdentity instead of crashing sign-in

const opaqueLoginStart = vi.fn();
const opaqueLoginFinish = vi.fn();
const mlsInitIdentity = vi.fn();
const mlsImportState = vi.fn();
const mlsGetKeyPackage = vi.fn();
const encryptDbField = vi.fn();
const decryptDbField = vi.fn();

const mockWorker = {
	opaqueLoginStart,
	opaqueLoginFinish,
	mlsInitIdentity,
	mlsImportState,
	mlsGetKeyPackage,
	encryptDbField,
	decryptDbField,
};

async function seedIdentity(overrides: Partial<Record<string, unknown>> = {}) {
	await db.identity.put({
		id: 1,
		deviceId: "device-uuid-0001",
		mlsIdentityId: "old-identity-id",
		mlsIdentityB64: "bWxzLWlkZW50aXR5LWJ5dGVz",
		...overrides,
	});
}

async function submitSignIn() {
	fireEvent.change(screen.getByLabelText(/handle/i), { target: { value: "alice" } });
	fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "S3cret!pw" } });
	fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
}

beforeEach(async () => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null, identityId: null });
	await db.identity.clear();

	opaqueLoginStart.mockResolvedValue({
		sessionId: "mock-login-session",
		message: new Uint8Array(32),
	});
	opaqueLoginFinish.mockResolvedValue({ finalization: new Uint8Array(64) });
	mlsInitIdentity.mockResolvedValue({
		identityId: "fresh-identity-id",
		keyPackage: new Uint8Array([1, 2, 3]),
		pqDecapKeyHandle: "pq-handle-init",
	});
	mlsImportState.mockResolvedValue({
		identityId: "restored-identity-id",
		groupIds: ["group-1"],
		generation: 5,
	});
	mlsGetKeyPackage.mockResolvedValue({
		keyPackage: new Uint8Array([4, 5, 6]),
		pqDecapKeyHandle: "pq-handle-restored",
	});
	// Pass-through: component tests never touch real crypto (react-hooks-only.md
	// "NEVER import crypto libraries directly in UI code" / testing-conventions.md
	// "mock the Comlink proxy; never import crypto libs into a component test").
	encryptDbField.mockImplementation(async (v: string) => v);
	decryptDbField.mockImplementation(async (v: string) => v);

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

describe("Login — sign-in MLS state rehydration", () => {
	it("with a stored provider-state blob, calls mlsImportState (not mlsInitIdentity) then mlsGetKeyPackage", async () => {
		await seedIdentity({
			mlsProviderStateB64: JSON.stringify({ stateB64: "c3RhdGUtYmxvYg==", generation: 4 }),
		});
		render(<Login />);
		await submitSignIn();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect(mlsImportState).toHaveBeenCalledTimes(1);
		const importArgs = mlsImportState.mock.calls[0];
		expect(importArgs[0]).toBeInstanceOf(Uint8Array);
		// RED 1: Login must NOT source the anti-replay floor from the envelope's
		// own generation (that self-referential compare can never reject). The
		// floor is owned/injected by the worker persistence wrapper, so Login
		// passes only the state bytes here.
		expect(importArgs).toHaveLength(1);

		expect(mlsGetKeyPackage).toHaveBeenCalledTimes(1);
		expect(mlsGetKeyPackage).toHaveBeenCalledWith("restored-identity-id");

		expect(mlsInitIdentity).not.toHaveBeenCalled();

		expect(useAuthStore.getState().identityId).toBe("restored-identity-id");
		expect(useAuthStore.getState().pqDecapKeyHandle).toBe("pq-handle-restored");

		const uploadCall = vi.mocked(AuthModule.uploadKeyPackage).mock.calls[0];
		expect(uploadCall[2]).toEqual(new Uint8Array([4, 5, 6]));

		const stored = await db.identity.get(1);
		expect(stored?.mlsIdentityId).toBe("restored-identity-id");
	});

	it("with no stored provider-state blob, falls back to mlsInitIdentity (existing behavior)", async () => {
		await seedIdentity(); // no mlsProviderStateB64 envelope
		render(<Login />);
		await submitSignIn();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect(mlsImportState).not.toHaveBeenCalled();
		expect(mlsGetKeyPackage).not.toHaveBeenCalled();
		expect(mlsInitIdentity).toHaveBeenCalledTimes(1);
		expect(mlsInitIdentity).toHaveBeenCalledWith(expect.any(Uint8Array));

		expect(useAuthStore.getState().identityId).toBe("fresh-identity-id");
		expect(useAuthStore.getState().pqDecapKeyHandle).toBe("pq-handle-init");

		const stored = await db.identity.get(1);
		expect(stored?.mlsIdentityId).toBe("fresh-identity-id");
	});

	it("when mlsImportState rejects (stale generation / corrupt blob), falls back to mlsInitIdentity instead of crashing sign-in", async () => {
		mlsImportState.mockRejectedValueOnce(new Error("generation_replay_rejected"));
		await seedIdentity({
			mlsProviderStateB64: JSON.stringify({ stateB64: "c3RhbGUtYmxvYg==", generation: 9 }),
		});
		render(<Login />);
		await submitSignIn();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect(mlsImportState).toHaveBeenCalledTimes(1);
		expect(mlsGetKeyPackage).not.toHaveBeenCalled();
		expect(mlsInitIdentity).toHaveBeenCalledTimes(1);

		expect(useAuthStore.getState().identityId).toBe("fresh-identity-id");

		const stored = await db.identity.get(1);
		expect(stored?.mlsIdentityId).toBe("fresh-identity-id");
	});

	it("when mlsImportState rejects, restores the pre-existing provider-state envelope instead of letting the fallback discard it (crypto-reviewer Y2)", async () => {
		mlsImportState.mockRejectedValueOnce(new Error("generation_replay_rejected"));
		const originalEnvelope = JSON.stringify({ stateB64: "c3RhbGUtYmxvYg==", generation: 9 });
		await seedIdentity({ mlsProviderStateB64: originalEnvelope });

		const setSpy = vi.spyOn(EncryptedPowehiDb.prototype, "setMlsProviderState");

		render(<Login />);
		await submitSignIn();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		expect(mlsInitIdentity).toHaveBeenCalledTimes(1);
		// The restoration must use the ORIGINAL stale/corrupt envelope's contents,
		// not anything derived from the fresh fallback identity — a failed import
		// must never forfeit the still-possibly-recoverable prior state.
		expect(setSpy).toHaveBeenCalledWith("c3RhbGUtYmxvYg==", 9);

		const stored = await db.identity.get(1);
		expect(stored?.mlsProviderStateB64).toBe(originalEnvelope);
	});

	it("security: a caught mlsImportState rejection is never logged (no-plaintext-logging)", async () => {
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		mlsImportState.mockRejectedValueOnce(new Error("generation_replay_rejected_secret_marker"));
		await seedIdentity({
			mlsProviderStateB64: JSON.stringify({ stateB64: "c3RhbGUtYmxvYg==", generation: 9 }),
		});

		render(<Login />);
		await submitSignIn();

		await waitFor(() => {
			expect(useAuthStore.getState().phase).toBe("app");
		});

		const allCalls = [...errorSpy.mock.calls, ...warnSpy.mock.calls].map((args) =>
			JSON.stringify(args),
		);
		for (const call of allCalls) {
			expect(call).not.toMatch(/generation_replay_rejected_secret_marker/);
		}
	});
});
