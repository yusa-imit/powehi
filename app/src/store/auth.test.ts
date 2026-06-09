import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "./auth";

afterEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null, sessionToken: null, identityId: null });
	vi.restoreAllMocks();
});

describe("useAuthStore", () => {
	it("starts in login phase with no device", () => {
		const state = useAuthStore.getState();
		expect(state.phase).toBe("login");
		expect(state.deviceId).toBeNull();
	});

	it("login() transitions to app phase and stores deviceId", () => {
		useAuthStore.getState().login("device-abc");
		const state = useAuthStore.getState();
		expect(state.phase).toBe("app");
		expect(state.deviceId).toBe("device-abc");
	});

	it("login() stores sessionToken when provided", () => {
		useAuthStore.getState().login("device-abc", "tok-xyz");
		const state = useAuthStore.getState();
		expect(state.sessionToken).toBe("tok-xyz");
	});

	it("login() without sessionToken stores null", () => {
		useAuthStore.getState().login("device-abc");
		expect(useAuthStore.getState().sessionToken).toBeNull();
	});

	it("login() stores identityId when provided", () => {
		useAuthStore.getState().login("device-abc", "tok-xyz", "identity-999");
		expect(useAuthStore.getState().identityId).toBe("identity-999");
	});

	it("login() without identityId stores null", () => {
		useAuthStore.getState().login("device-abc", "tok-xyz");
		expect(useAuthStore.getState().identityId).toBeNull();
	});

	it("logout() returns to login phase and clears deviceId, sessionToken and identityId", async () => {
		useAuthStore.getState().login("device-abc", "tok-xyz", "identity-abc");
		await useAuthStore.getState().logout();
		const state = useAuthStore.getState();
		expect(state.phase).toBe("login");
		expect(state.deviceId).toBeNull();
		expect(state.sessionToken).toBeNull();
		expect(state.identityId).toBeNull();
	});

	it("login() with empty deviceId still transitions phase", () => {
		useAuthStore.getState().login("");
		expect(useAuthStore.getState().phase).toBe("app");
	});

	it("multiple login() calls update deviceId", () => {
		useAuthStore.getState().login("device-1");
		useAuthStore.getState().login("device-2");
		expect(useAuthStore.getState().deviceId).toBe("device-2");
	});

	describe("logout() key-material cleanup", () => {
		beforeEach(() => {
			useAuthStore.getState().login("device-abc");
		});

		// Testing-convention note: verifying actual AES-GCM key clearance requires
		// a real Comlink worker which in turn needs the WASM bundle — not available
		// in the unit-test environment.  We mock the proxy per react-hooks-only.md
		// ("mock the Comlink proxy; never import crypto libs into a component test")
		// and verify the contractual call is made.  End-to-end correctness is covered
		// by the encrypted-db.test.ts wrong-key rejection test (cross-key decrypt throws).
		it("calls dropDbKey on the crypto worker so the AES-GCM key does not linger", async () => {
			const dropDbKey = vi.fn();
			const clearSessionState = vi.fn().mockResolvedValue(undefined);
			vi.spyOn(CryptoWorkerHook, "getCryptoWorkerProxy").mockReturnValue({
				dropDbKey,
				clearSessionState,
			} as unknown as ReturnType<typeof CryptoWorkerHook.getCryptoWorkerProxy>);

			await useAuthStore.getState().logout();

			expect(dropDbKey).toHaveBeenCalledOnce();
		});

		it("calls clearSessionState to wipe MLS and OPAQUE heap state on logout", async () => {
			const clearSessionState = vi.fn().mockResolvedValue(undefined);
			const dropDbKey = vi.fn();
			vi.spyOn(CryptoWorkerHook, "getCryptoWorkerProxy").mockReturnValue({
				clearSessionState,
				dropDbKey,
			} as unknown as ReturnType<typeof CryptoWorkerHook.getCryptoWorkerProxy>);

			await useAuthStore.getState().logout();

			expect(clearSessionState).toHaveBeenCalledOnce();
			// clearSessionState must be called before dropDbKey (documented order).
			expect(clearSessionState.mock.invocationCallOrder[0]).toBeLessThan(
				dropDbKey.mock.invocationCallOrder[0],
			);
		});

		it("still transitions to login phase even when worker is unavailable (null proxy)", async () => {
			vi.spyOn(CryptoWorkerHook, "getCryptoWorkerProxy").mockReturnValue(null);

			await useAuthStore.getState().logout();

			expect(useAuthStore.getState().phase).toBe("login");
			expect(useAuthStore.getState().deviceId).toBeNull();
		});
	});
});
