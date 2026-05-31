import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as CryptoWorkerHook from "../hooks/useCryptoWorker";
import { useAuthStore } from "./auth";

afterEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null });
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

	it("logout() returns to login phase and clears deviceId", () => {
		useAuthStore.getState().login("device-abc");
		useAuthStore.getState().logout();
		const state = useAuthStore.getState();
		expect(state.phase).toBe("login");
		expect(state.deviceId).toBeNull();
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
		it("calls dropDbKey on the crypto worker so the AES-GCM key does not linger", () => {
			const dropDbKey = vi.fn();
			vi.spyOn(CryptoWorkerHook, "getCryptoWorkerProxy").mockReturnValue({
				dropDbKey,
			} as unknown as ReturnType<typeof CryptoWorkerHook.getCryptoWorkerProxy>);

			useAuthStore.getState().logout();

			expect(dropDbKey).toHaveBeenCalledOnce();
		});

		it("still transitions to login phase even when worker is unavailable (null proxy)", () => {
			vi.spyOn(CryptoWorkerHook, "getCryptoWorkerProxy").mockReturnValue(null);

			useAuthStore.getState().logout();

			expect(useAuthStore.getState().phase).toBe("login");
			expect(useAuthStore.getState().deviceId).toBeNull();
		});
	});
});
