import { afterEach, describe, expect, it } from "vitest";
import { useAuthStore } from "./auth";

afterEach(() => {
	useAuthStore.setState({ phase: "login", deviceId: null });
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
});
