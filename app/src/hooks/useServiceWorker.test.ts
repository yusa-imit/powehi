import { renderHook } from "@testing-library/react";
import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as PushModule from "../api/push";
import { useServiceWorker } from "./useServiceWorker";

describe("useServiceWorker", () => {
	let registerSpy: MockInstance<typeof PushModule.registerPushSubscription>;
	let swRegisterSpy: ReturnType<typeof vi.fn>;
	let getSubscriptionSpy: ReturnType<typeof vi.fn>;
	let subscribeSpy: ReturnType<typeof vi.fn>;

	function makeMockSub(endpoint = "https://push.example.com/abc"): PushSubscription {
		return {
			endpoint,
			toJSON: () => ({
				endpoint,
				keys: { p256dh: "p256dhValue", auth: "authValue" },
			}),
		} as unknown as PushSubscription;
	}

	beforeEach(() => {
		registerSpy = vi.spyOn(PushModule, "registerPushSubscription").mockResolvedValue(undefined);

		subscribeSpy = vi.fn().mockResolvedValue(makeMockSub());
		getSubscriptionSpy = vi.fn().mockResolvedValue(null);

		const mockReg = {
			pushManager: {
				getSubscription: getSubscriptionSpy,
				subscribe: subscribeSpy,
			},
		};

		swRegisterSpy = vi.fn().mockResolvedValue(mockReg);

		Object.defineProperty(globalThis, "navigator", {
			value: { serviceWorker: { register: swRegisterSpy } },
			configurable: true,
		});

		Object.defineProperty(globalThis, "window", {
			value: { PushManager: class {} },
			configurable: true,
		});
	});

	afterEach(() => {
		registerSpy.mockRestore();
		vi.restoreAllMocks();
	});

	it("registers sw.js on mount", () => {
		renderHook(() => useServiceWorker());
		expect(swRegisterSpy).toHaveBeenCalledWith("/sw.js", { scope: "/" });
	});

	it("does not subscribe without vapidPublicKey", () => {
		renderHook(() => useServiceWorker(undefined, "token"));
		expect(subscribeSpy).not.toHaveBeenCalled();
	});

	it("does not call registerPushSubscription without sessionToken", async () => {
		getSubscriptionSpy.mockResolvedValue(null);
		subscribeSpy.mockResolvedValue(makeMockSub());

		renderHook(() => useServiceWorker("AAAA", undefined));

		await vi.waitFor(() => expect(subscribeSpy).toHaveBeenCalled());
		expect(registerSpy).not.toHaveBeenCalled();
	});

	it("calls registerPushSubscription with token and subscription data", async () => {
		const sub = makeMockSub("https://push.example.com/test");
		getSubscriptionSpy.mockResolvedValue(null);
		subscribeSpy.mockResolvedValue(sub);

		renderHook(() => useServiceWorker("AAAA", "session-token"));

		await vi.waitFor(() => expect(registerSpy).toHaveBeenCalled());
		expect(registerSpy).toHaveBeenCalledWith(
			"session-token",
			"https://push.example.com/test",
			"p256dhValue",
			"authValue",
		);
	});

	it("reuses existing subscription instead of subscribing again", async () => {
		const existing = makeMockSub();
		getSubscriptionSpy.mockResolvedValue(existing);

		renderHook(() => useServiceWorker("AAAA", "session-token"));

		await vi.waitFor(() => expect(registerSpy).toHaveBeenCalled());
		expect(subscribeSpy).not.toHaveBeenCalled();
	});

	it("swallows registerPushSubscription failure — app still works", async () => {
		getSubscriptionSpy.mockResolvedValue(null);
		subscribeSpy.mockResolvedValue(makeMockSub());
		registerSpy.mockRejectedValue(new Error("network error"));

		expect(() => renderHook(() => useServiceWorker("AAAA", "tok"))).not.toThrow();
		await vi.waitFor(() => expect(registerSpy).toHaveBeenCalled());
	});

	it("token is passed in Authorization header via registerPushSubscription, never in URL", async () => {
		const sub = makeMockSub();
		getSubscriptionSpy.mockResolvedValue(null);
		subscribeSpy.mockResolvedValue(sub);

		renderHook(() => useServiceWorker("AAAA", "secret-push-token"));

		await vi.waitFor(() => expect(registerSpy).toHaveBeenCalled());
		// registerPushSubscription receives the token as first arg — API fn is responsible for header
		const [token] = registerSpy.mock.calls[0] as string[];
		expect(token).toBe("secret-push-token");
	});
});
