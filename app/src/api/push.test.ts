import { type MockInstance, afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as PushModule from "./push";

const { registerPushSubscription, unregisterPushSubscription } = PushModule;

describe("push API", () => {
	let fetchSpy: MockInstance<typeof globalThis.fetch>;

	beforeEach(() => {
		fetchSpy = vi.spyOn(globalThis, "fetch");
	});

	afterEach(() => {
		fetchSpy.mockRestore();
	});

	describe("registerPushSubscription", () => {
		it("POSTs to /v1/push-subscriptions with correct body", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 201 }));

			await registerPushSubscription(
				"tok",
				"https://push.example.com/abc",
				"p256dhKey==",
				"authKey==",
			);

			expect(fetchSpy).toHaveBeenCalledWith("/v1/push-subscriptions", {
				method: "POST",
				headers: expect.objectContaining({
					"Content-Type": "application/json",
					Authorization: "Bearer tok",
				}),
				body: JSON.stringify({
					endpoint: "https://push.example.com/abc",
					p256dh: "p256dhKey==",
					auth: "authKey==",
				}),
			});
		});

		it("Bearer token is in Authorization header, not URL", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 201 }));

			await registerPushSubscription("secret-token", "https://push.example.com/x", "k", "a");

			const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("secret-token");
			const headers = init.headers as Record<string, string>;
			expect(headers.Authorization).toBe("Bearer secret-token");
		});

		it("does not include Authorization in body", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 201 }));

			await registerPushSubscription("my-token", "https://push.example.com/x", "k", "a");

			const [, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(init.body).not.toContain("my-token");
		});

		it("throws on non-2xx response", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ code: "bad_input" }), { status: 400 }),
			);

			await expect(
				registerPushSubscription("tok", "https://push.example.com/x", "k", "a"),
			).rejects.toThrow("bad_input");
		});

		it("throws with http_N code when no code in body", async () => {
			fetchSpy.mockResolvedValueOnce(new Response("{}", { status: 422 }));

			await expect(
				registerPushSubscription("tok", "https://push.example.com/x", "k", "a"),
			).rejects.toThrow("http_422");
		});
	});

	describe("unregisterPushSubscription", () => {
		it("sends DELETE to /v1/push-subscriptions with Bearer token", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await unregisterPushSubscription("tok");

			expect(fetchSpy).toHaveBeenCalledWith("/v1/push-subscriptions", {
				method: "DELETE",
				headers: expect.objectContaining({
					Authorization: "Bearer tok",
				}),
			});
		});

		it("Bearer token is in header, not URL", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await unregisterPushSubscription("delete-token");

			const [url] = fetchSpy.mock.calls[0] as [string, RequestInit];
			expect(url).not.toContain("delete-token");
		});

		it("resolves on 204", async () => {
			fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));

			await expect(unregisterPushSubscription("tok")).resolves.toBeUndefined();
		});

		it("throws on error response", async () => {
			fetchSpy.mockResolvedValueOnce(
				new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
			);

			await expect(unregisterPushSubscription("bad-tok")).rejects.toThrow("unauthorized");
		});
	});
});
