import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useRegionStore } from "./region";

describe("useRegionStore", () => {
	beforeEach(() => {
		// Reset store to initial state before each test
		useRegionStore.setState({ regionId: null, detectedAt: null });
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("starts with null regionId and detectedAt", () => {
		const { regionId, detectedAt } = useRegionStore.getState();
		expect(regionId).toBeNull();
		expect(detectedAt).toBeNull();
	});

	it("sets regionId from successful detect response", async () => {
		const mockFetch = vi
			.spyOn(window, "fetch")
			.mockResolvedValueOnce(
				new Response(JSON.stringify({ region_id: "eu-de-1" }), { status: 200 }),
			);

		await useRegionStore.getState().fetch();

		const { regionId, detectedAt } = useRegionStore.getState();
		expect(regionId).toBe("eu-de-1");
		expect(detectedAt).toBeTypeOf("number");
		mockFetch.mockRestore();
	});

	it("does not update state when response is non-ok", async () => {
		vi.spyOn(window, "fetch").mockResolvedValueOnce(new Response("", { status: 503 }));

		await useRegionStore.getState().fetch();

		expect(useRegionStore.getState().regionId).toBeNull();
	});

	it("does not update state on network error", async () => {
		vi.spyOn(window, "fetch").mockRejectedValueOnce(new TypeError("fetch failed"));

		// Should not throw
		await expect(useRegionStore.getState().fetch()).resolves.toBeUndefined();

		expect(useRegionStore.getState().regionId).toBeNull();
	});

	it("ignores response with empty region_id", async () => {
		vi.spyOn(window, "fetch").mockResolvedValueOnce(
			new Response(JSON.stringify({ region_id: "" }), { status: 200 }),
		);

		await useRegionStore.getState().fetch();

		expect(useRegionStore.getState().regionId).toBeNull();
	});
});
