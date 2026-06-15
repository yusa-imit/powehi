/**
 * useRegionDetect — unit tests (prd.md §7.6 region detection).
 *
 * The hook calls useRegionStore.fetch() once on mount and returns the
 * current regionId from the store. No PII, no auth — purely informational.
 */

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useRegionStore } from "../store/region";
import { useRegionDetect } from "./useRegionDetect";

describe("useRegionDetect (prd.md §7.6)", () => {
	beforeEach(() => {
		useRegionStore.setState({ regionId: null, detectedAt: null });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		useRegionStore.setState({ regionId: null, detectedAt: null });
	});

	it("returns null before fetch resolves", () => {
		vi.spyOn(window, "fetch").mockReturnValue(new Promise(() => {})); // never resolves
		const { result } = renderHook(() => useRegionDetect());
		expect(result.current).toBeNull();
	});

	it("returns regionId after store fetch resolves", async () => {
		vi.spyOn(window, "fetch").mockResolvedValueOnce(
			new Response(JSON.stringify({ region_id: "eu-de-1" }), { status: 200 }),
		);
		const { result } = renderHook(() => useRegionDetect());
		await act(async () => {});
		expect(result.current).toBe("eu-de-1");
	});

	it("calls store fetch exactly once on mount", async () => {
		const fetchSpy = vi.fn().mockResolvedValue(undefined);
		useRegionStore.setState({ fetch: fetchSpy } as unknown as ReturnType<
			typeof useRegionStore.getState
		>);

		renderHook(() => useRegionDetect());
		await act(async () => {});

		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it("returns null when fetch fails (network error)", async () => {
		vi.spyOn(window, "fetch").mockRejectedValueOnce(new TypeError("fetch failed"));
		const { result } = renderHook(() => useRegionDetect());
		await act(async () => {});
		expect(result.current).toBeNull();
	});

	it("returns null when server returns non-ok response", async () => {
		vi.spyOn(window, "fetch").mockResolvedValueOnce(new Response("", { status: 503 }));
		const { result } = renderHook(() => useRegionDetect());
		await act(async () => {});
		expect(result.current).toBeNull();
	});

	it("reflects store regionId already set before mount", async () => {
		useRegionStore.setState({ regionId: "ap-kr-1", detectedAt: 1_000_000 });
		vi.spyOn(window, "fetch").mockResolvedValueOnce(new Response("", { status: 503 }));
		const { result } = renderHook(() => useRegionDetect());
		// Already set in store — should be returned immediately.
		expect(result.current).toBe("ap-kr-1");
	});
});
