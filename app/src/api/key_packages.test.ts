import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fetchKeyPackage, getKeyPackageCount } from "./key_packages";

const fetchMock = vi.fn<typeof fetch>();
beforeEach(() => {
	vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

const TOKEN = "test-session-token";
const DEVICE_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";

// ── fetchKeyPackage ───────────────────────────────────────────────────────────

describe("fetchKeyPackage", () => {
	it("returns Uint8Array from server data field", async () => {
		const bytes = [0x01, 0x02, 0x03];
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ data: bytes }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const result = await fetchKeyPackage(TOKEN, DEVICE_ID);

		expect(result).toBeInstanceOf(Uint8Array);
		expect(Array.from(result)).toEqual(bytes);
	});

	it("sends auth header and hits correct path", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ data: [] }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		await fetchKeyPackage(TOKEN, DEVICE_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/key-packages/${DEVICE_ID}`);
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("throws not_found when no packages available", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "not_found" }), { status: 404 }),
		);
		await expect(fetchKeyPackage(TOKEN, DEVICE_ID)).rejects.toThrow("not_found");
	});
});

// ── getKeyPackageCount ────────────────────────────────────────────────────────

describe("getKeyPackageCount", () => {
	it("returns count from server response", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ count: 5 }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		const count = await getKeyPackageCount(TOKEN, DEVICE_ID);

		expect(count).toBe(5);
	});

	it("hits correct path with auth", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ count: 0 }), {
				status: 200,
				headers: { "Content-Type": "application/json" },
			}),
		);

		await getKeyPackageCount(TOKEN, DEVICE_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/key-packages/${DEVICE_ID}/count`);
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("throws on non-OK response", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
		);
		await expect(getKeyPackageCount(TOKEN, DEVICE_ID)).rejects.toThrow("unauthorized");
	});
});
