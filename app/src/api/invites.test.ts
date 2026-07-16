import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildInviteUrl, createInvite, extractInviteData, redeemInvite } from "./invites";

const fetchMock = vi.fn<typeof fetch>();
beforeEach(() => {
	vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

function jsonResp(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

const TOKEN = "test-session-token";
const CODE = "aabbccdd00112233aabbccdd00112233";
const HASH = "ab".repeat(32);
const DEVICE_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const KEY_PACKAGE = [1, 2, 3, 4];

// ── createInvite ──────────────────────────────────────────────────────────────

describe("createInvite", () => {
	it("sends Bearer token + key_package body, and returns code", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: CODE }, 201));

		const result = await createInvite(TOKEN, new Uint8Array(KEY_PACKAGE));

		expect(result.code).toBe(CODE);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/invites");
		expect(init?.method).toBe("POST");
		expect((init?.headers as Record<string, string>)?.Authorization).toBe(`Bearer ${TOKEN}`);
		const body = JSON.parse(init?.body as string) as { key_package: number[] };
		expect(body.key_package).toEqual(KEY_PACKAGE);
	});

	it("code is not in the request URL", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: CODE }, 201));
		await createInvite(TOKEN, new Uint8Array(KEY_PACKAGE));
		const [url] = fetchMock.mock.calls[0];
		expect(String(url)).not.toContain(CODE);
	});

	it("throws on non-ok response", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "rate_limited" }, 429));
		await expect(createInvite(TOKEN, new Uint8Array(KEY_PACKAGE))).rejects.toThrow("rate_limited");
	});

	it("throws with status code when body has no code field", async () => {
		fetchMock.mockResolvedValueOnce(new Response("", { status: 500 }));
		await expect(createInvite(TOKEN, new Uint8Array(KEY_PACKAGE))).rejects.toThrow(
			"invite_create_failed:500",
		);
	});
});

// ── redeemInvite ──────────────────────────────────────────────────────────────

describe("redeemInvite", () => {
	it("sends code in request body not URL", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_id: DEVICE_ID, key_package: KEY_PACKAGE }));

		await redeemInvite(TOKEN, CODE);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/invites/redeem");
		const body = JSON.parse(init?.body as string) as { code: string };
		expect(body.code).toBe(CODE);
		expect(String(url)).not.toContain(CODE);
	});

	it("sends Bearer token in Authorization header", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_id: DEVICE_ID, key_package: KEY_PACKAGE }));
		await redeemInvite(TOKEN, CODE);
		const [, init] = fetchMock.mock.calls[0];
		expect((init?.headers as Record<string, string>)?.Authorization).toBe(`Bearer ${TOKEN}`);
	});

	it("returns device_id and key_package on success", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_id: DEVICE_ID, key_package: KEY_PACKAGE }));
		const result = await redeemInvite(TOKEN, CODE);
		expect(result.device_id).toBe(DEVICE_ID);
		expect(result.key_package).toEqual(KEY_PACKAGE);
	});

	it("throws invite_not_found on 404", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "not_found" }, 404));
		await expect(redeemInvite(TOKEN, CODE)).rejects.toThrow("invite_not_found");
	});

	it("throws with server code on other errors", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "unauthorized" }, 401));
		await expect(redeemInvite(TOKEN, CODE)).rejects.toThrow("unauthorized");
	});
});

// ── buildInviteUrl ────────────────────────────────────────────────────────────

describe("buildInviteUrl", () => {
	it("places code + hash in URL fragment not path", () => {
		const url = buildInviteUrl("https://powehi.app", CODE, HASH);
		const parsed = new URL(url);
		expect(parsed.hash).toBe(`#${CODE}.${HASH}`);
		expect(parsed.pathname).not.toContain(CODE);
	});

	it("uses /i/connect as path", () => {
		const url = buildInviteUrl("https://powehi.app", CODE, HASH);
		expect(new URL(url).pathname).toBe("/i/connect");
	});

	it("uses provided origin", () => {
		const url = buildInviteUrl("http://localhost:5173", CODE, HASH);
		expect(url.startsWith("http://localhost:5173")).toBe(true);
	});
});

// ── extractInviteData ─────────────────────────────────────────────────────────

describe("extractInviteData", () => {
	it("extracts valid code + hash from hash with #", () => {
		expect(extractInviteData(`#${CODE}.${HASH}`)).toEqual({ code: CODE, keyPackageHash: HASH });
	});

	it("extracts valid code + hash from hash without #", () => {
		expect(extractInviteData(`${CODE}.${HASH}`)).toEqual({ code: CODE, keyPackageHash: HASH });
	});

	it("returns null when hash part is missing", () => {
		expect(extractInviteData(`#${CODE}`)).toBeNull();
	});

	it("returns null for short codes", () => {
		expect(extractInviteData(`#short.${HASH}`)).toBeNull();
	});

	it("returns null for uppercase hex code", () => {
		expect(extractInviteData(`#${CODE.toUpperCase()}.${HASH}`)).toBeNull();
	});

	it("returns null for uppercase hex hash", () => {
		expect(extractInviteData(`#${CODE}.${HASH.toUpperCase()}`)).toBeNull();
	});

	it("returns null for a short hash", () => {
		expect(extractInviteData(`#${CODE}.abcd`)).toBeNull();
	});

	it("returns null for UUID-with-hyphens code", () => {
		expect(extractInviteData(`#aabbccdd-0011-2233-aabb-ccdd00112233.${HASH}`)).toBeNull();
	});

	it("returns null for empty string", () => {
		expect(extractInviteData("")).toBeNull();
	});

	it("returns null for non-hex chars in code", () => {
		expect(extractInviteData(`#aabbccdd00112233aabbccdd0011gggg.${HASH}`)).toBeNull();
	});
});
