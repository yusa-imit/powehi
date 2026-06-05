import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { hashHandle, loginFinish, loginInit, regFinish, regInit, uploadKeyPackage } from "./auth";

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

const HANDLE_HASH = new Uint8Array(32).fill(0xab);
const OPAQUE_BYTES = new Uint8Array(64).fill(0x01);
const USER_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const DEVICE_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const NONCE = "cccccccc-cccc-cccc-cccc-cccccccccccc";
const TOKEN = "test-session-token";
const KP_BYTES = new Uint8Array(100).fill(0x55);

// ── hashHandle ────────────────────────────────────────────────────────────────

describe("hashHandle", () => {
	it("returns a 32-byte SHA-256 hash", async () => {
		const hash = await hashHandle("alice");
		expect(hash).toBeInstanceOf(Uint8Array);
		expect(hash.length).toBe(32);
	});

	it("produces the same hash for the same input (deterministic)", async () => {
		const h1 = await hashHandle("bob");
		const h2 = await hashHandle("bob");
		expect(Array.from(h1)).toEqual(Array.from(h2));
	});

	it("produces different hashes for different handles", async () => {
		const h1 = await hashHandle("alice");
		const h2 = await hashHandle("charlie");
		expect(Array.from(h1)).not.toEqual(Array.from(h2));
	});

	it("hash bytes are not equal to plaintext handle bytes (security invariant)", async () => {
		const handle = "alice";
		const hash = await hashHandle(handle);
		const plaintext = new TextEncoder().encode(handle);
		// SHA-256 is 32 bytes; "alice" is 5 bytes — lengths already differ
		expect(hash.length).toBe(32);
		expect(hash.length).not.toBe(plaintext.length);
	});
});

// ── regInit ───────────────────────────────────────────────────────────────────

describe("regInit", () => {
	it("posts to /v1/auth/register/init", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, opaque_response: [1, 2, 3] }));
		await regInit(HANDLE_HASH, OPAQUE_BYTES);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/auth/register/init");
		expect(init?.method).toBe("POST");
	});

	it("sends handle_hash as a number array, not as a string", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, opaque_response: [] }));
		await regInit(HANDLE_HASH, OPAQUE_BYTES);
		const [, init] = fetchMock.mock.calls[0];
		const body = JSON.parse(init?.body as string) as {
			handle_hash: unknown;
			opaque_request: unknown;
		};
		expect(Array.isArray(body.handle_hash)).toBe(true);
		expect((body.handle_hash as number[]).length).toBe(32);
		expect(Array.isArray(body.opaque_request)).toBe(true);
	});

	it("does not include plaintext handle in request body (security invariant)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, opaque_response: [] }));
		const handle = "sentinel_plaintext_reg";
		const handleHash = await hashHandle(handle);
		await regInit(handleHash, OPAQUE_BYTES);
		const [, init] = fetchMock.mock.calls[0];
		expect(init?.body as string).not.toContain("sentinel_plaintext_reg");
	});

	it("returns user_id and opaque_response from server", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, opaque_response: [4, 5, 6] }));
		const result = await regInit(HANDLE_HASH, OPAQUE_BYTES);
		expect(result.user_id).toBe(USER_ID);
		expect(result.opaque_response).toEqual([4, 5, 6]);
	});

	it("does not send Authorization header (pre-auth endpoint)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, opaque_response: [] }));
		await regInit(HANDLE_HASH, OPAQUE_BYTES);
		const [, init] = fetchMock.mock.calls[0];
		const headers = init?.headers as Record<string, string> | undefined;
		expect(headers?.Authorization).toBeUndefined();
	});

	it("throws server error code on failure", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "conflict" }), { status: 409 }),
		);
		await expect(regInit(HANDLE_HASH, OPAQUE_BYTES)).rejects.toThrow("conflict");
	});
});

// ── regFinish ─────────────────────────────────────────────────────────────────

describe("regFinish", () => {
	it("posts to /v1/auth/register/finish and returns user_id + device_id", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, device_id: DEVICE_ID }));
		const result = await regFinish(USER_ID, OPAQUE_BYTES, new Uint8Array(16));
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/auth/register/finish");
		expect(init?.method).toBe("POST");
		expect(result.user_id).toBe(USER_ID);
		expect(result.device_id).toBe(DEVICE_ID);
	});

	it("sends user_id, opaque_record, and mls_credential as number arrays (wire shape)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, device_id: DEVICE_ID }));
		const mls = new Uint8Array(16).fill(0xcc);
		await regFinish(USER_ID, OPAQUE_BYTES, mls);
		const [, init] = fetchMock.mock.calls[0];
		const body = JSON.parse(init?.body as string) as {
			user_id: unknown;
			opaque_record: unknown;
			mls_credential: unknown;
		};
		expect(body.user_id).toBe(USER_ID);
		expect(Array.isArray(body.opaque_record)).toBe(true);
		expect((body.opaque_record as number[]).length).toBe(OPAQUE_BYTES.length);
		expect(Array.isArray(body.mls_credential)).toBe(true);
		expect((body.mls_credential as number[]).length).toBe(mls.length);
	});

	it("does not send Authorization header (pre-auth endpoint)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ user_id: USER_ID, device_id: DEVICE_ID }));
		await regFinish(USER_ID, OPAQUE_BYTES, new Uint8Array(16));
		const [, init] = fetchMock.mock.calls[0];
		const headers = init?.headers as Record<string, string> | undefined;
		expect(headers?.Authorization).toBeUndefined();
	});

	it("throws server error code on failure", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "internal_error" }), { status: 500 }),
		);
		await expect(regFinish(USER_ID, OPAQUE_BYTES, new Uint8Array(16))).rejects.toThrow(
			"internal_error",
		);
	});
});

// ── loginInit ─────────────────────────────────────────────────────────────────

describe("loginInit", () => {
	it("posts to /v1/auth/login/init with handle_hash as number array", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResp({ user_id: USER_ID, opaque_ke2: [1, 2], login_nonce: NONCE }),
		);
		await loginInit(HANDLE_HASH, OPAQUE_BYTES);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/auth/login/init");
		const body = JSON.parse(init?.body as string) as { handle_hash: unknown };
		expect(Array.isArray(body.handle_hash)).toBe(true);
		expect((body.handle_hash as number[]).length).toBe(32);
	});

	it("returns user_id, opaque_ke2, and login_nonce", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResp({ user_id: USER_ID, opaque_ke2: [7, 8, 9], login_nonce: NONCE }),
		);
		const result = await loginInit(HANDLE_HASH, OPAQUE_BYTES);
		expect(result.user_id).toBe(USER_ID);
		expect(result.opaque_ke2).toEqual([7, 8, 9]);
		expect(result.login_nonce).toBe(NONCE);
	});

	it("does not include plaintext handle in request body (security invariant)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResp({ user_id: USER_ID, opaque_ke2: [], login_nonce: NONCE }),
		);
		const handle = "sentinel_plaintext_login";
		const handleHash = await hashHandle(handle);
		await loginInit(handleHash, OPAQUE_BYTES);
		const [, init] = fetchMock.mock.calls[0];
		expect(init?.body as string).not.toContain("sentinel_plaintext_login");
	});

	it("does not send Authorization header (pre-auth endpoint)", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResp({ user_id: USER_ID, opaque_ke2: [], login_nonce: NONCE }),
		);
		await loginInit(HANDLE_HASH, OPAQUE_BYTES);
		const [, init] = fetchMock.mock.calls[0];
		const headers = init?.headers as Record<string, string> | undefined;
		expect(headers?.Authorization).toBeUndefined();
	});

	it("throws server error code on failure", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "not_found" }), { status: 404 }),
		);
		await expect(loginInit(HANDLE_HASH, OPAQUE_BYTES)).rejects.toThrow("not_found");
	});
});

// ── loginFinish ───────────────────────────────────────────────────────────────

describe("loginFinish", () => {
	it("posts to /v1/auth/login/finish and returns session token", async () => {
		// Server returns a bare JSON string (the session token).
		fetchMock.mockResolvedValueOnce(jsonResp(TOKEN));
		const token = await loginFinish(OPAQUE_BYTES, NONCE, DEVICE_ID);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/auth/login/finish");
		expect(init?.method).toBe("POST");
		expect(token).toBe(TOKEN);
	});

	it("maps server 'unauthorized' code to 'invalid_credentials'", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
		);
		await expect(loginFinish(OPAQUE_BYTES, NONCE, DEVICE_ID)).rejects.toThrow(
			"invalid_credentials",
		);
	});

	it("sends opaque_ke3 as number array, login_nonce and device_id as strings (wire shape)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp(TOKEN));
		await loginFinish(OPAQUE_BYTES, NONCE, DEVICE_ID);
		const [, init] = fetchMock.mock.calls[0];
		const body = JSON.parse(init?.body as string) as {
			opaque_ke3: unknown;
			login_nonce: unknown;
			device_id: unknown;
		};
		expect(Array.isArray(body.opaque_ke3)).toBe(true);
		expect((body.opaque_ke3 as number[]).length).toBe(OPAQUE_BYTES.length);
		expect(body.login_nonce).toBe(NONCE);
		expect(body.device_id).toBe(DEVICE_ID);
	});

	it("does not send Authorization header (pre-auth endpoint)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp(TOKEN));
		await loginFinish(OPAQUE_BYTES, NONCE, DEVICE_ID);
		const [, init] = fetchMock.mock.calls[0];
		const headers = init?.headers as Record<string, string> | undefined;
		expect(headers?.Authorization).toBeUndefined();
	});

	it("passes other server error codes through unchanged", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "rate_limited" }), { status: 429 }),
		);
		await expect(loginFinish(OPAQUE_BYTES, NONCE, DEVICE_ID)).rejects.toThrow("rate_limited");
	});
});

// ── uploadKeyPackage ──────────────────────────────────────────────────────────

describe("uploadKeyPackage", () => {
	it("posts key package to correct device URL with Bearer token", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
		await uploadKeyPackage(TOKEN, DEVICE_ID, KP_BYTES);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/key-packages/${DEVICE_ID}`);
		expect(init?.method).toBe("POST");
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
		const body = JSON.parse(init?.body as string) as { packages: number[][] };
		expect(Array.isArray(body.packages)).toBe(true);
		expect(body.packages).toHaveLength(1);
	});

	it("token does not appear in the request URL (Authorization header only)", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
		await uploadKeyPackage(TOKEN, DEVICE_ID, KP_BYTES);
		const [url] = fetchMock.mock.calls[0];
		expect(url as string).not.toContain(TOKEN);
	});

	it("does not throw on HTTP failure (non-fatal)", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 500 }));
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		await expect(uploadKeyPackage(TOKEN, DEVICE_ID, KP_BYTES)).resolves.toBeUndefined();
		warnSpy.mockRestore();
	});

	it("logs HTTP status on failure without leaking key bytes", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 502 }));
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		await uploadKeyPackage(TOKEN, DEVICE_ID, KP_BYTES);
		expect(warnSpy).toHaveBeenCalledOnce();
		// Only the numeric HTTP status is logged — not key material
		expect(warnSpy.mock.calls[0][1]).toBe(502);
		warnSpy.mockRestore();
	});

	it("logs exactly two arguments on failure — prefix string and status code, nothing more", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 503 }));
		const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
		await uploadKeyPackage(TOKEN, DEVICE_ID, KP_BYTES);
		expect(warnSpy).toHaveBeenCalledOnce();
		expect(warnSpy.mock.calls[0]).toHaveLength(2);
		warnSpy.mockRestore();
	});
});
