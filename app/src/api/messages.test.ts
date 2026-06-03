import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	type Envelope,
	ackMessage,
	pollMessages,
	sendCommit,
	sendMessage,
	sendWelcome,
} from "./messages";

// Replace global fetch with a Vitest mock.
const fetchMock = vi.fn<typeof fetch>();
beforeEach(() => {
	vi.stubGlobal("fetch", fetchMock);
	// Default window.location.origin for URL construction.
	Object.defineProperty(window, "location", {
		value: { origin: "http://localhost" },
		writable: true,
	});
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
const GROUP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const ENV_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
const DEVICE_ID = "cccccccc-cccc-cccc-cccc-cccccccccccc";

// ── sendMessage ───────────────────────────────────────────────────────────────

describe("sendMessage", () => {
	it("posts ciphertext and returns envelope_id", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ envelope_id: ENV_ID }));

		const ct = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
		const id = await sendMessage(TOKEN, GROUP_ID, ct);

		expect(id).toBe(ENV_ID);
		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/messages");
		expect(init?.method).toBe("POST");
		const body = JSON.parse(init?.body as string) as {
			group_id: string;
			ciphertext: number[];
		};
		expect(body.group_id).toBe(GROUP_ID);
		expect(body.ciphertext).toEqual([0xde, 0xad, 0xbe, 0xef]);
	});

	it("includes ttl_seconds when provided", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ envelope_id: ENV_ID }));

		await sendMessage(TOKEN, GROUP_ID, new Uint8Array([1]), 300);

		const body = JSON.parse(fetchMock.mock.calls[0][1]?.body as string) as {
			ttl_seconds: number;
		};
		expect(body.ttl_seconds).toBe(300);
	});

	it("omits ttl_seconds when undefined", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ envelope_id: ENV_ID }));

		await sendMessage(TOKEN, GROUP_ID, new Uint8Array([1]));

		const body = JSON.parse(fetchMock.mock.calls[0][1]?.body as string) as Record<string, unknown>;
		expect("ttl_seconds" in body).toBe(false);
	});

	it("throws with server code on non-OK response", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "unauthorized" }, 401));
		await expect(sendMessage(TOKEN, GROUP_ID, new Uint8Array([1]))).rejects.toThrow("unauthorized");
	});

	it("throws http_500 when server returns no code", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({}, 500));
		await expect(sendMessage(TOKEN, GROUP_ID, new Uint8Array([1]))).rejects.toThrow("http_500");
	});
});

// ── sendWelcome ───────────────────────────────────────────────────────────────

describe("sendWelcome", () => {
	it("posts welcome bytes to correct endpoint", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

		await sendWelcome(TOKEN, GROUP_ID, new Uint8Array([0xaa, 0xbb]), DEVICE_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/messages/welcome");
		const body = JSON.parse(init?.body as string) as {
			group_id: string;
			welcome: number[];
			target_device_id: string;
		};
		expect(body.group_id).toBe(GROUP_ID);
		expect(body.welcome).toEqual([0xaa, 0xbb]);
		expect(body.target_device_id).toBe(DEVICE_ID);
	});

	it("throws on non-204 response", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "not_member" }, 403));
		await expect(sendWelcome(TOKEN, GROUP_ID, new Uint8Array([1]), DEVICE_ID)).rejects.toThrow(
			"not_member",
		);
	});
});

// ── sendCommit ────────────────────────────────────────────────────────────────

describe("sendCommit", () => {
	it("posts commit bytes and returns epoch", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ epoch: 7 }));

		const epoch = await sendCommit(TOKEN, GROUP_ID, new Uint8Array([0xff]));

		expect(epoch).toBe(7);
		const [url] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/messages/commit");
	});

	it("throws on failure", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "not_member" }, 403));
		await expect(sendCommit(TOKEN, GROUP_ID, new Uint8Array([1]))).rejects.toThrow("not_member");
	});
});

// ── pollMessages ──────────────────────────────────────────────────────────────

describe("pollMessages", () => {
	const mockEnvelope: Envelope = {
		id: ENV_ID,
		group_id: GROUP_ID,
		sender: DEVICE_ID,
		recipient: null,
		message_type: "Application",
		ciphertext: [1, 2, 3],
		epoch: null,
		created_at: "2026-06-03T12:00:00Z",
		expires_at: null,
	};

	it("returns parsed envelopes", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp([mockEnvelope]));

		const envelopes = await pollMessages(TOKEN);

		expect(envelopes).toHaveLength(1);
		expect(envelopes[0].id).toBe(ENV_ID);
		expect(envelopes[0].message_type).toBe("Application");
		const [url, init] = fetchMock.mock.calls[0];
		expect((url as string).startsWith("/v1/messages")).toBe(true);
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("appends since query param when provided", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp([]));

		await pollMessages(TOKEN, 1748952000);

		const [url] = fetchMock.mock.calls[0];
		expect(url as string).toContain("since=1748952000");
	});

	it("omits since query param when undefined", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp([]));

		await pollMessages(TOKEN);

		const [url] = fetchMock.mock.calls[0];
		expect(url as string).not.toContain("since");
	});

	it("throws on non-OK", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "rate_limited" }, 429));
		await expect(pollMessages(TOKEN)).rejects.toThrow("rate_limited");
	});
});

// ── ackMessage ────────────────────────────────────────────────────────────────

describe("ackMessage", () => {
	it("sends DELETE to correct path", async () => {
		fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));

		await ackMessage(TOKEN, ENV_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/messages/${ENV_ID}`);
		expect(init?.method).toBe("DELETE");
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("throws on non-204", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ code: "not_found" }, 404));
		await expect(ackMessage(TOKEN, ENV_ID)).rejects.toThrow("not_found");
	});
});
