import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { addMember, createGroup, listMembers, listPendingRemovals, removeMember } from "./groups";

const fetchMock = vi.fn<typeof fetch>();
beforeEach(() => {
	vi.stubGlobal("fetch", fetchMock);
});
afterEach(() => {
	vi.restoreAllMocks();
	vi.unstubAllGlobals();
});

function jsonResp(body: unknown, status = 204): Response {
	return new Response(status === 204 ? null : JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

const TOKEN = "test-session-token";
const GROUP_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const DEVICE_ID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

// ── createGroup ───────────────────────────────────────────────────────────────

describe("createGroup", () => {
	it("posts group_id to /v1/groups", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp(null, 204));

		await createGroup(TOKEN, GROUP_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe("/v1/groups");
		expect(init?.method).toBe("POST");
		const body = JSON.parse(init?.body as string) as { group_id: string };
		expect(body.group_id).toBe(GROUP_ID);
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("throws with server code on failure", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "conflict" }), { status: 409 }),
		);
		await expect(createGroup(TOKEN, GROUP_ID)).rejects.toThrow("conflict");
	});
});

// ── createGroup ── validation ─────────────────────────────────────────────────

describe("createGroup — validation", () => {
	it("rejects non-UUID groupId without making a network call", async () => {
		await expect(createGroup(TOKEN, "not-a-uuid")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects path-traversal groupId", async () => {
		await expect(createGroup(TOKEN, "../admin")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

// ── addMember ─────────────────────────────────────────────────────────────────

describe("addMember", () => {
	it("posts epoch to correct path", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp(null, 204));

		await addMember(TOKEN, GROUP_ID, DEVICE_ID, 3);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/groups/${GROUP_ID}/members/${DEVICE_ID}`);
		expect(init?.method).toBe("POST");
		const body = JSON.parse(init?.body as string) as { epoch: number };
		expect(body.epoch).toBe(3);
	});

	it("throws unauthorized when caller is not a member", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "unauthorized" }), { status: 403 }),
		);
		await expect(addMember(TOKEN, GROUP_ID, DEVICE_ID, 1)).rejects.toThrow("unauthorized");
	});

	it("rejects non-UUID groupId without fetch", async () => {
		await expect(addMember(TOKEN, "bad-id", DEVICE_ID, 0)).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects non-UUID deviceId without fetch", async () => {
		await expect(addMember(TOKEN, GROUP_ID, "maya", 0)).rejects.toThrow("invalid_device_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

// ── removeMember ──────────────────────────────────────────────────────────────

describe("removeMember", () => {
	it("sends DELETE to correct path", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp(null, 204));

		await removeMember(TOKEN, GROUP_ID, DEVICE_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/groups/${GROUP_ID}/members/${DEVICE_ID}`);
		expect(init?.method).toBe("DELETE");
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
	});

	it("throws on failure", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "not_found" }), { status: 404 }),
		);
		await expect(removeMember(TOKEN, GROUP_ID, DEVICE_ID)).rejects.toThrow("not_found");
	});

	it("rejects non-UUID groupId without fetch", async () => {
		await expect(removeMember(TOKEN, "g/members/x/admin", DEVICE_ID)).rejects.toThrow(
			"invalid_group_id",
		);
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects non-UUID deviceId without fetch", async () => {
		await expect(removeMember(TOKEN, GROUP_ID, "jordan?role=admin")).rejects.toThrow(
			"invalid_device_id",
		);
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

// ── listPendingRemovals ───────────────────────────────────────────────────────

describe("listPendingRemovals", () => {
	it("gets device_ids from correct path", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_ids: [DEVICE_ID] }, 200));

		const result = await listPendingRemovals(TOKEN, GROUP_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/groups/${GROUP_ID}/pending-removals`);
		expect(init?.method).toBe("GET");
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
		expect(result).toEqual([DEVICE_ID]);
	});

	it("returns an empty array when there are no pending removals", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_ids: [] }, 200));
		await expect(listPendingRemovals(TOKEN, GROUP_ID)).resolves.toEqual([]);
	});

	it("throws unauthorized when caller is not a member", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
		);
		await expect(listPendingRemovals(TOKEN, GROUP_ID)).rejects.toThrow("unauthorized");
	});

	it("rejects non-UUID groupId without fetch", async () => {
		await expect(listPendingRemovals(TOKEN, "not-a-uuid")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects path-traversal groupId without fetch", async () => {
		await expect(listPendingRemovals(TOKEN, "../admin")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});
});

// ── listMembers ──────────────────────────────────────────────────────────────

describe("listMembers", () => {
	it("gets device_ids and truncated from correct path", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_ids: [DEVICE_ID], truncated: false }, 200));

		const result = await listMembers(TOKEN, GROUP_ID);

		const [url, init] = fetchMock.mock.calls[0];
		expect(url).toBe(`/v1/groups/${GROUP_ID}/members`);
		expect(init?.method).toBe("GET");
		expect(init?.headers).toMatchObject({ Authorization: `Bearer ${TOKEN}` });
		expect(result).toEqual({ deviceIds: [DEVICE_ID], truncated: false });
	});

	it("returns truncated: true when the response is a prefix", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_ids: [DEVICE_ID], truncated: true }, 200));
		await expect(listMembers(TOKEN, GROUP_ID)).resolves.toEqual({
			deviceIds: [DEVICE_ID],
			truncated: true,
		});
	});

	it("throws unauthorized when caller is not a member", async () => {
		fetchMock.mockResolvedValueOnce(
			new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 }),
		);
		await expect(listMembers(TOKEN, GROUP_ID)).rejects.toThrow("unauthorized");
	});

	it("rejects non-UUID groupId without fetch", async () => {
		await expect(listMembers(TOKEN, "not-a-uuid")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects path-traversal groupId without fetch", async () => {
		await expect(listMembers(TOKEN, "../admin")).rejects.toThrow("invalid_group_id");
		expect(fetchMock).not.toHaveBeenCalled();
	});

	it("rejects a response whose device_ids is missing or not a string array (fail-safe: caller then skips the cross-check, same as any other fetch failure — never silently trusts a malformed shape)", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ truncated: false }, 200));
		await expect(listMembers(TOKEN, GROUP_ID)).rejects.toThrow("invalid_members_response");
	});

	it("rejects a response whose device_ids contains a non-string element", async () => {
		fetchMock.mockResolvedValueOnce(
			jsonResp({ device_ids: [DEVICE_ID, 1], truncated: false }, 200),
		);
		await expect(listMembers(TOKEN, GROUP_ID)).rejects.toThrow("invalid_members_response");
	});

	it("defaults truncated to true (safe direction) when the field is missing, rather than false", async () => {
		fetchMock.mockResolvedValueOnce(jsonResp({ device_ids: [DEVICE_ID] }, 200));
		await expect(listMembers(TOKEN, GROUP_ID)).resolves.toEqual({
			deviceIds: [DEVICE_ID],
			truncated: true,
		});
	});
});
