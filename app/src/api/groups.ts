/**
 * Group management HTTP client.
 *
 * Groups are MLS groups registered with the server so it can enforce
 * membership for message delivery. The server sees only opaque UUIDs.
 */

const API_BASE = "/v1";

// Strict opaque ID format: lowercase hex UUID (no path traversal, no injection)
const OPAQUE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function assertOpaqueId(id: string, name: string): void {
	if (!OPAQUE_ID_RE.test(id)) {
		throw new Error(`invalid_${name}`);
	}
}

function authHeaders(token: string): HeadersInit {
	return {
		"Content-Type": "application/json",
		Authorization: `Bearer ${token}`,
	};
}

async function throwOnError(resp: Response): Promise<void> {
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `http_${resp.status}`);
	}
}

/** POST /v1/groups — register a new MLS group. Creator becomes first member. */
export async function createGroup(token: string, groupId: string): Promise<void> {
	assertOpaqueId(groupId, "group_id");
	const resp = await fetch(`${API_BASE}/groups`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify({ group_id: groupId }),
	});
	await throwOnError(resp);
}

/**
 * POST /v1/groups/:groupId/members/:deviceId — add a device to the group.
 * Caller must be an existing group member.
 * @param epoch MLS epoch at which the member joined.
 */
export async function addMember(
	token: string,
	groupId: string,
	deviceId: string,
	epoch: number,
): Promise<void> {
	assertOpaqueId(groupId, "group_id");
	assertOpaqueId(deviceId, "device_id");
	const resp = await fetch(
		`${API_BASE}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(deviceId)}`,
		{
			method: "POST",
			headers: authHeaders(token),
			body: JSON.stringify({ epoch }),
		},
	);
	await throwOnError(resp);
}

/**
 * DELETE /v1/groups/:groupId/members/:deviceId — remove a device from the group.
 * Caller must be an existing group member.
 */
export async function removeMember(
	token: string,
	groupId: string,
	deviceId: string,
): Promise<void> {
	assertOpaqueId(groupId, "group_id");
	assertOpaqueId(deviceId, "device_id");
	const resp = await fetch(
		`${API_BASE}/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(deviceId)}`,
		{
			method: "DELETE",
			headers: { Authorization: `Bearer ${token}` },
		},
	);
	await throwOnError(resp);
}
