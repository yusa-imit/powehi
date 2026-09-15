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

/**
 * GET /v1/groups/:groupId/pending-removals — device UUIDs the group still
 * "owes" an MLS Remove for (server-side revocation bookkeeping only).
 *
 * This is a REQUEST for the client to act, never a proof: the server holds no
 * group state or keys and cannot construct or verify an MLS Remove (prd.md
 * §5.4). Callers MUST treat the returned device IDs as candidates requiring
 * explicit human confirmation before calling `removeMember` — never auto-execute.
 * Caller must already be a group member (401 otherwise).
 */
export async function listPendingRemovals(token: string, groupId: string): Promise<string[]> {
	assertOpaqueId(groupId, "group_id");
	const resp = await fetch(`${API_BASE}/groups/${encodeURIComponent(groupId)}/pending-removals`, {
		method: "GET",
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	const body = (await resp.json()) as { device_ids: string[] };
	return body.device_ids;
}

/**
 * GET /v1/groups/:groupId/members — device UUIDs the server records as
 * current members of `group_id`.
 *
 * This is one half of the local cross-check for the `pending-removals`
 * signal (prd.md §5.4): joining this list against a pending device_id can
 * catch server-side inconsistency (e.g. a pending-removal entry for a
 * device that was never a member, or one already removed), but NOT a fully
 * malicious/colluding server — the other half (binding device_ids to the
 * client's own MLS ratchet tree leaves) does not exist yet. See
 * `MembersResponse` doc comment in `groups.rs` for the full contract.
 *
 * `truncated: true` means `deviceIds` is a PREFIX, not the full membership
 * — callers MUST NOT treat absence from a truncated response as meaningful.
 * Caller must already be a group member (401 otherwise).
 */
export async function listMembers(
	token: string,
	groupId: string,
): Promise<{ deviceIds: string[]; truncated: boolean }> {
	assertOpaqueId(groupId, "group_id");
	const resp = await fetch(`${API_BASE}/groups/${encodeURIComponent(groupId)}/members`, {
		method: "GET",
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	const body = (await resp.json()) as { device_ids?: unknown; truncated?: unknown };
	// Validate rather than blindly trust the cast: a malformed/missing
	// `device_ids` must fail (the caller then skips the cross-check, same as
	// any other fetch failure) instead of silently becoming e.g. a char set
	// from `new Set(someString)`. A malformed/missing `truncated` defaults to
	// `true` (safe direction) rather than `false` — per `MembersResponse`'s
	// own contract, treating absence as meaningful is the false-eviction
	// failure mode this endpoint exists to avoid, so an unrecognized shape
	// must degrade toward "skip the cross-check", never toward "trust it".
	if (!Array.isArray(body.device_ids) || !body.device_ids.every((id) => typeof id === "string")) {
		throw new Error("invalid_members_response");
	}
	return { deviceIds: body.device_ids, truncated: body.truncated !== false };
}

/**
 * GET /v1/groups/:groupId/epoch — the server's current CAS epoch counter for
 * `groupId`, scoping data for a future `sendCommit` call.
 *
 * This is NOT the client's local MLS epoch (`mls_group.rs`'s remove-member
 * status-list item (a)): it only advances through `GroupRepository::
 * advance_epoch`'s CAS on an accepted Commit, so it legitimately diverges
 * from the local MLS epoch whenever a membership change reached the server
 * through a path that never called `sendCommit`. Treat the returned value as
 * an opaque CAS token for `sendCommit`'s `expectedEpoch`, never as a stand-in
 * for the client's own local MLS epoch tracking.
 *
 * Caller must already be a group member (401 otherwise; an unknown group id
 * answers identically, same non-oracle property as `listMembers`). A
 * non-home-region caller gets `502 region_mismatch` instead of a stale-or-
 * zero epoch (fail-closed, prd.md §3.5.1) — callers MUST treat that as a
 * distinct, retryable-elsewhere failure, not as "epoch 0".
 *
 * No production caller reads this yet — issue #2's wiring pass (item (a) in
 * `mls_group.rs`'s status list) is scoping-only until one exists. When a
 * caller does wire this into a `sendCommit` flow, it MUST call `getEpoch`,
 * drain the group's poll-loop backlog, stage, and send as work inside ONE
 * `withMlsCommitLock` acquisition (`app/src/lib/mlsCommitLock.ts`) — reading
 * the epoch outside that lock, or across two separate acquisitions, is
 * structurally stale by the time `stage` runs, even though the server's CAS
 * still fails such a stale attempt closed (`409 epoch_mismatch`) rather than
 * letting it fork the group.
 */
export async function getEpoch(token: string, groupId: string): Promise<number> {
	assertOpaqueId(groupId, "group_id");
	const resp = await fetch(`${API_BASE}/groups/${encodeURIComponent(groupId)}/epoch`, {
		method: "GET",
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	const body = (await resp.json().catch(() => ({}))) as { epoch?: unknown };
	if (typeof body.epoch !== "number" || !Number.isSafeInteger(body.epoch) || body.epoch < 0) {
		throw new Error("invalid_epoch_response");
	}
	return body.epoch;
}
