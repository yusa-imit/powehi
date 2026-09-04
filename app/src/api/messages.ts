/**
 * Messaging HTTP client.
 *
 * All payloads are opaque MLS ciphertext — never plaintext content.
 * Binary payloads sent as JSON arrays of integers (serde Vec<u8> default).
 * Auth: Bearer session token (never raw device UUID).
 */

const API_BASE = "/v1";

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

// ── Envelope type (mirrors Rust domain::Envelope) ────────────────────────────

export type MessageType = "Application" | "Welcome" | "Commit" | "Proposal";

export interface Envelope {
	id: string;
	group_id: string;
	/** Opaque UUID of the sending device — never a display name. */
	sender: string;
	recipient: string | null;
	message_type: MessageType;
	/** MLS ciphertext as JSON array of bytes. Decrypt via mlsDecrypt in the crypto worker. */
	ciphertext: number[];
	epoch: number | null;
	created_at: string;
	expires_at: string | null;
}

// ── Send ─────────────────────────────────────────────────────────────────────

/** POST /v1/messages — returns envelope_id. */
export async function sendMessage(
	token: string,
	groupId: string,
	ciphertext: Uint8Array,
	ttlSeconds?: number,
): Promise<string> {
	const resp = await fetch(`${API_BASE}/messages`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify({
			group_id: groupId,
			ciphertext: Array.from(ciphertext),
			...(ttlSeconds !== undefined ? { ttl_seconds: ttlSeconds } : {}),
		}),
	});
	await throwOnError(resp);
	const data = (await resp.json()) as { envelope_id: string };
	return data.envelope_id;
}

/** POST /v1/messages/welcome — unicast Welcome to a new group member. */
export async function sendWelcome(
	token: string,
	groupId: string,
	welcome: Uint8Array,
	targetDeviceId: string,
): Promise<void> {
	const resp = await fetch(`${API_BASE}/messages/welcome`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify({
			group_id: groupId,
			welcome: Array.from(welcome),
			target_device_id: targetDeviceId,
		}),
	});
	await throwOnError(resp);
}

/**
 * POST /v1/messages/commit — broadcast MLS Commit. Returns new epoch.
 * @param expectedEpoch The epoch this Commit was built against (the
 *   caller's own last-known epoch for the group) — the server uses it as a
 *   compare-and-swap precondition and rejects with `epoch_mismatch` (409) if
 *   another commit already landed first. On rejection, re-fetch the group's
 *   current epoch and rebuild the Commit before retrying; never resubmit the
 *   same commit bytes with a bumped epoch number.
 */
export async function sendCommit(
	token: string,
	groupId: string,
	commit: Uint8Array,
	expectedEpoch: number,
): Promise<number> {
	const resp = await fetch(`${API_BASE}/messages/commit`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify({
			group_id: groupId,
			commit: Array.from(commit),
			expected_epoch: expectedEpoch,
		}),
	});
	await throwOnError(resp);
	const data = (await resp.json()) as { epoch: number };
	return data.epoch;
}

// ── Poll ─────────────────────────────────────────────────────────────────────

/**
 * GET /v1/messages — poll for pending envelopes.
 * @param since RFC3339 timestamp — pass the `created_at` of the last envelope
 *   this caller fully processed, verbatim (never floored/rounded — a coarsened
 *   value can silently and permanently skip envelopes sharing that exact
 *   timestamp once results are paginated, cycle 351).
 * @param sinceId That same envelope's `id`. Required together with `since` to
 *   form an exact `(created_at, id)` resume cursor — see `find_pending`'s
 *   Rust doc comment (`powehi-port-outbound`) for why.
 */
export async function pollMessages(
	token: string,
	since?: string,
	sinceId?: string,
): Promise<Envelope[]> {
	const url = new URL(`${API_BASE}/messages`, window.location.origin);
	if (since !== undefined) url.searchParams.set("since", since);
	if (sinceId !== undefined) url.searchParams.set("since_id", sinceId);
	const resp = await fetch(url.pathname + url.search, {
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	return resp.json() as Promise<Envelope[]>;
}

// ── Ack ──────────────────────────────────────────────────────────────────────

/** DELETE /v1/messages/:id — acknowledge (delete) a delivered envelope. */
export async function ackMessage(token: string, envelopeId: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/messages/${envelopeId}`, {
		method: "DELETE",
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
}
