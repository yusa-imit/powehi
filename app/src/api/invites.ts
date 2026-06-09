/**
 * Invite link HTTP client (prd.md §8.3).
 *
 * POST /v1/invites        — create a 24-hour one-time invite code
 * POST /v1/invites/redeem — redeem an invite code (one-time)
 *
 * Security invariants:
 * - The invite code is sent in the request body, never in the URL path,
 *   so it never appears in server access logs or WAF traces.
 * - The shareable invite URL places the code in the #fragment (never sent
 *   to the server per browser standard). See buildInviteUrl().
 */

const API_BASE = "/v1";

export interface CreateInviteResponse {
	code: string;
}

export interface RedeemInviteResponse {
	device_id: string;
}

/** POST /v1/invites — create a one-time 24-hour invite code. */
export async function createInvite(sessionToken: string): Promise<CreateInviteResponse> {
	const resp = await fetch(`${API_BASE}/invites`, {
		method: "POST",
		headers: { Authorization: `Bearer ${sessionToken}` },
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `invite_create_failed:${resp.status}`);
	}
	return resp.json() as Promise<CreateInviteResponse>;
}

/**
 * POST /v1/invites/redeem — redeem an invite code.
 *
 * The code must be sent in the request body (not the URL path) so it never
 * appears in server logs. Returns the inviting device's opaque UUID.
 *
 * Throws "invite_not_found" on 404 (expired or invalid code).
 */
export async function redeemInvite(
	sessionToken: string,
	code: string,
): Promise<RedeemInviteResponse> {
	const resp = await fetch(`${API_BASE}/invites/redeem`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${sessionToken}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ code }),
	});
	if (resp.status === 404) throw new Error("invite_not_found");
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `invite_redeem_failed:${resp.status}`);
	}
	return resp.json() as Promise<RedeemInviteResponse>;
}

/**
 * Build the shareable invite URL.
 *
 * The code is placed in the URL fragment (#) so the browser never transmits
 * it to any server (prd.md §8.3). The path /i/connect is non-secret.
 */
export function buildInviteUrl(origin: string, code: string): string {
	return `${origin}/i/connect#${code}`;
}

/**
 * Extract an invite code from the current URL fragment.
 *
 * Returns the code string if the fragment is exactly 32 lowercase hex chars
 * (matching Uuid::new_v4().simple() output), otherwise null.
 */
export function extractInviteCode(hash: string): string | null {
	const code = hash.startsWith("#") ? hash.slice(1) : hash;
	if (code.length === 32 && /^[0-9a-f]{32}$/.test(code)) return code;
	return null;
}
