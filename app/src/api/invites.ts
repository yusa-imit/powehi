/**
 * Invite link HTTP client (prd.md §8.3).
 *
 * POST /v1/invites        — create a 24-hour one-time invite code
 * POST /v1/invites/redeem — redeem an invite code (one-time)
 *
 * Security invariants:
 * - The invite code is sent in the request body, never in the URL path,
 *   so it never appears in server access logs or WAF traces.
 * - The shareable invite URL places the code AND the inviter's KeyPackage
 *   hash in the #fragment (never sent to the server per browser standard).
 *   See buildInviteUrl()/extractInviteData(). The hash lets the recipient
 *   verify — locally, using only data the server never saw — that the
 *   KeyPackage returned by redeemInvite() wasn't substituted by a
 *   compromised/malicious server (the MITM protection prd.md §8.4 QR
 *   in-person exchange is meant to provide).
 */

const API_BASE = "/v1";

export interface CreateInviteResponse {
	code: string;
}

export interface RedeemInviteResponse {
	device_id: string;
	/** Raw KeyPackage bytes reserved at invite-creation time. */
	key_package: number[];
}

/**
 * POST /v1/invites — create a one-time 24-hour invite code pinned to
 * `keyPackage`, a KeyPackage the caller generated itself (via the crypto
 * worker's `mlsGetKeyPackage`, never fetched from or authored by the server).
 *
 * The server never computes or returns a hash of `keyPackage` — see
 * `InviteModal`, which hashes it locally before calling this function and
 * embeds that hash in the shareable URL's #fragment.
 */
export async function createInvite(
	sessionToken: string,
	keyPackage: Uint8Array,
): Promise<CreateInviteResponse> {
	const resp = await fetch(`${API_BASE}/invites`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${sessionToken}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({ key_package: Array.from(keyPackage) }),
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

/** 64 lowercase hex chars — SHA-256 hex digest. */
const KEY_PACKAGE_HASH_RE = /^[0-9a-f]{64}$/;
/** 32 lowercase hex chars — Uuid::new_v4().simple() output. */
const INVITE_CODE_RE = /^[0-9a-f]{32}$/;

export interface InviteFragmentData {
	code: string;
	keyPackageHash: string;
}

/**
 * Build the shareable invite URL.
 *
 * The code and the inviter's KeyPackage hash are placed in the URL fragment
 * (#) so the browser never transmits them to any server (prd.md §8.3/§8.4).
 * The path /i/connect is non-secret.
 */
export function buildInviteUrl(origin: string, code: string, keyPackageHash: string): string {
	return `${origin}/i/connect#${code}.${keyPackageHash}`;
}

/**
 * Extract the invite code and KeyPackage hash from the current URL fragment.
 *
 * Returns null unless the fragment is exactly `<32-hex-code>.<64-hex-hash>` —
 * both parts are required so the recipient always has a hash to verify
 * against (see `AcceptInviteModal`'s post-redeem verification step).
 */
export function extractInviteData(hash: string): InviteFragmentData | null {
	const raw = hash.startsWith("#") ? hash.slice(1) : hash;
	const dot = raw.indexOf(".");
	if (dot === -1) return null;
	const code = raw.slice(0, dot);
	const keyPackageHash = raw.slice(dot + 1);
	if (!INVITE_CODE_RE.test(code) || !KEY_PACKAGE_HASH_RE.test(keyPackageHash)) return null;
	return { code, keyPackageHash };
}
