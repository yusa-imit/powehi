/**
 * OPAQUE auth HTTP client.
 *
 * Binary payloads (Vec<u8> on the server) are transmitted as JSON arrays of
 * integers — serde's default encoding for Vec<u8>. No content or passwords
 * ever cross this layer; only OPAQUE protocol blobs and opaque IDs.
 */

const API_BASE = "/v1";

function toJsonArray(bytes: Uint8Array): number[] {
	return Array.from(bytes);
}

function fromJsonArray(arr: number[]): Uint8Array {
	return new Uint8Array(arr);
}

/** SHA-256 of the plaintext handle. Only the hash reaches the server. */
export async function hashHandle(handle: string): Promise<Uint8Array> {
	const bytes = new TextEncoder().encode(handle);
	const buffer = await crypto.subtle.digest("SHA-256", bytes);
	return new Uint8Array(buffer);
}

// ── Registration ─────────────────────────────────────────────────────────────

export interface RegInitResp {
	user_id: string;
	opaque_response: number[];
}

export async function regInit(
	handle_hash: Uint8Array,
	opaque_request: Uint8Array,
): Promise<RegInitResp> {
	const resp = await fetch(`${API_BASE}/auth/register/init`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			handle_hash: toJsonArray(handle_hash),
			opaque_request: toJsonArray(opaque_request),
		}),
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? "register_init_failed");
	}
	return resp.json() as Promise<RegInitResp>;
}

export interface RegFinishResp {
	user_id: string;
	device_id: string;
}

export async function regFinish(
	user_id: string,
	opaque_record: Uint8Array,
	mls_credential: Uint8Array,
	// §8.5 account restore: the Ed25519 verifying key derived from the user's
	// BIP-39 recovery phrase, submitted ONCE at registration time so a future
	// restore-account login can prove phrase possession against it server-side.
	// Optional/omitted (never sent as an explicit `undefined` key — JSON.stringify
	// drops it) for any caller that hasn't adopted recovery-phrase registration yet.
	recovery_pubkey?: Uint8Array,
): Promise<RegFinishResp> {
	const resp = await fetch(`${API_BASE}/auth/register/finish`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			user_id,
			opaque_record: toJsonArray(opaque_record),
			mls_credential: toJsonArray(mls_credential),
			recovery_pubkey: recovery_pubkey ? toJsonArray(recovery_pubkey) : undefined,
		}),
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? "register_finish_failed");
	}
	return resp.json() as Promise<RegFinishResp>;
}

// ── Login ────────────────────────────────────────────────────────────────────

export interface LoginInitResp {
	user_id: string;
	opaque_ke2: number[];
	login_nonce: string;
}

export async function loginInit(
	handle_hash: Uint8Array,
	opaque_ke1: Uint8Array,
): Promise<LoginInitResp> {
	const resp = await fetch(`${API_BASE}/auth/login/init`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			handle_hash: toJsonArray(handle_hash),
			opaque_ke1: toJsonArray(opaque_ke1),
		}),
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? "login_init_failed");
	}
	return resp.json() as Promise<LoginInitResp>;
}

export interface RecoveryProof {
	mls_credential: Uint8Array;
	signature: Uint8Array;
}

export async function loginFinish(
	opaque_ke3: Uint8Array,
	login_nonce: string,
	device_id: string,
	// §8.5 account restore: present only for a restore-account login from a
	// brand-new device with no local OPAQUE-linked device row yet. Proves
	// possession of the BIP-39 recovery phrase by signing login_nonce with the
	// phrase-derived Ed25519 key whose public half was registered once via
	// regFinish's recovery_pubkey. Optional/omitted for ordinary logins.
	recovery_proof?: RecoveryProof,
): Promise<string> {
	const resp = await fetch(`${API_BASE}/auth/login/finish`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({
			opaque_ke3: toJsonArray(opaque_ke3),
			login_nonce,
			device_id,
			recovery_proof: recovery_proof
				? {
						mls_credential: toJsonArray(recovery_proof.mls_credential),
						signature: toJsonArray(recovery_proof.signature),
					}
				: undefined,
		}),
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		const code = body.code ?? "login_finish_failed";
		throw new Error(code === "unauthorized" ? "invalid_credentials" : code);
	}
	// Server returns SessionToken(String) which serde serializes as a plain JSON string.
	return resp.json() as Promise<string>;
}

// ── Device management ─────────────────────────────────────────────────────────

export interface DeviceInfo {
	device_id: string;
	created_at: string;
	last_seen_at: string | null;
}

/** GET /v1/auth/devices — list all devices linked to the authenticated account. */
export async function listDevices(sessionToken: string): Promise<DeviceInfo[]> {
	const resp = await fetch(`${API_BASE}/auth/devices`, {
		headers: { Authorization: `Bearer ${sessionToken}` },
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `list_devices_failed:${resp.status}`);
	}
	return resp.json() as Promise<DeviceInfo[]>;
}

/** DELETE /v1/auth/devices/:id — revoke (delink) a device. Invalidates all its sessions. */
export async function revokeDevice(sessionToken: string, deviceId: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/auth/devices/${encodeURIComponent(deviceId)}`, {
		method: "DELETE",
		headers: { Authorization: `Bearer ${sessionToken}` },
	});
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `revoke_device_failed:${resp.status}`);
	}
}

// ── Key packages ──────────────────────────────────────────────────────────────

export async function uploadKeyPackage(
	token: string,
	device_id: string,
	key_package: Uint8Array,
): Promise<void> {
	const resp = await fetch(`${API_BASE}/key-packages/${device_id}`, {
		method: "POST",
		headers: {
			"Content-Type": "application/json",
			Authorization: `Bearer ${token}`,
		},
		body: JSON.stringify({
			packages: [toJsonArray(key_package)],
		}),
	});
	if (!resp.ok) {
		// Non-fatal: log upload failure without leaking error details (no-plaintext-logging rule).
		console.warn("[auth] key_package upload status:", resp.status);
	}
}

export { fromJsonArray };
