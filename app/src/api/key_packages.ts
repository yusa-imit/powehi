/**
 * KeyPackage HTTP client.
 *
 * KeyPackages are single-use MLS pre-keys. The server atomically marks one
 * consumed per fetch (SELECT FOR UPDATE SKIP LOCKED). Binary payloads
 * are JSON arrays of integers (serde Vec<u8> default).
 */

const API_BASE = "/v1";

async function throwOnError(resp: Response): Promise<void> {
	if (!resp.ok) {
		const body = (await resp.json().catch(() => ({}))) as { code?: string };
		throw new Error(body.code ?? `http_${resp.status}`);
	}
}

/**
 * GET /v1/key-packages/:deviceId — fetch and consume one KeyPackage.
 * Single-use: the server marks the package consumed before returning.
 * Used by the group creator to add a peer to an MLS group.
 */
export async function fetchKeyPackage(token: string, deviceId: string): Promise<Uint8Array> {
	const resp = await fetch(`${API_BASE}/key-packages/${deviceId}`, {
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	const data = (await resp.json()) as { data: number[] };
	return new Uint8Array(data.data);
}

/**
 * GET /v1/key-packages/:deviceId/count — number of unconsumed packages on file.
 * Use this to decide when to upload fresh packages (replenishment threshold).
 */
export async function getKeyPackageCount(token: string, deviceId: string): Promise<number> {
	const resp = await fetch(`${API_BASE}/key-packages/${deviceId}/count`, {
		headers: { Authorization: `Bearer ${token}` },
	});
	await throwOnError(resp);
	const data = (await resp.json()) as { count: number };
	return data.count;
}
