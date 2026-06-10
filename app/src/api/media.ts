/**
 * Media presigned-URL API client (prd.md §9.2).
 *
 * Security invariants:
 * - The server NEVER receives plaintext or ciphertext bytes — clients upload/
 *   download directly to/from Cloudflare R2 using short-lived presigned URLs.
 * - Bearer token is always in the Authorization header, never in the URL.
 * - All requests use HTTPS (enforced by the browser for Bearer-auth endpoints).
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

/**
 * POST /v1/media/upload-url — allocate a MediaId and get a presigned R2 PUT URL.
 *
 * @param token        Bearer session token
 * @param contentType  MIME type (e.g. "image/jpeg"). The server stores metadata only.
 * @param sizeBytes    Exact byte count of the encrypted blob (1–100MB).
 * @param groupId      Optional MLS group UUID. When set, all group members may download.
 * @returns            { mediaId, uploadUrl } — PUT ciphertext to uploadUrl directly.
 */
export async function requestMediaUpload(
	token: string,
	contentType: string,
	sizeBytes: number,
	groupId?: string,
): Promise<{ mediaId: string; uploadUrl: string }> {
	const body: Record<string, unknown> = {
		content_type: contentType,
		size_bytes: sizeBytes,
	};
	if (groupId !== undefined) {
		body.group_id = groupId;
	}
	const resp = await fetch(`${API_BASE}/media/upload-url`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify(body),
	});
	await throwOnError(resp);
	return resp.json() as Promise<{ mediaId: string; uploadUrl: string }>;
}

/**
 * POST /v1/media/:id/confirm — mark an upload complete after the R2 PUT succeeds.
 *
 * @param token    Bearer session token
 * @param mediaId  UUID returned by requestMediaUpload
 */
export async function confirmMediaUpload(token: string, mediaId: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/media/${mediaId}/confirm`, {
		method: "POST",
		headers: authHeaders(token),
	});
	await throwOnError(resp);
}

/**
 * GET /v1/media/:id/download-url — get a presigned R2 GET URL.
 *
 * The caller must be either the uploader or a member of the group the blob was
 * shared to. Fetch the blob from downloadUrl directly; the server never sees
 * the ciphertext bytes.
 *
 * @param token    Bearer session token
 * @param mediaId  UUID of the blob
 * @returns        { downloadUrl } — GET ciphertext from this URL, then decrypt.
 */
export async function getMediaDownloadUrl(
	token: string,
	mediaId: string,
): Promise<{ downloadUrl: string }> {
	const resp = await fetch(`${API_BASE}/media/${mediaId}/download-url`, {
		headers: authHeaders(token),
	});
	await throwOnError(resp);
	return resp.json() as Promise<{ downloadUrl: string }>;
}

/**
 * DELETE /v1/media/:id — delete a blob (uploader device only).
 *
 * @param token    Bearer session token
 * @param mediaId  UUID of the blob to delete
 */
export async function deleteMedia(token: string, mediaId: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/media/${mediaId}`, {
		method: "DELETE",
		headers: authHeaders(token),
	});
	await throwOnError(resp);
}
