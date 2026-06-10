/**
 * Web Push subscription API client.
 *
 * Registers / removes device push subscriptions with the server.
 * The server stores endpoint + keys to send opaque wake-up signals (RFC 8291).
 * SECURITY: endpoint and keys are sent over HTTPS with Bearer auth — never logged.
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
 * POST /v1/push-subscriptions — upsert this device's push subscription.
 *
 * @param token    Bearer session token
 * @param endpoint HTTPS push service endpoint from the browser PushSubscription
 * @param p256dh   Base64url-unpadded browser P-256 ECDH public key (65 bytes)
 * @param auth     Base64url-unpadded 16-byte auth secret
 */
export async function registerPushSubscription(
	token: string,
	endpoint: string,
	p256dh: string,
	auth: string,
): Promise<void> {
	const resp = await fetch(`${API_BASE}/push-subscriptions`, {
		method: "POST",
		headers: authHeaders(token),
		body: JSON.stringify({ endpoint, p256dh, auth }),
	});
	await throwOnError(resp);
}

/**
 * DELETE /v1/push-subscriptions — remove this device's push subscription.
 *
 * @param token Bearer session token
 */
export async function unregisterPushSubscription(token: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/push-subscriptions`, {
		method: "DELETE",
		headers: authHeaders(token),
	});
	await throwOnError(resp);
}
