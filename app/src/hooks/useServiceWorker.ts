import { useEffect } from "react";
import { registerPushSubscription } from "../api/push";

export interface PushSubscriptionResult {
	endpoint: string;
	p256dh: string;
	auth: string;
}

// Registers the Service Worker and subscribes to Web Push.
// VAPID public key enables push subscription; session token enables server registration.
// Both must be present for the full push flow. Missing either silently skips that step.
export function useServiceWorker(vapidPublicKey?: string, sessionToken?: string) {
	useEffect(() => {
		if (!("serviceWorker" in navigator)) return;

		navigator.serviceWorker
			.register("/sw.js", { scope: "/" })
			.then((reg) => {
				if (vapidPublicKey && "PushManager" in window) {
					return reg.pushManager
						.getSubscription()
						.then((existing) => {
							if (existing) return existing;
							return reg.pushManager.subscribe({
								userVisibleOnly: true,
								applicationServerKey: urlBase64ToUint8Array(vapidPublicKey),
							});
						})
						.then((sub) => {
							if (!sessionToken) return;
							const json = sub.toJSON();
							const keys = json.keys ?? {};
							const endpoint = sub.endpoint;
							const p256dh = keys.p256dh ?? "";
							const auth = keys.auth ?? "";
							// Endpoint stays in Authorization header only — never in URL path.
							return registerPushSubscription(sessionToken, endpoint, p256dh, auth).catch(() => {
								// Registration failure is non-fatal: app works without push.
							});
						});
				}
			})
			.catch((_err) => {
				// SW registration failure is non-fatal; app still works
			});
	}, [vapidPublicKey, sessionToken]);
}

function urlBase64ToUint8Array(base64String: string): Uint8Array<ArrayBuffer> {
	const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
	const base64 = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
	const raw = atob(base64);
	const result = new Uint8Array(raw.length);
	for (let i = 0; i < raw.length; i++) {
		result[i] = raw.charCodeAt(i);
	}
	return result;
}
