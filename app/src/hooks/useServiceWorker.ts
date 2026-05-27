import { useEffect } from "react";

export interface PushSubscriptionResult {
	endpoint: string;
	p256dh: string;
	auth: string;
}

// Registers the Service Worker and optionally subscribes to Web Push.
// The VAPID public key must be injected at runtime (env or server-config endpoint).
export function useServiceWorker(vapidPublicKey?: string) {
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
						.then((_sub) => {
							// TODO Phase 5: POST subscription to /v1/push/subscribe
						});
				}
			})
			.catch((_err) => {
				// SW registration failure is non-fatal; app still works
			});
	}, [vapidPublicKey]);
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
