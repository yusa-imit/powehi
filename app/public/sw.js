// Powehi Service Worker — Web Push RFC 8291
// SECURITY: push payloads are opaque wake-up signals.
// Message content is NEVER transmitted via push — it stays encrypted in IndexedDB.

const CACHE_NAME = "powehi-v1";
// UUID v4 canonical form — used to validate groupId from push payloads.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

self.addEventListener("install", (event) => {
	event.waitUntil(self.skipWaiting());
});

self.addEventListener("activate", (event) => {
	event.waitUntil(self.clients.claim());
});

// Push wake-up: payload is { groupId: UUID, epoch: number } — no content.
self.addEventListener("push", (event) => {
	let tag = "powehi-message";
	let safeGroupId = null;

	if (event.data) {
		try {
			const payload = event.data.json();
			const rawId = payload.groupId;
			// Validate shape before use — defense-in-depth against malformed/relay-injected payloads.
			if (typeof rawId === "string" && UUID_RE.test(rawId)) {
				safeGroupId = rawId;
				tag = `powehi-group-${safeGroupId}`;
			}
		} catch {
			// malformed payload — show generic notification anyway
		}
	}

	event.waitUntil(
		self.registration.showNotification("Powehi", {
			body: "New encrypted message",
			icon: "/icon.png",
			badge: "/badge.png",
			tag,
			data: safeGroupId ? { groupId: safeGroupId } : null,
			// NO message content ever in notification body
		}),
	);
});

self.addEventListener("notificationclick", (event) => {
	event.notification.close();
	event.waitUntil(
		self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((clients) => {
			const existingClient = clients.find((c) => c.url.startsWith(self.location.origin));
			if (existingClient) {
				return existingClient.focus();
			}
			return self.clients.openWindow("/");
		}),
	);
});
