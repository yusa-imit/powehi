import { useCallback, useEffect, useRef } from "react";

declare global {
	interface Window {
		// Injected by Tauri's WebView bridge — absent in plain browser contexts.
		__TAURI_INTERNALS__?: unknown;
	}
}

type NotifyFn = (opts: { title: string; body: string }) => void;

/**
 * Request native OS notification permission and return a stable callback that
 * fires a "New message" notification when the app window is not focused.
 *
 * Security invariants:
 *  - Title is always the app name; body is always "New message".
 *    No sender identity, no plaintext content, no message metadata ever appears
 *    in the notification (prd.md §3 threat model, §5 privacy).
 *  - `document.hasFocus()` guard suppresses the notification when the user is
 *    actively reading the conversation — no duplicate signal.
 *  - No-op outside Tauri (plain browser and test environments are unaffected).
 */
export function useTauriNotification(): () => void {
	// Holds sendNotification once the plugin is loaded and permission is granted.
	// Null until then, so the returned callback is safely a no-op.
	const senderRef = useRef<NotifyFn | null>(null);

	useEffect(() => {
		if (typeof window === "undefined" || !window.__TAURI_INTERNALS__) return;

		let active = true;

		import("@tauri-apps/plugin-notification")
			.then(async ({ isPermissionGranted, requestPermission, sendNotification }) => {
				if (!active) return;
				const already = await isPermissionGranted();
				const state = already ? "granted" : await requestPermission();
				if (active && state === "granted") {
					senderRef.current = sendNotification as NotifyFn;
				}
			})
			.catch(() => {
				/* plugin absent or permission API unavailable — safe to ignore */
			});

		return () => {
			active = false;
			senderRef.current = null;
		};
	}, []);

	return useCallback(() => {
		if (!senderRef.current) return;
		// Do not notify when the user is actively looking at the app.
		if (typeof document !== "undefined" && document.hasFocus()) return;
		senderRef.current({ title: "Powehi", body: "New message" });
	}, []);
}
