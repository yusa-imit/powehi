import { useEffect, useRef } from "react";

declare global {
	interface Window {
		// Injected by Tauri's WebView bridge — absent in plain browser contexts.
		__TAURI_INTERNALS__?: unknown;
	}
}

/**
 * Parse a deep-link URL and return the invite code, or null if unrecognised.
 *
 * Accepted formats (code = 32 lowercase hex chars, same as web hash format):
 *   Desktop custom scheme : powehi://invite/<code>
 *   Mobile universal link : https://powehi.app/i/<code>
 *
 * The code pattern is deliberately strict — it must match the server-issued
 * Uuid::new_v4().simple() output so there is no injection surface.
 */
export function parseDeepLink(url: string): string | null {
	// Desktop: powehi://invite/<32-hex>
	const desktop = /^powehi:\/\/invite\/([0-9a-f]{32})(?:[/?#]|$)/.exec(url);
	if (desktop) return desktop[1];
	// Mobile universal link: https://powehi.app/i/<32-hex>
	const mobile = /^https:\/\/powehi\.app\/i\/([0-9a-f]{32})(?:[/?#]|$)/.exec(url);
	if (mobile) return mobile[1];
	return null;
}

/**
 * Listen for Tauri deep-link events and extract invite codes.
 * Also checks `getCurrent()` on mount to handle the launch-via-deep-link case.
 * No-op when running outside of Tauri (plain browser environment).
 *
 * Uses a ref so `onInviteCode` can be updated without re-registering the
 * listener (avoids a gap between unlisten + re-listen).
 */
export function useDeepLink(onInviteCode: (code: string) => void): void {
	const callbackRef = useRef(onInviteCode);
	callbackRef.current = onInviteCode;

	useEffect(() => {
		if (typeof window === "undefined" || !window.__TAURI_INTERNALS__) return;

		let unlisten: (() => void) | undefined;

		import("@tauri-apps/plugin-deep-link")
			.then(async ({ getCurrent, onOpenUrl }) => {
				// Handle the launch-via-deep-link case (app started from a link).
				const initial = await getCurrent();
				if (initial) {
					for (const url of initial) {
						const code = parseDeepLink(url);
						if (code) callbackRef.current(code);
					}
				}
				// Register for subsequent deep-link events while the app is running.
				return onOpenUrl((urls) => {
					for (const url of urls) {
						const code = parseDeepLink(url);
						if (code) callbackRef.current(code);
					}
				});
			})
			.then((fn) => {
				unlisten = fn;
			})
			.catch(() => {
				/* plugin absent outside Tauri — ignore */
			});

		return () => {
			unlisten?.();
		};
	}, []); // mount-once: callbackRef handles callback identity changes
}
