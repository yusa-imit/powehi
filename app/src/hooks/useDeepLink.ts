import { useEffect, useRef } from "react";

declare global {
	interface Window {
		// Injected by Tauri's WebView bridge — absent in plain browser contexts.
		__TAURI_INTERNALS__?: unknown;
	}
}

/** Invite data extracted from a deep-link URL. */
export interface DeepLinkInvite {
	code: string;
	/** SHA-256 hex digest of the inviter's KeyPackage (prd.md §8.3) — see `AcceptInviteModal`. */
	keyPackageHash: string;
}

/**
 * Parse a deep-link URL and return the invite code + KeyPackage hash, or null
 * if unrecognised.
 *
 * Accepted formats (code = 32 lowercase hex chars, hash = 64 lowercase hex
 * chars, same `<code>.<hash>` shape as the web hash format):
 *   Desktop custom scheme : powehi://invite/<code>.<hash>
 *   Mobile universal link : https://powehi.app/i/<code>.<hash>
 *
 * The patterns are deliberately strict — code must match the server-issued
 * Uuid::new_v4().simple() output and hash a SHA-256 hex digest, so there is
 * no injection surface. Both parts are required: without a hash there is
 * nothing to verify the delivered KeyPackage against.
 */
export function parseDeepLink(url: string): DeepLinkInvite | null {
	// Desktop: powehi://invite/<32-hex>.<64-hex>
	const desktop = /^powehi:\/\/invite\/([0-9a-f]{32})\.([0-9a-f]{64})(?:[/?#]|$)/.exec(url);
	if (desktop) return { code: desktop[1], keyPackageHash: desktop[2] };
	// Mobile universal link: https://powehi.app/i/<32-hex>.<64-hex>
	const mobile = /^https:\/\/powehi\.app\/i\/([0-9a-f]{32})\.([0-9a-f]{64})(?:[/?#]|$)/.exec(url);
	if (mobile) return { code: mobile[1], keyPackageHash: mobile[2] };
	return null;
}

/**
 * Listen for Tauri deep-link events and extract invite codes.
 * Also checks `getCurrent()` on mount to handle the launch-via-deep-link case.
 * No-op when running outside of Tauri (plain browser environment).
 *
 * Uses a ref so `onInvite` can be updated without re-registering the
 * listener (avoids a gap between unlisten + re-listen).
 */
export function useDeepLink(onInvite: (invite: DeepLinkInvite) => void): void {
	const callbackRef = useRef(onInvite);
	callbackRef.current = onInvite;

	useEffect(() => {
		if (typeof window === "undefined" || !window.__TAURI_INTERNALS__) return;

		let unlisten: (() => void) | undefined;

		import("@tauri-apps/plugin-deep-link")
			.then(async ({ getCurrent, onOpenUrl }) => {
				// Handle the launch-via-deep-link case (app started from a link).
				const initial = await getCurrent();
				if (initial) {
					for (const url of initial) {
						const invite = parseDeepLink(url);
						if (invite) callbackRef.current(invite);
					}
				}
				// Register for subsequent deep-link events while the app is running.
				return onOpenUrl((urls) => {
					for (const url of urls) {
						const invite = parseDeepLink(url);
						if (invite) callbackRef.current(invite);
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
