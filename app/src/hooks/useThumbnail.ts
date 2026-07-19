/**
 * useThumbnail — decrypt and display an inline §9.4.1 thumbnail.
 *
 * The thumbnail ciphertext + key + iv arrive inside the MLS-decrypted payload.
 * The raw key is imported into the WASM opaque-handle map (`mediaImportKey`) and
 * zeroed immediately; decryption then runs entirely inside the WASM worker via the
 * handle (mirrors the main media-key receiver path, cycle 309/311). The raw pixels
 * are only in JS memory transiently while creating the object URL.
 *
 * Security:
 * - Only the LOCAL key copy is zeroed, in a `finally` covering the whole
 *   import+decrypt sequence (so an import failure still zeroes it, cycle 316
 *   YELLOW follow-up) — the canonical `thumbnail.key` in React `chats` state
 *   is left intact. Cycle 312 briefly zeroed the canonical array too (to close a
 *   narrow raw-key-lingers-during-queue-wait window), but that broke a much
 *   more common path: `chats` state is long-lived and the message list is
 *   unvirtualized with content-derived React keys, so switching away from a
 *   chat and back fully unmounts and remounts every message's `MediaImage`/
 *   `useThumbnail` — reusing the SAME `thumbnail` object reference. Zeroing
 *   the canonical key on first mount left every revisit decrypting an
 *   all-zero key, permanently and silently breaking the thumbnail (caught by
 *   the non-fatal catch below) after its first display. Reverted in cycle
 *   316 — same accepted tradeoff as the main media-key path (see
 *   `downloadAndDecryptMedia`'s doc comment), which never zeroed its
 *   canonical key for the same reason (it's also reused, by the forward-
 *   message flow).
 * - The key handle is dropped in a `finally` regardless of decrypt outcome.
 * - Object URL is revoked on unmount to prevent memory leaks.
 * - The handle-holding window runs through `mediaHandleLimiter` (shared with
 *   `useMediaReceive`'s `downloadAndDecryptMedia`) so an unvirtualized,
 *   media-heavy message list can't burst past the shared WASM handle cap
 *   (crypto-reviewer advisory, cycle 311).
 * - A fast chat-switch (unmount before this decrypt reached the front of the
 *   limiter's queue) aborts via `AbortController` so the queued decrypt is
 *   dropped instead of burning a slot + WASM handle on a discarded result
 *   (crypto-reviewer advisory B, cycle 312).
 */

import { useEffect, useState } from "react";
import { mediaHandleLimiter } from "../lib/mediaTransfer";
import { useCryptoWorker } from "./useCryptoWorker";
import type { ThumbnailPayload } from "./useMessages";

export interface ThumbnailState {
	objectUrl: string | null;
}

export function useThumbnail(thumbnail: ThumbnailPayload | undefined): ThumbnailState {
	const cryptoWorker = useCryptoWorker();
	const [objectUrl, setObjectUrl] = useState<string | null>(null);

	useEffect(() => {
		if (!thumbnail || !cryptoWorker) return;
		if (
			thumbnail.key.length !== 32 ||
			thumbnail.iv.length !== 12 ||
			thumbnail.ct.length === 0 ||
			thumbnail.ct.length > 16_384
		)
			return;
		let cancelled = false;
		let url: string | null = null;
		const controller = new AbortController();

		// Copy the raw key before queueing on the limiter. The canonical
		// `thumbnail.key` in `chats` state is intentionally left untouched — see
		// the hook-level doc comment above (cycle 316: zeroing it here broke
		// thumbnail redisplay on chat revisit).
		const key = new Uint8Array(thumbnail.key);

		mediaHandleLimiter(async () => {
			let mediaKeyHandle: string | null = null;
			try {
				const ct = new Uint8Array(thumbnail.ct);
				const iv = new Uint8Array(thumbnail.iv);
				({ mediaKeyHandle } = await cryptoWorker.mediaImportKey(key));
				// Zero the local copy immediately on the success path too (the
				// `finally` below also zeroes it, idempotently, so an import failure
				// is still covered) — keeps the raw-key-in-JS-memory window as tight
				// as before the cycle-316 finally-block fix (crypto-reviewer
				// defense-in-depth note, cycle 317).
				key.fill(0);
				const { pixels } = await cryptoWorker.mediaThumbnailDecryptWithHandle(
					mediaKeyHandle,
					ct,
					iv,
				);
				if (cancelled) return;
				const blob = new Blob([pixels], { type: "image/jpeg" });
				url = URL.createObjectURL(blob);
				setObjectUrl(url);
			} catch {
				// Thumbnail decryption failure is non-fatal; full image will still load.
			} finally {
				// Zero the local key copy on every path, including a throw from
				// `mediaImportKey` itself (crypto-reviewer YELLOW, cycle 316: the old
				// code zeroed only after a successful import, inside the `try`, so an
				// import failure left the local copy un-zeroed).
				key.fill(0);
				if (mediaKeyHandle) await cryptoWorker.mediaDropKey(mediaKeyHandle);
			}
		}, controller.signal).catch(() => {
			// Queued-but-aborted (fast unmount, crypto-reviewer advisory B, cycle 312):
			// the task body above never ran, so its local raw-key copy never reached
			// its own zero-after-import step — zero it here for the same hygiene.
			key.fill(0);
		});

		return () => {
			cancelled = true;
			controller.abort();
			if (url) URL.revokeObjectURL(url);
		};
	}, [thumbnail, cryptoWorker]);

	return { objectUrl };
}
