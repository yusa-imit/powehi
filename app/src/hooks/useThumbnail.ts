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
 * - The canonical thumbnail.key (raw, in React chats state) is copied and zeroed
 *   synchronously, BEFORE queueing on `mediaHandleLimiter` — not after import — so
 *   a burst that queues past the concurrency cap never leaves raw key bytes live
 *   in state for the queue-wait duration (crypto-reviewer advisory A, cycle 312).
 * - The local key copy is zeroed right after import, before decrypt even starts.
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

		// Copy + zero the canonical raw key synchronously, before queueing on the
		// limiter — a queued task must never keep raw key bytes live in the chats
		// state tree for the duration of the queue wait (crypto-reviewer advisory
		// A, cycle 312).
		const key = new Uint8Array(thumbnail.key);
		thumbnail.key.fill(0);

		mediaHandleLimiter(async () => {
			let mediaKeyHandle: string | null = null;
			try {
				const ct = new Uint8Array(thumbnail.ct);
				const iv = new Uint8Array(thumbnail.iv);
				({ mediaKeyHandle } = await cryptoWorker.mediaImportKey(key));
				// Zero the local key copy immediately after import (receiver-path
				// hygiene) — before decrypt even starts, mirroring the main media-key
				// flow.
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
