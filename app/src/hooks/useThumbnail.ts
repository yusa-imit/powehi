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
 * - thumbnail.key (raw) is zeroed right after import, before decrypt even starts.
 * - The key handle is dropped in a `finally` regardless of decrypt outcome.
 * - Object URL is revoked on unmount to prevent memory leaks.
 */

import { useEffect, useState } from "react";
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

		(async () => {
			let mediaKeyHandle: string | null = null;
			try {
				const ct = new Uint8Array(thumbnail.ct);
				const key = new Uint8Array(thumbnail.key);
				const iv = new Uint8Array(thumbnail.iv);
				({ mediaKeyHandle } = await cryptoWorker.mediaImportKey(key));
				// Zero the raw key immediately after import (receiver-path hygiene) —
				// before decrypt even starts, mirroring the main media-key flow.
				// Also zero the canonical number[] in the MediaPayload object held in chats state
				// so the raw key bytes don't linger in the React state tree after import.
				key.fill(0);
				thumbnail.key.fill(0);
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
		})();

		return () => {
			cancelled = true;
			if (url) URL.revokeObjectURL(url);
		};
	}, [thumbnail, cryptoWorker]);

	return { objectUrl };
}
