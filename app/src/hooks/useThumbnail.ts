/**
 * useThumbnail — decrypt and display an inline §9.4.1 thumbnail.
 *
 * The thumbnail ciphertext + key + iv arrive inside the MLS-decrypted payload.
 * `mediaThumbnailDecrypt` runs inside the WASM worker; the raw pixels are only
 * in JS memory transiently while creating the object URL.
 *
 * Security:
 * - thumbnail.key is zeroed after decryption via `.fill(0)` (same as mediaKey).
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
			try {
				const ct = new Uint8Array(thumbnail.ct);
				const key = new Uint8Array(thumbnail.key);
				const iv = new Uint8Array(thumbnail.iv);
				const { pixels } = await cryptoWorker.mediaThumbnailDecrypt(ct, key, iv);
				// Zero the key immediately after use (receiver-path hygiene).
				// Also zero the canonical number[] in the MediaPayload object held in chats state
				// so the raw key bytes don't linger in the React state tree after decryption.
				key.fill(0);
				thumbnail.key.fill(0);
				if (cancelled) return;
				const blob = new Blob([pixels], { type: "image/jpeg" });
				url = URL.createObjectURL(blob);
				setObjectUrl(url);
			} catch {
				// Thumbnail decryption failure is non-fatal; full image will still load.
			}
		})();

		return () => {
			cancelled = true;
			if (url) URL.revokeObjectURL(url);
		};
	}, [thumbnail, cryptoWorker]);

	return { objectUrl };
}
