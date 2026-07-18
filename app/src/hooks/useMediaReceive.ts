/**
 * useMediaReceive — download and AES-256-GCM-decrypt an incoming §9.2 media attachment.
 *
 * Security invariants (prd.md §9.2 + no-plaintext-logging.md):
 * - `mediaKey` bytes are imported into WASM and zeroed immediately (cycle 309,
 *   receiver-side opaque-handle pattern — closes the cycle-119 YELLOW); all actual
 *   decryption happens via the resulting opaque handle inside `downloadAndDecryptMedia`.
 * - Object URL is revoked on unmount or when `media` changes to prevent memory leaks.
 * - WASM verifies blobHash before AES-GCM decrypt (R-2 blob-swap detection).
 * - No key bytes, URL paths, or error details are logged.
 * - A fast chat-switch (unmount before this decrypt reached the front of the
 *   shared `mediaHandleLimiter` queue) aborts via `AbortController` so the
 *   queued decrypt is dropped rather than running to completion for a result
 *   that would just be discarded (crypto-reviewer advisory B, cycle 312).
 */

import { useEffect, useRef, useState } from "react";
import { downloadAndDecryptMedia, sniffMimeType } from "../lib/mediaTransfer";
import { useAuthStore } from "../store/auth";
import { useCryptoWorker } from "./useCryptoWorker";
import type { MediaPayload } from "./useMessages";

export interface MediaReceiveState {
	/** Blob object URL for <img src>. Null while loading or on error. */
	objectUrl: string | null;
	loading: boolean;
	/** True when download or decryption failed (opaque — no details). */
	error: boolean;
}

export function useMediaReceive(media: MediaPayload | undefined): MediaReceiveState {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();
	const [state, setState] = useState<MediaReceiveState>({
		objectUrl: null,
		loading: false,
		error: false,
	});
	// Holds the current object URL so cleanup can revoke it.
	const urlRef = useRef<string | null>(null);

	useEffect(() => {
		if (!media || !sessionToken || !cryptoWorker) return;

		let cancelled = false;
		const controller = new AbortController();

		const run = async () => {
			setState({ objectUrl: null, loading: true, error: false });
			try {
				const plaintext = await downloadAndDecryptMedia(
					media,
					sessionToken,
					cryptoWorker,
					controller.signal,
				);
				if (cancelled) return;

				// Real mimeType (cycle-296) is authoritative for the video/image hint when
				// present; otherwise fall back to the legacy chunked-implies-video heuristic.
				const videoHint =
					media.mimeType != null ? media.mimeType.startsWith("video/") : media.chunked === true;
				const url = URL.createObjectURL(
					new Blob([plaintext as Uint8Array<ArrayBuffer>], {
						type: sniffMimeType(plaintext, { videoHint }),
					}),
				);
				urlRef.current = url;
				setState({ objectUrl: url, loading: false, error: false });
			} catch {
				if (!cancelled) {
					setState({ objectUrl: null, loading: false, error: true });
				}
			}
		};

		void run();

		return () => {
			cancelled = true;
			controller.abort();
			if (urlRef.current) {
				URL.revokeObjectURL(urlRef.current);
				urlRef.current = null;
			}
		};
	}, [media, sessionToken, cryptoWorker]);

	return state;
}
