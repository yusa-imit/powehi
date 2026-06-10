/**
 * useMediaReceive — download and AES-256-GCM-decrypt an incoming §9.2 media attachment.
 *
 * Security invariants (prd.md §9.2 + no-plaintext-logging.md):
 * - `mediaKey` bytes are zeroed immediately in the `finally` block regardless of success/failure.
 * - Object URL is revoked on unmount or when `media` changes to prevent memory leaks.
 * - WASM verifies blobHash before AES-GCM decrypt (R-2 blob-swap detection).
 * - No key bytes, URL paths, or error details are logged.
 *
 * Known YELLOW (cycle 119): `media.mediaKey` arrives as a JS number[] from the
 * MLS-decrypted payload. Receiver-side opaque-handle pattern is future work.
 */

import { useEffect, useRef, useState } from "react";
import { getMediaDownloadUrl } from "../api/media";
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

/** Detect image MIME type from leading magic bytes; falls back to image/jpeg. */
function sniffMimeType(bytes: Uint8Array): string {
	if (bytes.length >= 3 && bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff)
		return "image/jpeg";
	if (
		bytes.length >= 4 &&
		bytes[0] === 0x89 &&
		bytes[1] === 0x50 &&
		bytes[2] === 0x4e &&
		bytes[3] === 0x47
	)
		return "image/png";
	if (bytes.length >= 3 && bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46)
		return "image/gif";
	if (
		bytes.length >= 12 &&
		bytes[8] === 0x57 &&
		bytes[9] === 0x45 &&
		bytes[10] === 0x42 &&
		bytes[11] === 0x50
	)
		return "image/webp";
	return "image/jpeg";
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

		const run = async () => {
			setState({ objectUrl: null, loading: true, error: false });
			const mediaKey = new Uint8Array(media.mediaKey);
			try {
				const { downloadUrl } = await getMediaDownloadUrl(sessionToken, media.blobId);
				if (cancelled) return;

				// redirect: "error" prevents silent SSRF via R2 redirect (defense-in-depth).
				const resp = await fetch(downloadUrl, { redirect: "error" });
				if (!resp.ok) throw new Error("download_failed");
				const ciphertextBuf = await resp.arrayBuffer();
				if (cancelled) return;

				const ciphertext = new Uint8Array(ciphertextBuf);
				const iv = new Uint8Array(media.iv);
				const blobHash = new Uint8Array(media.blobHash);

				// WASM verifies blobHash before AES-GCM decrypt (R-2 blob-swap detection).
				const plaintext = await cryptoWorker.mediaDecryptWithRawKey(
					mediaKey,
					iv,
					ciphertext,
					blobHash,
				);
				if (cancelled) return;

				const url = URL.createObjectURL(
					new Blob([plaintext as Uint8Array<ArrayBuffer>], { type: sniffMimeType(plaintext) }),
				);
				urlRef.current = url;
				setState({ objectUrl: url, loading: false, error: false });
			} catch {
				if (!cancelled) {
					setState({ objectUrl: null, loading: false, error: true });
				}
			} finally {
				// Always zero key bytes — invariant from prd.md §9.2.
				mediaKey.fill(0);
			}
		};

		void run();

		return () => {
			cancelled = true;
			if (urlRef.current) {
				URL.revokeObjectURL(urlRef.current);
				urlRef.current = null;
			}
		};
	}, [media, sessionToken, cryptoWorker]);

	return state;
}
