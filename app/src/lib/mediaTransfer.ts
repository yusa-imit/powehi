/**
 * Shared §9.2 media crypto pipeline — download+decrypt (receiver path) and
 * encrypt+upload+send (sender path) live here so the security-critical steps
 * (blobHash verification, key zeroing, opaque handle cleanup) have exactly one
 * implementation, reused by useMediaReceive, useMediaSend, and message
 * forwarding (ChatLayout's sendForwardToSelected) instead of being duplicated
 * per call site.
 *
 * Security invariants (prd.md §9.2 + no-plaintext-logging.md):
 * - The raw AES-256-GCM media key never crosses the WASM-JS boundary on send —
 *   `mediaEncrypt` returns an opaque handle, dropped in `finally` regardless of
 *   outcome.
 * - On receive, the raw key necessarily arrives inline in the MLS-decrypted payload
 *   once, but is imported into WASM (`mediaImportKey`) and zeroed immediately —
 *   from then on only the opaque handle is used (cycle 309, receiver-side
 *   opaque-handle pattern, mirroring the sender path).
 * - WASM verifies blobHash before AES-GCM decrypt (R-2, blob-swap detection).
 * - The R2 PUT/GET carries only ciphertext — the server never sees plaintext.
 * - No file content, key bytes, or error details are logged.
 *
 * §9.4.2: files larger than MEDIA_CHUNK_THRESHOLD use the chunked AES-256-GCM
 * path (mediaEncryptChunked / mediaDecryptChunkedWithHandle / mediaMessageCreateChunked)
 * instead of the single-shot media* calls; same key-hygiene invariants apply.
 */

import type * as Comlink from "comlink";
import {
	confirmMediaDownload,
	confirmMediaUpload,
	getMediaDownloadUrl,
	requestMediaUpload,
} from "../api/media";
import { sendMessage as sendMessageApi } from "../api/messages";
import type { MediaPayload } from "../hooks/useMessages";
import type { CryptoWorkerApi } from "../workers/crypto.worker";
import { createLimiter } from "./concurrencyLimiter";

type CryptoWorker = Comlink.Remote<CryptoWorkerApi>;

/**
 * §9.4.2 chunk-routing threshold. Files strictly larger than this use the
 * chunked AES-256-GCM path; files at or below it stay on the cheaper
 * single-shot path (a file of exactly one full chunk gains nothing from
 * chunking). 16 MiB, matching the WASM core's fixed chunk size.
 */
export const MEDIA_CHUNK_THRESHOLD = 16 * 1024 * 1024;

/**
 * Bounds how many receiver-path decrypts (`downloadAndDecryptMedia` here +
 * `useThumbnail`) hold a `MEDIA_KEYS` WASM handle at once. The message list
 * is unvirtualized (`ChatLayout.tsx`), so opening a media-heavy chat mounts
 * every attachment's decrypt in the same tick; without a cap that burst can
 * pressure the shared 256-slot `MAX_MEDIA_HANDLES` cap in
 * `powehi-crypto-wasm` (crypto-reviewer advisory, cycle 311). 32 is well
 * under 256, leaving headroom for concurrent sender-side handles, while
 * still decrypting well ahead of scroll speed.
 */
export const MEDIA_HANDLE_CONCURRENCY = 32;

/** Shared between `downloadAndDecryptMedia` and `useThumbnail` — see above. */
export const mediaHandleLimiter = createLimiter(MEDIA_HANDLE_CONCURRENCY);

/**
 * Detect image/video MIME type from leading magic bytes.
 * Falls back to `video/mp4` when `videoHint` is set (caller already knows this is a
 * §9.4.2 chunked/video attachment) and to `image/jpeg` otherwise, matching prior
 * behavior for callers that never pass the hint.
 */
export function sniffMimeType(bytes: Uint8Array, options?: { videoHint?: boolean }): string {
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
	// MP4/QuickTime family: ISO base media file format `ftyp` box at byte offset 4.
	if (
		bytes.length >= 8 &&
		bytes[4] === 0x66 &&
		bytes[5] === 0x74 &&
		bytes[6] === 0x79 &&
		bytes[7] === 0x70
	)
		return "video/mp4";
	// WebM/Matroska: EBML magic number.
	if (
		bytes.length >= 4 &&
		bytes[0] === 0x1a &&
		bytes[1] === 0x45 &&
		bytes[2] === 0xdf &&
		bytes[3] === 0xa3
	)
		return "video/webm";
	return options?.videoHint ? "video/mp4" : "image/jpeg";
}

/**
 * Download an R2 blob and AES-256-GCM-decrypt it using the key embedded in an
 * MLS-decrypted media message payload (receiver path).
 * Routes to the chunked reassembly decrypt (§9.4.2) when `media.chunked === true`.
 *
 * Cycle 309 (receiver-side opaque-handle pattern): the raw key bytes are imported
 * into WASM and zeroed IMMEDIATELY — before the download even starts — so they
 * never linger in JS memory for the lifetime of the network fetch. All decryption
 * from that point on goes through the opaque handle, dropped in `finally`.
 *
 * Pass `signal` so an unmount (chat switch away before this decrypt reached the
 * front of `mediaHandleLimiter`'s queue) dequeues it instead of letting it run
 * to completion for a discarded result (crypto-reviewer advisory B, cycle 312).
 */
export async function downloadAndDecryptMedia(
	media: MediaPayload,
	sessionToken: string,
	cryptoWorker: CryptoWorker,
	signal?: AbortSignal,
): Promise<Uint8Array> {
	return mediaHandleLimiter(async () => {
		const mediaKey = new Uint8Array(media.mediaKey);
		let handle: string;
		try {
			({ mediaKeyHandle: handle } = await cryptoWorker.mediaImportKey(mediaKey));
		} finally {
			mediaKey.fill(0);
		}
		try {
			const { downloadUrl } = await getMediaDownloadUrl(sessionToken, media.blobId);
			// redirect: "error" prevents silent SSRF via R2 redirect (defense-in-depth).
			const resp = await fetch(downloadUrl, { redirect: "error" });
			if (!resp.ok) throw new Error("download_failed");
			const ciphertext = new Uint8Array(await resp.arrayBuffer());
			const iv = new Uint8Array(media.iv);
			const blobHash = new Uint8Array(media.blobHash);
			const plaintext =
				media.chunked === true
					? ((await cryptoWorker.mediaDecryptChunkedWithHandle(
							handle,
							iv,
							ciphertext,
							blobHash,
							media.totalSize as number,
						)) as Uint8Array)
					: ((await cryptoWorker.mediaDecryptWithHandle(
							handle,
							iv,
							ciphertext,
							blobHash,
						)) as Uint8Array);
			// Fire-and-forget: only reached once blobHash verification + AES-GCM
			// decrypt both succeeded, i.e. the transfer is actually confirmed
			// complete (not merely granted a URL for — closes the cycle-289
			// ack-on-grant gap). Best-effort: must not block returning plaintext
			// to the caller or fail the receive on a transient network error.
			void confirmMediaDownload(sessionToken, media.blobId).catch(() => {});
			return plaintext;
		} finally {
			await cryptoWorker.mediaDropKey(handle).catch(() => {});
		}
	}, signal);
}

/**
 * Encrypt `bytes` with a fresh AES-256-GCM key, upload the ciphertext to R2,
 * and build+MLS-encrypt+deliver the §9.2 media message envelope to `groupId`.
 * The raw key never leaves WASM — `mediaDropKey` always runs in `finally`.
 * Pass `thumbHandle` (from `mediaThumbnailEncrypt`) to bundle an inline
 * encrypted thumbnail; omit it to send without one.
 *
 * Files strictly larger than `MEDIA_CHUNK_THRESHOLD` (16 MiB) route through the
 * §9.4.2 chunked path (`mediaEncryptChunked` + `mediaMessageCreateChunked`)
 * instead. Chunked video does NOT support thumbnails this cycle — if
 * `thumbHandle` is passed on the chunked path it is dropped (never silently
 * leaked) rather than used.
 */
export async function encryptAndSendMedia(
	bytes: Uint8Array,
	mimeType: string,
	identityId: string,
	groupId: string,
	sessionToken: string,
	cryptoWorker: CryptoWorker,
	thumbHandle?: string | null,
): Promise<void> {
	if (bytes.length > MEDIA_CHUNK_THRESHOLD) {
		// §9.4.2 thumbnails are out of scope — drop any handle rather than leak it.
		if (thumbHandle) {
			await cryptoWorker.mediaThumbnailDrop(thumbHandle).catch(() => {});
		}

		const { ciphertext, mediaKeyHandle, iv, blobHash, totalSize } =
			await cryptoWorker.mediaEncryptChunked(bytes);
		try {
			const { mediaId, uploadUrl } = await requestMediaUpload(
				sessionToken,
				mimeType,
				ciphertext.length,
				groupId,
			);

			// .slice(0) copies into a fresh ArrayBuffer so the BodyInit type is
			// unambiguous across DOM and Bun TypeScript environments.
			await fetch(uploadUrl, {
				method: "PUT",
				body: ciphertext.slice(0),
				headers: { "Content-Type": "application/octet-stream" },
			});

			await confirmMediaUpload(sessionToken, mediaId);

			const { ciphertext: mlsCiphertext } = await cryptoWorker.mediaMessageCreateChunked(
				identityId,
				groupId,
				mediaKeyHandle,
				mediaId,
				blobHash,
				iv,
				totalSize,
				mimeType,
			);

			await sendMessageApi(sessionToken, groupId, mlsCiphertext);
		} finally {
			await cryptoWorker.mediaDropKey(mediaKeyHandle);
		}
		return;
	}

	const { ciphertext, mediaKeyHandle, iv, blobHash } = await cryptoWorker.mediaEncrypt(bytes);
	try {
		const { mediaId, uploadUrl } = await requestMediaUpload(
			sessionToken,
			mimeType,
			ciphertext.length,
			groupId,
		);

		// .slice(0) copies into a fresh ArrayBuffer so the BodyInit type is
		// unambiguous across DOM and Bun TypeScript environments.
		await fetch(uploadUrl, {
			method: "PUT",
			body: ciphertext.slice(0),
			headers: { "Content-Type": "application/octet-stream" },
		});

		await confirmMediaUpload(sessionToken, mediaId);

		const { ciphertext: mlsCiphertext } = thumbHandle
			? await cryptoWorker.mediaMessageCreateWithThumbnail(
					identityId,
					groupId,
					mediaKeyHandle,
					mediaId,
					blobHash,
					iv,
					thumbHandle,
					mimeType,
				)
			: await cryptoWorker.mediaMessageCreate(
					identityId,
					groupId,
					mediaKeyHandle,
					mediaId,
					blobHash,
					iv,
					mimeType,
				);

		await sendMessageApi(sessionToken, groupId, mlsCiphertext);
	} finally {
		await cryptoWorker.mediaDropKey(mediaKeyHandle);
	}
}
