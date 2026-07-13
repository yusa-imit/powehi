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
 * - On receive, the raw key arrives inline in the MLS-decrypted payload (an
 *   accepted existing exposure, prd.md §9.2) and is always zeroed in `finally`.
 * - WASM verifies blobHash before AES-GCM decrypt (R-2, blob-swap detection).
 * - The R2 PUT/GET carries only ciphertext — the server never sees plaintext.
 * - No file content, key bytes, or error details are logged.
 */

import type * as Comlink from "comlink";
import { confirmMediaUpload, getMediaDownloadUrl, requestMediaUpload } from "../api/media";
import { sendMessage as sendMessageApi } from "../api/messages";
import type { MediaPayload } from "../hooks/useMessages";
import type { CryptoWorkerApi } from "../workers/crypto.worker";

type CryptoWorker = Comlink.Remote<CryptoWorkerApi>;

/** Detect image MIME type from leading magic bytes; falls back to image/jpeg. */
export function sniffMimeType(bytes: Uint8Array): string {
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

/**
 * Download an R2 blob and AES-256-GCM-decrypt it using the raw key embedded
 * in an MLS-decrypted media message payload (receiver path).
 * Always zeroes the key bytes, even on failure.
 */
export async function downloadAndDecryptMedia(
	media: MediaPayload,
	sessionToken: string,
	cryptoWorker: CryptoWorker,
): Promise<Uint8Array> {
	const mediaKey = new Uint8Array(media.mediaKey);
	try {
		const { downloadUrl } = await getMediaDownloadUrl(sessionToken, media.blobId);
		// redirect: "error" prevents silent SSRF via R2 redirect (defense-in-depth).
		const resp = await fetch(downloadUrl, { redirect: "error" });
		if (!resp.ok) throw new Error("download_failed");
		const ciphertext = new Uint8Array(await resp.arrayBuffer());
		const iv = new Uint8Array(media.iv);
		const blobHash = new Uint8Array(media.blobHash);
		return (await cryptoWorker.mediaDecryptWithRawKey(
			mediaKey,
			iv,
			ciphertext,
			blobHash,
		)) as Uint8Array;
	} finally {
		mediaKey.fill(0);
	}
}

/**
 * Encrypt `bytes` with a fresh AES-256-GCM key, upload the ciphertext to R2,
 * and build+MLS-encrypt+deliver the §9.2 media message envelope to `groupId`.
 * The raw key never leaves WASM — `mediaDropKey` always runs in `finally`.
 * Pass `thumbHandle` (from `mediaThumbnailEncrypt`) to bundle an inline
 * encrypted thumbnail; omit it to send without one.
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
				)
			: await cryptoWorker.mediaMessageCreate(
					identityId,
					groupId,
					mediaKeyHandle,
					mediaId,
					blobHash,
					iv,
				);

		await sendMessageApi(sessionToken, groupId, mlsCiphertext);
	} finally {
		await cryptoWorker.mediaDropKey(mediaKeyHandle);
	}
}
