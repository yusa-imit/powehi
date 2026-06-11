/**
 * useMediaSend — encrypt a local file and send it as an §9.2 MLS media message.
 *
 * Security invariants (prd.md §9.2 + §9.4.1 + no-plaintext-logging.md):
 * - The raw AES-256-GCM media key NEVER crosses the WASM-JS boundary.
 *   `mediaEncrypt` returns an opaque handle; `mediaMessageCreate[WithThumbnail]` reads the key
 *   inside WASM, builds the JSON payload, and MLS-encrypts it atomically.
 * - The thumbnail key also stays in WASM via `mediaThumbnailEncrypt` + opaque handle.
 * - The R2 PUT carries only ciphertext — the server never sees plaintext.
 * - `mediaDropKey` and `mediaThumbnailDrop` are always called in `finally`.
 * - No file content, key bytes, or error details are logged.
 */

import { useCallback } from "react";
import { confirmMediaUpload, requestMediaUpload } from "../api/media";
import { sendMessage as sendMessageApi } from "../api/messages";
import { useAuthStore } from "../store/auth";
import { useCryptoWorker } from "./useCryptoWorker";

const THUMB_MAX_DIM = 64;
const THUMB_QUALITY = 0.6;
const THUMB_MIME = "image/jpeg";

/**
 * Downscale `file` to at most 64×64 and JPEG-encode at quality 0.6.
 * Returns null if the file is not an image or if Canvas API is unavailable.
 * No plaintext pixels are logged; errors are swallowed (thumbnail is non-fatal).
 */
async function generateThumbnail(file: File): Promise<Uint8Array | null> {
	if (!file.type.startsWith("image/")) return null;
	try {
		const bitmap = await createImageBitmap(file);
		const scale = Math.min(THUMB_MAX_DIM / bitmap.width, THUMB_MAX_DIM / bitmap.height, 1);
		const w = Math.max(1, Math.round(bitmap.width * scale));
		const h = Math.max(1, Math.round(bitmap.height * scale));
		const canvas = document.createElement("canvas");
		canvas.width = w;
		canvas.height = h;
		const ctx = canvas.getContext("2d");
		if (!ctx) return null;
		ctx.drawImage(bitmap, 0, 0, w, h);
		bitmap.close();
		const blob = await new Promise<Blob | null>((res) =>
			canvas.toBlob(res, THUMB_MIME, THUMB_QUALITY),
		);
		if (!blob) return null;
		return new Uint8Array(await blob.arrayBuffer());
	} catch {
		return null;
	}
}

export interface MediaSendOptions {
	identityId: string | undefined;
	groupId: string | undefined;
}

export interface MediaSendHook {
	/** Encrypt `file` and deliver it as an MLS application message to the active group. */
	sendMedia: (file: File) => Promise<void>;
}

export function useMediaSend({ identityId, groupId }: MediaSendOptions): MediaSendHook {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	const sendMedia = useCallback(
		async (file: File): Promise<void> => {
			if (!sessionToken || !identityId || !groupId || !cryptoWorker) return;

			// Read file bytes — stays in JS memory only until passed to WASM encrypt.
			const fileBytes = new Uint8Array(await file.arrayBuffer());

			// AES-256-GCM encrypt. mediaKeyHandle is opaque — raw key stays in WASM.
			const { ciphertext, mediaKeyHandle, iv, blobHash } =
				await cryptoWorker.mediaEncrypt(fileBytes);

			// §9.4.1: try to generate and encrypt a thumbnail (non-fatal if unavailable).
			let thumbHandle: string | null = null;
			try {
				const thumbBytes = await generateThumbnail(file);
				if (thumbBytes !== null) {
					const { thumbHandle: h } = await cryptoWorker.mediaThumbnailEncrypt(thumbBytes);
					thumbHandle = h;
				}
			} catch {
				// Thumbnail generation/encryption failure is non-fatal.
			}

			try {
				// Allocate MediaId and get presigned R2 PUT URL from the server.
				const { mediaId, uploadUrl } = await requestMediaUpload(
					sessionToken,
					file.type || "application/octet-stream",
					ciphertext.length,
					groupId,
				);

				// PUT encrypted bytes directly to R2 — server never sees plaintext.
				// .slice(0) copies into a fresh ArrayBuffer so the BodyInit type is
				// unambiguous across DOM and Bun TypeScript environments.
				await fetch(uploadUrl, {
					method: "PUT",
					body: ciphertext.slice(0),
					headers: { "Content-Type": "application/octet-stream" },
				});

				// Tell the server the upload is complete.
				await confirmMediaUpload(sessionToken, mediaId);

				// Build and MLS-encrypt the app message payload.
				// Raw media key stays inside WASM; only the MLS ciphertext is returned.
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

				// Deliver the MLS envelope to the delivery service.
				await sendMessageApi(sessionToken, groupId, mlsCiphertext);
			} finally {
				// Always drop both handles regardless of success or failure.
				await cryptoWorker.mediaDropKey(mediaKeyHandle);
				if (thumbHandle !== null) {
					await cryptoWorker.mediaThumbnailDrop(thumbHandle).catch(() => {});
				}
			}
		},
		[sessionToken, identityId, groupId, cryptoWorker],
	);

	return { sendMedia };
}
