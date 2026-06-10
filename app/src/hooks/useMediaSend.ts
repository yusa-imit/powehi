/**
 * useMediaSend — encrypt a local file and send it as an §9.2 MLS media message.
 *
 * Security invariants (prd.md §9.2 + no-plaintext-logging.md):
 * - The raw AES-256-GCM media key NEVER crosses the WASM-JS boundary.
 *   `mediaEncrypt` returns an opaque handle; `mediaMessageCreate` reads the key
 *   inside WASM, builds the JSON payload, and MLS-encrypts it atomically.
 * - The R2 PUT carries only ciphertext — the server never sees plaintext.
 * - `mediaDropKey` is always called in `finally` so the handle is cleaned up
 *   whether the send succeeds or fails.
 * - No file content, key bytes, or error details are logged.
 */

import { useCallback } from "react";
import { confirmMediaUpload, requestMediaUpload } from "../api/media";
import { sendMessage as sendMessageApi } from "../api/messages";
import { useAuthStore } from "../store/auth";
import { useCryptoWorker } from "./useCryptoWorker";

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
				const { ciphertext: mlsCiphertext } = await cryptoWorker.mediaMessageCreate(
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
				// Always drop the handle regardless of success or failure.
				await cryptoWorker.mediaDropKey(mediaKeyHandle);
			}
		},
		[sessionToken, identityId, groupId, cryptoWorker],
	);

	return { sendMedia };
}
