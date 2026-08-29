/**
 * useMediaSend — encrypt a local file and send it as an §9.2 MLS media message.
 *
 * Security invariants (prd.md §9.2 + §9.4.1 + no-plaintext-logging.md; ADR-0004):
 * - The raw AES-256-GCM media key NEVER crosses the WASM-JS boundary during
 *   encrypt/upload/send. `mediaEncrypt` returns an opaque handle;
 *   `mediaMessageCreate[WithThumbnail]` reads the key inside WASM, builds the JSON
 *   payload, and MLS-encrypts it atomically.
 * - ADR-0004: AFTER the envelope is sent, and ONLY when a `persistOutgoing` sink was
 *   passed in, `encryptAndSendMedia` is asked (`{ exportKeyForPersistence: true }`)
 *   to also export the key once for Dexie persistence — see MediaSendOptions.
 *   persistOutgoing's doc comment below for what that buys. When no `persistOutgoing`
 *   is supplied the export is never even attempted, so raw key bytes never cross the
 *   WASM-JS boundary at all in that case, same as before this ADR.
 * - The thumbnail key also stays in WASM via `mediaThumbnailEncrypt` + opaque handle
 *   (unaffected by ADR-0004 — thumbnails stay out of scope, see below).
 * - The R2 PUT carries only ciphertext — the server never sees plaintext.
 * - `mediaDropKey` and `mediaThumbnailDrop` are always called in `finally`.
 * - No file content, key bytes, or error details are logged.
 */

import { useCallback } from "react";
import { encryptAndSendMedia } from "../lib/mediaTransfer";
import { useAuthStore } from "../store/auth";
import { useCryptoWorker } from "./useCryptoWorker";
import type { PersistedMessages } from "./usePersistentMessages";

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
	/**
	 * Persist the sender's own copy of a sent media message to Dexie (the same
	 * `usePersistentMessages().persistOutgoing` text sends already use) so it survives a
	 * reload. Optional so callers/tests that don't need persistence keep working
	 * unchanged — and when omitted, `sendMedia` skips the ADR-0004 key export below
	 * entirely (no persistence target means no reason to ever bring the raw key into
	 * JS scope).
	 *
	 * ADR-0004 (media-key local persistence): when this IS supplied, `sendMedia` passes
	 * `{ exportKeyForPersistence: true }` to `encryptAndSendMedia`, which — after the
	 * envelope has already been accepted by the server — exports a real, persistable
	 * `media` payload and passes it through as this call's 7th argument. The row this
	 * creates therefore carries a genuine `mediaJson` and re-renders as a real
	 * attachment (`MediaImage`) after reload, exactly like a received one, closing the
	 * "sent media never survives a reload" gap this hook previously had. The payload
	 * has no `thumbnail`: the §9.4.1 thumbnail key stays WASM-only on the sender path
	 * (out of scope for this ADR), so a rehydrated sent image re-fetches the full blob
	 * from R2 instead of showing the inline preview first. The export is best-effort —
	 * if it fails, `media` is simply `undefined` and the row still persists with the
	 * placeholder `text` alone, same as before this ADR.
	 */
	persistOutgoing?: PersistedMessages["persistOutgoing"];
}

export interface MediaSendHook {
	/** Encrypt `file` and deliver it as an MLS application message to the active group. */
	sendMedia: (file: File) => Promise<void>;
}

export function useMediaSend({
	identityId,
	groupId,
	persistOutgoing,
}: MediaSendOptions): MediaSendHook {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	const sendMedia = useCallback(
		async (file: File): Promise<void> => {
			if (!sessionToken || !identityId || !groupId || !cryptoWorker) return;

			// Read file bytes — stays in JS memory only until passed to WASM encrypt.
			const fileBytes = new Uint8Array(await file.arrayBuffer());

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
				const { envelopeId, ciphertextB64, media } = await encryptAndSendMedia(
					fileBytes,
					file.type || "application/octet-stream",
					identityId,
					groupId,
					sessionToken,
					cryptoWorker,
					thumbHandle,
					// ADR-0004: only ask for a persistable key when there is actually
					// somewhere to persist it — see MediaSendOptions.persistOutgoing's
					// doc comment above.
					{ exportKeyForPersistence: persistOutgoing !== undefined },
				);
				// placeholderText matches the optimistic bubble in ChatLayout's
				// handleFileSelect/sendVoice; `media` (see doc comment above) lets the
				// persisted row re-render as a real attachment after reload instead of
				// staying this placeholder forever.
				const placeholderText = file.type.startsWith("video/")
					? "Video attachment"
					: file.type.startsWith("audio/")
						? "Voice message"
						: "Image attachment";
				persistOutgoing?.(
					envelopeId,
					groupId,
					placeholderText,
					ciphertextB64,
					undefined,
					undefined,
					media,
				);
			} finally {
				// Always drop the thumbnail handle regardless of success or failure
				// (the media key handle is dropped inside encryptAndSendMedia itself).
				if (thumbHandle !== null) {
					await cryptoWorker.mediaThumbnailDrop(thumbHandle).catch(() => {});
				}
			}
		},
		[sessionToken, identityId, groupId, cryptoWorker, persistOutgoing],
	);

	return { sendMedia };
}
