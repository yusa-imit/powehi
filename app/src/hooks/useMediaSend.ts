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
	 * reload — this cycle's fix; previously `sendMedia` never called any persist hook,
	 * so every sent photo/video/voice note vanished from chat history on reload. Optional
	 * so callers/tests that don't need persistence keep working unchanged.
	 *
	 * KNOWN LIMITATION (architectural, not an oversight — see MessageRow.mediaJson's
	 * ASYMMETRY note, db/schema.ts): the row this creates carries a placeholder `text`
	 * ("Image attachment"/"Video attachment"/"Voice message", matching the existing
	 * optimistic bubble below) but NO `media` payload — the raw AES-256-GCM media key
	 * never crosses the WASM→JS boundary on send (`encryptAndSendMedia` only ever
	 * returns an opaque-handle-backed ciphertext), so there is no key to persist for a
	 * redisplayable copy. This is not a regression: even the live, not-yet-reloaded
	 * bubble for a message YOU sent has never rendered an inline preview in this app,
	 * only this same placeholder text — a reload now correctly preserves that
	 * placeholder instead of losing the message entirely.
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
				const { envelopeId, ciphertextB64 } = await encryptAndSendMedia(
					fileBytes,
					file.type || "application/octet-stream",
					identityId,
					groupId,
					sessionToken,
					cryptoWorker,
					thumbHandle,
				);
				// See MediaSendOptions.persistOutgoing's KNOWN LIMITATION doc comment — no
				// `media` payload passed, only a placeholder text (same convention as the
				// optimistic bubble in ChatLayout's handleFileSelect/sendVoice).
				const placeholderText = file.type.startsWith("video/")
					? "Video attachment"
					: file.type.startsWith("audio/")
						? "Voice message"
						: "Image attachment";
				persistOutgoing?.(envelopeId, groupId, placeholderText, ciphertextB64);
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
