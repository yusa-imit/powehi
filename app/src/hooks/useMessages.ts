/**
 * useMessages — poll for incoming MLS Application messages for an active group.
 *
 * Polls GET /v1/messages every POLL_INTERVAL_MS.  Application messages are
 * decrypted via the crypto worker and forwarded to `onMessage`.  Commit and
 * Proposal envelopes are acked silently.  Welcome envelopes are skipped —
 * useWelcomePoller owns Welcome processing and will ack them after mlsJoinGroup.
 *
 * Security invariants:
 * - Plaintext is never stored in component state; only the decoded string is
 *   passed to onMessage (react-hooks-only.md, no-plaintext-logging.md).
 * - Decryption errors are swallowed: a stale-epoch envelope cannot disrupt UI.
 * - Polling stops on unmount or when any required context is absent.
 */

import { useEffect, useRef } from "react";
import { type Envelope, ackMessage, pollMessages } from "../api/messages";
import { useAuthStore } from "../store/auth";
import { uint8ToBase64 } from "../utils/base64";
import { useCryptoWorker } from "./useCryptoWorker";

// Keep a direct store reference for use inside async callbacks (not a hook call).
const getAuthState = () => useAuthStore.getState();

const POLL_INTERVAL_MS = 3_000;

/**
 * Inline encrypted thumbnail from the MLS payload (prd.md §9.4.1).
 * Arrives alongside the image message; no R2 fetch required for display.
 * The caller must zero `key` after use: `new Uint8Array(thumb.key).fill(0)`.
 */
export interface ThumbnailPayload {
	ct: number[];
	key: number[];
	iv: number[];
}

/**
 * Parsed media attachment payload from an §9.2 image message.
 * mediaKey is the raw 32-byte AES-256-GCM key as a JS number array (from MLS-decrypted JSON).
 * The caller must zero it via `new Uint8Array(media.mediaKey).fill(0)` after use.
 */
export interface MediaPayload {
	blobId: string;
	blobHash: number[];
	mediaKey: number[];
	iv: number[];
	/** Optional inline thumbnail from §9.4.1. Present when sender used mediaMessageCreateWithThumbnail. */
	thumbnail?: ThumbnailPayload;
}

/**
 * Reply context embedded in a structured text message.
 * messageId references the envelope UUID of the quoted message.
 * excerpt is up to 100 chars of the original text, capped before send.
 */
export interface ReplyContext {
	messageId: string;
	excerpt: string;
}

export interface IncomingMessage {
	/** Raw envelope UUID — use for deduplication. */
	id: string;
	/** Opaque sending device UUID — never a display name. */
	senderId: string;
	/** MLS group UUID the message belongs to. */
	groupId: string;
	/** Decrypted plaintext as a string; "[image]" when type==="image". */
	text: string;
	/** Present when this is an §9.2 media attachment message. */
	media?: MediaPayload;
	/** Base64-encoded MLS application ciphertext — used for Dexie persistence. */
	ciphertextB64: string;
	/** MLS epoch used as primary sort key for Dexie ordering. */
	epochSeq: number;
	/** Unix ms at which this message expires (disappearing messages). undefined = no TTL. */
	expiresAt?: number;
	/** Quote-reply context: the message this is a reply to, if any. */
	replyTo?: ReplyContext;
}

/**
 * Allowed emoji for reactions. Validated server-side before calling onReaction.
 * Kept small and explicit to prevent free-form data smuggling via the emoji field.
 */
export const ALLOWED_REACTION_EMOJIS = ["👍", "❤️", "😂", "😮", "😢", "😡"] as const;
export type ReactionEmoji = (typeof ALLOWED_REACTION_EMOJIS)[number];

/**
 * Start polling for messages for the given MLS identity/group pair.
 *
 * @param identityId   Local MLS identity ID (from mlsInitIdentity).
 * @param groupId      MLS group UUID to filter and decrypt for.
 * @param onMessage    Stable callback invoked for each decrypted Application message.
 *                     Must be memoized with useCallback — passed as a dep.
 * @param onPqBinding  Optional callback invoked when a pq_init envelope is processed
 *                     (§5.3 Phase B). Receives the groupId and 16-char binding hex.
 * @param onTyping     Optional callback invoked when a typing_indicator envelope is
 *                     received. Receives the groupId. Not forwarded to onMessage.
 * @param onReaction      Optional callback invoked when a reaction envelope is received.
 *                        Receives groupId, targetMessageId, emoji (from ALLOWED_REACTION_EMOJIS),
 *                        and the sender device ID. Not forwarded to onMessage.
 * @param onReadReceipt      Optional callback invoked when a read_receipt envelope is received.
 *                           Receives groupId, messageIds (server UUID array, max 100), readAt (unix ms),
 *                           and senderDeviceId. Not forwarded to onMessage.
 * @param onDeliveryReceipt  Optional callback invoked when a delivery_receipt envelope is received.
 *                           Receives groupId, messageIds (server UUID array, max 100), and senderDeviceId.
 *                           Fired when the peer's device received and decrypted the message.
 *                           Not forwarded to onMessage.
 */
export function useMessages(
	identityId: string | undefined,
	groupId: string | undefined,
	onMessage: (msg: IncomingMessage) => void,
	onPqBinding?: (groupId: string, bindingHex: string) => void,
	onTyping?: (groupId: string) => void,
	onReaction?: (groupId: string, targetId: string, emoji: string, senderId: string) => void,
	onReadReceipt?: (
		groupId: string,
		messageIds: string[],
		readAt: number,
		senderDeviceId: string,
	) => void,
	onDeliveryReceipt?: (groupId: string, messageIds: string[], senderDeviceId: string) => void,
): void {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	// Stable ref so the polling closure always sees the latest callback
	// without needing it in the effect dep array (avoids re-mounting on every render).
	const onMessageRef = useRef(onMessage);
	useEffect(() => {
		onMessageRef.current = onMessage;
	});

	const onPqBindingRef = useRef(onPqBinding);
	useEffect(() => {
		onPqBindingRef.current = onPqBinding;
	});

	const onTypingRef = useRef(onTyping);
	useEffect(() => {
		onTypingRef.current = onTyping;
	});

	const onReactionRef = useRef(onReaction);
	useEffect(() => {
		onReactionRef.current = onReaction;
	});

	const onReadReceiptRef = useRef(onReadReceipt);
	useEffect(() => {
		onReadReceiptRef.current = onReadReceipt;
	});

	const onDeliveryReceiptRef = useRef(onDeliveryReceipt);
	useEffect(() => {
		onDeliveryReceiptRef.current = onDeliveryReceipt;
	});

	// Track the latest created_at we've seen to avoid re-delivering on restart.
	const sinceRef = useRef<number | undefined>(undefined);

	useEffect(() => {
		if (!sessionToken || !identityId || !groupId || !cryptoWorker) return;

		let cancelled = false;

		const processEnvelope = async (env: Envelope): Promise<void> => {
			if (env.message_type === "Welcome") {
				// Welcome envelopes are handled by useWelcomePoller — do not ack here.
				return;
			}
			if (env.message_type !== "Application" || env.group_id !== groupId) {
				// Commit / Proposal / off-group Application: ack silently.
				await ackMessage(sessionToken, env.id).catch(() => {});
				return;
			}

			try {
				const ciphertext = new Uint8Array(env.ciphertext);
				const { plaintext } = await cryptoWorker.mlsDecrypt(identityId, groupId, ciphertext);
				const decoded = new TextDecoder().decode(plaintext);
				// Base64-encode the wire ciphertext for Dexie persistence (safe loop, no spread).
				const ciphertextB64 = uint8ToBase64(env.ciphertext);
				const epochSeq = env.epoch ?? Date.now();

				// §9.2 / §5.3 Phase B: try JSON-parsing for structured messages.
				// Non-JSON or missing `type` field → treat as legacy plain text.
				let text = decoded;
				let media: MediaPayload | undefined;
				let replyTo: ReplyContext | undefined;
				let shouldDisplayMessage = true;
				try {
					const parsed = JSON.parse(decoded) as Record<string, unknown>;
					if (
						parsed.type === "image" &&
						typeof parsed.blobId === "string" &&
						Array.isArray(parsed.blobHash) &&
						Array.isArray(parsed.mediaKey) &&
						Array.isArray(parsed.iv)
					) {
						text = "[image]";
						const thumbRaw = (() => {
							const t = parsed.thumbnail;
							if (
								t !== null &&
								typeof t === "object" &&
								Array.isArray((t as Record<string, unknown>).ct) &&
								Array.isArray((t as Record<string, unknown>).key) &&
								Array.isArray((t as Record<string, unknown>).iv) &&
								((t as Record<string, unknown>).ct as number[]).length <= 16_384 &&
								((t as Record<string, unknown>).key as number[]).length === 32 &&
								((t as Record<string, unknown>).iv as number[]).length === 12
							) {
								return t as ThumbnailPayload;
							}
							return undefined;
						})();
						media = {
							blobId: parsed.blobId as string,
							blobHash: parsed.blobHash as number[],
							mediaKey: parsed.mediaKey as number[],
							iv: parsed.iv as number[],
							thumbnail: thumbRaw,
						};
					} else if (parsed.type === "typing_indicator") {
						// Peer is typing — notify ChatLayout; never displayed as a message.
						shouldDisplayMessage = false;
						onTypingRef.current?.(groupId);
					} else if (parsed.type === "reaction") {
						// Emoji reaction — never displayed as a message; callback only when params are valid.
						shouldDisplayMessage = false;
						if (
							typeof parsed.emoji === "string" &&
							typeof parsed.targetMessageId === "string" &&
							(ALLOWED_REACTION_EMOJIS as readonly string[]).includes(parsed.emoji) &&
							parsed.targetMessageId.length > 0
						) {
							onReactionRef.current?.(groupId, parsed.targetMessageId, parsed.emoji, env.sender);
						}
					} else if (parsed.type === "read_receipt") {
						// Read receipt — never displayed as a message; callback only when params are valid.
						shouldDisplayMessage = false;
						if (
							Array.isArray(parsed.messageIds) &&
							parsed.messageIds.length > 0 &&
							parsed.messageIds.length <= 100 &&
							(parsed.messageIds as unknown[]).every(
								(id) => typeof id === "string" && id.length > 0 && id.length <= 36,
							) &&
							typeof parsed.readAt === "number" &&
							Number.isFinite(parsed.readAt)
						) {
							onReadReceiptRef.current?.(
								groupId,
								parsed.messageIds as string[],
								parsed.readAt as number,
								env.sender,
							);
						}
					} else if (parsed.type === "delivery_receipt") {
						// Delivery receipt — never displayed as a message; callback only when params are valid.
						shouldDisplayMessage = false;
						if (
							Array.isArray(parsed.messageIds) &&
							parsed.messageIds.length > 0 &&
							parsed.messageIds.length <= 100 &&
							(parsed.messageIds as unknown[]).every(
								(id) => typeof id === "string" && id.length > 0 && id.length <= 36,
							)
						) {
							onDeliveryReceiptRef.current?.(groupId, parsed.messageIds as string[], env.sender);
						}
					} else if (parsed.type === "text" && typeof parsed.text === "string") {
						// Structured text message — may include a reply context.
						text = parsed.text;
						const rt = parsed.replyTo;
						if (rt !== null && typeof rt === "object") {
							const r = rt as Record<string, unknown>;
							if (
								typeof r.messageId === "string" &&
								r.messageId.length > 0 &&
								r.messageId.length <= 36 &&
								typeof r.excerpt === "string" &&
								r.excerpt.length > 0
							) {
								replyTo = { messageId: r.messageId, excerpt: (r.excerpt as string).slice(0, 100) };
							}
						}
					} else if (parsed.type === "pq_init" && Array.isArray(parsed.ct)) {
						// §5.3 Phase B: PQ invite confirmation — decap ML-KEM ciphertext + derive binding.
						shouldDisplayMessage = false;
						const pqHandle = getAuthState().pqDecapKeyHandle;
						if (pqHandle && cryptoWorker) {
							try {
								const ct = new Uint8Array(parsed.ct as number[]);
								const { sharedSecretHandle } = await cryptoWorker.mlKem768DecapV2(pqHandle, ct);
								const { bindingHex } = await cryptoWorker.mlsPqDeriveBinding(
									sharedSecretHandle,
									groupId,
								);
								await cryptoWorker.mlKem768DropDecapKey(pqHandle);
								getAuthState().clearPqDecapKeyHandle();
								onPqBindingRef.current?.(groupId, bindingHex);
							} catch {
								// PQ failure is non-fatal — classical E2EE channel remains active.
							}
						}
					}
				} catch {
					// Not JSON — plain text message, no action needed.
				}

				if (shouldDisplayMessage) {
					// Disappearing messages: parse server-set expires_at into unix ms.
					const expiresAt = env.expires_at ? new Date(env.expires_at).getTime() : undefined;
					onMessageRef.current({
						id: env.id,
						senderId: env.sender,
						groupId: env.group_id,
						text,
						media,
						ciphertextB64,
						epochSeq,
						expiresAt,
						replyTo,
					});
				}
				await ackMessage(sessionToken, env.id).catch(() => {});
			} catch {
				// Decryption failure (wrong epoch, tampered, etc.) — skip envelope.
				// Do NOT ack: the server should GC via TTL, not by client acknowledgement
				// of a message it couldn't read (could mask delivery bugs).
			}

			// Advance the since pointer to avoid re-fetching delivered envelopes.
			const ts = Math.floor(new Date(env.created_at).getTime() / 1000);
			if (sinceRef.current === undefined || ts >= sinceRef.current) {
				sinceRef.current = ts + 1;
			}
		};

		const poll = async () => {
			if (cancelled) return;
			try {
				const envelopes = await pollMessages(sessionToken, sinceRef.current);
				for (const env of envelopes) {
					if (cancelled) break;
					await processEnvelope(env);
				}
			} catch {
				// Network failure — silently retry on next interval.
			}
		};

		// Immediate first poll, then on interval.
		void poll();
		const handle = setInterval(() => void poll(), POLL_INTERVAL_MS);

		return () => {
			cancelled = true;
			clearInterval(handle);
		};
	}, [sessionToken, identityId, groupId, cryptoWorker]);
}
