/**
 * usePersistentMessages — persist and reload MLS messages via EncryptedPowehiDb.
 *
 * Security invariants:
 * - plaintextB64 is encrypted at rest by EncryptedPowehiDb (AES-GCM-256).
 * - ciphertextB64 stores the MLS wire ciphertext — also encrypted at rest.
 * - No plaintext appears in logs (no-plaintext-logging.md).
 * - encryptedDb is null when the crypto worker is unavailable — all paths
 *   fail closed (no write, no read, no error surfaced to caller).
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EncryptedPowehiDb } from "../db/encrypted-db";
import type { MessageRow } from "../db/schema";
import { db } from "../db/schema";
import { useAuthStore } from "../store/auth";
import { textToBase64 } from "../utils/base64";
import { useCryptoWorker } from "./useCryptoWorker";
import type { IncomingMessage, MediaPayload, ReplyContext } from "./useMessages";

export interface PersistedMessages {
	rows: MessageRow[];
	/** Count of IndexedDB write failures since mount. Never contains content — opaque counter only. */
	writeErrorCount: number;
	persistIncoming: (msg: IncomingMessage) => void;
	persistOutgoing: (
		id: string,
		groupId: string,
		text: string,
		ciphertextB64: string,
		replyTo?: ReplyContext,
		expiresAt?: number,
		/**
		 * §9.2 media attachment metadata (see MessageRow.mediaJson doc comment,
		 * db/schema.ts). Optional — text-only sends never pass this. As of ADR-0004,
		 * outgoing/send-path callers CAN pass a real `mediaKey` here too: when a caller
		 * opted in to `encryptAndSendMedia`'s `{ exportKeyForPersistence: true }`
		 * (`useMediaSend.ts` does this whenever a `persistOutgoing` sink exists), the raw
		 * key is exported once, AFTER the envelope is accepted by the server, and threaded
		 * through to this param — the sender's own copy then persists and rehydrates the
		 * same way the receive path (persistIncoming) always has. Callers with no
		 * persistence-worthy key (e.g. the forwarding flow, which does not opt in this
		 * cycle) still omit this param entirely and rely on `text` alone for a
		 * placeholder bubble.
		 */
		media?: MediaPayload,
	) => void;
	/** Delete expired messages from Dexie and update local rows state. */
	purgeExpired: () => void;
	/** Persist an "edit message" signal so the new text survives a reload. Best-effort. */
	persistEdit: (targetMessageId: string, newText: string) => void;
	/** Persist a "delete for everyone" signal so the tombstone survives a reload. Best-effort. */
	persistDelete: (targetMessageId: string) => void;
	/**
	 * Persist one sender's add/remove of a single emoji reaction so it survives a
	 * reload. Merged against the persisted map (not a full-replace) — see
	 * `markMessageReactionDelta` in encrypted-db.ts. Best-effort.
	 */
	persistReaction: (
		targetMessageId: string,
		emoji: string,
		senderId: string,
		action: "add" | "remove",
	) => void;
	/**
	 * Persist a newly-created poll message. Unlike other persist* helpers this CREATES the row
	 * (polls never go through persistOutgoing — there is no MLS envelope type for them, so
	 * they otherwise never reach Dexie at all). Best-effort.
	 */
	persistPollCreate: (
		id: string,
		groupId: string,
		poll: { question: string; options: { text: string; voters: string[] }[] },
		expiresAt?: number,
	) => void;
	/** Persist the current vote state for an existing poll message so votes survive a reload. Best-effort. */
	persistPollVote: (
		targetMessageId: string,
		poll: { question: string; options: { text: string; voters: string[] }[] },
	) => void;
	/** Persist a "delivery receipt" signal so the delivered indicator survives a reload. Best-effort. */
	persistDelivered: (targetMessageId: string) => void;
	/** Persist a "read receipt" signal (read flag + reader device ids) so it survives a reload. Best-effort. */
	persistRead: (targetMessageId: string, readBy: string[]) => void;
	/** Persist the star/bookmark toggle for a message so it survives a reload. Best-effort. */
	persistStarred: (targetMessageId: string, starred: boolean) => void;
	/**
	 * Persist a newly-scheduled ("send later") message. Like persistPollCreate this CREATES
	 * the row — a scheduled message has no MLS envelope until it actually fires, so it
	 * otherwise never reaches Dexie at all. Best-effort.
	 */
	persistScheduledCreate: (
		id: string,
		groupId: string,
		text: string,
		scheduledFor: number,
		expiresAt?: number,
	) => void;
	/** Persist a scheduled message firing: clears scheduledFor so it survives a reload as a normal message. Best-effort. */
	persistScheduledFire: (targetMessageId: string) => void;
	/** Persist cancellation of a scheduled message: deletes the row entirely. Best-effort. */
	persistCancelScheduled: (targetMessageId: string) => void;
	/**
	 * Atomically claim a scheduled message for firing (clears scheduledFor iff still set,
	 * inside one Dexie transaction) and return its live Dexie content, or undefined if it
	 * can't be claimed (already fired/cancelled by any tab, or crypto worker unavailable).
	 */
	claimScheduledFire: (targetMessageId: string) => Promise<MessageRow | undefined>;
	/**
	 * Message ids with a persist* write currently in flight (added when a persist* call
	 * starts, removed once its Dexie write settles). markMessageEdited/markMessageReactionDelta
	 * await an encryptDbField crypto-worker round-trip before the IndexedDB write lands —
	 * a group switch-away-and-back in that window re-reads via getMessagesByGroup and can
	 * observe the pre-write row. Callers that reconcile in-memory state against freshly
	 * loaded rows (ChatLayout's rehydration effect) must skip ids in this set rather than
	 * trust the possibly-stale read. Same Set object identity for the hook's lifetime —
	 * safe as a stable effect dependency despite being mutated in place.
	 */
	pendingWriteIds: Set<string>;
}

/**
 * Load and persist MLS application messages for one group.
 *
 * @param groupId  MLS group UUID. When undefined the hook is dormant (no reads/writes).
 */
export function usePersistentMessages(groupId: string | undefined): PersistedMessages {
	const { deviceId } = useAuthStore();
	const cryptoWorker = useCryptoWorker();
	const [rows, setRows] = useState<MessageRow[]>([]);
	const [writeErrorCount, setWriteErrorCount] = useState(0);
	const pendingWriteIdsRef = useRef<Set<string>>(new Set());

	const encryptedDb = useMemo(
		() => (cryptoWorker ? new EncryptedPowehiDb(db, cryptoWorker) : null),
		[cryptoWorker],
	);

	// On group change load all persisted messages from IndexedDB.
	useEffect(() => {
		if (!groupId || !encryptedDb) {
			setRows([]);
			return;
		}
		let cancelled = false;
		encryptedDb
			.getMessagesByGroup(groupId)
			.then((loaded) => {
				if (!cancelled) setRows(loaded);
			})
			.catch(() => {});
		return () => {
			cancelled = true;
		};
	}, [groupId, encryptedDb]);

	const persistIncoming = useCallback(
		(msg: IncomingMessage) => {
			if (!encryptedDb) return;
			// plaintextB64 stores base64-encoded UTF-8 bytes (matching the field name contract).
			// textToBase64 uses a safe byte-at-a-time loop — no spread, no RangeError risk.
			const row: MessageRow = {
				id: msg.id,
				groupId: msg.groupId,
				ciphertextB64: msg.ciphertextB64,
				senderDeviceId: msg.senderId,
				epochSeq: msg.epochSeq,
				receivedAt: Date.now(),
				plaintextB64: textToBase64(msg.text),
				expiresAt: msg.expiresAt,
				replyToJson: msg.replyTo ? JSON.stringify(msg.replyTo) : undefined,
				// §9.2 media attachment — the raw mediaKey legitimately arrives inline in the
				// MLS-decrypted payload on receive (existing invariant, mediaTransfer.ts), so
				// unlike persistOutgoing's media param this is captured verbatim. Closes the
				// "every received photo/video/voice note vanishes on reload" gap — media
				// send/receive never called any persist hook at all before this fix.
				mediaJson: msg.media ? JSON.stringify(msg.media) : undefined,
			};
			// Optimistically add to local state for immediate UI visibility.
			setRows((prev) => {
				if (prev.some((r) => r.id === row.id)) return prev;
				// Sort by receivedAt (wall-clock) — same namespace as outgoing messages,
				// so incoming and outgoing interleave in chronological order (Y1 fix).
				return [...prev, row].sort((a, b) => a.receivedAt - b.receivedAt);
			});
			encryptedDb.putMessage(row).catch(() => setWriteErrorCount((n) => n + 1));
		},
		[encryptedDb],
	);

	const persistOutgoing = useCallback(
		(
			id: string,
			groupId: string,
			text: string,
			ciphertextB64: string,
			replyTo?: ReplyContext,
			expiresAt?: number,
			media?: MediaPayload,
		) => {
			if (!encryptedDb || !deviceId) return;
			// epochSeq: Date.now() for outgoing — mlsEncrypt does not expose the MLS
			// sequence number. Display ordering now uses receivedAt (not epochSeq) so
			// the outgoing large-timestamp value no longer causes sort namespace mismatch.
			// epochSeq is retained for potential future replay-detection use at the WASM layer.
			// plaintextB64 stores base64-encoded UTF-8 (textToBase64 safe loop).
			// expiresAt: threaded through so the sender's own copy of a disappearing message
			// is purged by purgeExpired/rehydration the same as the recipient's copy — before
			// this fix, persistOutgoing never set it, so a self-sent disappearing message
			// survived forever in the sender's Dexie (security-auditor finding, cycle 337).
			const row: MessageRow = {
				id,
				groupId,
				ciphertextB64,
				senderDeviceId: deviceId,
				epochSeq: Date.now(),
				receivedAt: Date.now(),
				plaintextB64: textToBase64(text),
				replyToJson: replyTo ? JSON.stringify(replyTo) : undefined,
				expiresAt,
				mediaJson: media ? JSON.stringify(media) : undefined,
			};
			setRows((prev) => {
				if (prev.some((r) => r.id === row.id)) return prev;
				return [...prev, row];
			});
			encryptedDb.putMessage(row).catch(() => setWriteErrorCount((n) => n + 1));
		},
		[encryptedDb, deviceId],
	);

	const purgeExpired = useCallback(() => {
		if (!encryptedDb) return;
		const now = Date.now();
		// Remove from local state immediately for responsive UI.
		setRows((prev) => prev.filter((r) => !r.expiresAt || r.expiresAt > now));
		// Best-effort Dexie cleanup — errors are non-fatal.
		encryptedDb.purgeExpiredMessages().catch(() => {});
	}, [encryptedDb]);

	const persistEdit = useCallback(
		(targetMessageId: string, newText: string) => {
			if (!encryptedDb) return;
			const editedText = textToBase64(newText);
			setRows((prev) => prev.map((r) => (r.id === targetMessageId ? { ...r, editedText } : r)));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageEdited(targetMessageId, editedText)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistDelete = useCallback(
		(targetMessageId: string) => {
			if (!encryptedDb) return;
			const deletedAt = Date.now();
			setRows((prev) => prev.map((r) => (r.id === targetMessageId ? { ...r, deletedAt } : r)));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageDeleted(targetMessageId)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	/**
	 * Persists one sender's add/remove of a single emoji, merged against the
	 * currently-persisted map by `markMessageReactionDelta` rather than overwritten
	 * wholesale — closes the same cross-device-race class already fixed for
	 * `persistRead`'s readBy (see that method's doc comment + markMessageReactionDelta
	 * in encrypted-db.ts). The optimistic `rows` update below recomputes from `r`
	 * (React's latest functional-update snapshot, not a possibly-stale closure
	 * variable) so the in-memory mirror can't itself regress under a fast double-call,
	 * even though only the Dexie write is racing multiple *devices*.
	 */
	const persistReaction = useCallback(
		(targetMessageId: string, emoji: string, senderId: string, action: "add" | "remove") => {
			if (!encryptedDb) return;
			setRows((prev) =>
				prev.map((r) => {
					if (r.id !== targetMessageId) return r;
					let reactions: Record<string, string[]> = {};
					if (r.reactionsJson) {
						try {
							reactions = JSON.parse(r.reactionsJson) as Record<string, string[]>;
						} catch {
							reactions = {};
						}
					}
					const senders = reactions[emoji] ?? [];
					const alreadyIn = senders.includes(senderId);
					if (action === "add" && alreadyIn) return r;
					if (action === "remove" && !alreadyIn) return r;
					const nextSenders =
						action === "add" ? [...senders, senderId] : senders.filter((s) => s !== senderId);
					const nextReactions = { ...reactions };
					if (nextSenders.length === 0) {
						delete nextReactions[emoji];
					} else {
						nextReactions[emoji] = nextSenders;
					}
					return { ...r, reactionsJson: JSON.stringify(nextReactions) };
				}),
			);
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageReactionDelta(targetMessageId, emoji, senderId, action)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistPollCreate = useCallback(
		(
			id: string,
			groupId: string,
			poll: { question: string; options: { text: string; voters: string[] }[] },
			expiresAt?: number,
		) => {
			if (!encryptedDb || !deviceId) return;
			const pollJson = JSON.stringify(poll);
			// Polls have no MLS wire representation — ciphertextB64 uses the documented ""
			// sentinel (schema.ts), same "not applicable" convention as GroupRow.mlsStateB64.
			// expiresAt is threaded through so a poll created in a disappearing-message chat
			// is actually purged like every other message, instead of persisting forever
			// (security-auditor finding, this cycle — the retention policy must apply
			// uniformly regardless of message shape).
			const row: MessageRow = {
				id,
				groupId,
				ciphertextB64: "",
				senderDeviceId: deviceId,
				epochSeq: Date.now(),
				receivedAt: Date.now(),
				pollJson,
				expiresAt,
			};
			setRows((prev) => {
				if (prev.some((r) => r.id === row.id)) return prev;
				return [...prev, row];
			});
			encryptedDb.putMessage(row).catch(() => setWriteErrorCount((n) => n + 1));
		},
		[encryptedDb, deviceId],
	);

	/**
	 * KNOWN LIMITATION (security-auditor finding, accepted this cycle, not fixed): both this
	 * function and persistPollCreate await an encryptDbField round-trip before issuing their
	 * Dexie write, and persistPollCreate's row has two sensitive fields (ciphertextB64 "" +
	 * pollJson) vs this function's one — so if a vote fires immediately after the poll it
	 * targets was just created, this write's markMessagePoll (update-only, no-ops on a
	 * missing row) can reach IndexedDB before persistPollCreate's putMessage does, silently
	 * dropping the vote from Dexie (the in-memory `rows`/`chats` state is unaffected — both
	 * are optimistic updates that always land in call order). Narrow window (needs a vote
	 * within roughly one crypto-worker round-trip of the poll's own creation) and self-heals
	 * on the next vote against the same poll; not fixed here to avoid growing persist* into
	 * upsert-with-full-row-reconstruction, which would change its no-op-on-missing-row
	 * contract that markMessageEdited/Deleted/Reactions/Delivered/Read/Starred all share.
	 */
	const persistPollVote = useCallback(
		(
			targetMessageId: string,
			poll: { question: string; options: { text: string; voters: string[] }[] },
		) => {
			if (!encryptedDb) return;
			const pollJson = JSON.stringify(poll);
			setRows((prev) => prev.map((r) => (r.id === targetMessageId ? { ...r, pollJson } : r)));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessagePoll(targetMessageId, pollJson)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistDelivered = useCallback(
		(targetMessageId: string) => {
			if (!encryptedDb) return;
			setRows((prev) =>
				prev.map((r) => (r.id === targetMessageId ? { ...r, delivered: true } : r)),
			);
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageDelivered(targetMessageId)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	/**
	 * `readBy` is computed by the caller from a snapshot that may already be
	 * stale by write time — but `EncryptedPowehiDb.markMessageRead` unions it
	 * against the currently-persisted reader set inside a single Dexie
	 * transaction rather than overwriting, so two concurrent read_receipts for
	 * the same message can no longer clobber each other's entry (fixed cycle
	 * 322; was security-auditor YELLOW, cycle 321). `persistReaction` closes the
	 * same class of race the same way — see `markMessageReactionDelta`.
	 */
	const persistRead = useCallback(
		(targetMessageId: string, readBy: string[]) => {
			if (!encryptedDb) return;
			const readByJson = JSON.stringify(readBy);
			setRows((prev) =>
				prev.map((r) => (r.id === targetMessageId ? { ...r, read: true, readByJson } : r)),
			);
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageRead(targetMessageId, readBy)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistStarred = useCallback(
		(targetMessageId: string, starred: boolean) => {
			if (!encryptedDb) return;
			setRows((prev) => prev.map((r) => (r.id === targetMessageId ? { ...r, starred } : r)));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageStarred(targetMessageId, starred)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistScheduledCreate = useCallback(
		(id: string, groupId: string, text: string, scheduledFor: number, expiresAt?: number) => {
			if (!encryptedDb || !deviceId) return;
			// No MLS wire representation until the message actually fires — same "" ciphertextB64
			// sentinel convention as persistPollCreate.
			// expiresAt is threaded through so a scheduled message composed in a disappearing-
			// message chat is actually purged like every other message shape, instead of
			// persisting forever (security-auditor finding, cycle 339 — same retention-policy
			// gap already fixed for persistOutgoing/persistPollCreate: "the retention policy
			// must apply uniformly regardless of message shape"). Clock starts at schedule/
			// compose time, same as poll creation — if the TTL is shorter than the scheduling
			// delay the row purges before it ever fires, which is accepted (same class as
			// polls' known edge cases), not a confidentiality regression either way.
			const row: MessageRow = {
				id,
				groupId,
				ciphertextB64: "",
				senderDeviceId: deviceId,
				epochSeq: Date.now(),
				receivedAt: Date.now(),
				plaintextB64: textToBase64(text),
				scheduledFor,
				expiresAt,
			};
			setRows((prev) => {
				if (prev.some((r) => r.id === row.id)) return prev;
				return [...prev, row];
			});
			encryptedDb.putMessage(row).catch(() => setWriteErrorCount((n) => n + 1));
		},
		[encryptedDb, deviceId],
	);

	/**
	 * KNOWN LIMITATION (same class as persistPollCreate/persistPollVote, accepted there too):
	 * persistScheduledCreate's putMessage awaits an encryptDbField round-trip before its Dexie
	 * write lands. If this fires (or persistCancelScheduled below runs) within that window —
	 * i.e. before the row it targets has actually reached IndexedDB — the update/delete is a
	 * silent no-op (markMessage*-style methods never create a row), and the create's own write
	 * lands afterward, overwriting it as if nothing happened. Firing requires the scheduled
	 * time to elapse (seconds to hours after creation) and cancelling requires a separate user
	 * click after seeing the badge render — both are far outside a crypto round-trip's latency
	 * in practice, so this is not fixed here (would require the same upsert-with-full-row-
	 * reconstruction change rejected for polls, for the same reason: it would break every other
	 * markMessage*'s shared no-op-on-missing-row contract).
	 */
	const persistScheduledFire = useCallback(
		(targetMessageId: string) => {
			if (!encryptedDb) return;
			setRows((prev) =>
				prev.map((r) => (r.id === targetMessageId ? { ...r, scheduledFor: undefined } : r)),
			);
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.clearMessageScheduled(targetMessageId)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	const persistCancelScheduled = useCallback(
		(targetMessageId: string) => {
			if (!encryptedDb) return;
			setRows((prev) => prev.filter((r) => r.id !== targetMessageId));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.deleteMessage(targetMessageId)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
		},
		[encryptedDb],
	);

	/**
	 * Atomically claim a scheduled message for firing — see EncryptedPowehiDb.claimScheduledFire
	 * for why this must be a single atomic Dexie transaction rather than a separate
	 * check-then-act (crypto-reviewer finding, cycle 341: a bare read-then-send has a TOCTOU
	 * window spanning a full mlsEncrypt + network round trip, during which another tab's sweep
	 * — or this tab's own overlapping sweep tick — can also pass the check and double-fire this
	 * SAME scheduled message; scheduled rows are local-only until fired, so there is no separate
	 * device with its own copy to race against). This closes double-sending of this message, not
	 * the broader/pre-existing fact that every open tab holds its own independently-imported copy
	 * of the group's MLS sender ratchet (same as every other send path in this app) — see the
	 * fuller writeup on EncryptedPowehiDb.claimScheduledFire. Call this immediately before
	 * encrypting/sending. Returns the claimed row's live Dexie content (not the caller's possibly-
	 * stale in-memory snapshot) so the sender transmits the current text/expiresAt, not a stale
	 * pre-edit copy. Returns undefined — meaning "do not send" — if the row is missing, was
	 * already claimed/cancelled/fired by any tab, or the crypto worker is unavailable/errors
	 * (fails closed).
	 */
	const claimScheduledFire = useCallback(
		async (targetMessageId: string): Promise<MessageRow | undefined> => {
			if (!encryptedDb) return undefined;
			try {
				return await encryptedDb.claimScheduledFire(targetMessageId);
			} catch {
				return undefined;
			}
		},
		[encryptedDb],
	);

	return {
		rows,
		writeErrorCount,
		persistIncoming,
		persistOutgoing,
		purgeExpired,
		persistEdit,
		persistDelete,
		persistReaction,
		persistPollCreate,
		persistPollVote,
		persistDelivered,
		persistRead,
		persistStarred,
		persistScheduledCreate,
		persistScheduledFire,
		persistCancelScheduled,
		claimScheduledFire,
		pendingWriteIds: pendingWriteIdsRef.current,
	};
}
