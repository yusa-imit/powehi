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
import type { IncomingMessage } from "./useMessages";

export interface PersistedMessages {
	rows: MessageRow[];
	/** Count of IndexedDB write failures since mount. Never contains content — opaque counter only. */
	writeErrorCount: number;
	persistIncoming: (msg: IncomingMessage) => void;
	persistOutgoing: (id: string, groupId: string, text: string, ciphertextB64: string) => void;
	/** Delete expired messages from Dexie and update local rows state. */
	purgeExpired: () => void;
	/** Persist an "edit message" signal so the new text survives a reload. Best-effort. */
	persistEdit: (targetMessageId: string, newText: string) => void;
	/** Persist a "delete for everyone" signal so the tombstone survives a reload. Best-effort. */
	persistDelete: (targetMessageId: string) => void;
	/** Persist the current reaction map for a message so reactions survive a reload. Best-effort. */
	persistReaction: (targetMessageId: string, reactions: Record<string, string[]>) => void;
	/**
	 * Message ids with a persist* write currently in flight (added when a persist* call
	 * starts, removed once its Dexie write settles). markMessageEdited/markMessageReactions
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
		(id: string, groupId: string, text: string, ciphertextB64: string) => {
			if (!encryptedDb || !deviceId) return;
			// epochSeq: Date.now() for outgoing — mlsEncrypt does not expose the MLS
			// sequence number. Display ordering now uses receivedAt (not epochSeq) so
			// the outgoing large-timestamp value no longer causes sort namespace mismatch.
			// epochSeq is retained for potential future replay-detection use at the WASM layer.
			// plaintextB64 stores base64-encoded UTF-8 (textToBase64 safe loop).
			const row: MessageRow = {
				id,
				groupId,
				ciphertextB64,
				senderDeviceId: deviceId,
				epochSeq: Date.now(),
				receivedAt: Date.now(),
				plaintextB64: textToBase64(text),
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

	const persistReaction = useCallback(
		(targetMessageId: string, reactions: Record<string, string[]>) => {
			if (!encryptedDb) return;
			const reactionsJson = JSON.stringify(reactions);
			setRows((prev) => prev.map((r) => (r.id === targetMessageId ? { ...r, reactionsJson } : r)));
			pendingWriteIdsRef.current.add(targetMessageId);
			encryptedDb
				.markMessageReactions(targetMessageId, reactionsJson)
				.catch(() => setWriteErrorCount((n) => n + 1))
				.finally(() => pendingWriteIdsRef.current.delete(targetMessageId));
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
		pendingWriteIds: pendingWriteIdsRef.current,
	};
}
