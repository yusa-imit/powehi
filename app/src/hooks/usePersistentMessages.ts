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

import { useCallback, useEffect, useMemo, useState } from "react";
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
			};
			// Optimistically add to local state for immediate UI visibility.
			setRows((prev) => {
				if (prev.some((r) => r.id === row.id)) return prev;
				return [...prev, row].sort((a, b) => a.epochSeq - b.epochSeq);
			});
			encryptedDb.putMessage(row).catch(() => setWriteErrorCount((n) => n + 1));
		},
		[encryptedDb],
	);

	const persistOutgoing = useCallback(
		(id: string, groupId: string, text: string, ciphertextB64: string) => {
			if (!encryptedDb || !deviceId) return;
			// Use Date.now() as epochSeq for outgoing — mlsEncrypt does not expose the
			// MLS sequence number. Replay detection is enforced at the WASM layer; this
			// field is only used for display ordering in getMessagesByGroup().
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

	return { rows, writeErrorCount, persistIncoming, persistOutgoing };
}
