/**
 * useMessages — poll for incoming MLS Application messages for an active group.
 *
 * Polls GET /v1/messages every POLL_INTERVAL_MS.  Application messages are
 * decrypted via the crypto worker and forwarded to `onMessage`.  Welcome and
 * Commit envelopes are acked silently (they carry MLS state consumed by the
 * WASM layer, not display text).
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
import { useCryptoWorker } from "./useCryptoWorker";

const POLL_INTERVAL_MS = 3_000;

export interface IncomingMessage {
	/** Raw envelope UUID — use for deduplication. */
	id: string;
	/** Opaque sending device UUID — never a display name. */
	senderId: string;
	/** MLS group UUID the message belongs to. */
	groupId: string;
	/** Decrypted plaintext as a string. */
	text: string;
}

/**
 * Start polling for messages for the given MLS identity/group pair.
 *
 * @param identityId Local MLS identity ID (from mlsInitIdentity).
 * @param groupId    MLS group UUID to filter and decrypt for.
 * @param onMessage  Stable callback invoked for each decrypted Application message.
 *                   Must be memoized with useCallback — passed as a dep.
 */
export function useMessages(
	identityId: string | undefined,
	groupId: string | undefined,
	onMessage: (msg: IncomingMessage) => void,
): void {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	// Stable ref so the polling closure always sees the latest callback
	// without needing it in the effect dep array (avoids re-mounting on every render).
	const onMessageRef = useRef(onMessage);
	useEffect(() => {
		onMessageRef.current = onMessage;
	});

	// Track the latest created_at we've seen to avoid re-delivering on restart.
	const sinceRef = useRef<number | undefined>(undefined);

	useEffect(() => {
		if (!sessionToken || !identityId || !groupId || !cryptoWorker) return;

		let cancelled = false;

		const processEnvelope = async (env: Envelope): Promise<void> => {
			if (env.message_type !== "Application" || env.group_id !== groupId) {
				// Ack silently — Welcome/Commit/Proposal are consumed by WASM, not UI.
				await ackMessage(sessionToken, env.id).catch(() => {});
				return;
			}

			try {
				const ciphertext = new Uint8Array(env.ciphertext);
				const { plaintext } = await cryptoWorker.mlsDecrypt(identityId, groupId, ciphertext);
				const text = new TextDecoder().decode(plaintext);
				onMessageRef.current({
					id: env.id,
					senderId: env.sender,
					groupId: env.group_id,
					text,
				});
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
