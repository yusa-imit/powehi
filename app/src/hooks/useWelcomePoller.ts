/**
 * useWelcomePoller — global poll for MLS Welcome envelopes.
 *
 * Fires onNewGroup when a Welcome is successfully processed via mlsJoinGroup
 * in the WASM crypto layer.  Commit and Proposal envelopes are acked silently.
 * Application envelopes are left untouched for the per-group useMessages hook.
 *
 * Security invariants:
 * - Welcome bytes are passed directly to mlsJoinGroup; never logged or stored.
 * - groupId returned by WASM is an opaque hex string derived from MLS internals;
 *   it is not a server-visible identifier in the ciphertext sense.
 * - senderDeviceId is a server-assigned UUID; never a human-readable display name.
 */

import { useEffect, useRef } from "react";
import { type Envelope, ackMessage, pollMessages } from "../api/messages";
import { useAuthStore } from "../store/auth";
import { useCryptoWorker } from "./useCryptoWorker";

const POLL_INTERVAL_MS = 3_000;

export interface NewGroupEvent {
	/** Opaque WASM-internal hex group ID extracted from the Welcome message. */
	groupId: string;
	/** Opaque server-assigned UUID of the device that sent the Welcome. */
	senderDeviceId: string;
}

/**
 * Poll globally for Welcome envelopes and fire onNewGroup for each joined group.
 *
 * @param identityId  Local MLS identity ID (from mlsInitIdentity).
 * @param onNewGroup  Stable callback (memoized with useCallback) fired for each
 *                    new group join.
 */
export function useWelcomePoller(
	identityId: string | null | undefined,
	onNewGroup: (event: NewGroupEvent) => void,
): void {
	const { sessionToken } = useAuthStore();
	const cryptoWorker = useCryptoWorker();

	const onNewGroupRef = useRef(onNewGroup);
	useEffect(() => {
		onNewGroupRef.current = onNewGroup;
	});

	const sinceRef = useRef<number | undefined>(undefined);

	useEffect(() => {
		if (!sessionToken || !identityId || !cryptoWorker) return;

		let cancelled = false;

		const advanceSince = (createdAt: string): void => {
			const ts = Math.floor(new Date(createdAt).getTime() / 1000);
			if (sinceRef.current === undefined || ts >= sinceRef.current) {
				sinceRef.current = ts + 1;
			}
		};

		const processEnvelope = async (env: Envelope): Promise<void> => {
			if (env.message_type === "Application") {
				// Application envelopes are handled by per-group useMessages — skip.
				return;
			}

			if (env.message_type !== "Welcome") {
				// Commit / Proposal: ack silently; no content to process in this hook.
				await ackMessage(sessionToken, env.id).catch(() => {});
				advanceSince(env.created_at);
				return;
			}

			// Welcome: join the MLS group then fire the callback.
			// Ordering: callback fires BEFORE ack so that if the callback throws
			// (e.g., setChats reducer panics) the envelope remains on the server
			// for redelivery.  Only ack after UI state has been updated.
			try {
				const welcomeBytes = new Uint8Array(env.ciphertext);
				const { groupId } = await cryptoWorker.mlsJoinGroup(identityId, welcomeBytes);
				onNewGroupRef.current({ groupId, senderDeviceId: env.sender });
				await ackMessage(sessionToken, env.id).catch(() => {});
				advanceSince(env.created_at);
			} catch (err) {
				// mlsJoinGroup or callback failure (stale Welcome, wrong KeyPackage epoch, etc.).
				// Do NOT ack — server TTL will eventually expire the envelope. Diagnostic only —
				// err.name/message here is always an internal error code (e.g. a WASM/wasm-bindgen
				// error string describing which crypto step failed, or "setChats panic"), never
				// message content, PII, or ciphertext — see no-plaintext-logging.md's "error
				// categories, not payload" allowance. Without this, a Welcome that never joins
				// (the exact "contact never shows up" failure mode) is completely invisible —
				// mirrors AcceptInviteModal.tsx's accept_invite_failed logging (cycle 282).
				console.error(
					"welcome_join_failed",
					err instanceof Error ? err.name : typeof err,
					err instanceof Error ? err.message : String(err),
				);
			}
		};

		const poll = async (): Promise<void> => {
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

		void poll();
		const handle = setInterval(() => void poll(), POLL_INTERVAL_MS);

		return () => {
			cancelled = true;
			clearInterval(handle);
		};
	}, [sessionToken, identityId, cryptoWorker]);
}
