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

	const sinceRef = useRef<{ ts: string; id: string } | undefined>(undefined);

	useEffect(() => {
		if (!sessionToken || !identityId || !cryptoWorker) return;

		let cancelled = false;

		const processEnvelope = async (env: Envelope): Promise<void> => {
			if (env.message_type === "Application") {
				// Application envelopes are handled by per-group useMessages — skip.
				// Safe to leave unacked here: this hook's own fetch cursor still
				// advances past it regardless (poll()'s comment below), and
				// useMessages is a wholly separate hook instance with its own
				// independent cursor, unaffected by this one.
				return;
			}

			if (env.message_type !== "Welcome") {
				// Commit / Proposal: ack silently; no content to process in this hook.
				await ackMessage(sessionToken, env.id).catch(() => {});
				return;
			}

			// Welcome: join the MLS group then fire the callback.
			// Ordering: callback fires BEFORE ack so that if the callback throws
			// (e.g., setChats reducer panics) the envelope is never acked — it isn't
			// deleted server-side. Since the cycle 352 livelock fix, "remains for
			// redelivery" no longer means "retried within this mount": this mount's
			// fetch cursor advances past it regardless (see the catch block below and
			// poll()'s comment), so it's only actually redelivered on a future
			// remount. Still strictly better than acking on a callback failure, which
			// would delete it server-side with no redelivery path at all.
			try {
				const welcomeBytes = new Uint8Array(env.ciphertext);
				const { groupId } = await cryptoWorker.mlsJoinGroup(identityId, welcomeBytes);
				onNewGroupRef.current({ groupId, senderDeviceId: env.sender });
				await ackMessage(sessionToken, env.id).catch(() => {});
			} catch (err) {
				// Two different failure classes land here, not one: mlsJoinGroup
				// failures (stale Welcome, wrong KeyPackage epoch) are genuinely
				// permanent — retrying within this mount gains nothing. A thrown
				// onNewGroupRef callback (e.g. a setChats reducer panic) is a UI-layer
				// bug and could in principle be transient — but this hook has no way
				// to distinguish the two here, and re-running an already-succeeded
				// mlsJoinGroup is not safe to retry blindly, so both are treated the
				// same: not acked, not retried in-mount. Do NOT ack:
				// the 30-day default retention floor (cycle 350) eventually GCs it server-side;
				// meanwhile this mount's own fetch cursor still advances past it regardless
				// (poll()'s comment below), so redelivery to THIS device only happens on a future
				// remount (reload), when `sinceRef` resets to `undefined`. Diagnostic only —
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
				const envelopes = await pollMessages(
					sessionToken,
					sinceRef.current?.ts,
					sinceRef.current?.id,
				);
				// Advance the fetch cursor to this page's own last envelope,
				// UNCONDITIONALLY — same fix, same reasoning, as useMessages.ts's
				// identically-named comment (cycle 352): the fetch cursor's job is
				// "don't re-fetch what's already been seen", independent of
				// whether this hook acks/processes each individual envelope.
				// Without this, a page consisting entirely of envelopes this hook
				// skips (Application messages, left to useMessages) or fails to
				// join (undecryptable Welcomes — including a deliberate flood of
				// >`ENVELOPE_POLL_LIMIT` bogus Welcomes from an attacker's own
				// group, zero decrypt success required) would pin this cursor at
				// the identical page forever once `find_pending` started paging
				// the backlog (cycle 351) — a permanent "no new group ever
				// arrives" denial, the exact bug security-auditor caught before
				// this diff merged.
				if (envelopes.length > 0) {
					const last = envelopes[envelopes.length - 1];
					sinceRef.current = { ts: last.created_at, id: last.id };
				}
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
