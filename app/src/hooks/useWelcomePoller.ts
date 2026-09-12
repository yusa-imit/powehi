/**
 * useWelcomePoller — global poll for MLS Welcome envelopes.
 *
 * Fires onNewGroup when a Welcome is successfully processed via mlsJoinGroup
 * in the WASM crypto layer.  Proposal envelopes are acked silently (see the
 * Proposal branch below — an earlier design left them unacked on a
 * now-retracted theory; RFC 9420 §12.4 resolves a by-reference proposal
 * against the receiver's own local proposal store, which this codebase never
 * populates, so leaving the envelope unacked bought no safety and only grew
 * an unbounded backlog).  Commit
 * envelopes are skipped entirely without acking — useMessages.ts (the
 * per-active-group hook) owns Commit processing for its own group, in the
 * SAME poll loop/cursor as its Application decrypt, so the two stay in
 * server-delivery order relative to each other (see useMessages.ts's
 * top-of-module doc comment for why splitting Commit into this separate
 * global poller was tried and reverted — it broke that ordering guarantee:
 * with `max_past_epochs(0)`, a Commit merged on this hook's independent
 * timer could race ahead of an Application message from the same epoch
 * still queued on useMessages.ts's own timer, permanently stranding it).
 * Application envelopes are likewise left untouched for that hook.
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

			if (env.message_type === "Commit") {
				// Commit envelopes are owned by useMessages.ts's per-group poll
				// loop — see this module's top doc comment for why. Safe to leave
				// unacked here: this hook's own fetch cursor still advances past it
				// regardless (poll()'s comment below), and useMessages is a wholly
				// separate hook instance with its own independent cursor,
				// unaffected by this one.
				return;
			}

			if (env.message_type !== "Welcome") {
				// Proposal: ack silently; no content to process in this hook yet.
				// An earlier draft left this unacked (reasoning: a bystander's
				// later `ProposalOrRef::Reference` Commit needs the referenced
				// Proposal envelope to still exist server-side) — RETRACTED after
				// crypto-reviewer verification: RFC 9420 §12.4 resolves a
				// by-reference proposal against the RECEIVER'S OWN LOCAL
				// `MlsGroup::store_pending_proposal` store, never by re-fetching
				// the original Proposal envelope from the Delivery Service. This
				// codebase never calls `store_pending_proposal` at all
				// (`process_incoming_commit`'s doc comment, item (e), mls_group.rs)
				// so a by-reference Commit already fails identically here whether
				// or not the Proposal envelope is still on the server — leaving it
				// unacked bought nothing. It did cost something real: every
				// authenticated member's ordinary Proposal traffic (whether or not
				// ever referenced by a Commit) would accumulate unbounded, unacked,
				// re-paged from the head of the 30-day retention window on every
				// poll tick, chat switch, and reload (`sinceRef` resets on every
				// `groupId` change) — an attacker-growable backlog with no actual
				// safety benefit. Ack it like Commit/Proposal always were before
				// this file's Commit-processing wiring landed; standalone Proposal
				// processing itself remains a separate, still-unwired gap (issue #2
				// follow-up).
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
