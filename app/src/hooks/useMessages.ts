/**
 * useMessages — poll for incoming MLS Application and Commit envelopes for an
 * active group.
 *
 * Polls GET /v1/messages every POLL_INTERVAL_MS.  Application messages for
 * this hook's own group are decrypted via the crypto worker and forwarded to
 * `onMessage`, then acked.  Commit envelopes for this hook's own group are
 * merged via the atomic `mlsProcessCommit` and acked — see the Commit branch
 * below for the full ordering argument (issue #2).  Proposal envelopes are
 * acked silently (out of scope for issue #2).  Welcome envelopes are skipped
 * without acking — useWelcomePoller.ts's global poller owns Welcome (it has
 * no per-group concept to get wrong, and Welcome always arrives before this
 * hook has a `groupId` to be mounted with in the first place).
 *
 * Why Commit is processed HERE, in the SAME poll loop/cursor as Application,
 * rather than in the global useWelcomePoller.ts poller: an earlier attempt
 * moved Commit processing to the global poller specifically because this
 * hook only sees the currently-OPEN group while `pollMessages` returns
 * Commit envelopes for every group — crypto-reviewer flagged that as a real
 * bug (feeding a background group's Commit through this hook's fixed
 * `groupId` would misroute it), but ALSO flagged the two-poller split it
 * introduced as a NEW, more serious bug: this group's MLS Commit and
 * Application streams have independent poll cursors and independent
 * `setInterval(3000)` timers, so nothing guarantees a Commit merges only
 * after every Application envelope from the same or an earlier epoch has
 * already been decrypted. With `max_past_epochs(0)` (see `mls_group.rs`),
 * an epoch's keys are gone the instant a later Commit merges — so a Commit
 * racing ahead of a same-epoch Application message on a separate poll cycle
 * permanently strands that message (`NoPastEpochData`, dropped unacked
 * forever, not just delayed). Filtering Commit to `env.group_id === groupId`
 * here (same filter Application already uses) removes the original
 * misrouting concern WITHOUT re-splitting the stream: both message types
 * for the active group now flow through the same `sinceRef` cursor and the
 * same sequential per-envelope `await` loop in `poll()` below, so they are
 * always processed in the server's delivery order relative to each other.
 * Commit envelopes for a DIFFERENT (background) group are skipped without
 * acking — deferred, not lost: unacked envelopes are only GC'd by the
 * 30-day retention floor, and switching to that group resets `sinceRef`
 * (cycle 353) so its full backlog — Application AND Commit, still in
 * order — is rescanned from the start once it becomes the active chat.
 *
 * Security invariants:
 * - Plaintext is never stored in component state; only the decoded string is
 *   passed to onMessage (react-hooks-only.md, no-plaintext-logging.md).
 * - Commit bytes are passed directly to mlsProcessCommit; never logged or stored.
 * - Decryption errors are swallowed: a stale-epoch envelope cannot disrupt UI.
 * - Polling stops on unmount or when any required context is absent.
 */

import { useEffect, useRef } from "react";
import { type Envelope, ackMessage, pollMessages } from "../api/messages";
import { useAuthStore } from "../store/auth";
import { uint8ToBase64 } from "../utils/base64";
import { MLS_OWN_COMMIT_ERROR, MLS_OWN_COMMIT_PENDING_ERROR } from "../workers/cryptoWorkerErrors";
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
	/** True when this is a §9.4.2 chunked video attachment (large file streaming). */
	chunked?: boolean;
	/** True plaintext length in bytes. Present only when chunked === true. */
	totalSize?: number;
	/** Chunk size in bytes (constant 16 MiB, echoed from the sender). Present only when chunked === true. */
	chunkSize?: number;
	/**
	 * Real sender-side content type (e.g. "video/quicktime"), added cycle-296 alongside
	 * the legacy `type: "image"|"video"` size-bucket tag. Optional for backward
	 * compatibility with envelopes sent by an older client build — when absent, callers
	 * must keep falling back to the `chunked`-based image/video heuristic.
	 */
	mimeType?: string;
}

/**
 * Structural validator for a MediaPayload parsed from untrusted JSON — shared
 * between the live receive path (below) and Dexie rehydration
 * (ChatLayout.tsx) so both reject the same malformed shapes. Checks the same
 * invariants the receive path always has: thumbnail ct/key/iv must be
 * present-and-correctly-sized when a thumbnail is included at all, and
 * totalSize/chunkSize must be valid numbers when chunked === true. Without
 * this, a row a caller wrote via persistOutgoing's optional `media` param (or
 * a corrupted Dexie row) could pass a truthy-but-malformed `thumbnail` through
 * to MediaImage's useThumbnail, which indexes into `thumbnail.key.length`
 * with no try/catch in that call chain.
 */
export function isValidMediaPayload(value: unknown): value is MediaPayload {
	if (value === null || typeof value !== "object") return false;
	const v = value as Record<string, unknown>;
	if (
		typeof v.blobId !== "string" ||
		!Array.isArray(v.blobHash) ||
		!Array.isArray(v.mediaKey) ||
		!Array.isArray(v.iv)
	) {
		return false;
	}
	if (v.thumbnail !== undefined) {
		const t = v.thumbnail as Record<string, unknown> | null;
		if (
			t === null ||
			typeof t !== "object" ||
			!Array.isArray(t.ct) ||
			!Array.isArray(t.key) ||
			!Array.isArray(t.iv) ||
			(t.ct as number[]).length > 16_384 ||
			(t.key as number[]).length !== 32 ||
			(t.iv as number[]).length !== 12
		) {
			return false;
		}
	}
	if (v.chunked === true) {
		if (
			typeof v.totalSize !== "number" ||
			v.totalSize < 0 ||
			typeof v.chunkSize !== "number" ||
			v.chunkSize <= 0
		) {
			return false;
		}
	}
	return true;
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
 * @param onReactionRemove Optional callback invoked when a reaction_remove envelope is received.
 *                         Same signature as onReaction. Peers must only remove their own reactions;
 *                         enforcement is best-effort (validated by emoji allowlist + non-empty id).
 *                         Not forwarded to onMessage.
 * @param onReadReceipt      Optional callback invoked when a read_receipt envelope is received.
 *                           Receives groupId, messageIds (server UUID array, max 100), readAt (unix ms),
 *                           and senderDeviceId. Not forwarded to onMessage.
 * @param onDeliveryReceipt  Optional callback invoked when a delivery_receipt envelope is received.
 *                           Receives groupId, messageIds (server UUID array, max 100), and senderDeviceId.
 *                           Fired when the peer's device received and decrypted the message.
 *                           Not forwarded to onMessage.
 * @param onEdit             Optional callback invoked when an edit envelope is received.
 *                           Receives groupId, targetMessageId (≤36 chars), newText (≤10000 chars),
 *                           and senderDeviceId. Not forwarded to onMessage.
 * @param onDelete           Optional callback invoked when a delete envelope is received.
 *                           Receives groupId and targetMessageId (≤36 chars). Not forwarded to onMessage.
 * @param onPin              Optional callback invoked when a pin or unpin envelope is received.
 *                           Receives groupId, targetMessageId (≤36 chars), and action ("pin"|"unpin").
 *                           Not forwarded to onMessage.
 * @param onPresence         Optional callback invoked when a presence envelope is received.
 *                           Receives groupId and status ("online"|"offline"). Not forwarded to onMessage.
 *                           Heartbeat interval: sender emits every 30 s; receiver times out after 90 s.
 */
export function useMessages(
	identityId: string | undefined,
	groupId: string | undefined,
	onMessage: (msg: IncomingMessage) => void,
	onPqBinding?: (groupId: string, bindingHex: string) => void,
	onTyping?: (groupId: string) => void,
	onReaction?: (groupId: string, targetId: string, emoji: string, senderId: string) => void,
	onReactionRemove?: (groupId: string, targetId: string, emoji: string, senderId: string) => void,
	onReadReceipt?: (
		groupId: string,
		messageIds: string[],
		readAt: number,
		senderDeviceId: string,
	) => void,
	onDeliveryReceipt?: (groupId: string, messageIds: string[], senderDeviceId: string) => void,
	onEdit?: (
		groupId: string,
		targetMessageId: string,
		newText: string,
		senderDeviceId: string,
	) => void,
	onDelete?: (groupId: string, targetMessageId: string) => void,
	onPin?: (groupId: string, targetMessageId: string, action: "pin" | "unpin") => void,
	onPresence?: (groupId: string, status: "online" | "offline") => void,
	/**
	 * Fired once after EVERY successfully merged peer Commit for this hook's
	 * own group (crypto-reviewer HIGH-2) — an Add, a Remove of someone else,
	 * or a Remove of this device itself (`selfEvicted`). Merging a Commit
	 * changes the local MLS roster with no other user-visible signal
	 * anywhere in this hook; a caller MUST use this to invalidate/recompute
	 * anything that assumes the roster is stable (in particular the group
	 * Safety Number — see `ChatLayout.tsx`'s wiring — a merged Commit that
	 * never triggers a recompute would let a stale, pre-Commit fingerprint
	 * keep reading "verified" against a roster it no longer describes).
	 * `selfEvicted` is `false` (not "unknown") if the post-merge active-state
	 * check itself failed — the merge already succeeded either way, so the
	 * caller must still treat the roster as changed; only the eviction
	 * classification is uncertain in that rare case.
	 */
	onGroupChanged?: (groupId: string, selfEvicted: boolean) => void,
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

	const onReactionRemoveRef = useRef(onReactionRemove);
	useEffect(() => {
		onReactionRemoveRef.current = onReactionRemove;
	});

	const onReadReceiptRef = useRef(onReadReceipt);
	useEffect(() => {
		onReadReceiptRef.current = onReadReceipt;
	});

	const onDeliveryReceiptRef = useRef(onDeliveryReceipt);
	useEffect(() => {
		onDeliveryReceiptRef.current = onDeliveryReceipt;
	});

	const onEditRef = useRef(onEdit);
	useEffect(() => {
		onEditRef.current = onEdit;
	});

	const onDeleteRef = useRef(onDelete);
	useEffect(() => {
		onDeleteRef.current = onDelete;
	});

	const onPinRef = useRef(onPin);
	useEffect(() => {
		onPinRef.current = onPin;
	});

	const onPresenceRef = useRef(onPresence);
	useEffect(() => {
		onPresenceRef.current = onPresence;
	});

	const onGroupChangedRef = useRef(onGroupChanged);
	useEffect(() => {
		onGroupChangedRef.current = onGroupChanged;
	});

	// Track the (created_at, id) of the last envelope fully processed, to avoid
	// re-delivering on restart. An exact keyset cursor, not a rounded timestamp
	// — see pollMessages'/find_pending's doc comments (cycle 351).
	const sinceRef = useRef<{ ts: string; id: string } | undefined>(undefined);

	// Per-sender sliding window for reaction/reaction_remove envelopes. Each valid
	// reaction triggers markMessageReactionDelta's exclusive Dexie transaction lock
	// (2 crypto-worker round trips held under lock) — without a bound, a single
	// flooding sender (compromised device, or a peer replaying a batch) can hold that
	// lock often enough to head-of-line-block persistIncoming's putMessage on the same
	// origin. Bounding here drops the *callback*, not the ack, so a flooded reaction
	// past the budget is a real, permanent loss for THIS receiver — not deferred or
	// retried — accepted as the cost of bounding worst-case lock contention to at most
	// ~2 acquisitions/sec/sender; this is a deliberately different failure mode from
	// the malformed/invalid-envelope branches nearby, which discard content that was
	// never valid to begin with. Scope: this only bounds the exclusive-lock-acquisition
	// rate, layered on top of (not a replacement for) `decryptTimestampsRef` below,
	// which bounds the unconditional mlsDecrypt cost every Application envelope pays.
	// It does nothing server-side (queue growth, bandwidth). `reactionTimestampsRef`
	// lives for the hook's whole mount (one instance per logged-in session, `groupId`
	// just changes which chat it polls), so entries are swept in `poll()` below once
	// their window is fully stale — otherwise every distinct sender ever seen across
	// every group opened in this tab would linger in the map for the life of the
	// session.
	const reactionTimestampsRef = useRef<Map<string, number[]>>(new Map());

	// Per-sender sliding window gating the mlsDecrypt call itself — every Application
	// envelope for this group pays a real WASM AEAD decrypt attempt before type
	// dispatch, INCLUDING envelopes that turn out to be garbage/undecryptable (the
	// catch branch below still had to try). Without this, a flooding sender
	// (compromised device, or a peer replaying/forging a batch of ciphertext under
	// the group's known epoch/key material) can force this client to pay N decrypt
	// round trips with no bound at all — the reaction-specific limiter above only
	// covers the subset of envelopes that decrypt successfully AND parse as a
	// reaction. Deliberately more generous than the reaction budget (10/sec vs
	// 2/sec) since this gates ALL envelope types for a sender, including legitimate
	// bursts of real text messages, typing indicators, and receipts — not just the
	// cheap-to-produce, lock-contending reaction path.
	//
	// Over-budget envelopes are DEFERRED, not dropped — pushed onto
	// deferredEnvelopesRef below and retried on a later poll tick once the sender's
	// window has room again, rather than the reaction limiter's ack-but-drop
	// tradeoff. This matters because the server's `find_pending` query has no
	// re-delivery mechanism other than an explicit ack, and (since the cycle 352
	// livelock fix) the fetch cursor now ALWAYS advances past every envelope in a
	// polled page regardless of what this hook does with each one — so silently
	// discarding an envelope here without pushing it to this local queue would make
	// it unrecoverable for the lifetime of this mount. This budget is sized for
	// steady-state live traffic, not backlog catch-up — a single sender who simply
	// left a chat open for ~50 minutes accumulates ~100 presence-heartbeat envelopes
	// alone (one every 30s), which would exhaust the budget on the very next mount's
	// catch-up poll and silently swallow real text messages behind them. Deferral
	// keeps the decrypt-rate ceiling for genuine floods while costing legitimate
	// backlogs only latency (drained across subsequent poll ticks as the window
	// slides, from THIS local queue — not by the server re-sending them, see
	// poll()'s cursor-advance comment), never data loss. Same per-mount-lifetime/
	// sweep shape as `reactionTimestampsRef`.
	const decryptTimestampsRef = useRef<Map<string, number[]>>(new Map());

	// Envelopes deferred by withinDecryptRateLimit above (Application) or by
	// strict per-group head-of-line ordering (Commit — see the Commit branch's
	// comment for why), retried on the next poll tick (merged with that tick's
	// freshly-fetched envelopes, deduped by id — see poll() below). Bounded so a
	// sustained, sender-diverse flood can't grow this unboundedly in memory,
	// EACH message type against its OWN separate cap (MAX_DEFERRED_ENVELOPES for
	// Application, MAX_DEFERRED_COMMITS for Commit — see their definitions
	// below) so a flood of one type can never consume the other's reserved
	// headroom; once a type's own cap is full, a newly-deferred envelope of that
	// type is dropped (this IS a real, logged loss, but only past ~5x one
	// sender's full 10s decrypt budget of Application backlog, or
	// MAX_DEFERRED_COMMITS distinct Commits for the same group, not the ordinary
	// catch-up case above).
	const deferredEnvelopesRef = useRef<Envelope[]>([]);

	// Guards against overlapping poll() ticks — see the effect body's comment
	// where this is consumed for the full ordering argument. Deliberately a ref
	// at HOOK-BODY scope (shared across effect re-runs), not a local `let`
	// inside the effect (F6, crypto-reviewer LOW): this hook has exactly one
	// instance per session — ChatLayout mounts it once, `groupId` just changes
	// which chat it targets — so the effect can re-run (e.g. a `cryptoWorker`
	// or `sessionToken` identity change) WITHOUT the component unmounting. A
	// local `let` re-initialized to `false` on every effect run would let a new
	// run's poll() start immediately even while the PREVIOUS run's poll() is
	// still awaiting an in-flight `mlsProcessCommit`/`mlsDecrypt` call (the
	// `cancelled` flag only stops the loop between envelopes, it does not abort
	// an in-progress `await`) — reintroducing the exact concurrent-poll race
	// this guard exists to close for a re-run that keeps the SAME groupId.
	//
	// Holds the groupId AND a per-effect-run token of the currently in-flight
	// run, or `null` when none is in flight — NOT a bare boolean (fixed
	// post-review: a bare boolean shared across every groupId blocked a
	// brand-new group's very first poll for as long as a DIFFERENT, unrelated
	// group's stale request was still resolving, defeating the cycle 353
	// fix's whole point of an immediate full-backlog rescan on chat switch —
	// confirmed by `useMessages.test.ts`'s "does not let a stale in-flight
	// poll from the OLD group clobber the cursor after a groupId switch"
	// regression test). Keying by groupId ALONE is also insufficient — fixed
	// post-review a second time (F9): an A -> B -> A group-switch sequence
	// creates a SEPARATE effect run each time groupId changes, so the run for
	// the SECOND visit to A has a different closure than the run for the
	// FIRST visit, but both closures see the identical groupId string "A".
	// If the first visit's poll is still resolving (e.g. a slow network
	// round trip) when the user has already switched away and back, its
	// `finally` block would see `pollInFlightRef.current`'s groupId equal to
	// its own captured groupId and incorrectly clear the SECOND visit's
	// legitimately in-flight claim — reopening the exact concurrent-poll
	// race this guard exists to close, just via a same-group revisit instead
	// of a same-group re-run. `run` is a per-effect-run token (see
	// `runTokenRef` below) unique across every mount of this effect,
	// including two mounts for the same groupId — so a stale run's `finally`
	// only clears the slot if `run` ALSO still matches, which is false once a
	// newer run for the same group has claimed it.
	const pollInFlightRef = useRef<{ groupId: string; run: number } | null>(null);
	// Monotonic counter handed out one value per effect run (below), used
	// only to give `pollInFlightRef` a value that is unique per mount even
	// when `groupId` repeats (see that ref's doc comment, F9).
	const runTokenRef = useRef(0);

	useEffect(() => {
		if (!sessionToken || !identityId || !groupId || !cryptoWorker) return;

		// This hook has exactly one instance per logged-in session — ChatLayout
		// mounts it once, `groupId` just changes which chat it targets as the user
		// switches chats; it is NOT remounted per group. Reset the fetch cursor and
		// the group-scoped deferred queue on every effect run (in particular, every
		// groupId change) so a chat switch behaves like the fresh-mount full-backlog
		// rescan the rest of this file assumes. Without this, the cycle 352 livelock
		// fix's unconditional cursor advance (see poll() below) permanently skips
		// any cross-group envelope that arrived while a DIFFERENT group was active,
		// since — contrary to this file's prior assumption — no OTHER mounted
		// instance exists to ever re-fetch it. Confirmed and fixed cycle 353
		// (threat-model-checker RED finding on the cycle 352 diff).
		sinceRef.current = undefined;
		deferredEnvelopesRef.current = [];

		let cancelled = false;
		// Unique per effect run, including a second run for a repeated groupId
		// (F9) — see `pollInFlightRef`'s doc comment above for why a bare
		// groupId string is not enough to tell two mounts of the same group
		// apart.
		const runToken = ++runTokenRef.current;
		// Guards against overlapping poll() ticks during backlog catch-up: the
		// fetch cursor (sinceRef) advances to a page's last envelope BEFORE the
		// page finishes processing (intentional — see poll()'s own comment,
		// cycle 352 livelock fix). If a decrypt/ack round trip for page N is
		// still in flight when the next setInterval tick fires, that tick would
		// see the already-advanced cursor and start fetching/processing page
		// N+1 CONCURRENTLY with page N — racing the strict Application-then-
		// Commit-per-group delivery ordering this hook's whole design depends
		// on (see this file's top-of-module doc comment). Under
		// `max_past_epochs(0)`, a Commit from page N+1 merging before a
		// same-epoch Application envelope in page N has finished decrypting
		// permanently strands that message. `pollInFlightRef` (hook-body scope,
		// keyed by groupId — see its own doc comment for why NOT a bare
		// boolean, and why NOT a local variable here) closes this both within
		// one effect run AND across a same-instance, same-groupId effect
		// re-run (F6, crypto-reviewer LOW) — a re-run for a DIFFERENT groupId
		// (an ordinary chat switch) is deliberately NOT blocked by this guard.

		const REACTION_RATE_WINDOW_MS = 10_000;
		const REACTION_RATE_MAX = 20;

		const withinReactionRateLimit = (senderId: string): boolean => {
			const now = Date.now();
			const recent = (reactionTimestampsRef.current.get(senderId) ?? []).filter(
				(t) => now - t < REACTION_RATE_WINDOW_MS,
			);
			if (recent.length >= REACTION_RATE_MAX) {
				reactionTimestampsRef.current.set(senderId, recent);
				return false;
			}
			recent.push(now);
			reactionTimestampsRef.current.set(senderId, recent);
			return true;
		};

		// Bound reactionTimestampsRef's memory to currently-active senders: drop any
		// entry whose timestamps have all aged out of the window. Run once per poll
		// tick (not per envelope) — cheap, map size is bounded by recent distinct
		// senders, not by message volume.
		const sweepStaleReactionRateEntries = (): void => {
			const now = Date.now();
			for (const [senderId, timestamps] of reactionTimestampsRef.current) {
				if (!timestamps.some((t) => now - t < REACTION_RATE_WINDOW_MS)) {
					reactionTimestampsRef.current.delete(senderId);
				}
			}
		};

		const DECRYPT_RATE_WINDOW_MS = 10_000;
		const DECRYPT_RATE_MAX = 100;
		const MAX_DEFERRED_ENVELOPES = 500;
		// Commit envelopes get their OWN reserved bound, separate from
		// MAX_DEFERRED_ENVELOPES above (F2, crypto-reviewer HIGH): a legitimate
		// eviction Commit for this group must never be dropped just because an
		// Application-envelope flood from the very device that Commit is about
		// to evict has already filled the shared queue. At most one Commit per
		// epoch can ever legitimately be outstanding for a live group, so a
		// handful of slots is generous headroom for benign reordering/backlog,
		// while still bounding an attacker who floods FAKE Commit-typed
		// envelopes (this check runs before any signature/content
		// verification, so message_type alone is attacker-controlled).
		const MAX_DEFERRED_COMMITS = 16;
		// Per-SENDER sub-cap on MAX_DEFERRED_COMMITS above (F10,
		// crypto-reviewer HIGH — closes a gap the F2 fix left open): `sender`
		// is the authenticated device_id that submitted the envelope (stamped
		// server-side, unlike `message_type`, which is not verified until this
		// hook actually attempts `mlsProcessCommit`), so bounding the reserved
		// pool per sender means a SINGLE compromised or malicious device can
		// never occupy more than its own share of it. Without this, one
		// device sending MAX_DEFERRED_COMMITS junk Commit-typed envelopes
		// (trivial — `message_type` alone gates this branch, no signature or
		// content check has run yet) fills the entire reserved pool and
		// causes a LATER, genuinely legitimate Commit from a DIFFERENT
		// sender (e.g. an admin's real eviction of that very device) to be
		// silently dropped — deterministically defeating the PCS property
		// this wiring exists to provide, exactly the failure mode
		// MAX_DEFERRED_COMMITS alone was meant to prevent, just moved from
		// "any sender" to "one sender at a time". A small cap is enough once
		// the pool is actually contested by more than one sender: only one
		// Commit per epoch can ever legitimately be outstanding for a live
		// group (see MAX_DEFERRED_COMMITS's own comment above).
		//
		// This cap is a FAIRNESS bound among competing senders, not an
		// independent memory bound (fixed post-review, crypto-reviewer B1):
		// the check site below only enforces it once `deferredCommits.length
		// >= MAX_DEFERRED_COMMITS` — a single legitimate sender's backlog
		// (e.g. catching up on many real epoch changes after being offline)
		// can fill the WHOLE reserved pool with no rejection as long as no
		// other sender is contending for it. Applying this cap unconditionally,
		// before checking whether the pool even has room, previously dropped
		// a single busy sender's 5th+ legitimate backlog Commit outright (no
		// eviction fallback exists for a sender's own entries) — permanently
		// stranding every later Commit for the group under `max_past_epochs(0)`
		// with no attacker involved. See the check site for the corrected
		// ordering.
		const MAX_DEFERRED_COMMITS_PER_SENDER = 4;

		const withinDecryptRateLimit = (senderId: string): boolean => {
			const now = Date.now();
			const recent = (decryptTimestampsRef.current.get(senderId) ?? []).filter(
				(t) => now - t < DECRYPT_RATE_WINDOW_MS,
			);
			if (recent.length >= DECRYPT_RATE_MAX) {
				decryptTimestampsRef.current.set(senderId, recent);
				return false;
			}
			recent.push(now);
			decryptTimestampsRef.current.set(senderId, recent);
			return true;
		};

		const sweepStaleDecryptRateEntries = (): void => {
			const now = Date.now();
			for (const [senderId, timestamps] of decryptTimestampsRef.current) {
				if (!timestamps.some((t) => now - t < DECRYPT_RATE_WINDOW_MS)) {
					decryptTimestampsRef.current.delete(senderId);
				}
			}
		};

		// Bounded retry for the ack immediately following a successful peer
		// Commit merge (N1, crypto-reviewer nit): unlike every other ack in
		// this hook, losing THIS one is not simply "retried harmlessly on the
		// next poll" — MLS commit merging is not idempotent, so a later
		// re-delivery of the same already-merged peer Commit (its ack never
		// landed) fails openmls's wrong-epoch check and surfaces as the
		// generic commit_process_failed/Decrypt path forever, never the
		// safe-to-ack MLS_OWN_COMMIT_ERROR branch (that hash-tracking only
		// covers THIS device's own commits, not a peer's). A few bounded
		// retries close most of the transient-network-failure window without
		// becoming an unbounded retry loop (Tiger Style: put a limit on
		// everything); a still-unacked envelope after all attempts is no
		// worse than this hook's existing genuine-failure handling elsewhere.
		const MAX_ACK_RETRIES = 3;
		const ackAfterMergeWithRetry = async (envId: string): Promise<void> => {
			for (let attempt = 0; attempt < MAX_ACK_RETRIES; attempt++) {
				try {
					await ackMessage(sessionToken, envId);
					return;
				} catch {
					if (attempt < MAX_ACK_RETRIES - 1) {
						await new Promise((resolve) => setTimeout(resolve, 250 * (attempt + 1)));
					}
				}
			}
			// Diagnostic only — groupId is an opaque server-assigned UUID, never
			// content/PII. The commit is already merged locally; only the ack
			// failed, so a future rescan will hit the (harmless but permanent)
			// wrong-epoch Decrypt path described above for this one envelope.
			console.error("commit_ack_failed_after_merge", groupId);
		};

		const processEnvelope = async (env: Envelope): Promise<void> => {
			if (env.message_type === "Welcome") {
				// Welcome envelopes are handled by useWelcomePoller — do not ack here.
				return;
			}
			if (env.message_type === "Commit") {
				if (env.group_id !== groupId) {
					// Commit for a group other than the one this hook instance is
					// bound to — see this file's top-of-module doc comment for why
					// this hook (not a separate global poller) owns Commit, and why
					// an off-group Commit is deferred (left unacked) rather than
					// misrouted against the wrong MLS group state.
					return;
				}
				// Strict per-group head-of-line ordering (F1, crypto-reviewer HIGH):
				// a Commit must defer itself whenever ANYTHING is already sitting in
				// the deferred queue — checked FIRST, before the per-sender rate
				// limit, so a queue-non-empty defer never also consumes this
				// sender's decrypt-rate budget for nothing (F7). A non-empty queue
				// always means same-group work is outstanding (only this hook's
				// bound `groupId` is ever pushed onto it — off-group envelopes
				// `return` above before reaching either check), so deferring the
				// Commit behind it preserves delivery order relative to whatever is
				// already queued — INCLUDING a same-group Application envelope from
				// a DIFFERENT sender than the one that got deferred, which the
				// Application branch below must (and does, as of this fix) defer
				// itself behind for the identical reason: without deferring on the
				// Application side too, an unrelated sender's Application envelope
				// arriving later in the SAME page would decrypt immediately (its own
				// rate budget untouched), racing ahead of an earlier-in-delivery-
				// order Commit or Application entry now sitting in the queue — under
				// this group's `max_past_epochs(0)`, a Commit racing ahead of a
				// same-epoch Application message this way permanently strands it.
				// This terminates: `deferredEnvelopesRef.current` is drained at the
				// top of every tick and re-processed FIRST, in order, ahead of any
				// newly-fetched envelope (see poll()'s `combined` merge below) — a
				// still-blocked earlier envelope re-defers itself and everything
				// after it (Commit or Application) re-defers right behind it, until
				// the earlier envelope's rate-limit window frees up and it drains.
				//
				// The deferred-queue capacity check below uses a SEPARATE, smaller
				// bound (MAX_DEFERRED_COMMITS) than the Application branch's
				// MAX_DEFERRED_ENVELOPES (F2, crypto-reviewer HIGH): sharing one
				// capacity would let an Application-envelope flood from the very
				// device a Commit is about to evict fill the queue and force this
				// Commit to be silently dropped — deterministically suppressing its
				// own eviction, defeating the PCS property this wiring exists to
				// provide. Counting only Commit-typed entries against this bound
				// (not the queue's total length) means an Application flood can
				// never consume a Commit's reserved headroom. A SECOND, per-sender
				// sub-cap (MAX_DEFERRED_COMMITS_PER_SENDER, F10) additionally
				// bounds how much of THIS reserved pool a single sender can
				// occupy — see that constant's doc comment for why: without it, a
				// single sender flooding fake Commit-typed envelopes (this check
				// runs before any content verification) can alone exhaust the
				// whole reserved pool and starve out a legitimate Commit from a
				// DIFFERENT sender arriving later in the same page.
				//
				// A per-sender sub-cap alone is still bypassable by enough DISTINCT
				// senders (crypto-reviewer HIGH-1): MAX_DEFERRED_COMMITS /
				// MAX_DEFERRED_COMMITS_PER_SENDER colluding or compromised senders
				// can each fill their own share and jointly exhaust the whole pool
				// before a genuine Commit from yet another sender ever arrives. On
				// overflow, evict-oldest-from-the-largest-current-holder (below)
				// closes this: a newly-arriving sender with FEWER entries already
				// queued than some other sender is always entitled to bump that
				// other sender's oldest entry rather than being rejected outright —
				// so an admin's first eviction Commit for this group (0 entries of
				// its own) can always displace an existing entry as long as anyone
				// else holds more than 0, regardless of how many distinct senders
				// contributed the flood. Evicting only ever removes a Commit-typed
				// entry (never an Application one) and never reorders the entries
				// that remain, so it cannot violate the head-of-line ordering
				// argument above.
				if (deferredEnvelopesRef.current.length > 0 || !withinDecryptRateLimit(env.sender)) {
					const deferredCommits = deferredEnvelopesRef.current.filter(
						(e) => e.message_type === "Commit",
					);
					const deferredCommitCountForSender = deferredCommits.filter(
						(e) => e.sender === env.sender,
					).length;
					// Pool-fullness gates the per-sender fairness cap — checked in
					// THIS order, not the reverse (fixed post-review, crypto-reviewer
					// B1): `MAX_DEFERRED_COMMITS_PER_SENDER` exists ONLY to keep one
					// sender from starving OTHER senders once the shared pool is
					// actually contested (see that constant's doc comment); it is not
					// an independent memory bound — `MAX_DEFERRED_COMMITS` already is
					// one, and is sized "generous headroom for benign
					// reordering/backlog" on its own terms. The previous ordering ran
					// the per-sender check FIRST, unconditionally, so a single
					// legitimate committer's backlog (e.g. catching up on >4 epochs
					// of real admin activity after being offline) hit this reject
					// branch well before the pool had any real contention — with no
					// eviction fallback, since eviction never targets a sender's own
					// entries, that Commit was silently dropped, out of order,
					// permanently stranding every later Commit for this group under
					// `max_past_epochs(0)`, with no attacker involved at all. Gating
					// on pool-fullness first lets a single busy sender fill up to the
					// full reserved pool during legitimate backlog catch-up; the
					// fairness cap only starts rejecting/evicting once OTHER senders
					// are actually competing for the same slots — exactly the
					// multi-sender starvation scenario it was designed for.
					if (deferredCommits.length >= MAX_DEFERRED_COMMITS) {
						if (deferredCommitCountForSender >= MAX_DEFERRED_COMMITS_PER_SENDER) {
							// This sender already holds its own full share of the
							// reserved pool — never evict on its behalf, or a single
							// sender could unboundedly churn other senders' entries by
							// repeatedly re-sending.
							console.error("commit_process_deferred_queue_full", env.sender);
							return;
						}
						const perSenderCounts = new Map<string, number>();
						for (const e of deferredCommits) {
							perSenderCounts.set(e.sender, (perSenderCounts.get(e.sender) ?? 0) + 1);
						}
						let evictSender: string | null = null;
						let evictCount = deferredCommitCountForSender;
						for (const [sender, count] of perSenderCounts) {
							if (sender !== env.sender && count > evictCount) {
								evictSender = sender;
								evictCount = count;
							}
						}
						if (evictSender === null) {
							// Every other sender already holds AT MOST as many
							// slots as this one would — the pool is as fairly
							// saturated as it can get. Drop this arrival instead.
							console.error("commit_process_deferred_queue_full", env.sender);
							return;
						}
						const evictIndex = deferredEnvelopesRef.current.findIndex(
							(e) => e.message_type === "Commit" && e.sender === evictSender,
						);
						// Defensive (N2, crypto-reviewer nit): evictSender is derived
						// from deferredCommits, itself a filtered snapshot of this same
						// array, so evictIndex should always be found — but an
						// unguarded -1 here would splice the LAST element (the newest
						// entry, possibly this tick's own arrival) instead of the
						// intended victim. Drop defensively rather than risk that.
						if (evictIndex === -1) {
							console.error("commit_process_deferred_queue_full", env.sender);
							return;
						}
						deferredEnvelopesRef.current.splice(evictIndex, 1);
						// Diagnostic only — evictSender is an opaque device UUID.
						console.error("commit_process_deferred_queue_evicted", evictSender);
					}
					deferredEnvelopesRef.current.push(env);
					return;
				}
				try {
					const commitBytes = new Uint8Array(env.ciphertext);
					await cryptoWorker.mlsProcessCommit(identityId, groupId, commitBytes);
					try {
						// mls_process_commit's doc comment: a Commit that removes the
						// caller's OWN leaf still returns Ok — the caller MUST
						// separately detect eviction via `mlsGroupIsActive` (openmls's
						// own group-active state), NOT via `mlsGroupMembers`'s `isSelf`
						// leaf-index comparison — RFC 9420 §12.1.1 fills the leftmost
						// BLANK leaf on Add, and §12.3 applies Remove before Add within
						// one Commit, so a "kick and replace" Commit can land the NEW
						// member's leaf exactly on this device's just-vacated index,
						// making `isSelf` (incorrectly) true and silently missing the
						// eviction. Best-effort: a failure here must not turn an
						// already-successfully-merged Commit into an unacked retry loop.
						const active = await cryptoWorker.mlsGroupIsActive(identityId, groupId);
						if (!active) {
							// Diagnostic only — groupId is an opaque server-assigned UUID,
							// never content/PII.
							console.error("commit_self_evicted", groupId);
						}
						// Fired for EVERY merge, not just eviction — an Add also changes
						// the roster and must invalidate anything (e.g. the group Safety
						// Number) that assumes it is stable (crypto-reviewer HIGH-2).
						onGroupChangedRef.current?.(groupId, !active);
					} catch (evictionCheckErr) {
						// Self-eviction check is best-effort diagnostics only — a
						// failure here (F8, crypto-reviewer nit) must not turn an
						// already-successfully-merged Commit into an unacked retry
						// loop, but it must not be silently swallowed either, or a
						// forced eviction could go completely unnoticed. Diagnostic
						// only — never content/PII.
						console.error(
							"commit_self_evicted_check_failed",
							evictionCheckErr instanceof Error ? evictionCheckErr.name : typeof evictionCheckErr,
						);
						// The merge itself still succeeded (only the eviction check
						// failed) — the roster changed regardless, so still fire this.
						// `false` here is a conservative default, not a claim the
						// device was NOT evicted: it just means that classification is
						// unknown in this rare double-failure case.
						onGroupChangedRef.current?.(groupId, false);
					}
					await ackAfterMergeWithRetry(env.id);
				} catch (err) {
					if (err instanceof Error && err.message === MLS_OWN_COMMIT_ERROR) {
						// Case 2 (hash-verified, post-merge): this crate's own
						// tracking confirms these exact bytes are a commit THIS
						// device already merged — already applied locally, so
						// there is nothing to merge. Safe to ack. See
						// cryptoWorkerErrors.ts's MLS_OWN_COMMIT_ERROR doc comment.
						await ackMessage(sessionToken, env.id).catch(() => {});
						return;
					}
					if (err instanceof Error && err.message === MLS_OWN_COMMIT_PENDING_ERROR) {
						// Case 1 (openmls's own pre-merge signal, UNVERIFIED and
						// forgeable by any current group member — see
						// cryptoWorkerErrors.ts's MLS_OWN_COMMIT_PENDING_ERROR doc
						// comment, crypto-reviewer F3). Unlike the Case 2 branch
						// above, "already applied" does NOT hold here: a genuine
						// pre-confirm echo of this device's own staged commit is
						// still only staged, not merged, so acking would delete the
						// Delivery Service's only copy before this device ever
						// applies it — and a forged message would never have been
						// this device's own commit at all. Treat exactly like any
						// other rejection below: do not ack, log a content-free
						// diagnostic, let the unacked-envelope retry path (a future
						// poll, remount, or chat switch) handle it.
						console.error("commit_own_pending_unverified", groupId);
						return;
					}
					// Genuine failure (fork, stale epoch, decrypt error) — do NOT
					// ack, same reasoning as message_decrypt_failed below: the
					// 30-day retention floor eventually GCs it server-side, and
					// this hook's own fetch cursor still advances past it
					// regardless (poll()'s comment), so redelivery only happens on
					// a future remount or a switch away from and back to this
					// chat. Diagnostic only — never ciphertext/content.
					console.error(
						"commit_process_failed",
						err instanceof Error ? err.name : typeof err,
						err instanceof Error ? err.message : String(err),
					);
				}
				return;
			}
			if (env.message_type === "Proposal") {
				// Ack silently — see useWelcomePoller.ts's Proposal branch for the
				// full argument (retracted F5): leaving Proposal envelopes unacked
				// bought no real safety (RFC 9420 §12.4's `ProposalOrRef::Reference`
				// resolves against the receiver's own LOCAL `store_pending_proposal`
				// state, which this codebase never populates, not against a
				// re-fetch of the original envelope) while growing an unbounded,
				// attacker-inflatable backlog. Proposal processing itself remains a
				// separate, still-unwired gap (issue #2 follow-up).
				await ackMessage(sessionToken, env.id).catch(() => {});
				return;
			}
			if (env.message_type !== "Application") {
				return;
			}
			if (env.group_id !== groupId) {
				// Application envelope for a group other than the one this hook
				// instance is bound to (e.g. a background chat while a different
				// chat is active, or the pre-selection window before a real chat
				// is opened). Only ONE useMessages instance exists per session — its
				// `groupId` target changes as the user switches chats, it is NOT
				// remounted per group — and `pollMessages` returns envelopes across
				// ALL of the identity's groups — so acking here would permanently
				// delete a message before its own group is ever active.
				// root-caused in the cycle-293 message.spec.ts CI investigation:
				// the bug this replaced acked these away unconditionally, which
				// silently destroyed real cross-group messages, not just the E2E
				// seed-chat artifact. Leave unacked (mirrors useWelcomePoller's
				// existing "skip Application, don't touch it" contract) so this same
				// instance can pick it up once its target group changes — safe even
				// though THIS poll tick's fetch cursor advances past it
				// unconditionally (poll()'s comment) BECAUSE the effect resets
				// `sinceRef` on every groupId change (see the effect's top-of-body
				// comment, cycle 353 fix) — switching to this envelope's group later
				// re-scans the whole backlog from the beginning. Without that reset,
				// this envelope would be permanently unreachable once skipped —
				// confirmed and fixed cycle 353 (threat-model-checker/security-auditor
				// RED/HIGH finding on the cycle 352 diff).
				// Diagnostic only — env.group_id/groupId are opaque server-assigned
				// UUIDs, never PII/content (no-plaintext-logging.md allowance).
				console.error("message_group_mismatch", env.group_id, groupId);
				return;
			}

			// Strict per-group head-of-line ordering (F1, crypto-reviewer HIGH): defer
			// whenever the queue is already non-empty, checked FIRST so it never also
			// consumes this sender's decrypt-rate budget for nothing (F7) — mirrors
			// the Commit branch above, and for the identical reason: without this, an
			// unrelated sender's fresh-budget Application envelope arriving later in
			// the SAME page would decrypt immediately, racing ahead of an
			// earlier-in-delivery-order entry (Application OR Commit) already
			// deferred — under this group's `max_past_epochs(0)`, an Application
			// envelope racing ahead of an earlier same-epoch Commit (or vice versa)
			// can permanently strand it. See the Commit branch's comment for the full
			// argument; this is its Application-side half, closing the asymmetry a
			// prior version of this file left open.
			if (deferredEnvelopesRef.current.length > 0 || !withinDecryptRateLimit(env.sender)) {
				// Deferred instead of dropped (see deferredEnvelopesRef's doc comment
				// for why: dropping here risked silently losing legitimate backlog,
				// not just floods). Retried on a later poll tick once the queue drains
				// and/or the sender's rate window has room again. Counts only
				// Application-typed entries against MAX_DEFERRED_ENVELOPES — Commit
				// entries have their own separate, smaller reserved bound
				// (MAX_DEFERRED_COMMITS, see the Commit branch above) so an
				// Application flood can never consume a Commit's reserved headroom.
				const deferredApplicationCount = deferredEnvelopesRef.current.filter(
					(e) => e.message_type !== "Commit",
				).length;
				if (deferredApplicationCount < MAX_DEFERRED_ENVELOPES) {
					deferredEnvelopesRef.current.push(env);
				} else {
					// Diagnostic only, no envelope content — env.sender is an opaque
					// server-assigned device UUID (no-plaintext-logging.md allowance,
					// same as message_group_mismatch above).
					console.error("message_decrypt_deferred_queue_full", env.sender);
				}
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
				let textTtl: number | undefined;
				let shouldDisplayMessage = true;
				try {
					const parsed = JSON.parse(decoded) as Record<string, unknown>;
					if (parsed.type === "image" && isValidMediaPayload(parsed)) {
						text = "[image]";
						// mimeType is a display-only hint, not validated by isValidMediaPayload —
						// sanitize separately rather than making the whole payload's validity
						// (and thus whether the image displays at all) depend on this one field.
						// Built explicitly (not spread) so no stray fields (e.g. `type`) leak
						// from the untrusted `parsed` record into the stored MediaPayload.
						media = {
							blobId: parsed.blobId,
							blobHash: parsed.blobHash,
							mediaKey: parsed.mediaKey,
							iv: parsed.iv,
							thumbnail: parsed.thumbnail,
							mimeType: typeof parsed.mimeType === "string" ? parsed.mimeType : undefined,
						};
					} else if (
						parsed.type === "video" &&
						parsed.chunked === true &&
						isValidMediaPayload(parsed)
					) {
						// §9.4.2: chunked video attachment. No inline thumbnail this cycle
						// (§9.4.1 thumbnails are image-only) — do not invent one.
						text = "[video]";
						media = {
							blobId: parsed.blobId,
							blobHash: parsed.blobHash,
							mediaKey: parsed.mediaKey,
							iv: parsed.iv,
							chunked: true,
							totalSize: parsed.totalSize,
							chunkSize: parsed.chunkSize,
							mimeType: typeof parsed.mimeType === "string" ? parsed.mimeType : undefined,
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
							parsed.targetMessageId.length > 0 &&
							parsed.targetMessageId.length <= 36 &&
							withinReactionRateLimit(env.sender)
						) {
							onReactionRef.current?.(groupId, parsed.targetMessageId, parsed.emoji, env.sender);
						}
					} else if (parsed.type === "reaction_remove") {
						// Reaction removal — remove sender's emoji from the target message.
						shouldDisplayMessage = false;
						if (
							typeof parsed.emoji === "string" &&
							typeof parsed.targetMessageId === "string" &&
							(ALLOWED_REACTION_EMOJIS as readonly string[]).includes(parsed.emoji) &&
							parsed.targetMessageId.length > 0 &&
							parsed.targetMessageId.length <= 36 &&
							withinReactionRateLimit(env.sender)
						) {
							onReactionRemoveRef.current?.(
								groupId,
								parsed.targetMessageId,
								parsed.emoji,
								env.sender,
							);
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
					} else if (parsed.type === "edit") {
						// Message edit — never displayed as a new message; callback only when params are valid.
						shouldDisplayMessage = false;
						if (
							typeof parsed.targetMessageId === "string" &&
							parsed.targetMessageId.length > 0 &&
							parsed.targetMessageId.length <= 36 &&
							typeof parsed.newText === "string" &&
							parsed.newText.length > 0 &&
							parsed.newText.length <= 10_000
						) {
							onEditRef.current?.(groupId, parsed.targetMessageId, parsed.newText, env.sender);
						}
					} else if (parsed.type === "delete") {
						// Message delete — never displayed as a new message; callback only when targetMessageId is valid.
						shouldDisplayMessage = false;
						if (
							typeof parsed.targetMessageId === "string" &&
							parsed.targetMessageId.length > 0 &&
							parsed.targetMessageId.length <= 36
						) {
							onDeleteRef.current?.(groupId, parsed.targetMessageId);
						}
					} else if (parsed.type === "pin" || parsed.type === "unpin") {
						// Pin/unpin — never displayed as a message; callback only when targetMessageId is valid.
						shouldDisplayMessage = false;
						if (
							typeof parsed.targetMessageId === "string" &&
							parsed.targetMessageId.length > 0 &&
							parsed.targetMessageId.length <= 36
						) {
							onPinRef.current?.(groupId, parsed.targetMessageId, parsed.type);
						}
					} else if (parsed.type === "presence") {
						// Presence heartbeat — never displayed as a message; strict allowlist on status.
						shouldDisplayMessage = false;
						if (parsed.status === "online" || parsed.status === "offline") {
							onPresenceRef.current?.(groupId, parsed.status);
						}
					} else if (parsed.type === "text" && typeof parsed.text === "string") {
						// Structured text message — may include a reply context and/or TTL.
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
						// Receiver-side disappearing timer: sender embeds TTL (seconds) so the
						// receiver can set its own expiry without the server seeing the duration.
						if (
							typeof parsed.ttl === "number" &&
							Number.isFinite(parsed.ttl) &&
							parsed.ttl > 0 &&
							parsed.ttl <= 604_800
						) {
							textTtl = parsed.ttl as number;
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
					// Receiver-side TTL from encrypted payload takes precedence over server-set expires_at.
					// The server never sees plaintext TTL; the receiver derives its own expiry on decryption.
					const serverExpiresAt = env.expires_at ? new Date(env.expires_at).getTime() : undefined;
					const expiresAt = textTtl !== undefined ? Date.now() + textTtl * 1000 : serverExpiresAt;
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
			} catch (err) {
				// Decryption failure (wrong epoch, tampered, etc.) — skip envelope.
				// Do NOT ack: acking a message this client couldn't read could mask a
				// real delivery bug. NOTE: this does NOT mean the server GCs it via
				// TTL — `expires_at` is only ever set for disappearing messages (every
				// current send path posts `ttl_seconds: undefined` otherwise), so an
				// un-acked, non-disappearing envelope stays server-side indefinitely
				// (subject only to the 30-day default retention floor, cycle 350).
				// Since the cycle 352 livelock fix, THIS group's fetch cursor still
				// advances past it (poll()'s comment) — retrying every 3s gains
				// nothing for a genuinely-undecryptable envelope (wrong epoch/
				// tampered, not a transient failure) — so redelivery now only happens
				// on a full page reload, OR on switching away from and back to this
				// chat (the cycle 353 fix resets `sinceRef` on every groupId change,
				// since this hook is one long-lived instance whose target group
				// changes at runtime rather than remounting per chat — see the
				// effect's own top-of-body comment). Deferred to that later attempt,
				// not GC'd. A rare genuinely-transient failure here (as opposed to a
				// permanent wrong-epoch/tampered one) still has no automatic in-mount
				// retry — accepted, not fixed this cycle (next-cycle candidate).
				// Diagnostic only — err.name/message here is always an internal error
				// code (a WASM/wasm-bindgen error string describing which crypto step
				// failed), never message content, PII, or ciphertext — same allowance
				// AcceptInviteModal.tsx's accept_invite_failed and useWelcomePoller.ts's
				// welcome_join_failed already rely on. Closes the last silent-failure
				// gap in the message.spec.ts CI investigation (cycles 282-289): if a
				// real Application message for the active group is failing to decrypt,
				// this line will show it on the next CI run instead of leaving the
				// 30s toBeVisible timeout as the only signal.
				console.error(
					"message_decrypt_failed",
					err instanceof Error ? err.name : typeof err,
					err instanceof Error ? err.message : String(err),
				);
			}
			// NOTE: the resume cursor is advanced by poll() below, to the fetched
			// page's own last envelope — NOT here, per-envelope. See poll()'s
			// comment for why (cycle 352 fix for a livelock security-auditor
			// found in the cycle 351 pagination diff).
		};

		const poll = async () => {
			if (cancelled || pollInFlightRef.current?.groupId === groupId) return;
			pollInFlightRef.current = { groupId, run: runToken };
			try {
				const envelopes = await pollMessages(
					sessionToken,
					sinceRef.current?.ts,
					sinceRef.current?.id,
				);
				// Re-check cancelled AFTER the await: this closure's `cancelled` is
				// captured per effect-run, but `sinceRef`/`deferredEnvelopesRef` are
				// SHARED across runs (declared outside the effect, reset at the top of
				// each new run — see the cycle 353 fix above). Without this guard, a
				// poll started by the OLD run (e.g. right before a groupId switch) can
				// resolve AFTER the new run has already reset the cursor, and
				// unconditionally overwrite it with the old group's stale page tail —
				// reopening the exact permanent-cross-group-message-loss bug the reset
				// was meant to close, and for longer than before this fix (a chat
				// switch now requests a full head-of-backlog page instead of a near-
				// empty tail one, so the old run's in-flight request stays live
				// longer). threat-model-checker cycle 353 (verification round).
				if (cancelled) return;
				// Advance the fetch cursor to this page's own last envelope,
				// UNCONDITIONALLY — regardless of whether every envelope in it ends
				// up acked/processed below. `find_pending` (backend) now pages the
				// backlog (`ENVELOPE_POLL_LIMIT`, cycle 351/352), returning an exact
				// (created_at, id)-ordered PREFIX of it, so once this page has been
				// fetched, every envelope up to and including its last one has been
				// SEEN — the fetch cursor's only job is "don't re-fetch what's
				// already been looked at", independent of whatever this hook chooses
				// to DO with each one (ack it, defer it, or leave it for a different
				// poller instance).
				//
				// This closes a livelock security-auditor found in the cycle 351
				// pagination diff, where the OLD per-envelope advance (inside
				// processEnvelope, only reached past several early `return`s) let a
				// page consisting entirely of envelopes this hook doesn't act on —
				// a different group's Application messages, Welcomes (handled by
				// useWelcomePoller's own separately-cursored instance), or
				// decrypt-rate-deferred ones — pin the cursor forever: the next poll
				// would re-fetch the IDENTICAL page, forever, since nothing ever
				// advanced past it. Before `ENVELOPE_POLL_LIMIT` existed this was
				// harmless (every poll fetched the WHOLE backlog regardless), but
				// paging turned it into a real, even attacker-triggerable (a peer
				// sending >`ENVELOPE_POLL_LIMIT` Welcomes to a victim's own group
				// wedges this hook's cursor with zero decrypt required) denial of
				// message delivery that persists across reload (`sinceRef` resets to
				// `undefined`, but the server still returns the same wedged head-of-
				// queue page). Safe because:
				//   - This hook has exactly ONE instance per session — its `groupId`
				//     target changes at runtime as the user switches chats, it does
				//     NOT remount per group (ChatLayout.tsx mounts it once). The
				//     effect resets `sinceRef` (and the deferred queue) on every
				//     groupId change (see the effect's top-of-body comment, cycle 353
				//     fix), so switching to the group this envelope belongs to
				//     re-scans the ENTIRE backlog from the beginning. An earlier draft
				//     of this comment incorrectly assumed a SEPARATE mounted instance
				//     existed per group and would independently rescan on its own —
				//     that assumption was false and caused a real cross-group
				//     message-loss regression until the cycle 353 fix (threat-model-
				//     checker/security-auditor RED/HIGH finding); the groupId-change
				//     reset is what actually makes this safe now.
				//   - `useWelcomePoller` is a wholly separate hook instance with its
				//     own independent cursor; this hook advancing past a Welcome
				//     doesn't stop that poller from seeing and processing it.
				//   - Decrypt-rate-deferred envelopes are retried from the LOCAL
				//     `deferredEnvelopesRef` queue below (self-contained, doesn't
				//     depend on the server re-sending them past an unadvanced
				//     cursor) — see that ref's own doc comment for why deferral,
				//     not server redelivery, is the retry mechanism there. That queue
				//     is also reset on groupId change (same fix), since a decrypt-rate
				//     deferral is only ever for the group active when it was deferred.
				if (envelopes.length > 0) {
					const last = envelopes[envelopes.length - 1];
					sinceRef.current = { ts: last.created_at, id: last.id };
				}
				// Retry envelopes deferred by a prior tick's decrypt-rate limit,
				// merged with this tick's freshly-fetched ones. Since the cursor
				// above already advanced past every envelope in the tick that
				// deferred them, the server can no longer re-return the same ids —
				// this array is now the SOLE retry path for deferred envelopes. The
				// id-dedupe below is defensive (protects against any future change
				// that reintroduces overlap) rather than load-bearing today.
				const deferred = deferredEnvelopesRef.current;
				deferredEnvelopesRef.current = [];
				const seenIds = new Set<string>();
				const combined: Envelope[] = [];
				for (const env of [...deferred, ...envelopes]) {
					if (seenIds.has(env.id)) continue;
					seenIds.add(env.id);
					combined.push(env);
				}
				for (const env of combined) {
					if (cancelled) break;
					await processEnvelope(env);
				}
				sweepStaleReactionRateEntries();
				sweepStaleDecryptRateEntries();
			} catch {
				// Network failure — silently retry on next interval.
			} finally {
				// Only clear the slot this run itself claimed. Checking BOTH groupId
				// AND run (not groupId alone, F9) is what makes this safe: a stale
				// run for a DIFFERENT groupId (e.g. the OLD group in a chat switch)
				// never matches groupId; a stale run for the SAME groupId revisited
				// later (e.g. A -> B -> A, see pollInFlightRef's doc comment) matches
				// groupId but not run, so it still cannot clobber a NEWER run's
				// legitimately in-flight claim for that same group.
				if (
					pollInFlightRef.current?.groupId === groupId &&
					pollInFlightRef.current?.run === runToken
				) {
					pollInFlightRef.current = null;
				}
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
