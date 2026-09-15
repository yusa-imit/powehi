/**
 * withMlsCommitLock — mutual exclusion between the poll loop's incoming-Commit
 * merge (`useMessages.ts`) and any UI-initiated MLS operation (stage / confirm
 * / abort) for the SAME group.
 *
 * Partially closes `mls_group.rs`'s remove-member status-list item (f): with
 * no lock, a poll tick landing between a UI-initiated stage and its confirm
 * destroys the stage (item (e)), and if the Delivery Service had already
 * accepted that commit the group forks permanently under
 * `max_past_epochs(0)` — peers merge it, the committer never can. Every
 * caller that merges an incoming commit (`mlsProcessCommit`) OR
 * stages/confirms/aborts an outgoing one for an ALREADY-ACTIVE group MUST run
 * that work inside `withMlsCommitLock(groupId, ...)`, holding the group's
 * slot for the ENTIRE span that must not interleave — e.g. the whole
 * stage-to-confirm/abort sequence, not just each individual WASM call. This
 * module only enforces exclusivity for the span it is actually given; it
 * cannot protect a caller that releases and re-acquires mid-sequence, and the
 * guarantee does not hold in practice until a second caller (a UI-initiated
 * flow) actually acquires the same lock — today `useMessages.ts`'s poll loop
 * is the only caller, so there is no real contention to resolve yet.
 * (The existing UI-initiated MLS-mutating flows — `AcceptInviteModal.tsx`'s
 * create+add-member, and `useCryptoWorker.ts`'s compensating
 * `mlsRemoveMemberAbort` — are safe without this lock today only because
 * they operate on a group the poll loop cannot yet be bound to (a
 * newly-created group is not an open chat). Any NEW UI flow that touches an
 * ALREADY-ACTIVE group's MLS state — the case this lock exists for — MUST
 * acquire it.)
 *
 * Per-group, not global: a lock held for one group never blocks another
 * group's poll loop or UI flow. The key is `groupId` alone, not
 * `(identityId, groupId)` — intentionally: this over-serializes across
 * identities sharing a group rather than under-serializing, which is the
 * safe direction for a mutex whose entire purpose is preventing missed
 * exclusion.
 *
 * NOT reentrant. Calling `withMlsCommitLock` for a group from inside a
 * callback that already holds that same group's lock deadlocks: the inner
 * call waits behind the outer one, which can never finish because it is the
 * one doing the waiting. A caller that must drain a group's outstanding
 * poll-loop backlog before staging (`mls_group.rs` item (g)) MUST perform
 * that drain and the stage/confirm/abort as work inside ONE acquisition,
 * never as two separate `withMlsCommitLock` calls.
 *
 * Optional `signal` (crypto-reviewer F9): a caller still QUEUED behind a
 * holder that never settles (e.g. a Comlink call to a crashed worker) can
 * pass an `AbortSignal` to give up waiting instead of queuing forever —
 * `fn` is never invoked in that case. This does NOT free the wedged
 * holder's slot; it only lets a later caller stop waiting for it. The
 * signal stops having any effect as soon as this call ACQUIRES the
 * group's slot (i.e. is dequeued by `createLimiter`) — this happens
 * strictly before `fn` runs, not at the same instant: the `safeFn`
 * normalization wrapper below (crypto-reviewer F1) inserts its own
 * microtask between acquisition and the actual `fn()` call, during which
 * an abort is already too late to have any effect. `fn` itself remains
 * responsible for its own in-flight cancellation once running, exactly as
 * `createLimiter` already documents. The current sole caller
 * (`useMessages.ts`'s poll loop) does not pass one; a future UI-initiated
 * caller that cannot tolerate hanging indefinitely behind a wedged
 * poll-loop holder should.
 */

import { type Limiter, createLimiter } from "./concurrencyLimiter";

// Bounded, per Tiger Style ("put a limit on everything"): this module is a
// process-lifetime singleton, so without a cap it would grow by one entry per
// distinct groupId ever seen in the session. 128 is generous headroom for any
// realistic number of groups a single client is a member of.
const MAX_TRACKED_GROUPS = 128;

type LockEntry = {
	limiter: Limiter;
	active: number;
	lastUsed: number;
};

const locks = new Map<string, LockEntry>();

function evictIdleLruIfAtCapacity(): void {
	if (locks.size < MAX_TRACKED_GROUPS) return;
	let oldestKey: string | null = null;
	let oldestTime = Number.POSITIVE_INFINITY;
	for (const [key, entry] of locks) {
		if (entry.active === 0 && entry.lastUsed < oldestTime) {
			oldestKey = key;
			oldestTime = entry.lastUsed;
		}
	}
	// Every tracked group is currently busy: leave the cap exceeded rather
	// than evict an in-flight lock, which would silently break the
	// exclusivity guarantee for whichever group loses its entry.
	if (oldestKey !== null) locks.delete(oldestKey);
}

function entryFor(groupId: string): LockEntry {
	const existing = locks.get(groupId);
	if (existing) return existing;
	evictIdleLruIfAtCapacity();
	const entry: LockEntry = { limiter: createLimiter(1), active: 0, lastUsed: Date.now() };
	locks.set(groupId, entry);
	return entry;
}

/**
 * Run `fn` with exclusive access to `groupId`'s MLS commit lock.
 *
 * `signal`, if given and already-aborted or aborted while this call is still
 * QUEUED (not yet holding the group's slot), rejects with `AbortError`
 * without ever invoking `fn` — see the module doc comment (crypto-reviewer
 * F9). Has no effect once this call has acquired the group's slot, which
 * happens strictly before `fn` is invoked.
 */
export function withMlsCommitLock<T>(
	groupId: string,
	fn: () => Promise<T>,
	signal?: AbortSignal,
): Promise<T> {
	const entry = entryFor(groupId);
	entry.active++;
	entry.lastUsed = Date.now();
	// Defensive normalization (crypto-reviewer F1): `createLimiter`'s executor
	// is, in essence, `fn().finally(release)`. A `fn` that throws
	// SYNCHRONOUSLY (never returns a Promise at all) or returns a non-Promise
	// value means `.finally` is never reached, so `release` never runs —
	// PERMANENTLY wedging this group's capacity-1 mutex for the rest of the
	// process lifetime (verified by a probe test during review). Wrapping
	// `fn` in `Promise.resolve().then(fn)` guarantees the limiter always
	// receives a genuine Promise, so `.finally(release)` always fires,
	// regardless of how `fn` misbehaves.
	const safeFn = () => Promise.resolve().then(fn);
	return entry.limiter(safeFn, signal).finally(() => {
		entry.active--;
		entry.lastUsed = Date.now();
	});
}

/**
 * Number of groups this module currently tracks a lock entry for (busy or
 * idle). Test-only introspection (crypto-reviewer F10) — lets a test assert
 * the `MAX_TRACKED_GROUPS` eviction cap directly instead of inferring it from
 * timing/ordering side effects.
 */
export function trackedGroupCount(): number {
	return locks.size;
}
