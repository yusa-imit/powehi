import * as Comlink from "comlink";
import { EncryptedPowehiDb } from "../db/encrypted-db";
import { db } from "../db/schema";
import { uint8ToBase64 } from "../utils/base64";
import type {
	CryptoWorkerApi,
	MlsExportStateResult,
	MlsIdentityResult,
	MlsImportStateResult,
} from "../workers/crypto.worker";

// Module-level singleton — the worker and its Comlink proxy are created once
// and shared across all callers of this hook. This avoids spawning multiple
// Web Worker threads for what is logically a single stateful WASM runtime.
let workerProxy: Comlink.Remote<CryptoWorkerApi> | null = null;

// ── MLS provider-state persistence (worker-reload survival) ─────────────────
//
// MLS_CTX inside the WASM worker is a `thread_local!` that starts empty on
// every fresh worker instance — a page reload/re-login spins up a brand-new
// worker thread, wiping every MLS group's state. mls_export_state /
// mls_import_state (wasm_exports.rs, "MLS full-context export/import"
// section) close that gap: every ratchet-advancing call
// (mlsEncrypt/mlsDecrypt/mlsCreateGroup/mlsAddMember/mlsJoinGroup) re-exports
// the full context and durably persists it, so a reload restores the LATEST
// state rather than a stale snapshot.
//
// This module wraps the Comlink proxy at its single creation choke point
// (getProxy below) so every caller — ChatLayout, useWelcomePoller, auth.ts,
// Login.tsx — gets the persist-after-mutating-op behavior for free, without
// touching each of the ~15 call sites individually.
//
// SECURITY — persist-before-release (never release a ratchet-advanced result
// until the advanced state is durably persisted): the re-export + encrypted
// Dexie write for every ratchet-advancing method is `await`ed BEFORE the
// wrapped call returns its result to the caller. If that persist FAILS (quota
// exceeded, storage eviction, concurrent-txn error), the wrapped call now
// REJECTS rather than returning the ciphertext (see doFlush / runOnChain).
// This deliberately blocks message delivery on a failed persist — the correct
// tradeoff, because returning the ciphertext while the advanced state was NOT
// saved means a later crash+reload restores the pre-advance state and resumes
// the ratchet at an already-used position → catastrophic AEAD nonce/key reuse.
// (An earlier revision swallowed persist failures and still returned the
// result; that was the nonce-reuse hole this now closes.)
//
// SECURITY — anti-replay scope (what the generation counter does and does NOT
// protect against). Each persisted blob carries a monotonically increasing
// `generation`, and mls_import_state rejects a blob whose generation is below
// a caller-supplied floor (mls_group.rs `state.generation < min_generation`).
// The ONLY trustworthy floor available to a browser-only client is this
// module's in-session high-water-mark `currentGeneration`:
//   • On the FIRST import of a fresh worker session (every page reload / login
//     — the Login.tsx path), currentGeneration is 0, so the floor is 0 and the
//     gate accepts ANY authentic blob. A wholesale replay of an entire older-
//     but-authentic snapshot across a reload is therefore NOT prevented — there
//     is no server- or hardware-anchored monotonic counter in this client-only
//     model to compare against (checked: the Delivery Service tracks only a
//     per-group, client-driven, last-writer-wins `groups.epoch` with no login-
//     time read endpoint — nothing usable as an anchor). This residual risk is
//     accepted for this phase (threat-model-checker sign-off).
//   • On any SUBSEQUENT import within the SAME live session, the floor is the
//     real in-session high-water-mark, so a second import cannot roll the
//     ratchet back below state already advanced in this session.
// The floor is owned HERE (the mlsImportState wrapper substitutes
// currentGeneration); callers never supply it — passing the blob's own
// generation as its own floor would make the check compare a value to itself
// and never reject.
//
// Security: the exported blob contains live key material (Ed25519 signing
// key + MLS epoch secrets). It is persisted ONLY via EncryptedPowehiDb
// (AES-GCM at rest — see db/encrypted-db.ts SENSITIVE.identity) — never
// logged, never sent to the server (no-plaintext-logging: the blob itself is
// key material, not just PII).

/**
 * Method names that advance the MLS ratchet, or mint fresh single-use key
 * material (mlsGetKeyPackage), and must synchronously flush an up-to-date
 * persist to Dexie before the wrapped call resolves — rejecting if that
 * persist fails. In every one of these methods, `identityId` is the first
 * argument (args[0]).
 */
const SYNC_FLUSH_ARG_METHODS: ReadonlySet<string> = new Set([
	"mlsEncrypt",
	"mlsDecrypt",
	"mlsCreateGroup",
	"mlsAddMember",
	"mlsJoinGroup",
	"mlsGetKeyPackage",
]);

/**
 * Method names that mint a fresh identity — the generation high-water-mark
 * resets to 0, and the freshly-minted signer/identity state is durably
 * persisted before its public KeyPackage goes to the server. Unlike
 * SYNC_FLUSH_ARG_METHODS, the identityId to persist against comes from the
 * *result*, not the arguments.
 */
const IDENTITY_INIT_METHODS: ReadonlySet<string> = new Set([
	"mlsInitIdentity",
	"mlsInitIdentityFromPhrase",
]);

// A crypto-worker call (the raw Comlink RPC, or the doFlush persist that
// follows it) must never be able to hang forever: since every persisting
// method is serialized through the single shared `flushChain` (runOnChain
// below), one wedged call would permanently block every later call in the
// same page session — not just its own caller, but every subsequent MLS
// operation for the rest of the session (see runOnChain's doc comment for
// why a never-settling `fn()` poisons `flushChain` itself, not just `link`).
// Bound every call so a hang degrades to a diagnosable rejection instead.
//
// The "call" vs "persist" phase tag (logged via a content-free console.error
// — method name + phase only, never args/results — so it is safe under
// no-plaintext-logging and is picked up by e2e-live's forwardBrowserErrors)
// pinpoints which half timed out: the raw WASM/Comlink round trip, or the
// mlsExportState+encrypted-Dexie-write persist that follows it.
export const CRYPTO_CALL_TIMEOUT_MS = 15_000;

export class CryptoWorkerTimeoutError extends Error {
	constructor(method: string, phase: "call" | "persist") {
		super(`crypto_worker_timeout:${method}:${phase}`);
		this.name = "CryptoWorkerTimeoutError";
	}
}

function withTimeout<T>(
	promise: Promise<T>,
	method: string,
	phase: "call" | "persist",
): Promise<T> {
	return new Promise<T>((resolve, reject) => {
		const timer = setTimeout(() => {
			console.error("crypto_worker_timeout", method, phase);
			reject(new CryptoWorkerTimeoutError(method, phase));
		}, CRYPTO_CALL_TIMEOUT_MS);
		promise.then(
			(value) => {
				clearTimeout(timer);
				resolve(value);
			},
			(err) => {
				clearTimeout(timer);
				reject(err);
			},
		);
	});
}

// Generation high-water-mark for the current worker session. It is the
// generation of the last state DURABLY PERSISTED in this session (0 before the
// first persist). Reset to 0 by a fresh mlsInitIdentity(FromPhrase) or by
// clearSessionState (see resetGeneration below); raised only inside doFlush
// AFTER a persist succeeds, and by a successful mlsImportState — always via
// bumpCurrentGeneration, never a plain assignment (see its doc comment).
let currentGeneration = 0;

// Highest generation NUMBER ever issued to an export attempt (doFlush),
// whether or not that attempt ever completes. Candidate generation numbers
// for a new doFlush come from THIS counter, not `currentGeneration + 1` —
// see doFlush's doc comment for why: since withTimeout (above) lets a caller
// give up on a still-running export without truly cancelling it, more than
// one doFlush attempt can be in flight at once, and issuing from
// `currentGeneration + 1` would let two overlapping attempts compute the
// IDENTICAL candidate number. Always kept >= currentGeneration by
// bumpCurrentGeneration, so a freshly issued number is always provably newer
// than anything already durable.
let issuedGeneration = 0;

// Bumped by resetGeneration (identity re-init / clearSessionState). An
// abandoned doFlush issued in a PRIOR epoch must never be allowed to persist
// after a reset — its generation number means nothing relative to the new
// identity's numbering — regardless of what that number happens to be. See
// doFlush's write-time check.
let generationEpoch = 0;

/**
 * Reset the generation bookkeeping for a fresh identity/session.
 *
 * Runs serialized on writeChain (via runOnWriteChain below), NOT as a plain
 * synchronous mutation — this closes a crypto-reviewer RED finding: a plain
 * `generationEpoch += 1` here could land in the middle of an in-flight
 * doFlush write's check-then-write body (the check at the top of that body
 * and its `await encDb.setMlsProviderState(...)` are two separate ticks of
 * the event loop), letting an old-identity write's epoch check pass, then
 * physically persist to disk AFTER the reset, while the new identity's own
 * doFlush was wrongly skipped as "superseded" by that stale write's
 * subsequent bumpCurrentGeneration. Because writeChain gives every queued
 * task exclusive occupancy of the chain for its ENTIRE async body (a later
 * task can only start after the earlier one's promise fully settles), moving
 * the epoch flip onto the same chain guarantees it can only happen strictly
 * before or strictly after any given write's check-then-write body, never
 * during it.
 */
function resetGeneration(): Promise<void> {
	return runOnWriteChain(() => {
		currentGeneration = 0;
		issuedGeneration = 0;
		generationEpoch += 1;
	});
}

/**
 * Advance currentGeneration (and keep issuedGeneration in lockstep) after a
 * generation value becomes durable — either a completed Dexie write (doFlush)
 * or a completed mlsImportState. Math.max, not a plain assignment: an
 * abandoned-but-still-running call (see withTimeout) can resolve out of order
 * relative to a later one that already advanced past it — this must never
 * roll currentGeneration BACKWARDS. issuedGeneration is raised alongside it so
 * a later doFlush's freshly issued number is always > any durable value,
 * keeping the write-time supersede check in doFlush correct.
 */
function bumpCurrentGeneration(generation: number): void {
	currentGeneration = Math.max(currentGeneration, generation);
	issuedGeneration = Math.max(issuedGeneration, currentGeneration);
}

// Serializes every bookkeeping op (flushes, import floor read, resets) so they
// can never invoke mlsExportState concurrently against the single-threaded WASM
// worker, so writes land in Dexie in issue order, and so `currentGeneration`
// has exactly one writer at a time. Every op is chained onto this promise —
// see runOnChain.
let flushChain: Promise<void> = Promise.resolve();

// Serializes the ACTUAL Dexie write step of doFlush AND every generation-
// epoch flip (resetGeneration) — deliberately separate from flushChain/
// runOnChain, which withTimeout can now let a caller walk away from while the
// export itself is still running (see doFlush). Every write, once it reaches
// the front of this chain, does a final generation/epoch check against the
// freshest currentGeneration/generationEpoch and skips if superseded. Because
// the check-and-write happens serialized here, whichever task actually
// reaches the front of the queue LAST always sees the truest
// currentGeneration/generationEpoch — a stale (superseded) write can never
// physically land after a fresher one, regardless of the real-time
// completion order of the mlsExportState calls that produced them, AND
// resetGeneration's epoch flip can never land in the middle of an in-flight
// write's check-then-write body (see resetGeneration's doc comment) — only
// strictly before or strictly after it.
let writeChain: Promise<void> = Promise.resolve();

/**
 * Run `fn` serialized on writeChain and return the promise for THIS op — see
 * writeChain's doc comment for why doFlush's write and resetGeneration's
 * epoch flip must share this one chain.
 */
function runOnWriteChain<T>(fn: () => T | Promise<T>): Promise<T> {
	const link = writeChain.then(fn);
	writeChain = link.then(
		() => undefined,
		() => undefined,
	);
	return link;
}

/**
 * Export the current full MLS context (identity + every group) and durably
 * persist it to the encrypted `identity` row in Dexie.
 *
 * The candidate generation comes from issuedGeneration (see its doc comment),
 * not currentGeneration — this is what lets doFlush safely reissue a fresh,
 * collision-free number even while an earlier, abandoned (see withTimeout)
 * doFlush for the same identity might still be in flight.
 *
 * The actual write is additionally guarded by writeChain: once the export
 * resolves, the write only lands if the exported generation is still newer
 * than the current durable high-water-mark AND was issued in the current
 * generationEpoch — otherwise a later, already-completed write has superseded
 * it (only reachable via an abandoned withTimeout tail; see writeChain's doc
 * comment), and persisting this stale snapshot now would clobber the newer
 * on-disk state with older data. In that case doFlush resolves normally
 * WITHOUT writing — safe because the caller that issued this exact attempt
 * already observed a timeout rejection for it and never saw this result
 * (persist-before-release is therefore preserved for every caller that is
 * actually still waiting on this call).
 *
 * THROWS if the export or the encrypted persist fails (no swallow, superseded-
 * skip aside). Callers that await this (via runOnChain) therefore reject too —
 * a ratchet-advanced result must never be released while its advanced state is
 * not durably saved (persist-before-release; see the SECURITY header). Never
 * logs the blob, identityId, or generation (no-plaintext-logging).
 */
async function doFlush(raw: Comlink.Remote<CryptoWorkerApi>, identityId: string): Promise<void> {
	issuedGeneration += 1;
	const generation = issuedGeneration;
	const epochAtIssuance = generationEpoch;
	const result: MlsExportStateResult = await raw.mlsExportState(identityId, generation);
	const stateB64 = uint8ToBase64(result.stateBytes);
	const encDb = new EncryptedPowehiDb(db, raw);

	await runOnWriteChain(async () => {
		if (epochAtIssuance !== generationEpoch || result.generation <= currentGeneration) {
			// Superseded — see doFlush's doc comment. Skip the write entirely.
			return;
		}
		await encDb.setMlsProviderState(stateB64, result.generation);
		// Durable now — advance the high-water-mark to match on-disk state.
		bumpCurrentGeneration(result.generation);
	});
}

/**
 * Run `fn` serialized on the shared bookkeeping chain and return the promise
 * for THIS op so the caller can await its own outcome before returning.
 *
 * The shared chain is advanced to a settled-either-way continuation, so a
 * single failed op (e.g. a failed persist that must reject its caller) does
 * NOT poison ordering for subsequent ops, while the caller still observes this
 * op's success/failure through the returned promise.
 */
function runOnChain<T>(fn: () => Promise<T>): Promise<T> {
	const link = flushChain.then(fn);
	flushChain = link.then(
		() => undefined,
		() => undefined,
	);
	return link;
}

/**
 * Wraps the raw Comlink proxy so:
 *  - every ratchet-advancing MLS call, and mlsGetKeyPackage, awaits a fresh
 *    durable persist before returning, and REJECTS if that persist fails
 *    (persist-before-release — see the SECURITY header);
 *  - every identity-lifecycle call (mlsInitIdentity / mlsInitIdentityFromPhrase)
 *    resets the generation high-water-mark to 0 and awaits a fresh persist
 *    before returning (rejecting if it fails);
 *  - mlsImportState substitutes the trustworthy in-session floor
 *    (currentGeneration) as the import's min_generation — the caller never
 *    supplies it — then raises the high-water-mark to the imported generation;
 *  - clearSessionState resets the generation high-water-mark after the
 *    underlying WASM session-clear resolves.
 * All generation-bookkeeping mutations run serialized on flushChain (runOnChain)
 * so the persisted generation and currentGeneration can never disagree.
 * Every other method (encryptDbField/decryptDbField, media*, mlKem*, ...)
 * passes through untouched.
 */
export function wrapWithPersistence(
	raw: Comlink.Remote<CryptoWorkerApi>,
): Comlink.Remote<CryptoWorkerApi> {
	const handler: ProxyHandler<Comlink.Remote<CryptoWorkerApi>> = {
		get(target, prop) {
			// Comlink's Remote<T> proxy property access is dynamically typed by
			// design; narrowed immediately below.
			// biome-ignore lint/suspicious/noExplicitAny: see comment above
			const value = (target as any)[prop];
			if (typeof prop !== "string" || typeof value !== "function") {
				return value;
			}
			const orig = value as (...args: unknown[]) => Promise<unknown>;

			if (IDENTITY_INIT_METHODS.has(prop)) {
				return async (...args: unknown[]) => {
					const result = (await withTimeout(orig(...args), prop, "call")) as MlsIdentityResult;
					// Reset + first persist serialized together: the reset to 0 must
					// be ordered w.r.t. any still-pending flush from a prior op, and
					// the persist must reject the init call if it fails.
					await runOnChain(() =>
						withTimeout(
							(async () => {
								await resetGeneration();
								await doFlush(raw, result.identityId);
							})(),
							prop,
							"persist",
						),
					);
					return result;
				};
			}

			if (prop === "mlsImportState") {
				return async (...args: unknown[]) => {
					const stateBytes = args[0];
					// The floor is owned HERE, not by the caller: it is the in-session
					// high-water-mark, read serialized so it reflects any completed
					// import/flush. On the first import of a fresh worker
					// (currentGeneration = 0) the floor is 0 and no authentic blob is
					// rejected — cross-reload wholesale replay is NOT defended (see the
					// SECURITY header). A later in-session import cannot roll back below
					// already-advanced state.
					return runOnChain(() =>
						withTimeout(
							(async () => {
								const floor = currentGeneration;
								const result = (await orig(stateBytes, floor)) as MlsImportStateResult;
								// The gate guarantees result.generation >= floor. Via
								// bumpCurrentGeneration (not a plain assignment) for the same
								// orphaned-late-continuation reason as doFlush above — see its
								// doc comment.
								bumpCurrentGeneration(result.generation);
								return result;
							})(),
							prop,
							"call",
						),
					);
				};
			}

			if (SYNC_FLUSH_ARG_METHODS.has(prop)) {
				return async (...args: unknown[]) => {
					const result = await withTimeout(orig(...args), prop, "call");
					const identityId = args[0];
					if (typeof identityId === "string") {
						// Rejects (propagating out of the wrapped call) if the persist
						// fails — the ratchet-advanced result must not be released while
						// its advanced state is not durably saved.
						await runOnChain(() => withTimeout(doFlush(raw, identityId), prop, "persist"));
					}
					return result;
				};
			}

			// Reset the generation high-water-mark after the WASM-side session clear
			// so a subsequent login's first flush starts from generation 1. Serialized
			// on the chain so it never races an in-flight flush (single writer of
			// currentGeneration).
			if (prop === "clearSessionState") {
				return async (...args: unknown[]) => {
					const result = await withTimeout(orig(...args), prop, "call");
					await runOnChain(() => withTimeout(resetGeneration(), prop, "persist"));
					return result;
				};
			}

			return orig;
		},
	};
	// Constructing a Proxy over a Comlink.Remote<T> requires a target-shaped
	// cast; the handler above preserves the exact CryptoWorkerApi call surface
	// for every property.
	// biome-ignore lint/suspicious/noExplicitAny: see comment above
	return new Proxy(raw, handler as any) as Comlink.Remote<CryptoWorkerApi>;
}

function initWorker(): Comlink.Remote<CryptoWorkerApi> | null {
	try {
		const worker = new Worker(new URL("../workers/crypto.worker.ts", import.meta.url), {
			type: "module",
		});
		const raw = Comlink.wrap<CryptoWorkerApi>(worker);
		return wrapWithPersistence(raw);
	} catch {
		// WASM not built yet or unsupported environment — return null so the UI
		// can still render during development without the WASM bundle.
		return null;
	}
}

// Lazily initialise on first hook call.
function getProxy(): Comlink.Remote<CryptoWorkerApi> | null {
	if (workerProxy === null) {
		workerProxy = initWorker();
	}
	return workerProxy;
}

/**
 * Returns the Comlink-wrapped crypto worker proxy (shared singleton).
 * May return null if the WASM bundle is not available (e.g., during dev
 * before `pnpm build:wasm` has been run). Callers must null-check.
 *
 * Non-hook callers (e.g., Zustand stores) must use this instead of useCryptoWorker.
 */
export function getCryptoWorkerProxy(): Comlink.Remote<CryptoWorkerApi> | null {
	return getProxy();
}

/**
 * Returns the Comlink-wrapped crypto worker proxy (shared singleton).
 * May return null if the WASM bundle is not available (e.g., during dev
 * before `pnpm build:wasm` has been run). Callers must null-check.
 */
export function useCryptoWorker(): Comlink.Remote<CryptoWorkerApi> | null {
	return getProxy();
}
