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

// Generation high-water-mark for the current worker session. It is the
// generation of the last state DURABLY PERSISTED in this session (0 before the
// first persist). Reset to 0 by a fresh mlsInitIdentity(FromPhrase) or by
// clearSessionState (see those wrappers); raised only inside doFlush AFTER a
// persist succeeds, and by a successful mlsImportState. Never mutated off the
// serialization chain below (that would race an in-flight flush and let the
// persisted generation disagree with this value — see runOnChain).
let currentGeneration = 0;

// Serializes every bookkeeping op (flushes, import floor read, resets) so they
// can never invoke mlsExportState concurrently against the single-threaded WASM
// worker, so writes land in Dexie in issue order, and so `currentGeneration`
// has exactly one writer at a time. Every op is chained onto this promise —
// see runOnChain.
let flushChain: Promise<void> = Promise.resolve();

/**
 * Export the current full MLS context (identity + every group) and durably
 * persist it to the encrypted `identity` row in Dexie.
 *
 * The candidate generation is currentGeneration + 1. currentGeneration is
 * raised to it ONLY after the encrypted Dexie write resolves — so the
 * high-water-mark always matches the last state actually on disk.
 *
 * THROWS if the export or the encrypted persist fails (no swallow). Callers
 * that await this (via runOnChain) therefore reject too — a ratchet-advanced
 * result must never be released while its advanced state is not durably saved
 * (persist-before-release; see the SECURITY header). Never logs the blob,
 * identityId, or generation (no-plaintext-logging).
 *
 * MUST be invoked serialized (runOnChain) — it reads and writes
 * currentGeneration without further locking.
 */
async function doFlush(raw: Comlink.Remote<CryptoWorkerApi>, identityId: string): Promise<void> {
	const generation = currentGeneration + 1;
	const result: MlsExportStateResult = await raw.mlsExportState(identityId, generation);
	const stateB64 = uint8ToBase64(result.stateBytes);
	const encDb = new EncryptedPowehiDb(db, raw);
	await encDb.setMlsProviderState(stateB64, result.generation);
	// Durable now — advance the high-water-mark to match on-disk state.
	currentGeneration = result.generation;
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
					const result = (await orig(...args)) as MlsIdentityResult;
					// Reset + first persist serialized together: the reset to 0 must
					// be ordered w.r.t. any still-pending flush from a prior op, and
					// the persist must reject the init call if it fails.
					await runOnChain(async () => {
						currentGeneration = 0;
						await doFlush(raw, result.identityId);
					});
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
					return runOnChain(async () => {
						const floor = currentGeneration;
						const result = (await orig(stateBytes, floor)) as MlsImportStateResult;
						// The gate guarantees result.generation >= floor.
						currentGeneration = result.generation;
						return result;
					});
				};
			}

			if (SYNC_FLUSH_ARG_METHODS.has(prop)) {
				return async (...args: unknown[]) => {
					const result = await orig(...args);
					const identityId = args[0];
					if (typeof identityId === "string") {
						// Rejects (propagating out of the wrapped call) if the persist
						// fails — the ratchet-advanced result must not be released while
						// its advanced state is not durably saved.
						await runOnChain(() => doFlush(raw, identityId));
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
					const result = await orig(...args);
					await runOnChain(async () => {
						currentGeneration = 0;
					});
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
