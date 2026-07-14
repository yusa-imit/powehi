import "fake-indexeddb/auto";
import type * as Comlink from "comlink";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { db } from "../db/schema";
import type { CryptoWorkerApi } from "../workers/crypto.worker";
import {
	CRYPTO_CALL_TIMEOUT_MS,
	CryptoWorkerTimeoutError,
	getCryptoWorkerProxy,
	useCryptoWorker,
	wrapWithPersistence,
} from "./useCryptoWorker";

// useCryptoWorker owns a module-level singleton initialised lazily on first call.
// In the JSDOM test environment, the Web Worker module-type constructor throws,
// so initWorker() catches it and returns null — both exports should reflect this.

describe("useCryptoWorker / getCryptoWorkerProxy", () => {
	it("useCryptoWorker returns null or a proxy-like object (never throws)", () => {
		const result = useCryptoWorker();
		expect(result === null || typeof result === "object").toBe(true);
	});

	it("getCryptoWorkerProxy returns null or a proxy-like object (never throws)", () => {
		const result = getCryptoWorkerProxy();
		expect(result === null || typeof result === "object").toBe(true);
	});

	it("useCryptoWorker and getCryptoWorkerProxy return the same singleton reference", () => {
		const fromHook = useCryptoWorker();
		const fromUtil = getCryptoWorkerProxy();
		expect(fromHook).toBe(fromUtil);
	});

	it("repeated calls to useCryptoWorker return the same reference", () => {
		const first = useCryptoWorker();
		const second = useCryptoWorker();
		expect(first).toBe(second);
	});

	it("repeated calls to getCryptoWorkerProxy return the same reference", () => {
		const first = getCryptoWorkerProxy();
		const second = getCryptoWorkerProxy();
		expect(first).toBe(second);
	});
});

// crypto-reviewer findings 1, 3, 4 — exercised directly against wrapWithPersistence
// with a fake Comlink.Remote-shaped `raw` object (never a real Worker/WASM), so these
// stay pure unit tests of the persistence bookkeeping, matching react-hooks-only.md /
// testing-conventions.md ("mock the Comlink proxy; never import crypto libs into a
// component test").
describe("wrapWithPersistence — synchronous persist bookkeeping", () => {
	beforeEach(async () => {
		await db.identity.clear();
	});

	function fakeRaw(overrides: Record<string, unknown>): Comlink.Remote<CryptoWorkerApi> {
		return {
			encryptDbField: async (v: string) => v,
			decryptDbField: async (v: string) => v,
			...overrides,
		} as unknown as Comlink.Remote<CryptoWorkerApi>;
	}

	it("finding 1 (RED): a ratchet-advancing call's persist completes before the call resolves", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-ratchet" });
		const order: string[] = [];
		const raw = fakeRaw({
			mlsEncrypt: async () => {
				order.push("mlsEncrypt:call");
				return { ciphertext: new Uint8Array([9]) };
			},
			mlsExportState: async (_id: string, generation: number) => {
				order.push("mlsExportState:call");
				return { stateBytes: new Uint8Array([1, 2, 3]), generation };
			},
		});

		const proxy = wrapWithPersistence(raw);
		const result = await proxy.mlsEncrypt("identity-x", "group-x", new Uint8Array([1]));
		order.push("wrapper:resolved");

		// The export+persist must have already happened by the time the caller's
		// await resolves — no debounce, no fire-and-forget. A regression to the
		// old scheduled-persist behavior would let "wrapper:resolved" race ahead
		// of "mlsExportState:call".
		expect(order).toEqual(["mlsEncrypt:call", "mlsExportState:call", "wrapper:resolved"]);
		expect(result).toEqual({ ciphertext: new Uint8Array([9]) });

		const stored = await db.identity.get(1);
		expect(stored?.mlsProviderStateB64).toBeDefined();
	});

	it("finding 3 (YELLOW): mlsGetKeyPackage synchronously persists before returning", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-kp" });
		const order: string[] = [];
		const raw = fakeRaw({
			mlsGetKeyPackage: async () => {
				order.push("mlsGetKeyPackage:call");
				return { keyPackage: new Uint8Array([7]), pqDecapKeyHandle: "h1" };
			},
			mlsExportState: async (_id: string, generation: number) => {
				order.push("mlsExportState:call");
				return { stateBytes: new Uint8Array([1]), generation };
			},
		});

		const proxy = wrapWithPersistence(raw);
		await proxy.mlsGetKeyPackage("identity-kp");
		order.push("wrapper:resolved");

		expect(order).toEqual(["mlsGetKeyPackage:call", "mlsExportState:call", "wrapper:resolved"]);
	});

	it("finding 3 (YELLOW): mlsInitIdentity resets the generation and synchronously persists before returning", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-init" });
		const generations: number[] = [];
		const raw = fakeRaw({
			mlsInitIdentity: async () => ({
				identityId: "identity-init",
				keyPackage: new Uint8Array([1]),
				pqDecapKeyHandle: "h-init",
			}),
			mlsExportState: async (_id: string, generation: number) => {
				generations.push(generation);
				return { stateBytes: new Uint8Array([1]), generation };
			},
		});

		const proxy = wrapWithPersistence(raw);
		await proxy.mlsInitIdentity(new Uint8Array([1, 2, 3]));

		// Reset to 0, then incremented exactly once by the awaited flush.
		expect(generations).toEqual([1]);
	});

	it("finding 4 (YELLOW): clearSessionState resets the generation counter for the next identity-init flush", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-clear" });
		const generations: number[] = [];
		const raw = fakeRaw({
			mlsInitIdentity: async () => ({
				identityId: "identity-clear",
				keyPackage: new Uint8Array([1]),
				pqDecapKeyHandle: "h-clear",
			}),
			mlsExportState: async (_id: string, generation: number) => {
				generations.push(generation);
				return { stateBytes: new Uint8Array([1]), generation };
			},
			clearSessionState: async () => {},
		});

		const proxy = wrapWithPersistence(raw);
		await proxy.mlsInitIdentity(new Uint8Array([1]));
		await proxy.clearSessionState();
		await proxy.mlsInitIdentity(new Uint8Array([2]));

		// Both identity-init flushes land on generation 1 — clearSessionState must
		// reset the high-water-mark in between rather than letting it keep climbing
		// across a logout/login boundary.
		expect(generations).toEqual([1, 1]);
	});

	it("RED 1: the import floor is the in-session high-water-mark, not the blob's own generation", async () => {
		const floors: number[] = [];
		const raw = fakeRaw({
			clearSessionState: async () => {},
			mlsImportState: async (_bytes: Uint8Array, minGeneration: number) => {
				floors.push(minGeneration);
				return { identityId: "id", groupIds: [], generation: 5 };
			},
		});
		const proxy = wrapWithPersistence(raw);
		// Reset the module-level in-session high-water-mark to a known 0.
		await proxy.clearSessionState();

		// First import of a fresh session: the floor is 0 (no in-session prior
		// knowledge) — NOT the ignored caller-supplied arg (999), and NOT the
		// blob's own returned generation. This is the RED-1 fix: the freshness
		// gate no longer compares a value against itself.
		await proxy.mlsImportState(new Uint8Array([1]), 999);
		expect(floors).toEqual([0]);

		// A second import in the SAME session floors at the high-water-mark the
		// first import raised (5), so it cannot roll back below already-advanced
		// state.
		await proxy.mlsImportState(new Uint8Array([2]), 999);
		expect(floors).toEqual([0, 5]);
	});

	it("RED 2: a ratchet-advancing call REJECTS when its post-op persist fails (no silent success)", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-persist-fail" });
		const raw = fakeRaw({
			clearSessionState: async () => {},
			mlsEncrypt: async () => ({ ciphertext: new Uint8Array([9]) }),
			mlsExportState: async () => {
				throw new Error("quota_exceeded");
			},
		});
		const proxy = wrapWithPersistence(raw);
		await proxy.clearSessionState();

		// The ciphertext must NOT be released while its advanced state failed to
		// persist — the wrapped call rejects rather than resolving with the result.
		await expect(proxy.mlsEncrypt("id", "grp", new Uint8Array([1]))).rejects.toThrow();
	});

	it("RED 2: a failed persist does not poison the chain — a later flush still succeeds", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-persist-recover" });
		let failNext = true;
		const raw = fakeRaw({
			clearSessionState: async () => {},
			mlsEncrypt: async () => ({ ciphertext: new Uint8Array([9]) }),
			mlsExportState: async (_id: string, generation: number) => {
				if (failNext) {
					failNext = false;
					throw new Error("transient_storage_error");
				}
				return { stateBytes: new Uint8Array([1, 2, 3]), generation };
			},
		});
		const proxy = wrapWithPersistence(raw);
		await proxy.clearSessionState();

		await expect(proxy.mlsEncrypt("id", "grp", new Uint8Array([1]))).rejects.toThrow();
		// Chain not poisoned by the prior rejection: the next call's persist runs
		// and succeeds, and the result is released normally.
		await expect(proxy.mlsEncrypt("id", "grp", new Uint8Array([2]))).resolves.toEqual({
			ciphertext: new Uint8Array([9]),
		});
		const stored = await db.identity.get(1);
		expect(stored?.mlsProviderStateB64).toBeDefined();
	});
});

// A wedged crypto-worker call must degrade to a diagnosable rejection rather
// than hanging forever — see the "call"/"persist" withTimeout doc comment in
// useCryptoWorker.ts. Without this, one never-settling `fn()` permanently
// poisons the shared `flushChain`, wedging every subsequent MLS operation for
// the rest of the page session (not just the caller that first hit it).
describe("wrapWithPersistence — bounded timeout (never-settling calls degrade to a diagnosable rejection)", () => {
	// Fake timers are enabled per-test (after any Dexie/fake-indexeddb setup,
	// which relies on real macrotask timers internally) rather than in
	// beforeEach, to avoid stalling the DB fixture writes below.
	beforeEach(async () => {
		await db.identity.clear();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	function fakeRaw(overrides: Record<string, unknown>): Comlink.Remote<CryptoWorkerApi> {
		return {
			encryptDbField: async (v: string) => v,
			decryptDbField: async (v: string) => v,
			...overrides,
		} as unknown as Comlink.Remote<CryptoWorkerApi>;
	}

	/** A promise that intentionally never settles — simulates a wedged raw Comlink RPC. */
	function neverSettles<T>(): Promise<T> {
		return new Promise<T>(() => {});
	}

	it("a raw call that never settles rejects with CryptoWorkerTimeoutError instead of hanging forever", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-timeout-call" });
		const raw = fakeRaw({
			mlsCreateGroup: () => neverSettles(),
		});
		const proxy = wrapWithPersistence(raw);

		vi.useFakeTimers();
		const pending = expect(proxy.mlsCreateGroup("identity-x")).rejects.toThrow(
			CryptoWorkerTimeoutError,
		);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await pending;
	});

	it("a persist that never settles rejects with CryptoWorkerTimeoutError instead of hanging forever", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-timeout-persist" });
		const raw = fakeRaw({
			mlsCreateGroup: async () => ({ groupId: "g1" }),
			mlsExportState: () => neverSettles(),
		});
		const proxy = wrapWithPersistence(raw);

		vi.useFakeTimers();
		const pending = expect(proxy.mlsCreateGroup("identity-x")).rejects.toThrow(
			CryptoWorkerTimeoutError,
		);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await pending;
	});

	it("after a timed-out call, a later call is NOT wedged behind it (flushChain recovers)", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-timeout-recover" });
		const raw = fakeRaw({
			// First call's raw RPC never settles; second call behaves normally.
			mlsCreateGroup: vi
				.fn()
				.mockImplementationOnce(() => neverSettles())
				.mockImplementationOnce(async () => ({ groupId: "g2" })),
			mlsExportState: async (_id: string, generation: number) => ({
				stateBytes: new Uint8Array([1]),
				generation,
			}),
		});
		const proxy = wrapWithPersistence(raw);

		vi.useFakeTimers();
		const firstCall = expect(proxy.mlsCreateGroup("identity-x")).rejects.toThrow(
			CryptoWorkerTimeoutError,
		);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await firstCall;
		vi.useRealTimers();

		// The second call must resolve normally — proving the shared flushChain
		// was not left permanently stuck behind the first call's orphaned promise.
		await expect(proxy.mlsCreateGroup("identity-x")).resolves.toEqual({ groupId: "g2" });
	});

	it("an orphaned late-completing persist does not clobber a newer already-written on-disk generation (crypto-reviewer RED)", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-clobber-guard" });

		let resolveAExport: ((r: { stateBytes: Uint8Array; generation: number }) => void) | undefined;
		const aExportPromise = new Promise<{ stateBytes: Uint8Array; generation: number }>(
			(resolve) => {
				resolveAExport = resolve;
			},
		);
		let capturedAGeneration: number | undefined;

		const mlsExportState = vi
			.fn()
			.mockImplementationOnce((_id: string, generation: number) => {
				capturedAGeneration = generation;
				return aExportPromise;
			})
			.mockImplementation(async (_id: string, generation: number) => ({
				stateBytes: new Uint8Array([2]),
				generation,
			}));
		const raw = fakeRaw({
			clearSessionState: async () => {},
			mlsCreateGroup: async () => ({ groupId: "g" }),
			mlsExportState,
		});
		const proxy = wrapWithPersistence(raw);
		// Normalize the module-level generation counters to a known baseline —
		// they are shared singleton state across this whole test file.
		await proxy.clearSessionState();

		// Op A: the raw mlsCreateGroup call resolves instantly, but its doFlush's
		// mlsExportState hangs — the "persist" phase timeout fires and A's caller
		// gives up, while A's export keeps running (orphaned; see withTimeout).
		vi.useFakeTimers();
		const opA = expect(proxy.mlsCreateGroup("identity-x")).rejects.toThrow(
			CryptoWorkerTimeoutError,
		);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await opA;
		vi.useRealTimers();

		// Op B: issued AFTER A's timeout freed the chain — completes normally,
		// persisting a NEWER generation while A's export is still outstanding.
		await proxy.mlsCreateGroup("identity-x");
		const afterB = await db.identity.get(1);
		expect(afterB?.mlsProviderStateB64).toBeDefined();

		// A's orphaned export now finally resolves, carrying its STALE (lower)
		// generation number.
		expect(capturedAGeneration).toBeDefined();
		// biome-ignore lint/style/noNonNullAssertion: asserted defined above
		resolveAExport?.({ stateBytes: new Uint8Array([1]), generation: capturedAGeneration! });
		// Let A's now-unblocked write-chain continuation run.
		await new Promise((resolve) => setTimeout(resolve, 0));

		// The on-disk row must still reflect B's (newer) write — A's late,
		// superseded write must have been skipped rather than clobbering it.
		const afterA = await db.identity.get(1);
		expect(afterA?.mlsProviderStateB64).toEqual(afterB?.mlsProviderStateB64);
	});

	// crypto-reviewer RED (found in review of the writeChain/epoch design above):
	// the export-hangs case just above only exercises the epoch check running
	// AFTER a reset (correctly skips). It never exercised the write ITSELF
	// (encryptDbField inside encDb.setMlsProviderState) hanging while a reset
	// happens concurrently — where the check-then-write split across an
	// `await` let a stale write's check pass BEFORE the reset, then physically
	// land AFTER it, while the new identity's own write was wrongly skipped as
	// superseded. Fixed by routing resetGeneration's epoch flip through the
	// same writeChain doFlush's write uses (runOnWriteChain), so the two can
	// never interleave — this test pins that fix.
	it("a wedged Dexie write does not let a concurrent identity reset's own persist get silently skipped (crypto-reviewer RED)", async () => {
		await db.identity.put({ id: 1, deviceId: "dev-write-wedge-reset" });

		let resolveAEncrypt: ((v: string) => void) | undefined;
		const aEncryptPromise = new Promise<string>((resolve) => {
			resolveAEncrypt = resolve;
		});

		const encryptDbField = vi
			.fn()
			// A's setMlsProviderState write (the encrypted-envelope encrypt call)
			// wedges here — a hang inside the WRITE itself, not the export.
			.mockImplementationOnce(() => aEncryptPromise)
			.mockImplementation(async (v: string) => v);

		const raw = fakeRaw({
			encryptDbField,
			clearSessionState: async () => {},
			mlsInitIdentity: vi
				.fn()
				.mockResolvedValueOnce({ identityId: "identity-a" })
				.mockResolvedValueOnce({ identityId: "identity-c" }),
			mlsExportState: async (_id: string, generation: number) => ({
				stateBytes: new Uint8Array([generation]),
				generation,
			}),
		});
		const proxy = wrapWithPersistence(raw);
		await proxy.clearSessionState();

		// Op A: mlsInitIdentity for identity-a. Its raw call + export resolve
		// fine, but its doFlush's Dexie write wedges — the "persist" phase
		// withTimeout fires and A's caller gives up, while A's write task stays
		// queued (occupying) writeChain — see resetGeneration's doc comment.
		vi.useFakeTimers();
		const opA = expect(proxy.mlsInitIdentity(new Uint8Array([1]))).rejects.toThrow(
			CryptoWorkerTimeoutError,
		);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await opA;

		// A concurrent reset: its resetGeneration() must queue BEHIND A's still-
		// wedged write on writeChain (not race ahead of it), so it also cannot
		// complete until A's write settles — it times out at the outer layer too,
		// a diagnosable rejection rather than a silent skip or corruption.
		const resetOp = expect(proxy.clearSessionState()).rejects.toThrow(CryptoWorkerTimeoutError);
		await vi.advanceTimersByTimeAsync(CRYPTO_CALL_TIMEOUT_MS);
		await resetOp;
		vi.useRealTimers();

		// A's wedged write now finally resolves — it lands (issued and checked
		// entirely within the epoch that was still active while it was queued),
		// and only THEN can the queued reset's epoch flip actually run.
		resolveAEncrypt?.("encrypted-a-envelope");
		// Drain writeChain: A's write settles, then the reset's epoch flip runs.
		await new Promise((resolve) => setTimeout(resolve, 0));
		await new Promise((resolve) => setTimeout(resolve, 0));

		// A fresh identity-c init, issued after everything above has settled,
		// must succeed normally and its write must not be silently dropped as
		// "superseded" by leftover bookkeeping from the wedge/reset race.
		await proxy.mlsInitIdentity(new Uint8Array([3]));
		const finalRow = await db.identity.get(1);
		expect(finalRow?.mlsProviderStateB64).toBeDefined();
		// Pin the exact value, not just "defined": the reset must have actually
		// taken effect (post-reset generation 1, not a leftover pre-reset
		// number), proving the new identity's own write is the one on disk.
		// biome-ignore lint/style/noNonNullAssertion: asserted defined above
		const envelope = JSON.parse(finalRow!.mlsProviderStateB64!) as {
			stateB64: string;
			generation: number;
		};
		expect(envelope.generation).toBe(1);
	});
});
