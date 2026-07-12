import "fake-indexeddb/auto";
import type * as Comlink from "comlink";
import { beforeEach, describe, expect, it } from "vitest";
import { db } from "../db/schema";
import type { CryptoWorkerApi } from "../workers/crypto.worker";
import { getCryptoWorkerProxy, useCryptoWorker, wrapWithPersistence } from "./useCryptoWorker";

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
