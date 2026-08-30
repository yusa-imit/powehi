// ADR-0004 follow-up (crypto-reviewer A1, cycle 388) — `mediaExportKeyForStorage`'s
// return value must cross the worker boundary via Comlink.transfer, not
// structured-clone, so no unzeroed copy of the raw media key is left behind on
// the worker side once the call resolves. `transferMediaExportResult` is the
// extracted, synchronous piece of that fix (see crypto.worker.ts) — tested here
// directly since JSDOM can't construct the real `Worker`/wasm-pack plumbing
// (see useCryptoWorker.test.ts).
import * as Comlink from "comlink";
import { describe, expect, it } from "vitest";
import { transferMediaExportResult } from "./crypto.worker";

describe("transferMediaExportResult", () => {
	it("returns the same object reference (no defensive copy introduced)", () => {
		const result = { mediaKey: new Uint8Array([1, 2, 3, 4]) };
		expect(transferMediaExportResult(result)).toBe(result);
	});

	it("does not alter the mediaKey bytes", () => {
		const bytes = [0xaa, 0xbb, 0xcc, 0xdd];
		const result = { mediaKey: new Uint8Array(bytes) };
		const transferred = transferMediaExportResult(result);
		expect(Array.from(transferred.mediaKey)).toEqual(bytes);
	});

	it("Comlink.transfer records exactly this buffer as transferable for the reply postMessage", async () => {
		// Black-box check against Comlink's actual (undocumented) internal contract:
		// transfer() must produce an object Comlink's own wire-value encoder will
		// later serialize with this buffer in the transfer list. We can't reach
		// Comlink's private transferCache directly, so instead we drive a real
		// message round-trip through Comlink.expose/wrap and confirm the sender's
		// buffer is detached (byteLength 0) after the reply is posted — the
		// observable effect a structured-clone (copy, never detaches) would not
		// produce.
		const mediaKey = new Uint8Array([7, 7, 7, 7]);
		const api = {
			async mediaExportKeyForStorage() {
				return transferMediaExportResult({ mediaKey });
			},
		};

		const { port1, port2 } = new MessageChannel();
		try {
			Comlink.expose(api, port1);
			const remote = Comlink.wrap<typeof api>(port2);
			const received = await remote.mediaExportKeyForStorage();
			expect(Array.from(received.mediaKey)).toEqual([7, 7, 7, 7]);
			// The original buffer was transferred (moved), not cloned — it must be
			// detached on the sending side now.
			expect(mediaKey.buffer.byteLength).toBe(0);
		} finally {
			port1.close();
			port2.close();
		}
	});

	// crypto-reviewer R2 (cycle 391): the fix is only safe because mediaKey is
	// always a solely-owned buffer (see wasm_exports.rs `bytes_js`, which copies).
	// If that precondition were ever violated — e.g. mediaKey became a subarray
	// view over a larger buffer (in WASM's case, potentially the live linear
	// memory heap) — transferring it would hand the whole backing buffer to the
	// main thread and detach it inside the worker. The guard must reject that
	// shape loudly instead of silently transferring out-of-scope memory.
	it("throws if mediaKey is a non-zero-offset view (would transfer more than the key)", () => {
		const buffer = new ArrayBuffer(64);
		const view = new Uint8Array(buffer, 32, 4); // byteOffset 32, not the buffer's owner
		expect(() => transferMediaExportResult({ mediaKey: view })).toThrow("media_export_invariant");
	});

	it("throws if mediaKey is a partial-length view over a larger buffer", () => {
		const buffer = new ArrayBuffer(64);
		const view = new Uint8Array(buffer, 0, 4); // byteOffset 0, but buffer is larger than the view
		expect(() => transferMediaExportResult({ mediaKey: view })).toThrow("media_export_invariant");
	});

	it("does not throw for a full-length, zero-offset view (the real-world shape)", () => {
		const buffer = new ArrayBuffer(32);
		const view = new Uint8Array(buffer);
		expect(() => transferMediaExportResult({ mediaKey: view })).not.toThrow();
	});
});
