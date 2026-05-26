import * as Comlink from "comlink";
import type { CryptoWorkerApi } from "../workers/crypto.worker";

// Module-level singleton — the worker and its Comlink proxy are created once
// and shared across all callers of this hook. This avoids spawning multiple
// Web Worker threads for what is logically a single stateful WASM runtime.
let workerProxy: Comlink.Remote<CryptoWorkerApi> | null = null;

function initWorker(): Comlink.Remote<CryptoWorkerApi> | null {
	try {
		const worker = new Worker(new URL("../workers/crypto.worker.ts", import.meta.url), {
			type: "module",
		});
		return Comlink.wrap<CryptoWorkerApi>(worker);
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
 */
export function useCryptoWorker(): Comlink.Remote<CryptoWorkerApi> | null {
	return getProxy();
}
