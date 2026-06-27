import { describe, expect, it } from "vitest";
import { getCryptoWorkerProxy, useCryptoWorker } from "./useCryptoWorker";

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
