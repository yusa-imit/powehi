/**
 * concurrencyLimiter — unit tests.
 *
 * Verifies the bound used to cap concurrent receiver-path WASM media-handle
 * holders (`mediaHandleLimiter`, shared by `downloadAndDecryptMedia` and
 * `useThumbnail`) actually limits, queues, and releases correctly.
 */

import { describe, expect, it } from "vitest";
import { createLimiter } from "./concurrencyLimiter";

function deferred<T>() {
	let resolve!: (value: T) => void;
	const promise = new Promise<T>((r) => {
		resolve = r;
	});
	return { promise, resolve };
}

describe("createLimiter", () => {
	it("runs tasks immediately while under the concurrency cap", async () => {
		const limit = createLimiter(2);
		let started = 0;
		await Promise.all([
			limit(async () => {
				started++;
			}),
			limit(async () => {
				started++;
			}),
		]);
		expect(started).toBe(2);
	});

	it("queues tasks beyond the cap and never exceeds it concurrently", async () => {
		const limit = createLimiter(2);
		let active = 0;
		let maxActive = 0;
		const gates = Array.from({ length: 5 }, () => deferred<void>());

		const runs = gates.map((gate, i) =>
			limit(async () => {
				active++;
				maxActive = Math.max(maxActive, active);
				await gate.promise;
				active--;
				return i;
			}),
		);

		// Release gates one at a time; each release should backfill from the
		// queue without ever letting `active` exceed the cap.
		for (const gate of gates) {
			gate.resolve();
			// Let the released task's continuation (and its backfill) settle.
			await Promise.resolve();
			await Promise.resolve();
			await Promise.resolve();
		}

		const results = await Promise.all(runs);
		expect(results).toEqual([0, 1, 2, 3, 4]);
		expect(maxActive).toBeLessThanOrEqual(2);
		expect(active).toBe(0);
	});

	it("releases the slot even when the task throws", async () => {
		const limit = createLimiter(1);
		await expect(
			limit(async () => {
				throw new Error("boom");
			}),
		).rejects.toThrow("boom");

		// If the failed task's slot wasn't released, this would hang.
		let ran = false;
		await limit(async () => {
			ran = true;
		});
		expect(ran).toBe(true);
	});

	it("rejects a non-positive maxConcurrent", () => {
		expect(() => createLimiter(0)).toThrow();
	});
});
