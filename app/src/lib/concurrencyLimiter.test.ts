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

	it("dequeues an aborted-while-queued task without ever running it", async () => {
		const limit = createLimiter(1);
		const gate = deferred<void>();
		let ran = false;

		// Occupy the only slot so the next call must queue.
		const holder = limit(async () => {
			await gate.promise;
		});

		const controller = new AbortController();
		const queued = limit(async () => {
			ran = true;
		}, controller.signal);

		controller.abort();
		await expect(queued).rejects.toThrow(/aborted/i);
		expect(ran).toBe(false);

		// Releasing the holder must not resurrect the aborted task or leave the
		// limiter stuck — the next call should still run immediately.
		gate.resolve();
		await holder;
		let ranAfter = false;
		await limit(async () => {
			ranAfter = true;
		});
		expect(ranAfter).toBe(true);
	});

	it("rejects immediately for an already-aborted signal without queueing", async () => {
		const limit = createLimiter(1);
		const controller = new AbortController();
		controller.abort();
		let ran = false;
		await expect(
			limit(async () => {
				ran = true;
			}, controller.signal),
		).rejects.toThrow(/aborted/i);
		expect(ran).toBe(false);
	});

	it("lets an already-running task finish even if its signal aborts mid-flight", async () => {
		const limit = createLimiter(1);
		const controller = new AbortController();
		const gate = deferred<void>();
		let completed = false;

		const running = limit(async () => {
			await gate.promise;
			completed = true;
		}, controller.signal);

		// Task is already dequeued/running — abort now should have no effect on it.
		controller.abort();
		gate.resolve();
		await running;
		expect(completed).toBe(true);
	});
});
