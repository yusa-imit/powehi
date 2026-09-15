import { describe, expect, it, vi } from "vitest";
import { withMlsCommitLock } from "./mlsCommitLock";

function deferred<T>(): {
	promise: Promise<T>;
	resolve: (v: T) => void;
	reject: (e: unknown) => void;
} {
	let resolve!: (v: T) => void;
	let reject!: (e: unknown) => void;
	const promise = new Promise<T>((res, rej) => {
		resolve = res;
		reject = rej;
	});
	return { promise, resolve, reject };
}

describe("withMlsCommitLock", () => {
	it("runs a single task and resolves its value", async () => {
		await expect(withMlsCommitLock("group-a", async () => 42)).resolves.toBe(42);
	});

	it("serializes two tasks for the SAME group — the second never starts before the first finishes", async () => {
		const order: string[] = [];
		const first = deferred<void>();

		const p1 = withMlsCommitLock("group-b", async () => {
			order.push("first-start");
			await first.promise;
			order.push("first-end");
		});
		const p2 = withMlsCommitLock("group-b", async () => {
			order.push("second-start");
		});

		// Give the microtask queue a tick — if the lock were absent, "second-start"
		// would already have run before "first-end".
		await Promise.resolve();
		await Promise.resolve();
		expect(order).toEqual(["first-start"]);

		first.resolve();
		await Promise.all([p1, p2]);
		expect(order).toEqual(["first-start", "first-end", "second-start"]);
	});

	it("does NOT serialize tasks for DIFFERENT groups — one group's lock never blocks another's", async () => {
		const order: string[] = [];
		const first = deferred<void>();

		const p1 = withMlsCommitLock("group-c", async () => {
			order.push("c-start");
			await first.promise;
			order.push("c-end");
		});
		const p2 = withMlsCommitLock("group-d", async () => {
			order.push("d-start");
		});

		await p2;
		expect(order).toEqual(["c-start", "d-start"]);

		first.resolve();
		await p1;
		expect(order).toEqual(["c-start", "d-start", "c-end"]);
	});

	it("releases the lock even when the task throws, so a later task for the same group still runs", async () => {
		const boom = new Error("boom");
		await expect(
			withMlsCommitLock("group-e", async () => {
				throw boom;
			}),
		).rejects.toBe(boom);

		// If the lock were left held, this would hang forever — the test's own
		// timeout is the assertion.
		await expect(withMlsCommitLock("group-e", async () => "recovered")).resolves.toBe("recovered");
	});

	it("releases the lock when fn throws SYNCHRONOUSLY (never returns a Promise at all) — crypto-reviewer F1", async () => {
		const boom = new Error("sync boom");
		// Not `async () => { throw boom }` (which returns a rejected Promise) —
		// a genuinely synchronous throw, which is what previously bypassed
		// createLimiter's `fn().finally(release)` executor entirely and left
		// the mutex permanently wedged.
		const syncThrowingFn = (() => {
			throw boom;
		}) as () => Promise<never>;

		await expect(withMlsCommitLock("group-sync-throw", syncThrowingFn)).rejects.toBe(boom);

		// If the lock were left held, this would hang forever — the test's own
		// timeout is the assertion.
		await expect(withMlsCommitLock("group-sync-throw", async () => "recovered")).resolves.toBe(
			"recovered",
		);
	});

	it("releases the lock when fn returns a non-Promise value — crypto-reviewer F1", async () => {
		const nonPromiseFn = (() => 123) as unknown as () => Promise<number>;

		await expect(withMlsCommitLock("group-non-promise", nonPromiseFn)).resolves.toBe(123);

		// If the lock were left held, this would hang forever — the test's own
		// timeout is the assertion.
		await expect(withMlsCommitLock("group-non-promise", async () => "recovered")).resolves.toBe(
			"recovered",
		);
	});

	it("propagates the task's rejection to the specific caller that queued it, not to unrelated callers", async () => {
		const boom = new Error("boom");
		const first = withMlsCommitLock("group-f", async () => {
			throw boom;
		});
		const second = withMlsCommitLock("group-f", async () => "ok");

		await expect(first).rejects.toBe(boom);
		await expect(second).resolves.toBe("ok");
	});

	it("a third task for the same group waits behind both a first (throwing) and a second task", async () => {
		const order: string[] = [];
		const p1 = withMlsCommitLock("group-g", async () => {
			order.push("1");
			throw new Error("first fails");
		});
		const p2 = withMlsCommitLock("group-g", async () => {
			order.push("2");
		});
		const p3 = withMlsCommitLock("group-g", async () => {
			order.push("3");
		});

		await Promise.allSettled([p1, p2, p3]);
		expect(order).toEqual(["1", "2", "3"]);
	});

	it("runs many concurrently-queued tasks for the same group in FIFO order", async () => {
		const order: number[] = [];
		const tasks = Array.from({ length: 20 }, (_, i) =>
			withMlsCommitLock("group-h", async () => {
				order.push(i);
			}),
		);
		await Promise.all(tasks);
		expect(order).toEqual(Array.from({ length: 20 }, (_, i) => i));
	});

	it("evicts idle entries once MAX_TRACKED_GROUPS distinct groups have been used, without breaking exclusivity for a still-busy group", async () => {
		// Occupy one group with a long-running task, then churn far more than the
		// tracked cap through distinct groupIds — the busy group's lock must
		// still be honored throughout (it must never be evicted mid-flight).
		const busy = deferred<void>();
		const order: string[] = [];
		const busyTask = withMlsCommitLock("busy-group", async () => {
			order.push("busy-start");
			await busy.promise;
			order.push("busy-end");
		});

		for (let i = 0; i < 200; i++) {
			await withMlsCommitLock(`churn-${i}`, async () => {});
		}

		expect(order).toEqual(["busy-start"]);
		const raceTask = withMlsCommitLock("busy-group", async () => {
			order.push("race");
		});
		await Promise.resolve();
		await Promise.resolve();
		expect(order).toEqual(["busy-start"]);

		busy.resolve();
		await Promise.all([busyTask, raceTask]);
		expect(order).toEqual(["busy-start", "busy-end", "race"]);
	});
});

describe("withMlsCommitLock — fake timers sanity", () => {
	it("does not require timers to settle (pure microtask-based)", async () => {
		vi.useFakeTimers();
		try {
			const result = await withMlsCommitLock("group-timers", async () => "done");
			expect(result).toBe("done");
		} finally {
			vi.useRealTimers();
		}
	});
});
