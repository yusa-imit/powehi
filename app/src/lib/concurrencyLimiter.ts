/**
 * createLimiter — bound how many async tasks run concurrently.
 *
 * Used to cap concurrent WASM media-key-handle holders (receiver-path media +
 * thumbnail decrypt) well under the shared `MAX_MEDIA_HANDLES` cap in
 * `powehi-crypto-wasm` — the message list is unvirtualized, so opening a
 * media-heavy chat can otherwise mount hundreds of decrypts in the same tick
 * (crypto-reviewer advisory, cycle 311).
 *
 * Optional `signal`: a task still waiting in the queue when its signal aborts
 * (e.g. a fast chat-switch unmounting the component that queued it) is
 * dequeued and rejected WITHOUT ever running `fn` — it never burns a slot or
 * imports a WASM handle for work whose result will just be discarded
 * (crypto-reviewer advisory B, cycle 312). A task that has already been
 * dequeued (running, or about to run) is unaffected by a later abort — `fn`
 * itself is responsible for its own in-flight cancellation check.
 */

export type Limiter = <T>(fn: () => Promise<T>, signal?: AbortSignal) => Promise<T>;

function abortError(): DOMException {
	return new DOMException("Aborted", "AbortError");
}

export function createLimiter(maxConcurrent: number): Limiter {
	if (maxConcurrent < 1) throw new Error("maxConcurrent must be >= 1");
	let active = 0;
	const queue: Array<() => void> = [];

	const release = () => {
		active--;
		const next = queue.shift();
		if (next) {
			active++;
			next();
		}
	};

	return function limit<T>(fn: () => Promise<T>, signal?: AbortSignal): Promise<T> {
		if (signal?.aborted) return Promise.reject(abortError());
		return new Promise<void>((resolve, reject) => {
			let onAbort: (() => void) | undefined;
			const enter = () => {
				if (onAbort) signal?.removeEventListener("abort", onAbort);
				resolve();
			};
			if (active < maxConcurrent) {
				active++;
				enter();
				return;
			}
			queue.push(enter);
			if (signal) {
				onAbort = () => {
					const idx = queue.indexOf(enter);
					if (idx !== -1) {
						queue.splice(idx, 1);
						reject(abortError());
					}
					// Not found: already dequeued (running/about to run) — let it proceed.
				};
				signal.addEventListener("abort", onAbort, { once: true });
			}
		}).then(() => fn().finally(release));
	};
}
