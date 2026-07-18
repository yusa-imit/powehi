/**
 * createLimiter — bound how many async tasks run concurrently.
 *
 * Used to cap concurrent WASM media-key-handle holders (receiver-path media +
 * thumbnail decrypt) well under the shared `MAX_MEDIA_HANDLES` cap in
 * `powehi-crypto-wasm` — the message list is unvirtualized, so opening a
 * media-heavy chat can otherwise mount hundreds of decrypts in the same tick
 * (crypto-reviewer advisory, cycle 311).
 */

export type Limiter = <T>(fn: () => Promise<T>) => Promise<T>;

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

	return function limit<T>(fn: () => Promise<T>): Promise<T> {
		return new Promise<void>((resolve) => {
			if (active < maxConcurrent) {
				active++;
				resolve();
			} else {
				queue.push(resolve);
			}
		}).then(() => fn().finally(release));
	};
}
