import { expect, test } from "@playwright/test";

// Real-browser regression test for `Dexie.waitFor`-held IndexedDB transactions
// (encrypted-db.ts's markMessageReactionDelta/markMessageRead/markMessagePresenceStatus
// etc — anywhere a read-modify-write needs an async crypto-worker round trip
// *inside* an `rw` transaction). fake-indexeddb (used by encrypted-db.test.ts) settles
// every IDBRequest via its own timer shim and has never reproduced a spec-compliant
// engine auto-committing a transaction underneath `Dexie.waitFor` — the risk this
// guards against is real-engine IndexedDB transaction-lifetime behavior, which only a
// real browser can exercise (WebKit is the historically stricter engine here: it has a
// track record of committing an IDB transaction as soon as its microtask queue drains,
// which is exactly what `Dexie.waitFor` exists to prevent — see cycle 344/345/346 notes
// in .claude/memory/project-context.md, flagged as "F3" and deferred 3 cycles running).
// Mutation-verified (security-auditor, cycle 347): removing the `Dexie.waitFor` wrappers
// from markMessageReactionDelta makes this fail on BOTH the chromium and webkit
// projects below (TransactionInactiveError) — chromium's real IndexedDB engine already
// catches this class of regression, so the dedicated webkit project is engine-diversity
// insurance against future divergence, not a strict prerequisite for closing F3.
//
// Runs against `/src/*.ts` imported directly from the Vite dev server (no bundling) —
// this exercises the real Dexie + IndexedDB modules with zero backend/crypto-worker
// dependency, since EncryptedPowehiDb's `encryptor` param is an injectable interface
// (FieldEncryptor) and this test supplies a fake with a real `setTimeout`-based delay
// (a real macrotask, unlike a microtask-only Promise) to stand in for the crypto-worker
// postMessage round trip in production.
test.describe("Dexie.waitFor transaction liveness (real browser)", () => {
	test("markMessageReactionDelta survives a slow encryptor round trip without losing a concurrent merge", async ({
		page,
	}) => {
		await page.goto("/");

		const result = await page.evaluate(async () => {
			const { EncryptedPowehiDb } = await import("/src/db/encrypted-db.ts");
			const { PowehiDb } = await import("/src/db/schema.ts");

			// Isolate from any other IndexedDB state in this browser context. Reject
			// (not resolve) on "blocked" — that means another connection to
			// "PowehiDb" is still open (schema.ts's `export const db` singleton is
			// pre-login-reachable today, but if that ever changes, silently
			// continuing here would run the test against stale leftover state
			// instead of failing loudly; security-auditor, cycle 347).
			await new Promise<void>((resolve, reject) => {
				const req = indexedDB.deleteDatabase("PowehiDb");
				req.onsuccess = () => resolve();
				req.onerror = () => reject(req.error);
				req.onblocked = () => reject(new Error("deleteDatabase blocked by an open connection"));
			});

			const rawDb = new PowehiDb();
			await rawDb.open();

			// Fake FieldEncryptor: a real setTimeout delay (crosses a macrotask
			// boundary, unlike an immediately-resolved Promise) stands in for the
			// crypto-worker's postMessage round trip that Dexie.waitFor must keep
			// the transaction alive across.
			const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
			const store = new Map<string, string>();
			let counter = 0;
			const slowEncryptor = {
				async encryptDbField(value: string) {
					await delay(40);
					const token = `enc:${counter++}`;
					store.set(token, value);
					return token;
				},
				async decryptDbField(token: string) {
					await delay(40);
					const value = store.get(token);
					if (value === undefined) throw new Error(`unknown token: ${token}`);
					return value;
				},
			};

			// biome-ignore lint/suspicious/noExplicitAny: duck-typed FieldEncryptor, no import needed
			const encDb = new EncryptedPowehiDb(rawDb, slowEncryptor as any);

			await encDb.addMessage({
				id: "msg-liveness",
				groupId: "grp-liveness",
				ciphertextB64: "abc",
				senderDeviceId: "dev-1",
				epochSeq: 0,
				receivedAt: Date.now(),
			});

			// Two concurrent reaction deltas from different senders, same message —
			// the exact race markMessageReactionDelta's own unit test covers, but here
			// each leg's get→decrypt→merge→encrypt→put spans a real 80ms round trip
			// (2x40ms) inside the `rw` transaction via Dexie.waitFor. If the browser's
			// real IndexedDB engine auto-commits the transaction before the awaited
			// encryptor settles, one leg's `put` throws (transaction already
			// finished/aborted) instead of the merge landing cleanly.
			const outcome = await Promise.allSettled([
				encDb.markMessageReactionDelta("msg-liveness", "\u{1F44D}", "dev-1", "add"),
				encDb.markMessageReactionDelta("msg-liveness", "\u{2764}\u{FE0F}", "dev-2", "add"),
			]);

			const row = await encDb.getMessage("msg-liveness");
			const reactions = row?.reactionsJson ? JSON.parse(row.reactionsJson) : {};

			return {
				rejections: outcome
					.filter((o): o is PromiseRejectedResult => o.status === "rejected")
					.map((o) => String(o.reason)),
				reactions,
			};
		});

		// Neither leg's transaction should have been aborted by the engine.
		expect(result.rejections).toEqual([]);
		// Both concurrent senders' reactions must have merged, not clobbered.
		expect(result.reactions["\u{1F44D}"]).toEqual(["dev-1"]);
		expect(result.reactions["\u{2764}\u{FE0F}"]).toEqual(["dev-2"]);
	});
});
