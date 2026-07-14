import { expect, test } from "@playwright/test";
import { registerAndReachChat, signIn, uniqueHandle } from "./helpers";

// Live-backend E2E (testing-conventions.md: "E2E: Playwright for register/login
// (OPAQUE) ..."). Unlike ./e2e/*.spec.ts (which assert UI behavior with no
// backend reachable), this spec drives a REAL bin/powehi-server instance
// backed by real Postgres/Redis/MinIO — see docker-compose.yml and the
// `playwright-live-backend` CI job. Run locally with
// `pnpm --filter app e2e:live` once the compose stack + backend are up.
//
// Scope: OPAQUE registration (worker-side crypto, real network round trips)
// through to the chat layout rendering, then a reload + real sign-in with the
// same credentials (proves the device_id/MLS identity persisted to IndexedDB
// survives a refresh and the login/OPAQUE path also round-trips for real).
// Message send/receive across two real devices is covered by message.spec.ts.
test.describe("Live backend: registration + sign-in", () => {
	test("creates an account, reaches the chat layout, and can sign back in after a reload", async ({
		page,
	}) => {
		// Unique per run so re-runs against a persistent backend never collide
		// on "handle already registered".
		const handle = uniqueHandle();
		const password = "CorrectHorseBattery9!";

		await registerAndReachChat(page, handle, password);

		// A reload clears the in-memory session token (auth.ts) but keeps the
		// IndexedDB-persisted device_id + MLS identity — verifies real sign-in,
		// not just registration's internal auto-login.
		await page.reload();

		await signIn(page, handle, password);
	});
});
