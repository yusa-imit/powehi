import { randomUUID } from "node:crypto";
import { expect, test } from "@playwright/test";

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
// Message send/receive across two real devices is a larger follow-up (needs
// a second identity + MLS group join) intentionally left for a future cycle.
test.describe("Live backend: registration + sign-in", () => {
	test("creates an account, reaches the chat layout, and can sign back in after a reload", async ({
		page,
	}) => {
		// Unique per run so re-runs against a persistent backend never collide
		// on "handle already registered".
		const handle = `e2e-${randomUUID()}`;
		const password = "CorrectHorseBattery9!";

		await page.goto("/");

		await expect(page.getByRole("heading", { name: /powehi/i })).toBeVisible();

		await page.getByRole("button", { name: /new to powehi\? create account/i }).click();

		await page.getByRole("textbox", { name: /handle/i }).fill(handle);
		await page.locator("input[type='password']").fill(password);
		await page.getByRole("button", { name: "Create account" }).click();

		// OPAQUE registration + MLS identity init + server round trips all
		// happen before this dialog renders — allow generous time.
		const recoveryDialog = page.getByRole("dialog", { name: /recovery phrase/i });
		await expect(recoveryDialog).toBeVisible({ timeout: 30_000 });
		await recoveryDialog.getByRole("button", { name: /i have saved my recovery phrase/i }).click();

		await expect(page.getByTestId("chat-sidebar")).toBeVisible({ timeout: 30_000 });

		// A reload clears the in-memory session token (auth.ts) but keeps the
		// IndexedDB-persisted device_id + MLS identity — verifies real sign-in,
		// not just registration's internal auto-login.
		await page.reload();

		await expect(page.getByRole("textbox", { name: /handle/i })).toBeVisible();
		await page.getByRole("textbox", { name: /handle/i }).fill(handle);
		await page.locator("input[type='password']").fill(password);
		await page.getByRole("button", { name: "Sign in" }).click();

		await expect(page.getByTestId("chat-sidebar")).toBeVisible({ timeout: 30_000 });
	});
});
