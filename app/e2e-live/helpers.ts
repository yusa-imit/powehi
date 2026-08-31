import { randomInt, randomUUID } from "node:crypto";
import type { BrowserContext, Page } from "@playwright/test";
import { expect } from "@playwright/test";

/** A random unique handle, safe to register repeatedly against a persistent backend. */
export function uniqueHandle(): string {
	return `e2e-${randomUUID()}`;
}

/**
 * `auth_governor` (rate_limit.rs) rate-limits `/v1/auth/*` per client IP.
 * Playwright's requests carry no `CF-Connecting-IP`/`X-Forwarded-For`/
 * `X-Real-IP` header, so every `BrowserContext` in this suite falls through
 * to the same `0.0.0.0` fallback bucket and simulated devices exhaust each
 * other's burst — auth.spec.ts alone fits inside burst=8, but adding
 * message.spec.ts's two-device flow on top blows it. Give each simulated
 * device its own X-Real-IP so the governor treats them as distinct clients,
 * same as it would behind a real reverse proxy. This is a test-harness
 * fidelity fix, not a rate-limit change — `auth_governor`'s production
 * burst/refill values are untouched.
 */
export async function simulateDistinctClientIp(context: BrowserContext): Promise<void> {
	const ip = `10.${randomInt(1, 255)}.${randomInt(1, 255)}.${randomInt(1, 255)}`;
	await context.setExtraHTTPHeaders({ "x-real-ip": ip });
}

/**
 * Forward uncaught page exceptions and `console.error` output to the test
 * runner's stdout (captured by CI logs), prefixed with `label` so a two-device
 * spec can tell which page a failure came from.
 *
 * Diagnostic only — a WASM panic message or a JS `Error.message`/stack is a
 * code-path description, never message content, PII, or ciphertext, so this
 * does not violate `no-plaintext-logging`. Only `error`-level console output
 * and `pageerror` are forwarded (not every `console.log`), to avoid dragging
 * in incidental app state.
 */
export function forwardBrowserErrors(page: Page, label: string): void {
	page.on("pageerror", (err) => {
		console.error(`[${label} pageerror]`, err.message);
	});
	page.on("console", (msg) => {
		if (msg.type() === "error") {
			console.error(`[${label} console.error]`, msg.text());
		}
	});
}

/**
 * Drives the real "create account" flow (OPAQUE registration + MLS identity
 * init, all real network round trips) through to the chat layout rendering,
 * and dismisses the recovery-phrase dialog.
 */
export async function registerAndReachChat(
	page: Page,
	handle: string,
	password: string,
): Promise<void> {
	await page.goto("/");

	await expect(page.getByRole("heading", { name: /powehi/i })).toBeVisible();

	await page.getByRole("button", { name: /new to powehi\? create account/i }).click();

	await page.getByRole("textbox", { name: /handle/i }).fill(handle);
	await page.locator("input[type='password']").fill(password);
	await page.getByRole("button", { name: "Create account" }).click();

	// OPAQUE registration + MLS identity init + server round trips all happen
	// before this dialog renders — allow generous time.
	const recoveryDialog = page.getByRole("dialog", { name: /recovery phrase/i });
	await expect(recoveryDialog).toBeVisible({ timeout: 30_000 });
	await recoveryDialog.getByRole("button", { name: /i have saved my recovery phrase/i }).click();

	await expect(page.getByTestId("chat-sidebar")).toBeVisible({ timeout: 30_000 });
}

/**
 * Drives the real "sign in" flow (OPAQUE login KE1/KE2/KE3) through to the
 * chat layout rendering. Assumes the page is currently on the login screen
 * (e.g. after a fresh `page.goto` or a `page.reload()`, which clears the
 * in-memory session token but keeps the IndexedDB-persisted device_id/MLS
 * identity for this handle).
 */
export async function signIn(page: Page, handle: string, password: string): Promise<void> {
	await expect(page.getByRole("textbox", { name: /handle/i })).toBeVisible();
	await page.getByRole("textbox", { name: /handle/i }).fill(handle);
	await page.locator("input[type='password']").fill(password);
	await page.getByRole("button", { name: "Sign in" }).click();

	await expect(page.getByTestId("chat-sidebar")).toBeVisible({ timeout: 30_000 });
}

/**
 * Drives the real "log out" flow through the sidebar Settings icon → Log out
 * button (SettingsPanel.tsx), which calls useAuthStore().logout() — awaiting
 * clearSessionState() then dropDbKey() on the crypto worker before resetting
 * auth state back to the login phase. Assumes the page is currently on the
 * chat layout (i.e. `chat-sidebar` is visible).
 *
 * Unlike `page.reload()` (which only drops the in-memory session token by
 * restarting the tab), this exercises the actual in-app button path a real
 * user has to sign out — there was no UI caller for `logout()` at all before
 * SettingsPanel.tsx was wired up.
 */
export async function logOut(page: Page): Promise<void> {
	await page.getByRole("button", { name: "Settings" }).click();
	await expect(page.getByTestId("settings-panel")).toBeVisible();

	await page.getByTestId("settings-logout-btn").click();

	await expect(page.getByRole("heading", { name: /powehi/i })).toBeVisible({ timeout: 15_000 });
	await expect(page.getByRole("textbox", { name: /handle/i })).toBeVisible();
}
