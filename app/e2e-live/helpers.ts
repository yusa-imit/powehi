import { randomUUID } from "node:crypto";
import type { Page } from "@playwright/test";
import { expect } from "@playwright/test";

/** A random unique handle, safe to register repeatedly against a persistent backend. */
export function uniqueHandle(): string {
	return `e2e-${randomUUID()}`;
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
