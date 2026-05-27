import { expect, test } from "@playwright/test";

// Force the app into the "app" phase by injecting Zustand store state via localStorage is not supported;
// instead we navigate and verify the login screen guards correctly.
test.describe("Chat layout", () => {
	test("login screen guards the chat layout", async ({ page }) => {
		await page.goto("/");

		// Chat layout only renders after successful login; initially login screen shows.
		await expect(page.locator("input[type='password']")).toBeVisible();

		// No chat sidebar or message list should be visible before login.
		await expect(page.locator("[data-testid='chat-sidebar']")).not.toBeVisible();
	});

	test("login screen has no console errors on load", async ({ page }) => {
		const errors: string[] = [];
		page.on("console", (msg) => {
			if (msg.type() === "error") errors.push(msg.text());
		});

		await page.goto("/");
		await page.waitForLoadState("networkidle");

		// Filter known non-critical errors (SW registration in test env, WASM not loaded)
		const critical = errors.filter(
			(e) =>
				!e.includes("service worker") &&
				!e.includes("ServiceWorker") &&
				!e.includes("wasm") &&
				!e.includes("WASM"),
		);
		expect(critical).toHaveLength(0);
	});
});
