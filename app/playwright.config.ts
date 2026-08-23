import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
	testDir: "./e2e",
	fullyParallel: true,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 2 : 0,
	workers: process.env.CI ? 1 : undefined,
	reporter: "list",
	use: {
		baseURL: "http://localhost:5173",
		trace: "on-first-retry",
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
		{
			// Extra engine-diversity coverage for IndexedDB transaction-lifetime
			// behavior against future divergence (see dexie-transaction-liveness.spec.ts's
			// doc comment — chromium's project above already catches this class of
			// regression too) — scoped to just that spec via testMatch so the rest
			// of the suite doesn't pay a second real-browser run per spec.
			name: "webkit-dexie-liveness",
			testMatch: /dexie-transaction-liveness\.spec\.ts/,
			use: { ...devices["Desktop Safari"] },
		},
	],
	webServer: {
		command: "pnpm dev",
		url: "http://localhost:5173",
		reuseExistingServer: !process.env.CI,
		timeout: 30_000,
	},
});
