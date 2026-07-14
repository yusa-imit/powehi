import { defineConfig, devices } from "@playwright/test";

// Live-backend E2E harness (testing-conventions.md: "E2E: Playwright for
// register/login (OPAQUE) and message send/receive"). Separate from
// playwright.config.ts (whose ./e2e specs assert UI behavior with NO backend
// running) so the existing frontend-only Playwright CI job is unaffected —
// this config only picks up ./e2e-live, never ./e2e.
//
// Requires a real backend reachable at POWEHI_DEV_BACKEND_URL (default
// http://localhost:8080, matching docker-compose.yml + bin/powehi-server's
// default POWEHI__PORT) — see docker-compose.yml and
// .github/workflows/ci-e2e-live.yml's `playwright-live-backend` job.
export default defineConfig({
	testDir: "./e2e-live",
	fullyParallel: false,
	forbidOnly: !!process.env.CI,
	retries: process.env.CI ? 1 : 0,
	workers: 1,
	timeout: 60_000,
	reporter: "list",
	use: {
		baseURL: "http://localhost:5173",
		// security-auditor finding (cycle 277, low/defense-in-depth): a retry
		// trace's DOM snapshots would capture the recovery-phrase mnemonic and
		// typed password rendered in this spec. Not currently exfiltrated (CI
		// never uploads test-results/), but do NOT add a step that uploads
		// Playwright traces/screenshots from this config without redacting or
		// dropping the recovery-phrase and login steps first.
		trace: "on-first-retry",
	},
	projects: [
		{
			name: "chromium",
			use: { ...devices["Desktop Chrome"] },
		},
	],
	webServer: {
		command: "pnpm dev",
		url: "http://localhost:5173",
		reuseExistingServer: !process.env.CI,
		timeout: 30_000,
	},
});
