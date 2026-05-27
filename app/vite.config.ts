import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const WASM_REAL_PATH = join(__dirname, "src/wasm/powehi_crypto_wasm.js");
const WASM_STUB_ID = "\0virtual:powehi-wasm-stub";

// Resolves the wasm-pack JS glue to a no-op virtual module when the artifact
// is absent (CI without the wasm-build step, or fresh checkout).
// When wasm-pack has been run, the real file is found first and this has
// no effect.
function powehiWasmStub(): Plugin {
	return {
		name: "powehi-wasm-stub",
		enforce: "pre",
		resolveId(id: string) {
			if (id.includes("powehi_crypto_wasm") && !existsSync(WASM_REAL_PATH)) {
				return WASM_STUB_ID;
			}
		},
		load(id: string) {
			if (id === WASM_STUB_ID) {
				// Minimal shape: default export is the wasm-bindgen init function.
				// All named exports are stubs — callers catch errors gracefully.
				return "export default async function init() {}";
			}
		},
	};
}

export default defineConfig({
	plugins: [powehiWasmStub(), react(), tailwindcss()],
	worker: {
		format: "es",
		// The stub plugin must also run in the worker-build context so that
		// vite:worker-import-meta-url does not fail when bundling the worker.
		plugins: () => [powehiWasmStub()],
	},
	test: {
		environment: "jsdom",
		globals: true,
		setupFiles: ["./src/test-setup.ts"],
		include: ["src/**/*.{test,spec}.{ts,tsx}"],
		exclude: ["e2e/**", "node_modules/**"],
	},
});
