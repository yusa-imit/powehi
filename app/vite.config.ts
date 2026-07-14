import { createHash } from "node:crypto";
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

// Computes SHA-256 integrity hash for Subresource Integrity (SRI).
// Only active during `pnpm build` (apply: "build"); never runs in dev or tests.
function sriPlugin(): Plugin {
	function sriHash(content: string | Uint8Array): string {
		return `sha256-${createHash("sha256")
			.update(content instanceof Uint8Array ? Buffer.from(content) : content)
			.digest("base64")}`;
	}

	// Builds the name→hash map from ctx.bundle inside transformIndexHtml.
	// This avoids the timing hazard where a separate generateBundle hook with
	// order:"post" would run AFTER Vite's own HTML-emitting generateBundle hook
	// (which calls transformIndexHtml), leaving the map empty at transform time.
	function buildHashMap(bundle: Record<string, unknown>): Map<string, string> {
		const map = new Map<string, string>();
		for (const [name, chunk] of Object.entries(bundle)) {
			if (chunk !== null && typeof chunk === "object") {
				if ("code" in chunk && typeof (chunk as { code: unknown }).code === "string") {
					map.set(name, sriHash((chunk as { code: string }).code));
				} else if ("source" in chunk && (chunk as { source: unknown }).source != null) {
					map.set(name, sriHash((chunk as { source: string | Uint8Array }).source));
				}
			}
		}
		return map;
	}

	function injectSriScript(input: string, hashes: Map<string, string>): string {
		return input.replace(
			/<script\b([^>]*)\bsrc="(\/assets\/[^"]+)"([^>]*)>/g,
			(match: string, before: string, src: string, after: string): string => {
				const key = src.replace(/^\//, "");
				const integrity = hashes.get(key);
				if (integrity && !match.includes("integrity=")) {
					return `<script${before} src="${src}" integrity="${integrity}"${after}>`;
				}
				return match;
			},
		);
	}

	function injectSriLink(input: string, hashes: Map<string, string>): string {
		return input.replace(
			/<link\b([^>]*)\bhref="(\/assets\/[^"]+)"([^>]*)\/?>/g,
			(match: string, before: string, href: string, after: string): string => {
				const key = href.replace(/^\//, "");
				const integrity = hashes.get(key);
				if (integrity && !match.includes("integrity=")) {
					return `<link${before} href="${href}" integrity="${integrity}"${after}/>`;
				}
				return match;
			},
		);
	}

	return {
		name: "powehi-sri",
		apply: "build",
		transformIndexHtml: {
			order: "post",
			handler(html: string, ctx: { bundle?: Record<string, unknown> }): string {
				const hashes = ctx.bundle ? buildHashMap(ctx.bundle) : new Map<string, string>();
				const result = injectSriLink(injectSriScript(html, hashes), hashes);
				// Fail fast if any /assets/ script or link is missing an integrity hash.
				const missing = [
					...(result.match(/<script\b[^>]*\bsrc="\/assets\/[^"]*"[^>]*>/g) ?? []),
					...(result.match(/<link\b[^>]*\bhref="\/assets\/[^"]*"[^>]*\/?>/g) ?? []),
				].filter((tag) => !tag.includes("integrity="));
				if (missing.length > 0) {
					throw new Error(
						`[powehi-sri] ${missing.length} asset(s) missing SRI integrity:\n${missing.join("\n")}`,
					);
				}
				return result;
			},
		},
	};
}

export default defineConfig({
	plugins: [powehiWasmStub(), react(), tailwindcss(), sriPlugin()],
	server: {
		// Dev-only: `src/api/*.ts` fetches relative `/v1/...` (matches the
		// production reverse-proxy topology, prd.md §12.2), but `vite dev`
		// itself doesn't proxy anything by default. Without this, `pnpm dev`
		// can never reach a real backend. Overridable for the live-backend
		// E2E harness (docker-compose.yml + e2e-live/) via an env var so a
		// differently-mapped CI backend port doesn't require editing this file.
		proxy: {
			"/v1": {
				target: process.env.POWEHI_DEV_BACKEND_URL ?? "http://localhost:8080",
				changeOrigin: true,
			},
		},
	},
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
		// Large test files (e.g. ChatLayout with 100+ renders) accumulate V8 heap
		// within one worker. Forks pool allows per-process --max-old-space-size;
		// threads pool (the default) ignores execArgv so the OOM is unavoidable there.
		//
		// On a 16GB host the forks pool defaults to one fork per core (~10), and
		// `--max-old-space-size=8192` lets EACH fork grow to 8GB — up to ~80GB of
		// permitted heap, which sends the machine deep into swap (observed >20GB
		// resident during autonomous-dev cycles). Cap the fork count and halve the
		// per-fork heap so the aggregate ceiling is maxForks * heap = 2 * 4GB = 8GB.
		pool: "forks",
		poolOptions: {
			forks: {
				minForks: 1,
				maxForks: 2,
				execArgv: ["--max-old-space-size=4096"],
			},
		},
	},
});
