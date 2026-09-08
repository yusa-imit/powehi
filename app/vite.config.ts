import { createHash } from "node:crypto";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const WASM_REAL_PATH = join(__dirname, "src/wasm/powehi_crypto_wasm.js");
const WASM_CRATE_DIR = join(__dirname, "../crates/client/powehi-crypto-wasm");
const WASM_STUB_ID = "\0virtual:powehi-wasm-stub";
// Bounds the staleness-check walk (issue #6) — the crate's own source tree is
// two orders of magnitude smaller than this; a runaway walk here would mean a
// symlink loop or a misconfigured WASM_CRATE_DIR, not real crate growth.
const STALENESS_WALK_FILE_LIMIT = 2000;

// Latest mtime (ms) across the crate's Cargo.toml/build.rs/src/** — the
// inputs that determine whether a built WASM artifact is up to date. Returns
// null if the crate dir is missing (shouldn't happen from a real checkout,
// but this check must never itself crash `vite dev`/`vitest`).
function latestWasmCrateSourceMtimeMs(): number | null {
	if (!existsSync(WASM_CRATE_DIR)) return null;
	let latest = 0;
	let visited = 0;
	function walk(dir: string): void {
		for (const entry of readdirSync(dir, { withFileTypes: true })) {
			if (visited >= STALENESS_WALK_FILE_LIMIT) return;
			visited += 1;
			const full = join(dir, entry.name);
			if (entry.isDirectory()) {
				// tests/ is a separate wasm-bindgen test target — editing it doesn't
				// change the shipped lib artifact, so it's excluded from staleness.
				if (
					entry.name === "target" ||
					entry.name === "pkg" ||
					entry.name === "pkg-node" ||
					entry.name === "tests"
				)
					continue;
				walk(full);
			} else if (entry.name.endsWith(".rs") || entry.name === "Cargo.toml") {
				const mtime = statSync(full).mtimeMs;
				if (mtime > latest) latest = mtime;
			}
		}
	}
	walk(WASM_CRATE_DIR);
	return latest > 0 ? latest : null;
}

// Loud, once-per-process signal for the failure mode issue #6 documented:
// a missing or stale WASM artifact makes every OPAQUE/MLS call silently
// no-op via the stub below, with no build error and no other warning.
//
// Skipped under Vitest: per testing-conventions.md, unit tests mock the
// Comlink worker boundary and never exercise the real WASM module, and CI's
// `vitest` job (ci-frontend.yml) intentionally only builds the `--target
// nodejs` artifact (for wasm-bindgen glue tests), never `app/src/wasm` — so
// this warning would otherwise fire on every green CI run and train
// reviewers to ignore it, defeating its purpose for the cases (dev server,
// `vite build`) it actually matters for.
function warnIfWasmArtifactMissingOrStale(): void {
	if (process.env.VITEST) return;
	if (!existsSync(WASM_REAL_PATH)) {
		console.warn(
			"[powehi-wasm-stub] app/src/wasm/powehi_crypto_wasm.js not found — " +
				"every OPAQUE/MLS call will silently no-op. Run `pnpm build:wasm` " +
				"from the repo root before testing real crypto flows.",
		);
		return;
	}
	const artifactMtime = statSync(WASM_REAL_PATH).mtimeMs;
	const sourceMtime = latestWasmCrateSourceMtimeMs();
	if (sourceMtime !== null && sourceMtime > artifactMtime) {
		console.warn(
			"[powehi-wasm-stub] app/src/wasm/powehi_crypto_wasm.js is older than " +
				"crates/client/powehi-crypto-wasm's sources — the loaded WASM build " +
				"may be missing recent exports. Run `pnpm build:wasm` to refresh it.",
		);
	}
}

// Resolves the wasm-pack JS glue to a no-op virtual module when the artifact
// is absent (CI without the wasm-build step, or fresh checkout).
// When wasm-pack has been run, the real file is found first and this has
// no effect.
function powehiWasmStub(): Plugin {
	return {
		name: "powehi-wasm-stub",
		enforce: "pre",
		buildStart() {
			warnIfWasmArtifactMissingOrStale();
		},
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
		// GH Actions-only: `.rejects.toThrow(string)` assertions have hit a rare
		// chai/@vitest-expect edge case (vitest-dev/vitest#4559-class — the
		// rejection-path message check dereferences an unset `.message` and
		// throws "Cannot read properties of undefined (reading 'indexOf')")
		// on ~2 of the last 16 CI — Frontend runs, always on test files
		// untouched by the triggering commit and never reproducible locally
		// across repeated full-suite runs. A real regression still fails
		// every retry (deterministic), so this only absorbs the transient
		// upstream flake — it does not widen what "green" means.
		retry: process.env.CI ? 1 : 0,
	},
});
