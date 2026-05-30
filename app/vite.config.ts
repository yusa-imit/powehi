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
	const hashes = new Map<string, string>(); // "assets/foo.js" → "sha256-..."

	function sriHash(content: string | Uint8Array): string {
		return `sha256-${createHash("sha256")
			.update(content instanceof Uint8Array ? Buffer.from(content) : content)
			.digest("base64")}`;
	}

	function injectSriScript(input: string): string {
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

	function injectSriLink(input: string): string {
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
		// order: "post" ensures this runs after all other plugins have mutated chunks,
		// so hashes are computed over the final emitted bytes.
		generateBundle: {
			order: "post" as const,
			handler(_opts: unknown, bundle: Record<string, unknown>) {
				for (const [name, chunk] of Object.entries(bundle)) {
					if (
						chunk !== null &&
						typeof chunk === "object" &&
						"code" in chunk &&
						typeof (chunk as { code: unknown }).code === "string"
					) {
						hashes.set(name, sriHash((chunk as { code: string }).code));
					} else if (
						chunk !== null &&
						typeof chunk === "object" &&
						"source" in chunk &&
						(chunk as { source: unknown }).source != null
					) {
						hashes.set(name, sriHash((chunk as { source: string | Uint8Array }).source));
					}
				}
			},
		},
		transformIndexHtml: {
			enforce: "post",
			handler(html: string): string {
				const result = injectSriLink(injectSriScript(html));
				// Verify every /assets/ script and link received an integrity hash.
				// A missing hash means the chunk was not in the bundle map — fail fast
				// rather than silently ship an unprotected resource.
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
