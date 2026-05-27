// Bundle budget gate: initial JS < 200KB gz, WASM < 800KB gz (prd.md §7)
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

const DIST = new URL("../dist", import.meta.url).pathname;
const JS_BUDGET_GZ = 200 * 1024; // 200KB gzip
const WASM_BUDGET_GZ = 800 * 1024; // 800KB gzip

if (!existsSync(DIST)) {
	console.error("dist/ not found — run `pnpm build` first");
	process.exit(1);
}

function gzSize(path) {
	return gzipSync(readFileSync(path), { level: 9 }).length;
}

function walk(dir) {
	return readdirSync(dir).flatMap((name) => {
		const full = join(dir, name);
		return statSync(full).isDirectory() ? walk(full) : [full];
	});
}

const files = walk(DIST);

let failed = false;

// JS chunks that are loaded on initial route (index-*.js)
const initChunks = files.filter((f) => f.endsWith(".js") && /index-[\w-]+\.js$/.test(f));
for (const f of initChunks) {
	const gz = gzSize(f);
	const kb = (gz / 1024).toFixed(1);
	const rel = f.replace(DIST, "");
	if (gz > JS_BUDGET_GZ) {
		console.error(`OVER BUDGET: ${rel} = ${kb}KB gz (limit 200KB)`);
		failed = true;
	} else {
		console.log(`OK: ${rel} = ${kb}KB gz`);
	}
}

// WASM files
const wasmFiles = files.filter((f) => f.endsWith(".wasm"));
for (const f of wasmFiles) {
	const gz = gzSize(f);
	const kb = (gz / 1024).toFixed(1);
	const rel = f.replace(DIST, "");
	if (gz > WASM_BUDGET_GZ) {
		console.error(`OVER BUDGET: ${rel} = ${kb}KB gz (limit 800KB)`);
		failed = true;
	} else {
		console.log(`OK: ${rel} = ${kb}KB gz`);
	}
}

if (initChunks.length === 0) {
	console.log("(no initial JS chunks found — skipping JS budget check)");
}
if (wasmFiles.length === 0) {
	console.log("(no WASM files found — skipping WASM budget check)");
}

process.exit(failed ? 1 : 0);
