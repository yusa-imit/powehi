// Closes the JS-glue password copy-back gap cycle 398 flagged and cycles
// 399/400 deferred (see .claude/memory/project-context.md "cycle 398" /
// "cycle 399" entries and wasm_bindgen_tests.rs's own coverage-note comment
// block above its OPAQUE zeroize tests).
//
// wasm_exports.rs's four OPAQUE exports (opaque_registration_start/finish,
// opaque_login_start/finish) take `password: &mut [u8]` and wrap it in the
// `PasswordScrubGuard` RAII guard so the Rust-side WASM-linear-memory copy is
// zeroized on every exit path (see that guard's doc comment). Cycle 398 added
// `wasm-pack test --node` coverage in wasm_bindgen_tests.rs proving the
// guard's `Drop` fires — but those tests call the exports as plain Rust
// (`opaque_registration_start(&mut password)`), which never goes through the
// wasm-bindgen-*generated JS glue*'s `passArray8ToWasm0` malloc +
// `__wbg___wbindgen_copy_to_typed_array_*` copy-back machinery that a real
// browser/Comlink caller's `Uint8Array` argument actually goes through. That
// glue-level copy-back is what THIS file proves: that the caller's own
// `Uint8Array` — not just the WASM-internal copy — ends up all-zero.
//
// Why this must run under Node's `--target nodejs` build, not the
// `--target web` build the app ships (`app/src/wasm/`, built by the root
// `build:wasm` script): `--target web` glue calls
// `fetch(new URL("./powehi_crypto_wasm_bg.wasm", import.meta.url))`, and
// Node's native `fetch` does not support `file://` URLs (confirmed by direct
// experiment — throws). `--target nodejs` glue instead does a synchronous
// `fs.readFileSync` + `new WebAssembly.Instance(...)`, which loads natively
// under plain Vitest (jsdom env, no browser, no dev server). The copy-back
// logic wasm-bindgen generates for a `&mut [u8]` parameter is identical
// regardless of target — only the module-loading strategy differs — so this
// is the SAME real JS glue a browser caller exercises, not a mock of it.
//
// This is TEST-ONLY tooling: `pnpm run build:wasm:node` (root package.json)
// produces `crates/client/powehi-crypto-wasm/pkg-node/` — gitignored, never
// shipped, entirely separate from the production `--target web` artifact and
// the `powehiWasmStub` Vite plugin fallback (vite.config.ts), which are both
// left untouched by this file.
//
// Scope (deliberately narrower than wasm_bindgen_tests.rs's 7-test shape):
//   - opaque_registration_start / opaque_login_start: SUCCESS-path zeroize.
//     Fully self-contained — no server needed.
//   - opaque_registration_finish / opaque_login_finish: ERROR-path zeroize
//     (unknown session id) — the earliest possible error return, reachable
//     without a server.
// NOT covered here: *_finish SUCCESS-path zeroize, and the wrong-password
// negative control (cycle 398's `test_opaque_login_finish_wrong_password_fails_and_zeroizes`,
// added after crypto-reviewer round 1 caught an earlier draft using
// unequal-length passwords that stayed green under an eager-scrub mutation
// for the wrong reason — see that test's doc comment). Both require a real
// client<->server OPAQUE round trip. Rust-side, wasm_bindgen_tests.rs gets
// this "for free" by linking opaque-ke's server types directly into the same
// wasm32 test binary; this file has no such counterpart reachable from plain
// Node/Vitest without either (a) adding new test-only server-simulation
// `#[wasm_bindgen]` exports to wasm_exports.rs (production file — out of
// scope per this change's constraints) or (b) a second, independently-audited
// JS/WASM OPAQUE implementation whose wire format is verified byte-compatible
// with opaque-ke's (unverified, high-risk rabbit hole, not attempted). A
// canned/fixed server-response fixture is not viable either: registration
// and login messages embed fresh ephemeral values from `OsRng` on every call,
// so a pre-recorded server response never validates against a freshly
// generated client message. Left as a candidate for a future cycle, same as
// cycle 398 left this file's scope open.
import { existsSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// `new URL(".", import.meta.url)` cannot be used here: under Vitest's jsdom
// environment, the global `URL` constructor resolves relative URLs against
// jsdom's `http://localhost:3000/` location rather than the given file: base
// (a jsdom/environment quirk, confirmed by direct experiment — it throws
// "The URL must be of scheme file"). Deriving the directory from
// `fileURLToPath(import.meta.url)` + `dirname()` avoids the global `URL`
// class entirely.
const __dirname = dirname(fileURLToPath(import.meta.url));

// `pkg-node/` is a gitignored local/CI build artifact (see root package.json's
// `build:wasm:node` script and .gitignore) — absent on a fresh checkout that
// hasn't run that script. Resolved without a static `import` specifier (which
// would make `tsc -b` fail to resolve the module on a checkout where the
// directory doesn't exist yet) — same reasoning as `vite.config.ts`'s
// `powehiWasmStub` plugin, applied at the TypeScript level instead of Vite's.
const PKG_NODE_PATH = join(
	__dirname,
	"..",
	"..",
	"..",
	"crates",
	"client",
	"powehi-crypto-wasm",
	"pkg-node",
	"powehi_crypto_wasm.js",
);

const pkgNodeExists = existsSync(PKG_NODE_PATH);

// In CI, a missing artifact must fail loudly, not silently skip this
// security-invariant gate. If the `--out-dir` in the `build:wasm:node` script,
// wasm-pack's output naming, or this crate's name ever drifts, a silent skip
// would leave CI green with zero coverage of the zeroize invariant below —
// same `process.env.CI` pattern already used by vite.config.ts / playwright.config.ts.
if (!pkgNodeExists && process.env.CI) {
	throw new Error(
		`OPAQUE wasm-glue zeroize test: expected build artifact not found at ${PKG_NODE_PATH}. The 'Build OPAQUE wasm-bindgen nodejs-target test artifact' CI step (ci-frontend.yml) should have produced it via \`pnpm run build:wasm:node\` before Vitest ran.`,
	);
}

/** Minimal shape of the subset of `pkg-node`'s CJS exports this file calls. */
interface OpaqueWasmModule {
	opaque_registration_start(password: Uint8Array): { sessionId: string; message: Uint8Array };
	opaque_login_start(password: Uint8Array): { sessionId: string; message: Uint8Array };
	opaque_registration_finish(
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	): unknown;
	opaque_login_finish(sessionId: string, password: Uint8Array, serverResponse: Uint8Array): unknown;
}

// Only required (loaded) when the artifact is present — requiring it
// unconditionally would throw on a fresh checkout, defeating the graceful
// skip below.
const wasm: OpaqueWasmModule | null = pkgNodeExists
	? (createRequire(import.meta.url)(PKG_NODE_PATH) as OpaqueWasmModule)
	: null;

function freshPassword(): Uint8Array {
	return new TextEncoder().encode("correct horse battery staple, wasm-glue test");
}

describe.skipIf(!pkgNodeExists)(
	"OPAQUE wasm-bindgen JS-glue password copy-back zeroize (--target nodejs artifact)",
	() => {
		it("opaque_registration_start zeroizes the caller's Uint8Array after a successful call", () => {
			const password = freshPassword();
			const before = password.slice();
			expect(before.some((b) => b !== 0)).toBe(true); // sanity: password started non-zero

			const result = (wasm as OpaqueWasmModule).opaque_registration_start(password);

			expect(typeof result.sessionId).toBe("string");
			expect(result.message).toBeInstanceOf(Uint8Array);
			expect(result.message.length).toBeGreaterThan(0);
			expect(password.every((b) => b === 0)).toBe(true);
		});

		it("opaque_login_start zeroizes the caller's Uint8Array after a successful call", () => {
			const password = freshPassword();
			const before = password.slice();
			expect(before.some((b) => b !== 0)).toBe(true); // sanity: password started non-zero

			const result = (wasm as OpaqueWasmModule).opaque_login_start(password);

			expect(typeof result.sessionId).toBe("string");
			expect(result.message).toBeInstanceOf(Uint8Array);
			expect(result.message.length).toBeGreaterThan(0);
			expect(password.every((b) => b === 0)).toBe(true);
		});

		it("opaque_registration_finish zeroizes the caller's Uint8Array even on an unknown-session-id error", () => {
			const password = freshPassword();
			const before = password.slice();
			expect(before.some((b) => b !== 0)).toBe(true); // sanity: password started non-zero

			expect(() =>
				(wasm as OpaqueWasmModule).opaque_registration_finish(
					"nonexistent-session-id",
					password,
					new Uint8Array(32),
				),
			).toThrow();

			expect(password.every((b) => b === 0)).toBe(true);
		});

		it("opaque_login_finish zeroizes the caller's Uint8Array even on an unknown-session-id error", () => {
			const password = freshPassword();
			const before = password.slice();
			expect(before.some((b) => b !== 0)).toBe(true); // sanity: password started non-zero

			expect(() =>
				(wasm as OpaqueWasmModule).opaque_login_finish(
					"nonexistent-session-id",
					password,
					new Uint8Array(32),
				),
			).toThrow();

			expect(password.every((b) => b === 0)).toBe(true);
		});
	},
);
