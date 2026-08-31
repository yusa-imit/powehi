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
// Scope — now matching wasm_bindgen_tests.rs's OPAQUE zeroize coverage, but
// at the JS-glue level rather than as plain Rust calls:
//   - opaque_registration_start / opaque_login_start: SUCCESS-path zeroize.
//     Fully self-contained — no server needed.
//   - opaque_registration_finish / opaque_login_finish: ERROR-path zeroize
//     (unknown session id) — the earliest possible error return, reachable
//     without a server.
//   - opaque_registration_finish / opaque_login_finish: SUCCESS-path zeroize,
//     via a real client<->server OPAQUE round trip.
//   - opaque_login_finish wrong-password negative control: login must be
//     rejected AND the buffer must still be zeroed.
//
// The last two needed a JS-reachable OPAQUE server. Rust-side,
// wasm_bindgen_tests.rs gets one "for free" by linking opaque-ke's server
// types into its own native test binary, but those helpers are private to
// that binary and invisible from the `--target nodejs` artifact. Earlier
// cycles left the gap open because the alternatives were bad: a canned
// server-response fixture cannot work (registration/login messages embed
// fresh `OsRng` ephemerals on every call, so a pre-recorded response never
// validates against a freshly generated client message), and a second,
// independently-audited JS/WASM OPAQUE implementation would need its wire
// format proven byte-compatible with opaque-ke's — a high-risk rabbit hole.
//
// Closed instead by `crates/client/powehi-crypto-wasm/src/test_server_sim.rs`:
// the same opaque-ke server types and the same `DefaultCipherSuite`, behind
// JS-callable `__powehi_test_only_server_sim_*` wrappers gated by the
// default-off `test-server-sim` Cargo feature. That feature is passed by
// exactly one caller — the `build:wasm:node` script that produces the
// gitignored `pkg-node/` artifact this file loads. The production
// `build:wasm` script (`--target web`, the artifact the browser gets) passes
// no `--features` flag, so those exports do not exist in it; the
// `__POWEHI_TEST_SERVER_SIM_BUILD_DO_NOT_SHIP` positive-control assertion in
// the first test below pins that this file really is running against a
// feature-enabled build (and would catch the feature silently failing to
// propagate, which would otherwise make the round-trip tests error out for an
// unrelated-looking reason).
//
// Caveat inherited from wasm_bindgen_tests.rs's own scope note: the simulated
// server uses THIS crate's `DefaultCipherSuite`, not the real server adapter's
// separately-declared one in `crates/adapters/outbound/powehi-opaque`. The two
// are currently field-for-field identical (Ristretto255 + TripleDH/SHA-512 +
// Argon2id), so the round trip is representative — but this file does NOT
// prove cross-crate ciphersuite agreement; that remains a pre-existing,
// separate gap.
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
	): { exportKey: Uint8Array; upload: Uint8Array };
	opaque_login_finish(
		sessionId: string,
		password: Uint8Array,
		serverResponse: Uint8Array,
	): { exportKey: Uint8Array; finalization: Uint8Array };
	// TEST-ONLY server simulation — present only in a `--features test-server-sim`
	// build (see the header comment). Never in the shipped `--target web` artifact.
	__POWEHI_TEST_SERVER_SIM_BUILD_DO_NOT_SHIP(): string;
	__powehi_test_only_server_sim_new(): string;
	__powehi_test_only_server_sim_drop(serverHandle: string): void;
	__powehi_test_only_server_sim_register(
		serverHandle: string,
		identity: string,
		registrationRequest: Uint8Array,
	): Uint8Array;
	__powehi_test_only_server_sim_store_password_file(
		serverHandle: string,
		identity: string,
		registrationUpload: Uint8Array,
	): void;
	__powehi_test_only_server_sim_login_start(
		serverHandle: string,
		identity: string,
		credentialRequest: Uint8Array,
	): Uint8Array;
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

// Each OPAQUE step is handed its own freshly-encoded copy: the previous step
// zeroized the buffer it was given (that is the whole invariant under test),
// and opaque-ke 4.x needs the real password again at *_finish because it
// re-runs the KSF. Same shape as wasm_bindgen_tests.rs's round-trip tests.
function encodePassword(text: string): Uint8Array {
	return new TextEncoder().encode(text);
}

/**
 * Two DELIBERATELY EQUAL-LENGTH passwords for the wrong-password negative
 * control. Cycle 398's crypto-reviewer round rejected an earlier draft that
 * used unequal lengths: OPAQUE hashes the password bytes directly (no
 * fixed-width digest first), so two all-zero buffers of DIFFERENT lengths
 * still map to different OPRF inputs and login legitimately fails — meaning
 * the test would stay green under an "eager scrub before use" regression for
 * entirely the wrong reason. At equal length, an eager scrub makes both sides
 * derive from the same all-zero password, login wrongly SUCCEEDS, and the
 * `toThrow()` assertion fires. See the matching doc comment on
 * `test_opaque_login_finish_wrong_password_fails_and_zeroizes` in
 * crates/client/powehi-crypto-wasm/tests/wasm_bindgen_tests.rs.
 */
const PW_LEN = 32;
const REAL_PASSWORD = "A".repeat(PW_LEN);
const DIFFERENT_PASSWORD = "B".repeat(PW_LEN);

/**
 * Boolean-only export-key equality.
 *
 * Deliberately NOT `expect(loginKey).toEqual(regKey)` and NOT
 * `expect(Array.from(loginKey)).toEqual(Array.from(regKey))`: on failure Vitest
 * renders both operands, which would print 32 bytes of live OPAQUE export key
 * into the CI log (rule: no-plaintext-logging — key material must never reach
 * log output, and CI logs are far less protected than the key itself).
 * `Array.from` additionally materializes two extra plain-`Array` copies of key
 * material on the JS heap that nothing ever scrubs. Collapsing the comparison
 * to a boolean means a failure prints `false`, and no copy outlives this call.
 */
function sameExportKey(a: Uint8Array, b: Uint8Array): boolean {
	return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

describe.skipIf(!pkgNodeExists)(
	"OPAQUE wasm-bindgen JS-glue password copy-back zeroize (--target nodejs artifact)",
	() => {
		// Positive control for the whole file: every round-trip test below depends
		// on the TEST-ONLY `test-server-sim` Cargo feature having actually
		// propagated through `wasm-pack build --target nodejs -- --features
		// test-server-sim`. Without this assertion, a silent regression in that
		// wiring (feature renamed, `--` separator dropped, script edited) would
		// surface as a confusing "not a function" deep inside a round trip rather
		// than as a clear statement of what is missing.
		it("is running against a test-server-sim-enabled build (positive control)", () => {
			const mod = wasm as OpaqueWasmModule;
			expect(typeof mod.__POWEHI_TEST_SERVER_SIM_BUILD_DO_NOT_SHIP).toBe("function");
			expect(mod.__POWEHI_TEST_SERVER_SIM_BUILD_DO_NOT_SHIP()).toContain("TEST-ONLY");
			expect(typeof mod.__powehi_test_only_server_sim_new).toBe("function");
		});

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

		it("opaque_registration_finish zeroizes the caller's Uint8Array after a SUCCESSFUL round trip", () => {
			const mod = wasm as OpaqueWasmModule;
			const server = mod.__powehi_test_only_server_sim_new();
			const identity = "wasm-glue-reg@powehi.test";
			try {
				const startPassword = freshPassword();
				const start = mod.opaque_registration_start(startPassword);
				const serverResponse = mod.__powehi_test_only_server_sim_register(
					server,
					identity,
					start.message,
				);

				// Fresh copy: `opaque_registration_start` already zeroized the one above.
				const finishPassword = freshPassword();
				expect(finishPassword.some((b) => b !== 0)).toBe(true); // sanity: started non-zero

				const finish = mod.opaque_registration_finish(
					start.sessionId,
					finishPassword,
					serverResponse,
				);

				// Sanity that this really is the success path, not a swallowed error.
				expect(finish.upload).toBeInstanceOf(Uint8Array);
				expect(finish.upload.length).toBeGreaterThan(0);
				expect(finish.exportKey.length).toBe(32);
				expect(finish.exportKey.some((b) => b !== 0)).toBe(true);

				expect(finishPassword.every((b) => b === 0)).toBe(true);
			} finally {
				mod.__powehi_test_only_server_sim_drop(server);
			}
		});

		it("opaque_login_finish zeroizes the caller's Uint8Array after a SUCCESSFUL round trip", () => {
			const mod = wasm as OpaqueWasmModule;
			const server = mod.__powehi_test_only_server_sim_new();
			const identity = "wasm-glue-login@powehi.test";
			try {
				// --- Registration, so the simulated server holds a password file ---
				const regStart = mod.opaque_registration_start(freshPassword());
				const regResponse = mod.__powehi_test_only_server_sim_register(
					server,
					identity,
					regStart.message,
				);
				const regFinish = mod.opaque_registration_finish(
					regStart.sessionId,
					freshPassword(),
					regResponse,
				);
				mod.__powehi_test_only_server_sim_store_password_file(server, identity, regFinish.upload);

				// --- Login with the same password ---
				const loginStart = mod.opaque_login_start(freshPassword());
				const credentialResponse = mod.__powehi_test_only_server_sim_login_start(
					server,
					identity,
					loginStart.message,
				);

				const finishPassword = freshPassword();
				expect(finishPassword.some((b) => b !== 0)).toBe(true); // sanity: started non-zero

				const loginFinish = mod.opaque_login_finish(
					loginStart.sessionId,
					finishPassword,
					credentialResponse,
				);

				// Sanity that this really is the success path.
				expect(loginFinish.finalization).toBeInstanceOf(Uint8Array);
				expect(loginFinish.finalization.length).toBeGreaterThan(0);
				expect(loginFinish.exportKey.length).toBe(32);
				expect(loginFinish.exportKey.some((b) => b !== 0)).toBe(true);
				// The durable export key must be identical across registration and
				// login for the same password (RFC 9807). This doubles as proof the
				// password genuinely reached opaque-ke on both legs. Compared
				// boolean-only — see `sameExportKey`.
				expect(loginFinish.exportKey.length).toBe(regFinish.exportKey.length);
				expect(sameExportKey(loginFinish.exportKey, regFinish.exportKey)).toBe(true);

				expect(finishPassword.every((b) => b === 0)).toBe(true);
			} finally {
				mod.__powehi_test_only_server_sim_drop(server);
			}
		});

		// Negative control the two success-path tests cannot provide. See the
		// PW_LEN / REAL_PASSWORD / DIFFERENT_PASSWORD comment above for why the
		// equal length is load-bearing: it is what makes this test go RED under an
		// "eager scrub before use" regression in PasswordScrubGuard (registration
		// and login would both silently derive from an all-zero password, so this
		// wrong-password login would spuriously SUCCEED and `toThrow()` would fail).
		//
		// The test runs BOTH legs against the same server handle, the same
		// identity, and the same stored password file, and asserts the correct
		// password logs in cleanly before asserting the wrong one is rejected.
		// Without that in-test positive control, `toThrow()` would be satisfied by
		// ANY failure — a typo in the identity, a password file that never got
		// stored, a dropped sim handle — so the test could quietly stop exercising
		// the wrong-password path (and therefore stop catching the eager-scrub
		// regression it exists for) while still reporting green. Running both legs
		// makes "the only difference between the passing and failing leg is the
		// password" a structural property of the test rather than an assumption.
		it("opaque_login_finish rejects a wrong same-length password and still zeroizes the buffer", () => {
			const mod = wasm as OpaqueWasmModule;
			const server = mod.__powehi_test_only_server_sim_new();
			const identity = "wasm-glue-wrong-pw@powehi.test";
			expect(REAL_PASSWORD.length).toBe(DIFFERENT_PASSWORD.length);
			try {
				// --- Register with the real password ---
				const regStart = mod.opaque_registration_start(encodePassword(REAL_PASSWORD));
				const regResponse = mod.__powehi_test_only_server_sim_register(
					server,
					identity,
					regStart.message,
				);
				const regFinish = mod.opaque_registration_finish(
					regStart.sessionId,
					encodePassword(REAL_PASSWORD),
					regResponse,
				);
				mod.__powehi_test_only_server_sim_store_password_file(server, identity, regFinish.upload);

				// --- Positive control: the CORRECT password, same server + identity
				//     + password file, must log in cleanly. Called directly rather
				//     than via `expect(...).not.toThrow()` so that an unexpected
				//     failure surfaces the real error instead of a generic assertion
				//     message. The export key matching registration's proves this leg
				//     genuinely completed the AKE, not merely that it did not throw.
				const okStart = mod.opaque_login_start(encodePassword(REAL_PASSWORD));
				const okResponse = mod.__powehi_test_only_server_sim_login_start(
					server,
					identity,
					okStart.message,
				);
				const okPassword = encodePassword(REAL_PASSWORD);
				const okFinish = mod.opaque_login_finish(okStart.sessionId, okPassword, okResponse);
				expect(okFinish.exportKey.length).toBe(regFinish.exportKey.length);
				expect(sameExportKey(okFinish.exportKey, regFinish.exportKey)).toBe(true);
				expect(okPassword.every((b) => b === 0)).toBe(true);

				// --- Negative leg: identical to the positive control above in every
				//     respect EXCEPT the password, which is DIFFERENT, non-zero, and
				//     the SAME LENGTH. ---
				const loginStart = mod.opaque_login_start(encodePassword(DIFFERENT_PASSWORD));
				const credentialResponse = mod.__powehi_test_only_server_sim_login_start(
					server,
					identity,
					loginStart.message,
				);

				const wrongPassword = encodePassword(DIFFERENT_PASSWORD);
				expect(wrongPassword.some((b) => b !== 0)).toBe(true); // sanity: started non-zero

				expect(() =>
					mod.opaque_login_finish(loginStart.sessionId, wrongPassword, credentialResponse),
				).toThrow();

				expect(wrongPassword.every((b) => b === 0)).toBe(true);
			} finally {
				mod.__powehi_test_only_server_sim_drop(server);
			}
		});
	},
);
