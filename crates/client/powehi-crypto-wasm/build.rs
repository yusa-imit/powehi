// Build-script marker for the TEST-ONLY `test-server-sim` feature.
//
// The feature is default-off and gates `src/test_server_sim.rs`, which adds
// JS-callable OPAQUE *server* simulation exports used only by
// `app/src/workers/opaqueWasmZeroize.node.test.ts` against the gitignored
// `--target nodejs` build. Nothing else in this crate is affected by this file.
//
// Emitting a `cargo:warning` makes an accidental
// `--features test-server-sim` on a production `wasm-pack build --target web`
// visible in the build log instead of silently shipping extra exports.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var_os("CARGO_FEATURE_TEST_SERVER_SIM").is_some() {
        println!(
            "cargo:warning=powehi-crypto-wasm: TEST-ONLY feature `test-server-sim` is ENABLED. \
             This build exposes __powehi_test_only_server_sim_* exports and MUST NOT be shipped \
             to browsers. Expected only for `pnpm run build:wasm:node`."
        );
    }
}
