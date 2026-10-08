# Phase 7: CLI Client (Rust) — CLI-first

## Status: IN PROGRESS (owner directive 2026-10-08, ADR-0006)

**Priority rule**: this phase is the FEATURE-mode work queue. Take the first
unchecked item, in order. The web client (`app/`) is in maintenance: CI-red,
`bug` issues, and security fixes only — no new web features until every box
below is checked. See `docs/decisions/0006-cli-first-client.md`, prd.md §7A.

## Definition of Done (in order)
- [x] 7.1 Extract `crates/client/powehi-crypto-core` — move `kem`,
  `kem_credential`, `media`, `mls_group`, `opaque`, `recovery` out of
  `powehi-crypto-wasm` (pure move, no logic change, no `wasm-bindgen`/`js-sys`
  deps in the core). `powehi-crypto-wasm` re-exports them and keeps only
  `wasm_exports.rs` + glue. Gate: all existing Rust tests pass, `pnpm build:wasm`
  succeeds, Vitest green, crypto-reviewer PASS. Add `crates/client/powehi-crypto-core/**`
  to the `paths` filters of `.github/workflows/ci-frontend.yml` so core changes still run
  the WASM/Vitest job.
- [x] 7.2 `crates/client/powehi-cli` skeleton — lib + thin bin `powehi`, `clap`
  subcommands, `--server <url>`, `--profile <name>`, per-profile data dir.
  `powehi status` hits `GET /health` and `GET /v1/region/detect`. Unit tests
  against an in-test HTTP server. README gains a CLI section (only for what
  the CLI actually does at that commit).
- [x] 7.3 Encrypted profile store — AES-256-GCM per record, key =
  HKDF-SHA256(OPAQUE `export_key`, CLI-specific info label), dir `0700` / files
  `0600`, atomic writes, zeroize on drop. Tests: round trip, wrong key → typed
  error, tampered file → typed error, no plaintext bytes on disk. crypto-reviewer.
- [x] 7.4 `powehi register` / `powehi login` — OPAQUE via the core, password from
  TTY with echo off (never argv), device registration, recovery phrase shown
  once at register. Session token in memory or encrypted store only.
  crypto-reviewer.
- [x] 7.5 Identity + KeyPackages — MLS identity generated and persisted in the
  store; KeyPackages uploaded; top-up when
  `GET /v1/key-packages/:device_id/count` is low.
- [x] 7.6 Start a 1:1 conversation — `powehi invite create` /
  `powehi invite redeem` (prd.md §8.3), group create, add member, Welcome sent
  and joined (prd.md §4.2). Carry-over from 7.5 review: on Welcome join, look up the decap key
  by KeyPackageRef in `pq-keys`, and before decapsulating validate the dk (FIPS 203 §7.3 hash
  check; dk-embedded ek matches the uploaded one); consumed refs are pruned.
- [ ] 7.7 Send and receive — FIRST, `pq_init` (prd.md §5.3 Phase B; the web sends it after the
  Welcome, CLI 7.6 does not, so CLI 1:1s are classical-only until this lands): redeemer runs
  `kem_credential::verify_encap_key` on the inviter's KeyPackage ek, adds a FIPS 203 §7.2
  modulus check on the ek, encapsulates and sends `pq_init`; joiner decapsulates with the dk
  stored in the `conv-*` record. Then `inbox` calls `welcome::join_pending` and applies the
  issue #24 policy. Also: `powehi send <conversation>` (body from stdin, not
  argv), `powehi inbox` (fetch `/v1/messages`, decrypt, persist, ack). Incoming
  Commits use the one-shot merge (ADR-0005).
- [ ] 7.8 `powehi chat <conversation>` — interactive line REPL with live delivery
  over `/v1/ws` (Bearer), reconnect with catch-up via `since` (prd.md §7.6:
  max 3 retries, then tell the user).
- [ ] 7.9 `powehi verify <conversation>` — Safety Number display (prd.md §5.6),
  verified flag stored in the profile store.
- [ ] 7.10 E2E gate — two CLI profiles register, start a conversation, and
  exchange messages both ways against the docker-compose backend (`#[ignore]`d
  live test + CI job, like `e2e-live`).
- [ ] 7.11 threat-model-checker pass on the CLI as a new client platform
  (at-rest store, argv/history, scrollback, multiple profiles per machine).

## Follow-ups (not Phase 7 DoD)
- Full-screen TUI (`ratatui`) on top of the same lib.
- Media send/receive (prd.md §9), groups of more than two, member Remove
  (blocked on issue #2 items (e)/(g)), multi-device, recovery-phrase restore.
- CLI ↔ web interop test once web work resumes.

## Notes
- The core modules already compile on the native host (`openmls_rust_crypto`),
  and only `wasm_exports.rs` touches `wasm_bindgen` — so 7.1 is a move.
- Server auth is `Authorization: Bearer` on REST and on the `/v1/ws` upgrade, so
  a native client needs no server change to get WebSocket delivery.
- Route new CLI code to `backend-lead` (Rust crates) and anything touching the
  crypto core or the store to `crypto-lead`.
