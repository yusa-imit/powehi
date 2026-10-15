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
- [x] 7.7 Send and receive — (slice D done, cycle 519: `inbox` joins only invite-minted KeyPackages (interim #24 policy; `powehi accept` for others awaits the owner decision); slice A done, #29: redeemer-side `pq_init` send, ek §7.2
  check, `peer_pq_encap_key`; slice B done, cycle 517: `powehi inbox` = join Welcomes, decrypt
  Application messages from the conv peer, joiner-side `pq_init` receive (dk discarded),
  store as `rx-*` records, ack; slice C done, cycle 518: `powehi send` (stdin body) + `powehi read` (show + remove stored `rx-*`);  FIRST, `pq_init` (prd.md §5.3 Phase B; the web sends it after the
  Welcome, CLI 7.6 does not, so CLI 1:1s are classical-only until this lands): redeemer runs
  `kem_credential::verify_encap_key` on the inviter's KeyPackage ek, adds a FIPS 203 §7.2
  modulus check on the ek, encapsulates and sends `pq_init`; joiner decapsulates with the dk
  stored in the `conv-*` record. Then `inbox` calls `welcome::join_pending` and applies the
  issue #24 policy. Also: `powehi send <conversation>` (body from stdin, not
  argv), `powehi inbox` (fetch `/v1/messages`, decrypt, persist, ack). Incoming
  Commits use the one-shot merge (ADR-0005).
- [x] 7.8 `powehi chat <conversation>` — interactive line REPL with live delivery
  over `/v1/ws` (Bearer), reconnect with catch-up via `since` (prd.md §7.6:
  max 3 retries, then tell the user).
- [x] 7.9 `powehi verify <conversation>` — Safety Number display (prd.md §5.6),
  verified flag stored in the profile store. (`--confirm` records the comparison;
  a later key change reports CHANGED. Pairwise number now lives in `powehi-crypto-core::safety`.)
- [x] 7.10 E2E gate — two CLI profiles register, start a conversation, and
  exchange messages both ways against the docker-compose backend (`#[ignore]`d
  live test + CI job, like `e2e-live`). (`src/live_e2e.rs`; job `cli-live-backend` in `ci-e2e-live.yml`.)
- [x] 7.11 threat-model-checker pass on the CLI as a new client platform
  (at-rest store, argv/history, scrollback, multiple profiles per machine). Verdict YELLOW (cycle 524);
  accepted risks in prd §3.2/§3.3/§7A.3; fixed now: parent/owner dir checks.

## Follow-ups (not Phase 7 DoD)
- From 7.11 (FIX-NOW, not yet done): ~~in-session provider-state generation floor (F6)~~ (done, cycle 527); ~~opaque record names (F1)~~ (done, cycle 543: `<hmac tag>.rc2`, name inside the ciphertext, PHS1 stores migrated at open; deferred from review: tags are deterministic per account (same filenames on every copy/device — add a per-store salt before multi-device, needs PHS3), decrypted record names are not zeroized, one damaged record still blocks the whole profile, but since cycle 544 `open` errors name the offending file via `StoreError::Record{tag,..}`); ~~`Received.body` as bytes not JSON number array~~ (done, cycle 529: hex string, legacy array still readable) — size buckets (F9, padding: cycle 541 pads NEW groups via `mls_group::PADDING_SIZE`=256; groups created earlier are migrated by `load_group` via `set_configuration`, cycle 542; web `wasm_exports` still loads directly); ~~disable core dumps~~ (done, cycle 531: `hardening::disable_core_dumps` at startup) and
  zeroize plaintext copies (F8, partial, cycle 532: `Received` wipes `body` on drop, `Pending.text` is `Zeroizing`; cycle 533: `render`/`sanitize` now return `Zeroizing<String>`, pre-sized, parsed without a `serde_json::Value`; still open: serde_json's escape scratch buffer (any text with a newline/quote/backslash leaves an unwiped copy; fix needs a wiping allocator or a custom parser, crypto-lead call), ~~`to_vec(&Received)` realloc~~ (done, cycle 547), legacy `visit_seq`)  [~~`decrypt_message` return type~~ done, cycle 546: `Zeroizing<Vec<u8>>`; openmls's internal decrypted copy stays unwiped, crypto-lead call]; ~~mark WS Authorization header sensitive (F10)~~ (done, cycle 526);
  ~~TLS 1.3-only for reqwest+WS~~ (done, cycle 528: ClientHello-inspection tests, no rcgen needed; the Cloudflare `tls_1_3` Terraform setting (F11) is done, cycle 539: `cloudflare_zone_setting.tls_1_3`); ~~record `ring` exception for the CLI~~ (done, cycle 536: deny.toml wrappers ban + rule doc). All need crypto-reviewer.
- ~~Blocking requirement for any CLI Commit-merge work: wire the §5.6 CHANGED alert into `read`/`chat`/`send`~~
  (done, cycle 537: `verify::changed_since_verified`, warn-only on stderr; blocking on change is not decided).
  ~~Re-run the check after each `inbox::receive` in `chat::sync`; Welcome for an existing group_id is not joined~~
  (done, cycle 538: `chat::alert_if_changed` warns when the number turns CHANGED; `welcome::join_one` skips a
  Welcome whose MLS group is already held — a conversation record without the group is an interrupted join and
  is still finished). Policy: issue #53.
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
