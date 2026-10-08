# ADR-0006: CLI-First Client — a Rust Terminal Client Becomes the Primary Client

## Status: Active (owner directive, 2026-10-08)

## Context

Phases 1-6 shipped a React 19 + WASM web client (`app/`) as the only client.
Every phase DoD box is checked, yet the web client still cannot be used end to
end in production: the SPA has no deployment path (issue #1), live delivery
runs on 3-second polling because the browser cannot attach an `Authorization`
header to a WebSocket handshake (issue #3), and the frontend loop has spent
many recent cycles on browser-specific plumbing (Comlink worker boundaries,
Dexie encryption, IndexedDB lock ordering) rather than on chat itself.

The project owner directed on 2026-10-08 that development switch to a
**CLI-first** client: a Rust program you chat with from a terminal.

Facts that make this cheap:

- The crypto core already builds and tests on the native host target.
  `crates/client/powehi-crypto-wasm` uses `openmls_rust_crypto` on
  `cfg(not(target_arch = "wasm32"))`, and its core modules (`mls_group`,
  `opaque`, `kem`, `kem_credential`, `media`, `recovery`) contain no
  `wasm_bindgen`/`js_sys` code — only `wasm_exports.rs` does.
- The server authenticates every REST route and `/v1/ws` with
  `Authorization: Bearer <session_token>`, which a native client can send on
  both HTTP and the WebSocket upgrade. The CLI gets real-time delivery that the
  browser cannot.
- `reqwest` and `tokio-tungstenite` are already in `Cargo.lock`.

## Decision

1. Add a Rust terminal client, crate `crates/client/powehi-cli`, binary
   `powehi`. It is the primary client until Phase 7 DoD
   (`docs/phases/phase-7/STATUS.md`) is complete.
2. Extract the platform-neutral crypto modules into a pure-Rust crate
   `crates/client/powehi-crypto-core`. `powehi-crypto-wasm` keeps only the
   wasm-bindgen glue and re-exports the core. The CLI depends on the core, never
   on the `-wasm` crate. This is a move, not a rewrite: no crypto logic changes.
3. The web client (`app/`) enters **maintenance**: CI-red fixes, `bug`-labeled
   issues, and security fixes on behavior that already shipped. No new web
   features, no new web UI, until Phase 7 DoD is complete.
4. Shared crypto-core work (e.g. issue #2 items (e)/(g) in `mls_group.rs`) and
   server work the CLI needs are not frozen; they serve both clients.
5. First UX is a line-oriented REPL plus scriptable subcommands. A full-screen
   TUI is a follow-up, not part of Phase 7 DoD.

## Rationale

- One language end to end: the CLI calls `openmls`/`opaque-ke` directly, with
  no JS↔WASM marshalling, so crypto bugs reproduce in plain `cargo test`.
- A native client exercises the server protocol (OPAQUE, KeyPackages, Welcome,
  Commit, application messages, WS delivery) without browser constraints, so
  protocol gaps surface sooner.
- A terminal client needs no hosting (sidesteps issue #1 for dogfooding) and is
  the shortest path to two people actually chatting.

## Security requirements specific to a CLI

The non-negotiables in `CLAUDE.md` apply unchanged. A terminal adds these:

- **No plaintext at rest.** Local state lives in a per-profile directory
  (`0700`, files `0600`), every record AES-256-GCM encrypted under a key
  derived with HKDF-SHA256 from the OPAQUE `export_key`, with a CLI-specific
  `info` label (domain-separated from the web client's Dexie key). Writes are
  atomic (temp file, fsync, rename). The `export_key` and derived key are
  zeroized after use.
- **No secrets or message text in argv.** Passwords are read from the TTY with
  echo off; message bodies come from the REPL or stdin, never from a command
  argument, because argv leaks to shell history and `ps`.
- **No session token on disk in plaintext.** It lives in memory, or inside the
  encrypted store.
- **No content in logs.** `tracing` output (stderr, `RUST_LOG`) carries
  operation names and status codes only (rule: `no-plaintext-logging`).
- Required reviews: `crypto-reviewer` for the core extraction and the store,
  `threat-model-checker` once for the new client platform (local-at-rest,
  terminal scrollback, multi-profile on one machine).

## Consequences

- New Phase 7 in `docs/phases/phase-7/STATUS.md`; prd.md gains §7A and a Phase 7
  DoD in §15.4.
- The cron loop (`powehi-dev-v1`) pulls FEATURE work from Phase 7 in order.
  Web-only items in the "Next cycle candidates" list are parked.
- Issues #1 and #3 (web deploy, web WS client) are parked, not closed: they
  return when web work resumes.
- Revisit trigger: Phase 7 DoD complete, or the owner reverses the directive.
