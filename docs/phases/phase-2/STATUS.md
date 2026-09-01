# Phase 2: Crypto Core MVP

## Status: COMPLETE (cycle 11)

## Definition of Done
- [x] powehi-crypto crate with openmls integration — MLS group create/encrypt/decrypt (openmls + openmls_rust_crypto) — cycle 8
- [x] OPAQUE registration/login flow (server + client WASM) — opaque-ke, draft-irtf-cfrg-opaque — cycle 8
- [x] MLS group create/join/message round-trip test — cycle 8
- [x] WASM crypto worker with Comlink bindings — `wasm_exports.rs` + `crypto.worker.ts`; zeroize on export_key — cycle 10, commit b5c58b0
- [x] Forward secrecy invariant test passing — cycle 8
- [x] crypto-reviewer pass on all crypto code — YELLOW (opaque-ke 3.x vs pinned-version rule waiver, recorded in `crypto-libraries-pinned.md`; max_past_epochs(0) explicit; identity binding documented) — cycle 8/10

## Notes
- See prd.md Phase 2 section for full requirements
- Requires crypto-lead + mls-engineer + opaque-engineer + wasm-builder
- WASM compilation verified (`wasm-pack --target web`, 1.5MB binary) with a
  dedicated CI job — cycle 11
- opaque-ke was later upgraded off the 3.x waiver (see project-context.md,
  `crypto-libraries-pinned.md` for current pin); this file records the
  cycle-8/10/11 state at which Phase 2's DoD was first satisfied.
- This file was left at "Pending"/all-unchecked long after the phase actually
  completed. Backfilled at cycle 409 from `.claude/memory/project-context.md`'s
  Phase checklist; no functional change.
