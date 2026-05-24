# Powehi — Project Context (autonomous dev anchor)

> Source of truth for the `powehi-dev-v1` cron loop: current state + phase checklist.
> Full architecture: `docs/prd.md`. Agent system: `docs/orchestration.md`.

## What this is
E2EE zero-knowledge web messenger. The server NEVER sees plaintext. Rust hexagonal
backend + React 19 / WASM frontend + 3-tier multi-region infra. Protocols: MLS
(RFC 9420), OPAQUE (RFC 9807), Web Push (RFC 8291).

## Non-negotiables (NEVER violate — these gate every commit)
- Server NEVER sees plaintext message content.
- No homegrown crypto. Only `openmls`, `opaque-ke`, RustCrypto (rule: crypto-libraries-pinned).
- Crypto code MUST pass the `crypto-reviewer` agent before commit.
- Architectural / new-metadata changes MUST pass `threat-model-checker`.
- Backend handlers MUST pass `security-auditor`.
- No plaintext logging of content / PII / ciphertext (rule: no-plaintext-logging).
- Every layer has a test gate (rule: testing-conventions).

## Current state (2026-05-24)
- Planning docs complete: `docs/prd.md` (v3), `docs/orchestration.md`, `docs/decisions/` (ADR-0001, 0002).
- Agent infra complete: `.claude/agents` (22), `skills` (7), `rules` (6), `commands` (4), `hooks` (5).
- Design system available: `DESIGN.md` + `docs/design/powehi-design-system/` + `/powehi-design` skill — read before any UI work.
- **Phase 1 in progress.** Workspace skeleton bootstrapped (commit 940a065): 18 crates compile, tests green, clippy clean.
- React 19 + Vite 6 scaffold complete (commit 312864d): pnpm workspace, Vitest 2/2 green, Biome clean, TypeScript strict.
- WASM build pipeline complete (commit f498ae1): openmls 0.8 + js feature, wasm-pack --target web, pnpm build:wasm, bulk-memory wasm-opt flag.
- Next action: CI GitHub Actions (fmt, clippy, nextest, biome) — delegate to ci-pipeline-author.
- Build/test (once code exists):
  - `cargo build --workspace`
  - `cargo nextest run --workspace` (fallback `cargo test --workspace` if nextest absent)
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - frontend `pnpm --filter app test` (Vitest) + `biome check`
  - infra `terraform validate` / `helm lint` (skill: infra-test)

## Phase checklist (prd.md §15.4; per-phase DoD in docs/phases/phase-N/STATUS.md)

### Phase 1 — Foundation & DevOps Skeleton  ← ACTIVE
- [x] Cargo workspace + hexagonal crate skeleton (domain → ports → application → adapters → bin), prd.md §6.1 — commit 940a065
- [x] powehi-domain (zero external deps) + powehi-port-inbound/outbound trait stubs — commit 940a065
- [x] React 19 + Vite 6 scaffold under `/app` — commit 312864d (pnpm workspace, Tailwind v4, Vitest, Biome, design tokens)
- [x] WASM build pipeline (empty `powehi-crypto-wasm` compiles to wasm32-unknown-unknown) — commit f498ae1
- [ ] CI: GitHub Actions (fmt, clippy, nextest, biome) — delegate to ci-pipeline-author
- [ ] Terraform base (Hetzner k3s) skeleton — delegate to terraform-author
- [ ] `cargo nextest` 100% on skeleton; hexagonal dependency direction holds

### Phase 2 — Crypto Core MVP
- [ ] `powehi-crypto-wasm` w/ openmls; OPAQUE register/login; MLS group round-trip; Comlink worker; forward-secrecy invariant test; crypto-reviewer pass

### Phase 3 — Backend Services & API
- [ ] MLS Delivery Service; KeyPackage Service; Auth (OPAQUE); WS hub; Media (R2); rate limiting; security-auditor pass

### Phase 4 — Frontend & Integration
- [ ] Login/Chat UI; Dexie encrypted storage; crypto worker; Service Worker push; Playwright E2E; bundle budget (<200KB init, <800KB WASM)
- UI MUST follow the design system — invoke `/powehi-design` or read `DESIGN.md` first. Brand non-negotiables (dark-first, cream text, dual-light orange=action / photon-blue=encryption, lock always photon-blue) are hard rules. Map `colors_and_type.css` → Tailwind v4 OKLCH.

### Phase 5 — Hardening
- [ ] SLSA L3 reproducible builds; cosign + Rekor; threat-model-checker pass; load test; observability; PQ migration doc

### Phase 6 — Global Infrastructure
- [ ] gRPC mesh + mTLS; AP-Seoul Tier 1; cross-region p99 <200ms; failover; KeyPackage replication; data residency; infra-test gate

## Notes for the autonomous dev
- Implement ONE checklist item per cycle. Flip `[ ]` → `[x]` here when done.
- Delegate domain work via Task to the project's subagents: crypto-lead, backend-lead,
  frontend-lead, infra-lead; reviewers crypto-reviewer / security-auditor / threat-model-checker.
- Use skills: add-rust-crate, add-mls-test, new-api-endpoint, verify-reproducible-build,
  threat-model-update, infra-test.
- Review is part of writing: implement → run the relevant review agent → fix → commit.
