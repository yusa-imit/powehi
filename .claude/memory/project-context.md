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

## Current state (2026-05-26, cycle 17 — STABILIZATION)
- Planning docs complete: `docs/prd.md` (v3), `docs/orchestration.md`, `docs/decisions/` (ADR-0001, 0002).
- Agent infra complete: `.claude/agents` (22), `skills` (7), `rules` (6), `commands` (4), `hooks` (5).
- Design system available: `DESIGN.md` + `docs/design/powehi-design-system/` + `/powehi-design` skill — read before any UI work.
- **Phase 1 COMPLETE. Phase 2 COMPLETE (cycle 11). Phase 3 ACTIVE (cycle 12).**
- **Stabilization cycle 13 (commits 19b1551 + 8e266c8):**
  - Fixed red CI: cycle-12 code was missing `cargo fmt` — rustfmt diff in error.rs/lib.rs/auth.rs/messaging.rs fixed.
  - Added 21 new unit tests (total workspace: 51 passing):
    - AuthService: register_finish, login_init (known/unknown), register_device, revoke_device (3 cases)
    - KeyPackageService: upload, fetch_one, fetch_one empty→NotFound, count lifecycle
    - MessagingService: send_message, send_commit epoch-advance, send_commit unknown group, poll filter, ack delete
    - middleware: AuthenticatedDevice extractor — valid UUID, missing header, non-UUID, wrong scheme, empty (all 401)
  - cargo audit: clean (instant unmaintained warning via openmls is pre-existing waiver)
  - CI fix: committed pre-formatted code; lesson: always run `cargo fmt --all` before committing
- **Stabilization cycle 15 (commit 23e92ac):**
  - CI: green. cargo audit: clean. clippy -D warnings: clean.
  - Added 14 new tests (total workspace: 87 passing — was 73):
    - powehi-rest-api: 11 handler-level tests using success/NotFound mocks: send_message 200, poll 200 empty, poll with since, ack 204, ack invalid id 400, send_welcome 204, send_commit epoch, upload 200 ids, fetch_one 200 data, count 200, fetch_one 404. Total rest-api: 26.
    - powehi-config: 3 unit tests: region() wraps region_id, roundtrips, load() defaults. Total config: 3.
  - GroupId/DeviceId JSON serialization confirmed (newtype struct → UUID string)
- React 19 + Vite 6 scaffold complete (commit 312864d): pnpm workspace, Vitest 2/2 green, Biome clean, TypeScript strict.
- WASM build pipeline complete (commit f498ae1): openmls 0.8 + js feature, wasm-pack --target web, pnpm build:wasm, bulk-memory wasm-opt flag.
- CI complete (commit 35ac5b9): ci-rust.yml (fmt→clippy+nextest) + ci-frontend.yml (biome+vitest); all local gates pass.
- Stabilization cycle 5 (commit 69891fa): pnpm version fix in ci-frontend.yml (9→10.28.2), cargo-audit CI gate added, RUSTSEC-2023-0071 (rsa, not compiled) acknowledged in audit.toml, 21 domain unit tests green (19 new: group, envelope, key_package, region, error).
- Stabilization cycle 6 (commit 3bf58b1): CI — Rust was red (cargo-binstall nextest install failing silently → exit 101); fixed by replacing binstall approach with `taiki-e/install-action@nextest`, the nextest-recommended CI installation method. All 21 tests + clippy + cargo-audit pass locally.
- Phase 1 COMPLETE (cycle 8). Phase 2 in progress.
- Comlink worker + wasm-bindgen exports DONE (cycle 10). crypto-reviewer YELLOW, both findings addressed.
- **Phase 2 COMPLETE (cycle 11).** All crypto core items done. Phase 3 begins next cycle.
- **Phase 3 cycle 12 (commit a31ff1a):** REST API axum adapter implemented:
  - `powehi-rest-api` fully wired: AppState(Arc<dyn AuthUseCase|MessagingUseCase|KeyPackageUseCase>)
  - Routes: /v1/auth/{register,login}/{init,finish}, /v1/messages (send/welcome/commit/poll/ack), /v1/key-packages (upload/fetch/count)
  - AuthenticatedDevice extractor (Bearer token = DeviceId UUID, stub — Redis session deferred)
  - ApiError: DomainError → HTTP status, code-only response (no detail leak)
  - DefaultBodyLimit::max(512KB) global cap
  - 10 tests green: health, auth-bypass ×3, 413 body limit, error-mapping ×5
  - security-auditor: PASS (YELLOW-1 body limit fixed; YELLOW-2 stub auth documented; YELLOW-3 app-layer auth deferred)
- **Phase 3 cycle 14 (commit c46eec3):** Composition root: powehi-postgres (5 sqlx repos: User/Device/Envelope/Group/KeyPackage + 0001_initial.sql migration + atomic KP fetch via SELECT FOR UPDATE SKIP LOCKED), powehi-redis (RedisCache CachePort + RedisEventBus DomainEventBus), bin/powehi-server full DI wiring; domain From<Uuid>/as_uuid() added to 4 ID types; 73 tests pass; security-auditor GREEN.
- **Phase 3 cycle 16 (commit 9c9d886):** WS hub implemented:
  - `powehi-ws-hub`: WsHub (tokio::sync::broadcast fan-out, 512-capacity ring), WsNotification enum (envelope_received/epoch_advanced/member_added/member_removed — no ciphertext, only opaque UUIDs), ws_handler (Bearer auth before upgrade → 401 before 101, ping/pong, Lagged skip), WsEventBus (composes RedisEventBus + WsHub dispatch).
  - MessagingService: now publishes EnvelopeReceived/EpochAdvanced events after save (removed dead_code attr).
  - Server main.rs: WsHub + WsEventBus wired; GET /v1/ws mounted alongside REST.
  - Design: global broadcast (all devices get wake-up signal, filter by polling REST) — narrows to group/device targeting in Phase 5.
  - 87 → 95 tests; clippy clean; security-auditor PASS (YELLOW-1: auth stub same as REST, YELLOW-2: no WS rate limit yet — both deferred to rate-limit work).
- **Stabilization cycle 17 (commits 166cb01 + 253c55d):**
  - Fixed RED CI: clippy::collapsible_match in powehi-ws-hub/handler.rs — async match guard not allowed; restructured to `should_break` bool pattern.
  - Added 5 auth-invariant unit tests to handler.rs (total ws-hub: 13, workspace: 100 passing — was 95).
  - Security hardening from security-auditor review (YELLOW findings addressed):
    - `max_message_size(4096)` on WebSocketUpgrade (finding 6: Ping amplification)
    - 10s send timeout on all `socket.send` calls (finding 8: slowloris hold)
    - Disconnect on unexpected client frames Text/Binary (finding 7: DoS vector)
    - Documented global-broadcast as known-deferred Phase 5 decision (finding 4)
  - cargo audit: clean (RUSTSEC-2024-0384 `instant` via openmls is existing waiver).
  - gh issues: none open.
  - clippy --workspace -D warnings: CLEAN.
- Next action (Phase 3): OPAQUE auth adapter (real opaque-ke server-side register/login in powehi-opaque).
- Follow-up (crypto-reviewer Finding 1): upgrade opaque-ke from 3.0 (draft-16) to stable 4.x (RFC 9807) when stable version ships (currently only 4.1.0-pre.2 available). Waiver recorded in .claude/rules/crypto-libraries-pinned.md.
- Workspace deps added in cycle 8: openmls_rust_crypto, openmls_basic_credential, openmls_traits, argon2 (all in workspace Cargo.toml).
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
- [x] CI: GitHub Actions (fmt, clippy, nextest, biome) — commit 35ac5b9
- [x] Terraform base (Hetzner k3s) skeleton — commit d87891f (modules/hetzner-k3s, envs/{dev,prod-eu,cloudflare}, infra-test manual pass)
- [x] `cargo nextest` 100% on skeleton; hexagonal dependency direction holds — cycle 8 (verified: 21/21 domain tests pass; domain←ports←application; adapters→ports only, NOT application)

### Phase 2 — Crypto Core MVP  ← COMPLETE (cycle 11)
- [x] `powehi-crypto-wasm` w/ openmls; OPAQUE register/login; MLS group round-trip; Comlink worker; forward-secrecy invariant test; crypto-reviewer pass
  - [x] OPAQUE registration/login (opaque-ke 3.0, draft-irtf-cfrg-opaque-16): registration_start/finish + login_start/finish/full; 2 tests green — cycle 8
  - [x] MLS group create/encrypt/decrypt (openmls 0.8.1 + openmls_rust_crypto): roundtrip + forward-secrecy invariant; 2 tests green — cycle 8
  - [x] Crypto-reviewer: YELLOW (no RED). Warnings: opaque-ke 3.x vs rule 4.x (follow-up needed), max_past_epochs(0) now explicit, identity binding documented — cycle 8
  - [x] Comlink worker / wasm-bindgen exports — cycle 10 (commit b5c58b0): wasm_exports.rs + crypto.worker.ts; zeroize on export_key; Biome fixed; 30/30 tests green; crypto-reviewer YELLOW (waiver for opaque-ke 3.x recorded in crypto-libraries-pinned.md)
  - [x] WASM compilation test (wasm-pack --target web) — cycle 11: wasm-pack 0.15 success, 1.5MB binary, CI job added to ci-frontend.yml

### Phase 3 — Backend Services & API  ← ACTIVE
- [x] REST API axum adapter: AppState, auth/messaging/key-package routes, AuthenticatedDevice extractor, ApiError, 512KB body limit, 10 tests — cycle 12 (commit a31ff1a); security-auditor PASS
- [x] Composition root: wire Postgres + Redis outbound adapters into bin/powehi-server; DI wiring for AppState — cycle 14 (commit c46eec3); security-auditor GREEN
- [x] WS hub: real-time push via WebSocket (envelope delivery notifications) — cycle 16 (commit 9c9d886); security-auditor PASS
- [ ] OPAQUE auth adapter: real opaque-ke server-side register/login in powehi-opaque
- [ ] Rate limiting (tower middleware or governor)
- [ ] Media (R2 upload/download via powehi-r2 adapter)

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
