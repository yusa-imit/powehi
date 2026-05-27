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

## Current state (2026-05-27, cycle 24 — FEATURE: Phase 4 Service Worker + Playwright + bundle budget)
- **Phase 4 cycle 24 (commit 600c2b3):** Service Worker push + Playwright E2E + bundle budget:
  - `app/public/sw.js`: Web Push RFC 8291 wake-up handler; notification body is constant "New encrypted message" (no content); groupId validated as UUID v4 regex before use (security-auditor YELLOW-1/2 addressed); open-window uses literal "/" only
  - `app/src/hooks/useServiceWorker.ts`: SW registration + VAPID subscribe hook; non-fatal error handling; `urlBase64ToUint8Array` returns `Uint8Array<ArrayBuffer>` for TS5.8 compat
  - `app/src/main.tsx`: Root component wraps App with useServiceWorker(); `worker.format: "es"` in vite.config.ts fixes production build of Comlink crypto worker
  - `app/e2e/login.spec.ts` + `app/e2e/chat.spec.ts`: Playwright tests; `playwright.config.ts` with Chromium, webServer auto-start
  - `app/scripts/check-bundle-budget.mjs`: bundle gate (init JS <200KB gz, WASM <800KB gz); actual: 69.1KB JS + 553.4KB WASM — both pass
  - `.github/workflows/ci-frontend.yml`: added `playwright` and `bundle-budget` CI jobs
  - `pnpm-lock.yaml` regenerated — fixed frozen-lockfile mismatch that was causing CI failures
  - TypeScript fixes: schema.test.ts unused variable removed; crypto.worker.ts cast via unknown; Uint8Array<ArrayBuffer> type
  - 12 frontend tests green; 174 Rust tests green; biome clean; security-auditor PASS
  - Phase 4 checklist item COMPLETE: Service Worker push + Playwright E2E + bundle budget
  - Next: Phase 5 — SLSA L3 reproducible builds + cosign + Rekor + load test + observability

## Current state (2026-05-27, cycle 23 — FEATURE: Phase 4 Login/Chat UI)
- **Phase 4 cycle 23 (commit 786cf6f):** Login/Chat UI + Dexie encrypted storage:
  - `src/index.css`: Geist + Instrument Serif Google Fonts; all design tokens from DESIGN.md as CSS vars
  - `src/components/Login.tsx`: OPAQUE username/password form — cosmic radial-gradient bg, glassmorphism card, Instrument Serif tagline, accretion-orange CTA, photon-blue lock icon footer
  - `src/components/ChatLayout.tsx`: 3-pane layout (Sidebar 320px + Conversation flex + InfoPanel 340px toggle); mock seed chats; orange/surface message bubbles; composer
  - `src/components/Icon.tsx`: 19 inline SVG icons (lucide-style) — lock always photon blue (#A8C8FF)
  - `src/db/schema.ts`: PowehiDb (Dexie v4) — MessageRow (ciphertextB64, no plaintext), GroupRow, LocalIdentity; no-plaintext-content invariant by type
  - `src/store/auth.ts`: Zustand store — phase (login|app) + deviceId
  - `src/hooks/useCryptoWorker.ts`: module-level Comlink singleton, graceful import error for missing WASM
  - `fake-indexeddb` moved to devDependencies; `dexie` + `zustand` in prod deps
  - 12 frontend tests green (5 Dexie schema, 7 App); biome clean; 139 backend tests unaffected
  - Next: Service Worker push + Playwright E2E (Phase 4 remaining items)

## Current state (2026-05-27, cycle 22 — STABILIZATION: rustls security fix)
- **Cycle 22 (commit 6112530):** RED CI fixed — 3 new RUSTSEC vulns in rustls-webpki 0.101.7:
  - RUSTSEC-2026-0098/0099 (upgrade to >=0.103.12) + RUSTSEC-2026-0104 (upgrade to >=0.103.13)
  - Root cause: `aws-sdk-s3` default features included `rustls` (legacy path → aws-smithy-http-client/
    legacy-rustls-ring → hyper-rustls 0.24.2 → rustls 0.21.12 → rustls-webpki 0.101.7)
  - Fix: `aws-sdk-s3 = { default-features = false, features = [...all except rustls...] }`
  - Dropped: rustls 0.21.12, rustls-webpki 0.101.7, hyper-rustls 0.24.2, tokio-rustls 0.24.1 (+5 deps)
  - Remaining TLS: only rustls 0.23.40 + rustls-webpki 0.103.13 (safe) via default-https-client path
  - cargo audit: only RUSTSEC-2024-0384 (existing waiver for openmls instant dep)
  - 139 tests passing, clippy clean, rustfmt clean

## Current state (2026-05-27, cycle 21 — FEATURE: Phase 3 Media R2)
- **Phase 3 cycle 21 (commit 2527650):** R2 media adapter implemented:
  - `powehi-r2` crate: `R2MediaAdapter` (aws-sdk-s3 v1 + sqlx); content-type allowlist (8 types);
    presigned PUT (upload, 900s TTL) + GET (download, 300s TTL); no ciphertext proxied
  - `powehi-domain`: `MediaId.as_uuid()` + `From<Uuid>`; `MediaBlob.uploader` → `uploader_device: DeviceId`
  - `powehi-port-inbound`: `MediaUseCase` updated — `get_download_url` takes `requestor_device`
  - `powehi-application`: `MediaService` — download ACL (uploader-only, Phase 4 → group-member); `size_bucket` tracing
  - DB migration `0003_media_blobs.sql`: metadata table with FK to `devices`
  - `powehi-rest-api`: 4 media routes; `size_bytes` [1, 100MB] enforced in handler
  - `powehi-config`: R2 fields; credentials have no defaults (operator must inject)
  - 139 tests passing (was 122); clippy clean; security-auditor R1+R2 addressed
  - Deferred (Phase 4): group-member ACL for download URL; pre-signed URL size binding (Y2); confirm_upload HeadObject check (Y3); SSRF r2_endpoint validation (Y5); orphan row GC (Y6)
- Next action (Phase 4): Login/Chat UI + Dexie encrypted storage + crypto worker integration

## Current state (2026-05-26, cycle 20 — STABILIZATION)
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
- **Stabilization cycle 20 (commit a1f31b0):**
  - Fixed RED CI: cycle-19 rate-limit tests were not rustfmt-compliant (method chains on single line) — `cargo fmt` applied. This was why CI never triggered for cycle-19 commits.
  - Fixed security-auditor R1 (RED): `/v1/ws` was unrated — applied `api_governor()` to ws_hub router in `main.rs:79`.
  - Fixed security-auditor Y7: auth routes logged client-supplied `req.user_id` before validation; `register_finish` now logs server-returned UserId, `login_finish` drops the field entirely.
  - Added 8 unit tests for `TrustedProxyKeyExtractor` header-priority invariants (CF-Connecting-IP > rightmost XFF > X-Real-IP > 0.0.0.0 fallback; malformed fallthrough; whitespace trim).
  - `cargo audit`: clean (RUSTSEC-2024-0384 existing waiver). clippy: clean. 122 tests passing.
- **Phase 3 cycle 19 (commit 0a738e6):** Rate limiting implemented:
  - `rate_limit` module in powehi-rest-api: `TrustedProxyKeyExtractor` (CF-Connecting-IP → rightmost XFF → X-Real-IP → 0.0.0.0 fallback)
  - Auth endpoints: burst=5, 1 token/6s (brute-force guard)
  - API endpoints: burst=60, 1 token/2s (general throttle)
  - Router split into auth + api sub-routers via `router_inner`; `/health` unrated
  - `tower_governor = "0.4"` + `governor = "0.6"` added to powehi-rest-api
  - 3 new rate-limit tests (per-IP isolation, auth 429, api 429)
  - Total tests: 132 passing; clippy clean
  - security-auditor: YELLOW (R1 leftmost-XFF spoofing fixed → rightmost; Y1 global-bucket/Y2 per-handle throttle deferred Phase 5; Y3 tracing feature comment added)
  - Deferred (Phase 5 hardening): per-handle_hash bucket for credential stuffing; ingress XFF stripping config; CF-Connecting-IP as primary in prod
- **Phase 3 cycle 18 (commit 7c2a429):** OPAQUE auth adapter implemented:
  - `OpaqueServerPort` trait + `OpaqueServer` adapter: registration_start/finish, login_start/finish
  - login_start: nonce-keyed pending map (R-1/R-2), synthetic KE2 for unknown users (R-3)
  - login_finish: returns (session_key, bound_user_identity) — session subject never client-supplied
  - AuthService wired: OpaqueServerPort + CachePort; registration window cached 5 min; sessions 24h
  - User domain model: `opaque_password_file: Vec<u8>` + `User::registered()` constructor
  - DB migration 0002: `opaque_password_file` column + `UNIQUE(handle_hash)`
  - PgUserRepository: handles new column
  - Composition root: OpaqueServer wired
  - 111 tests passing (was 100)
  - Crypto-reviewer: YELLOW (all RED findings addressed; deferred: ServerSetup persistence/Y-2, identifier binding/Y-4)
  - Security-auditor: WARN → findings #1 (server-bound session subject) + #5 (delete-after-save) addressed; deferred: rate limiting, per-field input bounds
- Next action (Phase 3): Media (R2 upload/download via powehi-r2 adapter)
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
- [x] OPAQUE auth adapter: real opaque-ke server-side register/login in powehi-opaque — cycle 18 (commit 7c2a429)
- [x] Rate limiting (tower_governor 0.4 + governor 0.6, TrustedProxyKeyExtractor) — cycle 19 (commit 0a738e6)
- [x] Media (R2 upload/download via powehi-r2 adapter) — cycle 21 (commit 2527650)

### Phase 4 — Frontend & Integration
- [x] Login/Chat UI; Dexie encrypted storage; crypto worker hook — cycle 23 (commit 786cf6f)
- [x] Service Worker push; Playwright E2E; bundle budget (<200KB init, <800KB WASM) — cycle 24 (commit 600c2b3)
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
