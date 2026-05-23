# Powehi — E2EE Zero-Knowledge Web Messenger

## What this is
End-to-end encrypted web messenger. The server NEVER sees plaintext.
See `/docs/prd.md` for full architecture. See `/docs/orchestration.md` for agent system design.

## Build & Test (planned — not yet implemented)
- Backend build: `cargo build --workspace`
- Backend test: `cargo nextest run --workspace` (testcontainers for adapter integration tests)
- Backend lint: `cargo clippy --workspace --all-targets -- -D warnings`
- Frontend dev: `pnpm --filter app dev`
- Frontend test: `pnpm --filter app test` (Vitest), E2E `pnpm --filter app e2e` (Playwright)
- Frontend lint: `biome check`
- WASM build: `pnpm --filter app build:wasm`
- Infra validate: `terraform validate` + `tflint`/`tfsec`; `helm lint` + `kubeconform` + `conftest`
- Testing standards live in `.claude/rules/testing-conventions.md` (every layer has a gate)

## Architecture
- Backend: Rust workspace at `/crates/` (axum + tokio + sqlx)
- Frontend: React 19 + Vite 6 at `/app/`
- WASM Crypto: `/crates/powehi-crypto/` compiled to wasm32-unknown-unknown
- Infra: Terraform at `/infra/terraform/`, Helm at `/infra/helm/`
- Protocols: MLS (RFC 9420), OPAQUE (RFC 9807), Web Push (RFC 8291)
- Design system: `DESIGN.md` → `docs/design/powehi-design-system/` + `/powehi-design` skill (read before any UI work; brand rules are hard)

## Non-negotiables
- Server NEVER sees plaintext message content
- No homegrown crypto. Use openmls, opaque-ke, RustCrypto only
- All crypto code must pass crypto-reviewer agent before merge
- All architectural changes must pass threat-model-checker
- No plaintext logging of message content, user PII, or ciphertext payloads

## Agent routing
- Crypto/MLS/OPAQUE/PQ work: delegate to `crypto-lead`
- Rust backend crates: delegate to `backend-lead`
- Frontend React/Vite/IndexedDB: delegate to `frontend-lead`
- K8s/Terraform/CI: delegate to `infra-lead`
- Cross-cutting or large tasks: delegate to `lead-orchestrator`
- Default to single agent for tasks completable in <20 tool calls

## Style
- Communicate in Korean with English technical terms
- Cite prd.md section numbers when justifying design decisions
