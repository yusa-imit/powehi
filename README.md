# POWEHI

End-to-end encrypted, zero-knowledge web messenger. The server never sees
plaintext message content. Full architecture: `docs/prd.md`. Agent/orchestration
design: `docs/orchestration.md`. Working conventions for the autonomous dev loop:
`CLAUDE.md`.

## Architecture at a glance

- **Backend** — Rust hexagonal workspace under `crates/` (axum + tokio + sqlx).
  `domain` → `ports` → `application` → `adapters` → `bin/powehi-server`.
- **Frontend** — React 19 + Vite 6 under `app/`, encrypted local storage via
  Dexie, all crypto routed through a Comlink-wrapped Web Worker.
- **Crypto** — `crates/client/powehi-crypto-wasm`, compiled to
  `wasm32-unknown-unknown`. MLS (RFC 9420) via `openmls`, OPAQUE (RFC 9807) via
  `opaque-ke`, everything else via RustCrypto. No homegrown crypto.
- **Infra** — Terraform/OpenTofu under `infra/terraform` (Hetzner k3s,
  Cloudflare), Helm charts under `infra/helm`.

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Rust | `1.98.1` | pinned in `rust-toolchain.toml`; installs `rustfmt`/`clippy` + the `wasm32-unknown-unknown` target automatically via rustup |
| Node.js | 20+ | any version compatible with pnpm 10 |
| pnpm | `10.28.2` | pinned via `packageManager` in `package.json`; use `corepack enable` to get the exact version |
| wasm-pack | `0.13.1` | CI installs a SHA-256-pinned binary (`.github/actions/install-wasm-pack`); install the same version locally, or run `pnpm build:wasm` after installing any wasm-pack that supports `--target web` |
| Docker | any recent version | only needed for `docker-compose.yml` (local Postgres/Redis/MinIO) and the `#[ignore]`d testcontainers integration tests |

## Setup

```bash
# Rust toolchain (rustup reads rust-toolchain.toml automatically)
rustup show

# Node dependencies (workspace-wide)
corepack enable
pnpm install

# Local backing services for manual `powehi-server` runs and live-backend E2E
docker compose up -d
```

## Build & test

```bash
# Backend
cargo build --workspace
cargo nextest run --workspace   # fallback: cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
cargo audit
cargo deny check

# WASM crypto core (crates/client/powehi-crypto-wasm -> app/src/wasm)
pnpm build:wasm

# Frontend (from repo root; app/ is a pnpm workspace member)
pnpm --filter app dev      # dev server
pnpm --filter app test     # Vitest
pnpm --filter app e2e      # Playwright (mocked backend)
pnpm --filter app e2e:live # Playwright against docker-compose backend
biome check                # lint/format check

# Infra (after any change under infra/)
terraform validate && tflint && tfsec
helm lint && kubeconform && conftest test
```

Testing standards and what gate applies to which layer: `.claude/rules/testing-conventions.md`.

## CLI client (`powehi`)

The primary client is the terminal client in `crates/client/powehi-cli` (prd.md §7A).
`powehi status`, `register`, `login` and `invite create` / `invite redeem` are functional; the
other subcommands parse but report "not implemented yet".

```bash
cargo run -p powehi-cli -- --server http://localhost:8080 status
# global flags: --server <url>, --profile <name>, --data-dir <dir>
# (env: POWEHI_SERVER, POWEHI_PROFILE, POWEHI_DATA_DIR)
```

Passwords are never accepted as arguments and message bodies are read from stdin only.
`register` and `login` prompt for the handle and password on the controlling terminal
(`/dev/tty`, echo off), run OPAQUE against the server, and unlock the profile store. `register`
shows a 24-word recovery phrase once on the terminal (not stdout) and stores only keys derived
from it, encrypted. The session token lives in memory only; every command that needs one logs in
again.

Starting a 1:1 conversation: `powehi invite create [--wait <secs>]` prints a link
`<server>/i/connect#<code>.<sha256 of the pinned KeyPackage>`; the peer pipes it to
`powehi invite redeem` (stdin, never argv). The redeemer verifies the KeyPackage against the hash
in the link, creates the MLS group and sends the Welcome; with `--wait` the inviter polls for it
and joins (otherwise the join happens when `inbox` lands). Each conversation is a `conv-<group id>`
record in the profile store.

The library contains an encrypted profile store (`powehi_cli::store`, Unix only): AES-256-GCM
records under `<data-dir>/powehi/<profile>/` (dir `0700`, files `0600`), keyed from the OPAQUE
`export_key` via HKDF-SHA256. `register` creates it and `login` unlocks it.

## Non-negotiables

- The server never sees plaintext message content.
- No homegrown crypto — only `openmls`, `opaque-ke`, RustCrypto.
- All crypto code passes `crypto-reviewer` before merge; architectural changes pass
  `threat-model-checker`; backend/infra changes pass `security-auditor`.
- No plaintext logging of message content, user PII, or ciphertext payloads.

See `CLAUDE.md` for the full non-negotiables list and agent routing.
