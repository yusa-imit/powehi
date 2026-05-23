---
name: add-rust-crate
description: Scaffold a new powehi-* Rust crate inside the hexagonal workspace with Cargo.toml, lib.rs module layout, thiserror error type, and a passing nextest. Use when adding a crate to the backend workspace.
---

# Add a Rust crate (hexagonal-aware)

Delegate the actual writing to `rust-crate-builder`. This skill is the checklist.

## Decide the layer first (prd.md §6.1)
The crate's layer dictates allowed dependencies — enforced at compile time via Cargo.toml:
- `domain/` → ZERO external deps except `serde` derive. No tokio/axum/sqlx.
- `ports/` → depends only on `powehi-domain`.
- `application/` → `powehi-domain` + `powehi-port-*` only. Never an adapter.
- `adapters/` → application + ports + domain + concrete tech (sqlx, tonic, axum).
- `bin/powehi-server` → the only place that wires everything (Composition Root).

## Steps
1. Confirm the crate name follows `powehi-*` (rule: `crates-naming`) and place it in the correct layer dir.
2. `Cargo.toml`: pin versions from prd.md §6.2; use `workspace = true` for shared deps. Run `cargo deny check` before adding anything new (rule: `crypto-libraries-pinned` if it touches crypto).
3. `src/lib.rs` with explicit `pub mod`; `src/error.rs` with a `thiserror` error type. No `unwrap()`/`expect()` in lib code.
4. Add the crate to the workspace `members` list.
5. Write at least one unit test. If the crate is an outbound adapter touching Postgres/Redis, add a `testcontainers` integration test (see rule: `testing-conventions`).
6. Verify: `cargo build -p <crate>` and `cargo nextest run -p <crate>` both green.

## Done when
- `cargo build --workspace` and `cargo nextest run -p <crate>` pass.
- `cargo clippy -p <crate> --all-targets -- -D warnings` is clean.
- The dependency direction does not violate the hexagonal rule (a domain/ports crate must not pull an adapter).
