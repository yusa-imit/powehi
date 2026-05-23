---
paths:
  - "crates/**/*.rs"
  - "crates/**/Cargo.toml"
---

# Rust crate naming and structure

All crates in the workspace follow the `powehi-*` naming convention.

## Crate structure
- Each crate: `crates/powehi-<name>/`
- Public API in `src/lib.rs` with explicit `pub mod` declarations
- Error types: `src/error.rs` using `thiserror`
- No `unwrap()` or `expect()` in library code — propagate errors with `?`

## Naming
- Crate names: `powehi-auth`, `powehi-ws`, `powehi-mls`, etc.
- Module names: snake_case
- Types: PascalCase
- Constants: SCREAMING_SNAKE_CASE

## Dependencies
- Pin major versions in workspace Cargo.toml
- Use workspace dependencies (`workspace = true`) in member crates
- Run `cargo deny check` before adding new dependencies
