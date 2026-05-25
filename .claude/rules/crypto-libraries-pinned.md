---
paths:
  - "**/Cargo.toml"
  - "**/package.json"
---

# Crypto library policy

Only use audited, well-known cryptography libraries. Never implement crypto primitives.

## Rust (Cargo.toml)
Approved libraries only:
- `openmls` >= 0.7.2 (MLS protocol)
- `opaque-ke` 4.x (OPAQUE aPAKE) — **WAIVER (2026-05-25)**: currently pinned at 3.0 (draft-irtf-cfrg-opaque-16). Only `4.1.0-pre.2` (pre-release) is available as of this date. Upgrade to stable 4.x when released; tracked in project-context.md. codebase comment in opaque.rs documents the draft-vs-RFC delta. No production deploy until this is resolved.
- RustCrypto crates: `aes-gcm`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `argon2`, `hkdf`, `sha2`
- `ml-kem` (post-quantum, when PQ phase begins)
- `getrandom` with `wasm_js` feature for WASM targets

Do NOT add:
- `ring` (conflicts with openmls on WASM)
- `openssl` bindings (not WASM-compatible)
- Any crate that rolls its own primitives

## Frontend (package.json)
- Crypto operations MUST go through the WASM crypto worker via Comlink
- No direct crypto libraries in the frontend bundle
- Exception: `@serenity-kit/opaque` or `opaque-wasm` for client-side OPAQUE flows
