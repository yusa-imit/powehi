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
- `opaque-ke` 4.x (OPAQUE aPAKE) — stable, RFC 9807. Migrated 3.0 → 4.0.1 on 2026-07-19; the draft-irtf-cfrg-opaque-16 waiver is retired. PQ-hybrid OPRF (X25519+ML-KEM-768) remains a future upgrade within the 4.x line, gated on ADR-0003 Phase B.
- RustCrypto crates: `aes-gcm`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`, `argon2`, `hkdf`, `sha2`
- `ml-kem` (post-quantum, when PQ phase begins)
- `getrandom` with `wasm_js` feature for WASM targets

Do NOT add:
- `ring` (conflicts with openmls on WASM)
- `openssl` bindings (not WASM-compatible)
- Any crate that rolls its own primitives

## opaque-ke major-version migrations (stored password files)
Before bumping opaque-ke across a major version once live user credentials exist,
prove wire compatibility with a fixture test — do NOT rely on source inspection.
See `powehi-opaque/src/lib.rs` `mod interop_v3` for the pattern (a 3.0.0-serialized
blob checked under 4.0.1). Findings from that test, which apply to any future bump:
- The per-user `ServerRegistration` password file IS byte-compatible 3.0 -> 4.0.1.
- The server long-term `ServerSetup` (OPRF seed + AKE keypair) is NOT compatible
  3.0 -> 4.0.1 (both 128 B; 4.0.1 rejects the 3.0 layout). Since login re-derives
  each user's OPRF key from `ServerSetup.oprf_seed`, password-file portability is
  necessary but NOT sufficient: a live migration also needs a portable/persisted
  `ServerSetup` or a forced re-registration. No impact today (no prod users;
  `ServerSetup` is regenerated on startup), but any future bump MUST carry an
  explicit `ServerSetup` migration story, not just a password-file fixture.

## Frontend (package.json)
- Crypto operations MUST go through the WASM crypto worker via Comlink
- No direct crypto libraries in the frontend bundle
- Exception: `@serenity-kit/opaque` or `opaque-wasm` for client-side OPAQUE flows
