---
name: verify-reproducible-build
description: Verify the WASM crypto core and frontend build are byte-reproducible and that container images are signed (cosign + Rekor). Use before a release/canary or when auditing supply-chain integrity.
---

# Verify reproducible build (SLSA target: Level 3)

Background: prd.md §12.6, §2.2 (Auditability over Obscurity). The whole zero-knowledge claim rests on users being able to confirm the binary matches the public source.

## Steps
1. **Pin the toolchain**: confirm `rust-toolchain.toml`, Node/pnpm version pins, and committed `Cargo.lock` + `pnpm-lock.yaml` are present and unchanged.
2. **Deterministic build**: build twice in a clean environment with `SOURCE_DATE_EPOCH` set to a fixed value.
   - WASM: `pnpm --filter app build:wasm` → record `sha256` of the `.wasm` artifact.
   - Frontend: `pnpm --filter app build` → hash the output bundle.
3. **Compare**: the two independent builds must produce identical hashes. Any difference = non-reproducible; investigate (timestamps, absolute paths, parallelism nondeterminism, embedded build metadata).
4. **Signing**: container images signed via cosign keyless (OIDC), with a Sigstore Rekor transparency log entry. Verify with `cosign verify`.
5. **Bundle budget** (ties to prd.md §7, Phase 2/4 DoD): WASM < 800KB gzipped, initial route < 200KB gzipped.

## Done when
- Two clean builds yield identical artifact hashes.
- `cosign verify` succeeds and a Rekor entry exists.
- A copy-pasteable user verification snippet (build → hash → compare) is documented.

## Do not
- Do not store signing keys in the repo or in Actions secrets — keyless OIDC only (agent: `ci-pipeline-author`).
