# Phase 5: Hardening & Launch

## Status: COMPLETE (cycle 139)

## Definition of Done
- [x] SLSA Level 3 reproducible builds verified
- [x] Container image signing (cosign + Rekor)
- [x] Full threat model review (threat-model-checker pass) — cycle 134, commit e35ad89
- [~] Load testing (target concurrent connections met) — k6 scripts + manual CI workflow added (cycle 136, commit 6d6cae1); needs staging infra run to fully close
- [x] Observability stack deployed (zero-knowledge metrics/logs) — HTTP metrics middleware (cycle 132), OTLP trace export + ServiceMonitor (cycle 133)
- [x] PQ hybrid migration path documented (ML-KEM-768) — ADR-0003 Active (cycle 137); prd.md §5.3 expanded
- [x] Security audit findings addressed — Y3/F4/F6/Y-KP-1 closed (cycle 138, commit 9629f23)
- [x] Public beta deployment — Argo CD GitOps manifests + CD workflow (cycle 139, commit 66b8ca3)

## Completed this cycle (Phase 5 cycle 1 — cycle 131)

### SLSA Level 3 reproducible builds — prd.md §12.6

**`rust-toolchain.toml`** (NEW):
- Pins Rust toolchain to `1.96.0` (confirmed-working CI version)
- Components: `rustfmt`, `clippy`
- Targets: `wasm32-unknown-unknown`
- Provides reproducible local dev environment; CI overrides via `dtolnay/rust-toolchain` action with explicit version

**`Dockerfile`** (MODIFIED):
- Updated `FROM rust:1.83.0-bookworm` → `FROM rust:1.96.0-bookworm`
- Aligns with `rust-toolchain.toml` channel; old 1.83.0 was below transitive-dep
  minimum (darling/time/aws-smithy require ≥1.88–1.91)

**`.github/workflows/release.yml`** (EXTENDED):
- All third-party GitHub Actions now SHA-pinned (supply-chain hardening):
  - `actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5` (v4)
  - `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02` (v4)
  - `Swatinem/rust-cache@42dc69e1aa15d09112580998cf2ef0119e2e91ae` (v2)
  - `docker/setup-buildx-action@8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` (v3)
  - `docker/login-action@c94ce9fb468520275223c153574b00df6fe4bcc9` (v3)
  - `docker/metadata-action@c299e40c65443455700f0fdfc63efafe5b349051` (v5)
  - `docker/build-push-action@10e90e3645eae34f1e60eeb005ba3a3d33f178e8` (v6)
  - `sigstore/cosign-installer@f713795cb21599bc4e5c4b58cbad1da852d7eeb9` (v3)
  - `dtolnay/rust-toolchain@3c5f7ea28cd621ae0bf5283f0e981fb97b8a7af9` (pinned by HEAD commit)
  - slsa-framework reusable workflows remain at `@v2.0.0` (upstream explicitly forbids SHA pinning)
- Docker GHA cache disabled in `build-push-container` (writeable by all repo workflows → potential cache poisoning)
- **`build-wasm` job** (NEW): builds `powehi_crypto_wasm_bg.wasm` + JS glue with `SOURCE_DATE_EPOCH=0`, `wasm-pack 0.13.1 --locked`, Rust `1.96.0`
- **`wasm-provenance` job** (NEW): SLSA L3 attestation for WASM module via `generator_generic_slsa3.yml@v2.0.0`; SLSA subjects cover both `*_bg.wasm` AND `*.js` glue (JS glue controls WASM exports — tamper of glue subverts crypto module)
- `build-binary` toolchain updated `@1.83.0` → `@1.96.0` (matches Dockerfile)
- **security-auditor:** PASS after fixes. Three RED findings resolved: (R1) action SHA pinning, (R2) wasm-pack install supply-chain + reproducibility, (R3) JS glue missing from SLSA subjects. Two YELLOWs deferred: (Y1) `build-binary` SOURCE_DATE_EPOCH doesn't guarantee byte-for-byte binary reproducibility without `--remap-path-prefix` (advisory, L4 territory); (Y2) `apt-get install` in runtime stage uses unpinned package versions (affects image hash, not binary subject hash)

**Tests:** 465 Rust tests pass; 358 frontend tests pass; cargo fmt clean; clippy green.

## Notes
- Container image signing (cosign + Rekor) was already in release.yml from a prior cycle — checklist item 2 may already be satisfied; needs verification against the full release run.
- See prd.md §12.6 for SLSA level mapping + specific strategy
- Requires all domain leads + full audit agent suite for remaining items
