---
description: Prepare a canary deployment. Validates build reproducibility, runs security checks, and generates deployment artifacts.
arguments:
  - name: environment
    description: Target environment (dev, staging, prod)
    optional: true
---

# Deploy Canary to $ARGUMENTS

Prepare and validate a canary deployment.

## Steps

1. Determine target environment (default: dev)
2. Pre-flight checks:
   - All tests pass (`cargo nextest run --workspace`, frontend Vitest + Playwright)
   - No clippy warnings (`cargo clippy --workspace --all-targets -- -D warnings`)
   - Security audit clean (`cargo audit`, `cargo deny check`)
   - WASM build reproducible (compare hash with `SOURCE_DATE_EPOCH`)
   - Infra validated for the target env (skill: infra-test) — `terraform validate`/`plan`,
     `helm lint`, `kubeconform`, `conftest` all green for changed infra paths
3. For staging/prod:
   - Require crypto-reviewer pass for any crypto changes since last deploy
   - Require security-auditor pass
   - Require threat-model-checker pass for any architectural changes
4. Build artifacts:
   - Container image with distroless base
   - SBOM generation
   - cosign signature
5. Report readiness status and any blocking issues

## Safety
- NEVER auto-deploy to prod. Always require explicit user confirmation.
- NEVER skip security checks "to save time"
