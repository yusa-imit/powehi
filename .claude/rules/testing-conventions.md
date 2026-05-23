---
paths:
  - "crates/**"
  - "app/**"
  - "infra/**"
---

# Testing conventions (all layers must be tested)

Every layer carries its own test gate. A change is not "done" until its layer's gate is green. See prd.md §6.2, §12.5 and the per-phase DoD (§15.4).

## The test pyramid
- **Unit** (fast, no I/O): pure logic, edge cases. Domain/application crates should be unit-testable with in-memory port fakes (no DB) — this is a benefit of the hexagonal split (prd.md §16.6 ADR-001).
- **Integration** (real dependencies via `testcontainers`): outbound adapters against real Postgres/Redis; R2 via S3-compatible test container or stub.
- **E2E** (Playwright): full user flows (register → message round-trip).
- **Property-based** (`proptest`): crypto round-trips and serialization.

## Backend (crates/**)
- Runner: `cargo nextest run --workspace` (must be 100% on the touched crate).
- Outbound adapter (Postgres/Redis/R2) → `testcontainers` integration test required.
- DB migration → apply + rollback both verified locally (agent: `db-schema-author`).
- No `unwrap()`/`expect()` in lib code paths under test.

## Frontend (app/**)
- Unit/component: **Vitest** + Testing Library. Co-locate the test with the component.
- Crypto worker boundary: mock the Comlink proxy; never import crypto libs into a component test.
- E2E: **Playwright** for register/login (OPAQUE) and message send/receive.
- Budget assertion: build must stay under prd.md §7 budgets (initial route < 200KB gz, WASM < 800KB gz) — treat a budget regression as a failing test.

## Infra (infra/**)
Static validation is the infra equivalent of unit tests — run it before merge (skill: `infra-test`):
- Terraform: `fmt -check`, `validate`, `tflint`, `tfsec`/`checkov`, `plan` (no surprise destroy of stateful resources).
- Helm/K8s: `helm lint`, `helm template` → `kubeconform` + `conftest` (resource limits, deny-all NetworkPolicy, no literal secrets, no `:latest`, runAsNonRoot).
- DR behavior (prd.md §4A.7, §12.9) is exercised by the failover drill + cross-region synthetic checks (§13.4), not unit tests — but a config change to failover/routing must be plan-reviewed.

## Security-invariant tests (cross-cutting — required for security-relevant changes)
- **No plaintext leak**: assert log/metric output is content-free (rule: `no-plaintext-logging`). Never assert behavior by reading plaintext out of logs.
- **Forward secrecy / PCS**: see skill `add-mls-test`.
- **Auth bypass impossible**: unauthenticated request to a protected endpoint returns 401.
- Fixtures must not contain real-looking PII or real keys.

## Who owns what
- App/crypto/backend tests → `test-author` (+ `crypto-reviewer` for crypto).
- Infra validation → `terraform-author` / `k8s-manifest-author`; wired into CI by `ci-pipeline-author`.
