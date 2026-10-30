---
name: infra-test
description: Statically validate OpenTofu before merge — fmt, validate, lint, security scan, mocked-provider tests, and zero-knowledge log/secret policy checks. Use after any change under infra/.
---

# Infra test (pre-merge static validation)

Closes the gap where infra changes had no test gate equivalent to `cargo nextest` for code. Delegate execution to `terraform-author`; `ci-pipeline-author` wires the same checks into CI. See rule: `testing-conventions` (Infra section) and ADR-0007.

## OpenTofu (infra/terraform/**)
1. `tofu fmt -check -recursive` — formatting.
2. `tofu validate` per root module (`-backend=false`) — syntax + provider schema.
3. `tflint` — provider-specific lint (AWS/Cloudflare).
4. `trivy config` — security misconfig scan (public buckets, missing encryption, open security groups).
5. `tofu test` with mocked providers — module contracts without cloud credentials.
6. Assert: no secrets in `.tf` or in plan output; remote state backend is encrypted. Never apply `prod` from a session.

## Zero-knowledge guardrails (prd.md §13.2)
- No log/metric config that would emit payloads, plaintext user IDs, or ciphertext.
- Metrics labels are bounded (no cardinality bombs / user-supplied label values).

## Done when
- All of the above pass for the changed module.
