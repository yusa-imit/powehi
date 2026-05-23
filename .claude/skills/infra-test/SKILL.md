---
name: infra-test
description: Statically validate Terraform and Kubernetes/Helm before merge — fmt, validate, plan, lint, policy (OPA/conftest), manifest schema (kubeconform), and zero-knowledge log/secret policy checks. Use after any change under infra/.
---

# Infra test (pre-merge static validation)

Closes the gap where infra changes had no test gate equivalent to `cargo nextest` for code. Delegate execution to `terraform-author` (Terraform) and `k8s-manifest-author` (Helm/K8s); `ci-pipeline-author` wires the same checks into CI. See rule: `testing-conventions` (Infra section) and `helm-conventions`.

## Terraform (infra/terraform/**)
1. `terraform fmt -check -recursive` — formatting.
2. `terraform validate` per module — syntax + provider schema.
3. `tflint` — provider-specific lint (Hetzner/Cloudflare).
4. `tfsec` or `checkov` — security misconfig scan (public buckets, missing encryption, open security groups).
5. `terraform plan` against a non-prod workspace — no unexpected destroy/replace of stateful resources (Postgres, R2 buckets).
6. Assert: no secrets in `.tf` or in plan output; remote state backend is encrypted (rule: `helm-conventions` Terraform section).

## Kubernetes / Helm (infra/helm/**)
1. `helm lint <chart>` — chart sanity.
2. `helm template <chart> -f values.yaml` — render, then pipe to:
   - `kubeconform` (or `kubeval`) — manifest schema validation against the target k8s version.
   - `conftest test` (OPA/Rego policies) — enforce: every container has resource limits + requests; a deny-all `NetworkPolicy` exists; no literal `Secret` data (must reference external-secrets-operator); no `:latest` image tags; runAsNonRoot.
3. Diff render across `values-{dev,staging,prod}.yaml` (and per-region overrides) to catch env drift.

## Zero-knowledge guardrails (prd.md §13.2)
- No log/metric config that would emit payloads, plaintext user IDs, or ciphertext.
- Metrics labels are bounded (no cardinality bombs / user-supplied label values).

## Done when
- All of the above pass for the changed module/chart.
- For a multi-region change, the per-region rendered diff is reviewed and intentional.
