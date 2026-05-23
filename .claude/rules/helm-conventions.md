---
paths:
  - "infra/helm/**"
  - "infra/terraform/**"
  - "infra/**/*.yaml"
  - "infra/**/*.yml"
---

# Infrastructure conventions

## Helm charts
- One chart per service under `infra/helm/<service>/`
- Use `external-secrets-operator` for secret injection — never hardcode secrets
- All values must have sensible defaults in `values.yaml`
- Resource limits required for every container (no unbounded pods)
- NetworkPolicy in every chart (deny-all default, explicit allows)

## Terraform
- Modules under `infra/terraform/modules/<name>/`
- Environment configs: `infra/terraform/envs/{dev,staging,prod}/`
- Remote state with encryption — never local state in production
- No secrets in `.tf` files — use `TF_VAR_*` or vault provider
- All outputs reviewed for secret leakage

## Observability
- Logs must be content-free (no message payloads, no PII, no ciphertext)
- Use opaque internal IDs, never user-supplied identifiers
- Metrics: Prometheus format, no cardinality bombs (bounded label values)
