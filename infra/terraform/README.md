# Powehi — Terraform / OpenTofu Infrastructure

OpenTofu >= 1.6 (see `.terraform-version`). Hetzner Cloud (Tier 1, Frankfurt)
and Cloudflare edge (Tier 3) resources for the Powehi E2EE messenger.

## Directory layout

```
infra/terraform/
├── modules/hetzner-k3s/       reusable k3s cluster module (control + worker nodes)
└── envs/
    ├── dev/                   dev environment (1 control, 1 worker)
    ├── prod-eu/               production EU environment (3 control, 3 worker)
    └── cloudflare/            Cloudflare DNS / WAF stubs (standalone root module)
```

## Prerequisites

- OpenTofu >= 1.6  (or Terraform >= 1.6)
- `TF_VAR_hcloud_token` — Hetzner Cloud API token
- `TF_VAR_cloudflare_api_token` — Cloudflare API token (cloudflare module only)
- `TF_VAR_cloudflare_zone_id` — Cloudflare zone ID (cloudflare module only)

**Never** put real tokens in `terraform.tfvars` or any `.tf` file.
Copy the relevant `terraform.tfvars.example` to `terraform.tfvars`, fill in
the non-secret values, and export the secret tokens as `TF_VAR_*` env vars.

## Workflow

```bash
# 1. Enter the target environment
cd infra/terraform/envs/dev        # or prod-eu, or cloudflare

# 2. Initialise (downloads providers)
tofu init          # or: terraform init

# 3. Review the plan — confirm no surprise destroy/replace of Postgres or R2
tofu plan

# 4. Apply
tofu apply
```

## Security invariants

- Secrets arrive only through `TF_VAR_*` environment variables.
- `*.tfvars` (real values) are gitignored; only `*.tfvars.example` is committed.
- State files (`*.tfstate`) are gitignored locally; use an encrypted remote
  backend (S3-compatible + SSE) before promoting to staging or production.
- Cloudflare WAF rules must not be disabled without a documented reason in the
  commit message referencing the relevant rule ID.
