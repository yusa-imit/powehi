# Powehi infrastructure (OpenTofu)

AWS Seoul (`ap-northeast-2`) plus Cloudflare edge, per ADR-0007. Phase 9.2 delivers the
layout, the one-time `bootstrap/` stack and the CI checks. Network, data (9.3) and edge (9.4)
modules exist; compute follows in 9.5.

```
infra/terraform/
  .terraform-version   OpenTofu pin (1.12.1), read by CI and tofuenv/mise
  .tflint.hcl
  bootstrap/           run ONCE by the owner: state bucket, OIDC, deploy roles, budget
  modules/             shared modules (9.3+)
  envs/staging/        root module, state key staging/terraform.tfstate
  envs/prod/           root module, state key prod/terraform.tfstate
```

Nothing here may add a service that processes ciphertext content. Logs and metrics must stay
content-free (no payload, no plaintext user IDs).

## What bootstrap creates

| Resource | Purpose |
|---|---|
| S3 bucket `powehi-tfstate-<account>-<region>` | State. Versioned, SSE-KMS (customer key, rotating), all public access blocked, TLS 1.2+ only, owner-enforced. |
| KMS key `alias/powehi-tfstate` | Encrypts state (state contains secrets). |
| IAM OIDC provider for GitHub | No long-lived AWS keys anywhere. |
| `powehi-staging-deploy`, `powehi-prod-deploy` | Assumable only by `repo:yusa-imit/powehi:environment:staging` and `...:environment:production` (exact `StringEquals` on `sub` and `aud`). |
| `powehi-plan-readonly` | Assumable only by `repo:yusa-imit/powehi:pull_request` (any same-repo branch PR). Read-only; reads ONLY `staging/*` state (KMS only via S3), never `prod/*`; cannot write state or the lock file, cannot read secret values. |
| Permissions boundaries `powehi-boundary-<env>` | Deploy roles may only create roles with this boundary, so they cannot mint admins. |
| Guardrail policies `powehi-guardrail-<env>` | Separate managed policy with explicit Deny (role/policy mutation outside `powehi-<env>-svc-*`, trust-policy edits, boundary removal, users, access keys, OIDC/SAML providers, cross-env tag mutation). The deploy role cannot edit it. |
| Deploy policies `powehi-deploy-<env>-*` | Resource- and tag-scoped Allow statements (create needs `aws:RequestTag/Environment=<env>`, mutate needs `aws:ResourceTag/Environment=<env>`). |
| AWS Budget `powehi-monthly` | $150/month, alerts at 80 % and 100 % actual plus 100 % forecast, e-mailed to the owner. |

## Owner steps (issue #118, steps 4-5)

Prerequisites: AWS account (steps 1-3 of #118), `tofu` 1.12.1 (`mise use opentofu@1.12.1`
or the release binary), the AWS CLI, admin credentials for the first run only
(`aws sso login` or a short-lived admin session; do not create IAM user keys).

0. FIRST create both GitHub Environments (step 4 below), before the bootstrap apply. The
   OIDC `sub` `environment:production` is only a gate if the Environment and its protection
   rules already exist; an unconfigured Environment is created on first use with no rules.

1. Run bootstrap once:
   ```sh
   cd infra/terraform/bootstrap
   tofu init
   tofu apply -var owner_email=<your e-mail> \
              -var github_repository_id=$(gh api repos/yusa-imit/powehi --jq .id) \
              -var 'allowed_account_ids=["<12-digit account id>"]'
   ```
   Review the plan first. Confirm the AWS Budgets subscription e-mail that AWS sends.
   Keep `terraform.tfstate` (git-ignored) somewhere safe, or later migrate it into the
   state bucket under key `bootstrap/terraform.tfstate`.
2. Note the outputs: `tofu output`.
3. Per env, create the backend file (git-ignored) and initialise:
   ```sh
   cd infra/terraform/envs/staging
   cp backend.hcl.example backend.hcl      # fill bucket / region / kms_key_id from the outputs
   cp staging.tfvars.example staging.tfvars  # set domain
   tofu init -backend-config=backend.hcl
   ```
   Repeat for `envs/prod`. The domain is always the `domain` variable; it is never
   hard-coded in the code.
4. Create GitHub Environments (Settings, Environments):
   - `staging`: no required reviewers; deployment branch policy limited to `main`.
   - `production`: required reviewer, deployment branch policy limited to `main`.
   Both Environments MUST have the deployment branch policy set to `main`; otherwise any
   branch (including an unreviewed PR branch in the same repo) can obtain the environment
   `sub` and assume the deploy role. Also enable "Require review from Code Owners" on `main`
   (`.github/CODEOWNERS` covers `.github/workflows/**` and `infra/**`).
5. Add the secrets and variables below.

### GitHub Environment secrets and variables

| Scope | Name | Kind | Value |
|---|---|---|---|
| Environment `staging` | `AWS_ROLE_ARN` | secret | `deploy_role_arns["staging"]` output |
| Environment `production` | `AWS_ROLE_ARN` | secret | `deploy_role_arns["prod"]` output |
| Repository | `AWS_PLAN_ROLE_ARN` | secret | `plan_role_arn` output |
| Repository | `AWS_REGION` | variable | `ap-northeast-2` |
| Repository | `TF_STATE_BUCKET` | variable | `state_bucket` output |
| Repository | `TF_STATE_KMS_KEY_ARN` | variable | `state_kms_key_arn` output |
| Environment `staging` / `production` | `DOMAIN` | variable | the domain bought in step 1 of #118 |
| Environment `staging` / `production` | `CLOUDFLARE_API_TOKEN` | secret | token scoped to the zone, R2 and Tunnel only (used by `modules/edge`, 9.4) |
| Repository | `CLOUDFLARE_ACCOUNT_ID` | secret | Cloudflare account ID |

Role ARNs are not secret in themselves; they are stored as secrets to keep them out of logs.
Workflows that use them need `permissions: id-token: write` and
`aws-actions/configure-aws-credentials` (arrives with 9.7).

## Edge owner step (9.4, issue #118)

Use two DIFFERENT Cloudflare API tokens: one in the `staging` Environment secret and one in
the `production` Environment secret, exported as `CLOUDFLARE_API_TOKEN` (env only, never
tfvars). Set `cloudflare_account_id` in `<env>.tfvars`.

Permissions per token (neither may hold "API Tokens Edit" or other account-admin power):
- both: Zone Read, DNS Edit (zone), Cloudflare Tunnel Edit (account), Workers R2 Storage
  Write (account-wide, needed to create the bucket);
- staging ONLY (the zone-owning env): Zone Settings Edit and Zone WAF Edit.

Cloudflare limitation, accepted risk (needs the owner's call): Tunnel Edit, DNS Edit and R2
bucket creation cannot be scoped per env, so a staging token can in principle modify the prod
tunnel, DNS and bucket. Separate tokens limit exposure of the prod secret, not this reach.

- **Shared zone.** Staging and prod use one zone, so its singletons (the four TLS settings,
  the zone-level managed WAF ruleset and the auth rate-limit ruleset) are owned by staging
  (`manage_zone = true`, applied first by the 9.7 auto-apply); prod passes false and creates
  just its tunnel, CNAME and bucket. Staging's edge must never be destroyed while prod runs.
  The rate-limit expression is path-only (Free plan, covers both hosts; the server routes
  those paths POST-only). If the Free zone already has a firewall_managed or ratelimit
  entrypoint ruleset, import it before apply and never delete it.
- **R2 token.** Creating the bucket-scoped R2 token needs "API Tokens Edit", so
  `create_r2_token` defaults to false. The owner mints the per-env token once, out of band
  (object read/write on `powehi-<env>-media` only, optionally IP-restricted and with an
  expiry) and stores it in Secrets Manager. `create_r2_token = true` (owner-run apply with a
  broader token) lets the module do it; `r2_token_allowed_cidrs` (task public IPs, no NAT)
  and `r2_token_expires_on` then restrict it.
- **Secrets.** No tunnel secret is in state: the module omits `tunnel_secret` and has no
  token output. The owner fetches the tunnel token out of band (`cloudflared tunnel token
  <tunnel_id>`, the dashboard or the API) into Secrets Manager for the 9.5 sidecar. Non-secret
  outputs: `api_hostname`, `tunnel_id`, `r2_endpoint`, `r2_bucket` (and `r2_access_key_id`);
  they map to `POWEHI__R2_ENDPOINT`, `POWEHI__R2_BUCKET`, `POWEHI__R2_ACCESS_KEY_ID`.
- **Accepted risk.** If `create_r2_token` is true, the token value sits in KMS-encrypted
  state. Staging state is readable by the PR plan role, i.e. by same-repo PR workflows, so
  the 9.7 plan job must never receive the Cloudflare deploy token.

Plan assumptions: free/pro zone, one rate-limit rule. Not applied or planned locally (no
credentials); CI runs `tofu test` with a mocked provider.

## CI (`.github/workflows/ci-infra.yml`)

`tofu fmt -check -recursive`, `tofu init -backend=false` + `tofu validate` per root,
`tflint`, `trivy config`, and `tofu test` (mocked AWS provider, asserts the OIDC `sub`/`aud`
conditions and the state bucket lock-down). None of them needs cloud credentials. Run them
locally from `infra/terraform`:

```sh
tofu fmt -check -recursive
(cd bootstrap && tofu init -backend=false && tofu validate && tofu test)
```

## Operating notes and residual risks

- **Production approval gate is self-approvable.** The AI runs as the owner account
  (`yusa-imit`), which is also the only required reviewer on `production`. It can therefore
  approve its own production deployment. A separate approver account (or a non-owner
  reviewer with "Prevent self-review") is required for the gate to mean anything; see the
  need-human issue opened with this PR. Until then treat the production gate as advisory.
- **Privilege-escalation design.** Workload roles/policies are `powehi-<env>-svc-*`, the only
  names a deploy role may write; deploy roles, plan role, boundaries, guardrails and deploy
  policies match no writable pattern and are additionally covered by `NotResource` denies in
  the guardrail policy. `iam:AttachRolePolicy` is limited by an `iam:PolicyARN` allow-list
  (ECS task execution policy and `powehi-<env>-svc-*`), `CreateRole` requires the boundary,
  and `UpdateAssumeRolePolicy` is denied everywhere (trust is fixed at creation).
- **Residual: external trust on new roles.** IAM has no condition key for the content of a
  trust policy, so a deploy job can still `CreateRole` (svc prefix, boundary attached) that
  trusts a foreign account. Impact is capped by the boundary (own log streams, own
  `powehi/<env>/*` secret values, own-namespace metrics) but secret reads are included. Mitigate
  with the Environment gates above and by reviewing svc role trust in every plan. (CODEOWNERS
  gates merges only and does not limit what a PR-branch workflow can do.) IAM paths are
  denied (`role/*/*`, `policy/*/*`).
- **Residual: unscopable APIs.** `Describe*/List*` need `Resource: *` (read-only, region
  locked, in `powehi-deploy-discovery`). `ecs:RegisterTaskDefinition` cannot be constrained by
  family name (gated on the request tag; a registered definition can only run through
  `CreateService`/`UpdateService`, which require `ecs:task-definition` to match
  `task-definition/powehi-<env>-*:*`, and `iam:PassRole` admits only svc roles). Recommended
  residual fix: put prod in its own AWS account so staging credentials cannot reach it at all.
  EC2 child creates (SG, subnet, route table, endpoint, NAT, ...) require the PARENT to carry
  the env tag, plus a guardrail Deny on `ec2:Create*` against other-env-tagged parents. Some EC2 actions with several
  resource types only check the tag of the resource named in the condition. Cross-env Modify/
  Delete is blocked twice: by the allow (tag must equal own env) and by an explicit Deny when a
  resource carries another env's `Environment` tag. Untagged resources are only reachable by
  name-prefix scoped services; tag everything (provider `default_tags` already does).
- **Optional hardening: CloudTrail S3 data events** on the state bucket (and KMS decrypt
  events, which are on by default) would record every state read/write, including the plan
  role's. Not built; consider enabling a data-event trail before prod holds real secrets.

- PR plans must use `tofu plan -lock=false` (the plan role is deliberately unable to write
  the `.tflock` object).
- The PR plan role (`sub = ...:pull_request`) is obtainable by ANY same-repo branch PR,
  including one that rewrites the workflow. CODEOWNERS and branch protection gate merging, not
  running, so they are NOT a mitigation for what this role can read. It is therefore limited
  to `staging/*` state; prod state is readable only by the prod deploy role, so prod plans
  run only in the Environment-gated (`production`, `main`-only) job. Never run a prod plan in
  the PR job. Staging state still holds staging secrets: keep "Require approval for outside
  collaborators" on. Fork PRs get no OIDC token.
- Deploy policies are region-locked and scoped by name prefix and env tag (see above); 9.3-9.5 may need to extend the action lists when new resource types are added.
- Renaming or deleting the GitHub repository frees `yusa-imit/powehi` for re-registration;
  `github_repository_id` (set in step 1) closes that gap through the `repository_id` claim.

## Constraints for later phases (security-auditor, 9.2)

- 9.5/9.7: reference the task definition by the full revision ARN from this env's own state,
  never by family name alone. `ecs:RegisterTaskDefinition` cannot be scoped to a family, so a
  stray revision in another env's family must never be picked up as "latest".
- 9.7: PR plan logs of this public repo are world-readable. Mark sensitive values, and keep
  `pull_request_target` / `workflow_run` workflows out of the repo (the plan role's fork
  isolation relies on it).
- Deploy trust requires `ref = refs/heads/main` in addition to the Environment `sub`.
- Not covered yet (follow-ups): CloudTrail / IAM Access Analyzer, a bucket policy limiting
  `prod/*` to the prod role, `kms:ViaService` on the deploy roles' state key access.
