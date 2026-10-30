# Phase 9: Real Deployment — AWS Seoul + Cloudflare Edge

## Status: PLANNED (owner decisions 2026-10-20, ADR-0007) — starts after Phase 8

**Priority rule**: this file becomes the FEATURE-mode work queue once every Phase 8 box
is checked. Take the first unchecked item, in order. If an item needs the owner
prerequisites (issue #118) and they are not done yet, skip to the next item that does
not need them (9.6 needs none), and say so in the summary. Never apply to `prod` from
a session: prod changes go through the `production` GitHub Environment approval.

## Owner decisions (2026-10-20)

| Topic | Decision |
|---|---|
| Existing IaC | Discard it (Hetzner k3s, Helm, ArgoCD, k8s OPA policies, smart-router Worker, multi-region drills, `cd.yml`) |
| Platform | AWS for compute and data, Cloudflare for DNS/TLS/WAF/R2 |
| Compute | ECS Fargate (ARM64); ingress through Cloudflare Tunnel (ADR-0007 §3) |
| Region | Seoul `ap-northeast-2` only; a second region is out of scope |
| Budget | Minimal shape per env; staging always on; about $150/month total |
| Applies | Staging applies automatically on merge; prod only after owner approval |
| Extra scope | CLI release binaries on GitHub Releases (no Homebrew tap, no notarization) |
| Out of scope | Web SPA deploy (#1), real-infra load test (#4), EU region |

## Prerequisites (owner, issue #118 — not an AI work item)
Domain bought and added to Cloudflare; AWS account; Cloudflare account with R2; after
9.2, a one-time bootstrap apply and the GitHub Environments with their secrets. The
domain is a variable everywhere (`var.domain`); never hard-code `powehi.app`.

## Definition of Done (in order)

### Clean slate
- [x] 9.1 Discard the current IaC — delete `infra/terraform/` (Hetzner module, envs
  `dev`/`prod-eu`/`prod-ap-seoul`/`cloudflare`), `infra/helm/`, `infra/argocd/`,
  `infra/policy/`, `infra/cloudflare/workers/smart-router/`, `infra/synthetic/` and
  `.github/workflows/cd.yml`. Strip the Helm/kubeconform/conftest/ArgoCD steps from
  `ci-infra.yml` (keep it as the home of the new OpenTofu checks). Remove or rewrite
  what only made sense for Kubernetes: `.claude/rules/helm-conventions.md`,
  `.claude/agents/k8s-manifest-author.md`, `.claude/commands/deploy-canary.md`, and the
  Helm/k8s parts of `.claude/skills/infra-test/SKILL.md`,
  `.claude/agents/ci-pipeline-author.md`, `.claude/rules/testing-conventions.md` and
  `CLAUDE.md` (Build & Test, Architecture). Keep `Dockerfile`, `release.yml`,
  `infra/k6/` (parked #4) and `load-test.yml`. Rewrite prd §4A.1, §12.1–§12.4,
  §12.8 and §12.9 to the ADR-0007 topology (single region, Tier 1 only; multi-region as
  future design without Hetzner/Oracle). The 8.1 edge TLS setting is deleted here and
  re-created in 9.4.

### Foundations (built and tested without cloud credentials)
- [ ] 9.2 OpenTofu layout, bootstrap and CI checks — new `infra/terraform/` with
  `bootstrap/`, `modules/` and `envs/{staging,prod}`; OpenTofu version pinned in
  `.terraform-version`; S3 backend with native locking (`use_lockfile`). `bootstrap/`
  (run once by the owner) creates the versioned, encrypted, public-access-blocked state
  bucket, the GitHub OIDC provider, per-env deploy roles trusted only for
  `repo:yusa-imit/powehi:environment:<env>` plus a read-only plan role for PRs, and an
  AWS Budgets alarm at $150/month (80 % and 100 % alerts to the owner). A README lists
  the exact owner steps and the GitHub Environment secrets for #118. CI (`ci-infra.yml`):
  `tofu fmt -check`, `tofu validate`, `tflint`, `trivy config`, and `tofu test` with
  mocked providers. security-auditor.
- [ ] 9.3 Network and data modules — VPC over two AZs; public subnets for tasks with no
  NAT gateway; private subnets for data. RDS PostgreSQL 16 `db.t4g.micro` single-AZ,
  gp3 20 GB, encrypted, `rds.force_ssl = 1`, RDS-managed master password in Secrets
  Manager, automated backups 7 days with PITR, deletion protection + final snapshot on
  prod. ElastiCache (Valkey or Redis OSS 7) `cache.t4g.micro` with in-transit TLS and an
  AUTH token. Security groups: data stores accept only the service SG. `tofu test`
  asserts encryption, TLS, no public access, and backup settings. security-auditor.
- [ ] 9.4 Edge module (Cloudflare) — DNS records under `var.domain` (`api.` and
  `api-staging.`), TLS settings (minimum 1.3, TLS 1.3 on: re-creates 8.1), WAF managed
  rules and rate limiting on the auth endpoints within the plan's limits, the R2 media
  bucket (APAC location hint) with a bucket-scoped R2 token, and a Cloudflare Tunnel
  per env routing its hostname to the task. The server's `R2_*` settings point at it.
  security-auditor.
- [ ] 9.5 Service module (ECS Fargate) — cluster, ARM64 task with the `powehi-server`
  image pinned by digest from GHCR and a `cloudflared` sidecar; task SG with **no
  inbound rules**; public IP for outbound only. Secrets (database URL, Redis auth, R2
  keys, VAPID key, handle-oracle token, tunnel token) are created out of band and passed
  to the task by Secrets Manager ARN — no secret values in tfvars or state. Execution
  and task roles with least privilege. CloudWatch log group, 14-day retention, no
  message content or PII in logs (rule no-plaintext-logging). Health check on
  `/health`; deployment circuit breaker with rollback. Migrations run once per deploy
  (the server's startup `run_migrations` today; make sure two tasks starting together
  cannot race it). security-auditor.

### CLI distribution (needs no cloud credentials)
- [x] 9.6 CLI release binaries — a release workflow on tags `cli-v*` builds `powehi`
  for macOS arm64/x86_64 and Linux x86_64/arm64 (static Linux builds), reproducibly
  (`SOURCE_DATE_EPOCH`, as `release.yml` does for the server); publishes a GitHub
  Release with SHA-256 checksums, cosign keyless signatures and SLSA provenance.
  `docs/cli.md` gains an install section: download, verify checksum and signature, and
  on macOS clear the quarantine attribute (`xattr -d com.apple.quarantine powehi`).
  The default server stays as is until 9.9.
  Shipped cycle 699: `.github/workflows/cli-release.yml` (4-target matrix, SHA256SUMS, cosign
  bundles, SLSA generic provenance) + `docs/cli.md` Install. Not exercisable before a `cli-v*` tag
  is pushed: the first tag is the real test (the musl build on the arm runner is unproven). Known gaps from security-auditor: release is published before provenance is attached (non-atomic); builds are not bit-reproducible across machines.

### Environments and delivery (need issue #118)
- [ ] 9.7 Staging environment and infra workflow — `envs/staging` composes the modules.
  `infra-apply.yml`: on PRs touching `infra/`, `tofu plan` for staging and prod with the
  read-only role, posted as a PR comment; on merge, apply staging (Environment
  `staging`), then a smoke test: two CLI profiles register, invite, and exchange messages
  both ways against `https://api-staging.<domain>` (reuse `src/live_e2e.rs` with the
  server URL from the environment).
- [ ] 9.8 Server CD — after `release.yml` builds and signs an image, a deploy workflow
  updates the staging ECS service to the new digest, runs the smoke test, then waits for
  `production` approval to update prod and run the smoke test there. Rollback =
  redeploy the previous digest; document it.
- [ ] 9.9 Production environment — `envs/prod` (deletion protection, final snapshot,
  PITR), applied only through the `production` approval. After the first apply: smoke
  test against `https://api.<domain>`; set the production certificate pin set using the
  8.7 mechanism (or the outcome of its need-human issue); set the CLI `DEFAULT_SERVER`
  to the prod URL and cut a CLI release (9.6). Update prd §12A data residency
  (KR-home data in Seoul) and close #5. Pin strategy: issue #131; when the set becomes
  non-empty, change the `pinning` test that allows an empty `PRODUCTION_PINS` to require
  at least two pins.

### Operations
- [ ] 9.10 Monitoring and alarms — CloudWatch alarms to the owner by SNS email: running
  task count below 1, task restarts, RDS CPU/free storage/connections, cache memory;
  Cloudflare health check on `/health` with notifications. Server metrics from the admin
  port by the cheapest path that fits prd §13 (zero-knowledge observability: no content,
  no PII, no per-user labels); record the choice in ADR-0007.
- [ ] 9.11 Backup and restore drill + runbook — restore the latest prod snapshot (or a
  PITR point) into a temporary instance attached to staging, run the smoke test, record
  measured RPO/RTO in prd §12.7. Write `docs/guides/operations.md`: deploy, rollback,
  restore, secret rotation, tunnel token rotation, pin rotation, cost check.

### Gate
- [ ] 9.12 Security gate — threat-model-checker on the deployed architecture (new trust
  boundaries: AWS account and roles, CI OIDC, Cloudflare Tunnel, Secrets Manager, R2
  token); security-auditor on all of `infra/`; prd §3 updated with the accepted risks.
