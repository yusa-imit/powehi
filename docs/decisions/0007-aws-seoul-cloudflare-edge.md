# ADR-0007: AWS Seoul (ECS Fargate) + Cloudflare Edge Replace Hetzner k3s

## Status: Accepted (owner decisions, 2026-10-20). Supersedes ADR-0002.

Implementation: Phase 9 (`docs/phases/phase-9/STATUS.md`), which starts after Phase 8.

## Context

- The IaC under `infra/` was never applied, and no environment runs today. It covers:
  - an OpenTofu Hetzner k3s module with `dev`/`prod-eu`/`prod-ap-seoul` envs;
  - a Helm chart, ArgoCD apps and Kubernetes OPA policies;
  - a Cloudflare smart-router Worker for multi-region routing;
  - multi-region synthetic drills;
  - an ArgoCD-based CD workflow.
- Issue #5: the "Seoul" environment is Hetzner Singapore. PIPA needs the data of users
  whose home region is Korea to stay in Korea.
- Operator: one person. Budget set by the owner: about $150/month in total, for a
  minimal production plus an always-on staging of the same shape.
- What the server needs:
  - one binary, `powehi-server` (REST/WS on 8080, an admin port, gRPC on 9090 for the
    region mesh);
  - PostgreSQL 16, Redis 7, S3-compatible object storage (the shipped R2 adapter);
  - outbound Web Push.

## Decision

1. **Discard the current IaC**: the Hetzner module and envs, the Helm chart, ArgoCD,
   the Kubernetes OPA policies, the smart-router Worker, the multi-region synthetic
   drills, and `cd.yml`. Keep the `Dockerfile`, `release.yml` and the k6 scripts.
2. **Compute and data on AWS `ap-northeast-2` (Seoul).**
   - Compute: ECS Fargate (ARM64).
   - Data: RDS PostgreSQL 16 (`db.t4g.micro`, single-AZ) and ElastiCache
     (Valkey or Redis OSS 7, `cache.t4g.micro`).
   - Secrets Manager for secrets; CloudWatch for logs and alarms.
   - No NAT gateway: tasks run in public subnets with **no inbound security-group
     rules**, and the data stores sit in private subnets.
3. **Edge on Cloudflare.**
   - DNS, TLS (minimum 1.3), WAF and rate limiting.
   - R2 for encrypted media.
   - **Cloudflare Tunnel** (a `cloudflared` sidecar in the task) is the only way into the
     origin: no load balancer and no public origin. If the tunnel turns out to limit
     WebSocket behaviour or throughput, fall back to an ALB that admits only
     Cloudflare, and record that change here.
4. **Single region first.** The multi-region design in prd §4A stays the long-term
   target, but Phase 9 does not build it. Modules take the region as an input, so a
   second region later is a new env, not a rewrite.
5. **Two always-on environments of the same shape: `staging` and `prod`.**
   - IaC: OpenTofu, with state in S3 using native locking.
   - CI credentials: GitHub OIDC roles, so there are no long-lived AWS keys.
   - Every PR gets a plan. A merge applies staging automatically. Prod applies only
     after the owner approves the `production` GitHub Environment.
6. **CLI distribution: GitHub Release binaries only.**
   - Targets: macOS arm64/x86_64 and Linux x86_64/arm64.
   - Each release carries SHA-256 checksums, cosign keyless signatures and SLSA
     provenance.
   - No Homebrew tap and no Apple notarization. macOS users clear the quarantine
     attribute themselves; the install guide says how.
7. **Out of scope for Phase 9**: deploying the web SPA (#1), a load test on real
   infrastructure (#4), and a second region.

## Rationale

- A Seoul region inside Korea removes the PIPA blocker in #5.
- Fargate removes cluster operations: no k3s upgrades and no control plane to run. An
  EKS control plane alone (~$73/month per cluster) does not fit the budget.
- The tunnel saves a load balancer (~$20/month per env). It also keeps the origin
  unreachable except through Cloudflare.
- R2 keeps media egress free and reuses the adapter that already ships.

## Consequences

- **Tooling removed**: the Helm/ArgoCD/Kubernetes-policy tooling, the
  `helm-conventions` rule, and the Kubernetes-specific agents and commands are
  removed or rewritten (9.1).
- **Downtime on failure**: with single-AZ RDS and one task per env, a failure means
  downtime until ECS or RDS recovers. This is accepted at this budget. Recovery
  rests on automated backups and point-in-time restore; 9.11 measures and documents
  RPO and RTO.
- **Pinning is constrained**: Cloudflare Universal SSL keys are managed by Cloudflare
  and rotate, so leaf-key pinning is unlikely to work (8.7). The production pin set
  is decided in 9.9.
- **Public IPs on tasks**: Web Push, R2 and the tunnel need outbound internet, so each
  task gets a public IPv4 address (about $4/month).
- **Cost** (rough on-demand estimate, Seoul, per env):

  | Item | Monthly |
  |---|---|
  | Fargate | ~$20 |
  | RDS | ~$21 |
  | ElastiCache | ~$17 |
  | Public IPv4 | ~$4 |
  | Logs and secrets | ~$5 |
  | **Per env** | **~$65-70** |

  Two envs come to about $140. The bootstrap module creates an AWS Budgets alarm
  at $150/month.

## Addendum: metrics and alarms (9.10)

- **Metrics source**: AWS-native metrics only: ECS Container Insights (`RunningTaskCount`), RDS and
  ElastiCache CloudWatch metrics, plus ECS task state-change events. They are infrastructure
  aggregates with no message content, no PII and no per-user labels (prd section 13). Container
  Insights is enabled on the cluster for this; the cost is a few dollars per month.
- **Notification path**: CloudWatch alarms (ALARM and OK) and an EventBridge rule for unexpected task
  stops publish to one SNS topic per env (customer-managed KMS key) with an owner e-mail subscription.
  Cloudflare `/health` checks and their e-mail notification are available in the edge module behind
  `enable_healthcheck` (paid zone plan required).
- **Server admin port**: stays unexposed. No scraping, no Amazon Managed Prometheus, no Grafana now:
  they add cost and a new egress/ingress path for a one-task service.
- **Deferred**: application-level metrics (request rates, queue depth) wait until there is traffic
  that justifies them. When added, they must keep the same rule (no content, no PII, no per-user
  labels) and go to CloudWatch under the `Powehi/<env>` namespace the deploy roles already allow.
