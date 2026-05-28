# Phase 6: Global Infrastructure (Multi-Region)

## Status: In Progress

## Definition of Done
- [x] gRPC mesh + mTLS cross-region communication working (tonic + rustls)
- [x] AP-Seoul Tier 1 region runs independently (own Postgres primary, Redis, full stack) — Terraform env `prod-ap-seoul` (Hetzner sin1) + Helm chart `infra/helm/powehi/` complete
- [ ] Cross-region message round-trip p99 <200ms (EU↔KR), incl. gRPC forwarding
- [ ] Single-region failure auto-failover verified (RTO <5min, RPO <30s)
- [ ] KeyPackage cross-region replication + consume integrity verified (no double-consume)
- [x] Cross-region synthetic monitoring operational (10-min EU↔KR round-trip) — `infra/synthetic/cross-region-p99.js` + `infra/synthetic/failover-drill.sh`
- [x] Data residency at K8s layer: deny-all NetworkPolicy + ESO injection — only port 50051 (gRPC ciphertext) and 443 (R2/Web Push blobs) cross regions; Postgres/Redis restricted in-cluster. PIPA note: sin1=Singapore, not Korea — KR-home user PII must not be stored here until real KR DC acquired.
- [ ] Edge Worker smart routing (Cloudflare) operational
- [x] threat-model-checker: YELLOW (no crypto/ZK weakening; Singapore≠Korea documented in prd.md §4A.1 + Terraform; gRPC egress to 0.0.0.0/0:50051 accepted risk documented)
- [x] infra-test gate: `helm lint` clean (0 errors), `tofu validate` green for prod-eu + prod-ap-seoul

## Completed this cycle (Phase 6 cycle 2)
- `infra/terraform/envs/prod-ap-seoul/` — mirrors prod-eu at Hetzner Singapore (sin1), cx41 HA cluster
- `infra/helm/powehi/` — full Helm chart: Deployment, Service, ConfigMap, HPA, NetworkPolicy (deny-all), ExternalSecret (ESO), ServiceAccount
- `infra/synthetic/cross-region-p99.js` — k6 constant-arrival-rate monitor, p99 <200ms threshold, ZK guard
- `infra/synthetic/failover-drill.sh` — idempotent failover drill with RTO measurement

## Notes
- See prd.md §4A (multi-region architecture), §15.4 Phase 6 for full requirements
- Requires infra-lead + terraform-author + k8s-manifest-author + ci-pipeline-author
- Cross-region integration tests must cover the split-brain / replication-timing scenarios in prd.md §3.5
- This phase is split out from Phase 5 (Hardening) per prd.md §15.4 — the STATUS set previously stopped at phase-5
- AP-Seoul proxy: prd.md §4A says Oracle Cloud / Vultr; all infra is on Hetzner so sin1 (Singapore) is used as the nearest available DC
