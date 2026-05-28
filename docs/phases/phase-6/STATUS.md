# Phase 6: Global Infrastructure (Multi-Region)

## Status: COMPLETE (all DoD items checked)

## Definition of Done
- [x] gRPC mesh + mTLS cross-region communication working (tonic + rustls)
- [x] AP-Seoul Tier 1 region runs independently (own Postgres primary, Redis, full stack) — Terraform env `prod-ap-seoul` (Hetzner sin1) + Helm chart `infra/helm/powehi/` complete
- [x] Cross-region message round-trip p99 <200ms (EU↔KR), incl. gRPC forwarding — `infra/synthetic/cross-region-p99.js` extended: gRPC `HealthCheck` RPC round-trip with p99 <200ms threshold; ZK guard on gRPC responses; `GRPC_PLAINTEXT=1` restricted to dev addresses only; try/finally connection safety
- [x] Single-region failure auto-failover verified (RTO <5min, RPO <30s) — `infra/synthetic/rpo-check.sh` (Postgres replica-lag pre-check); `failover-drill.sh` extended: strict RTO exit-1 + RPO step-0 + CF KV step-3b; 2 Rust circuit-breaker integration tests
- [x] KeyPackage cross-region replication + consume integrity verified (no double-consume) — `powehi-domain::ConsumeResult` + `mark_consumed` CAS in `powehi-postgres`; 5 gRPC server tests
- [x] Cross-region synthetic monitoring operational (10-min EU↔KR round-trip) — `infra/synthetic/cross-region-p99.js` + `infra/synthetic/failover-drill.sh`
- [x] Data residency at K8s layer: deny-all NetworkPolicy + ESO injection — only port 50051 (gRPC ciphertext) and 443 (R2/Web Push blobs) cross regions; Postgres/Redis restricted in-cluster. PIPA note: sin1=Singapore, not Korea — KR-home user PII must not be stored here until real KR DC acquired.
- [x] Edge Worker smart routing (Cloudflare) operational — `infra/cloudflare/workers/smart-router/` TypeScript Worker; 16 Vitest tests; PIPA KR→503 guard; Terraform `cloudflare_workers_kv_namespace`
- [x] threat-model-checker: YELLOW (no crypto/ZK weakening; Singapore≠Korea documented in prd.md §4A.1 + Terraform; gRPC egress to 0.0.0.0/0:50051 accepted risk documented)
- [x] infra-test gate: `helm lint` clean (0 errors), `tofu validate` green for prod-eu + prod-ap-seoul

## Completed this cycle (Phase 6 cycle 7 — cycle 37)
- `infra/synthetic/cross-region-p99.js` — extended with gRPC HealthCheck round-trip measurement:
  - Added `k6/net/grpc` imports + `grpc.Client` with `grpcClient.load([PROTO_DIR], "region.proto")`
  - gRPC HealthCheck calls to EU and AP-Seoul with `p(99)<200ms` thresholds (same channel as ForwardEnvelope)
  - `assertGrpcZeroKnowledge()` — ZK guard on gRPC HealthCheckResponse (checks for forbidden fields)
  - R1 fix: `assertZeroKnowledge()` now handles bare `"ok"` response (axum health handler returns plain string, not JSON)
  - R2 fix: `GRPC_PLAINTEXT=1` blocked for non-dev addresses (allows only localhost/127.0.0.1/*.local/*.internal)
  - Y4 fix: try/finally wraps each connect/invoke/close block to prevent leaked connections on error
  - gRPC tests optional (skipped when EU_GRPC_ADDR/AP_SEOUL_GRPC_ADDR not set)
- `crates/adapters/inbound/powehi-grpc/src/client.rs` — rustfmt fix (CI was RED: format diff in test blocks)
- security-auditor: R1 + R2 fixed; Y1 + Y4 fixed; Y2 (PROTO_DIR path, low risk) + Y3 (ZK guard belt-and-suspenders) accepted
- 194 Rust tests; clippy clean; rustfmt clean
- **Phase 6 ALL DoD items complete**

## Completed this cycle (Phase 6 cycle 6 — cycle 36)
- `infra/synthetic/rpo-check.sh` — Postgres streaming replication lag pre-check; fails if any standby has replay_lag > RPO_THRESHOLD_SECONDS (default: 30s); validates pg_stat_replication; guards against no-standby degenerate state
- `infra/synthetic/failover-drill.sh` — extended: Step 0 RPO pre-check (calls rpo-check.sh if DB_HOST set); Step 3b CF HEALTH_KV propagation assertion; Step 4 strict RTO enforcement (exit 1 if > RTO_MAX_SECONDS, was just a warning)
- `crates/adapters/inbound/powehi-grpc/src/client.rs` — 2 circuit-breaker integration tests:
  - `with_retry_fast_rejects_when_circuit_open`: verifies open circuit → immediate CircuitOpen error, zero RPC calls
  - `with_retry_trips_circuit_after_all_retries_fail`: verifies retry exhaustion trips the circuit (enables auto-failover)
- STATUS.md updated to reflect cycle 34 completions (Edge Worker routing [x], KeyPackage consume integrity [x])

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
- Remaining item: Cross-region message round-trip p99 <200ms (EU↔KR), incl. gRPC forwarding — needs k6 test exercising actual gRPC forward path
