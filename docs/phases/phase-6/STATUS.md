# Phase 6: Global Infrastructure (Multi-Region)

## Status: Pending

## Definition of Done
- [ ] gRPC mesh + mTLS cross-region communication working (tonic + rustls)
- [ ] AP-Seoul Tier 1 region runs independently (own Postgres primary, Redis, full stack)
- [ ] Cross-region message round-trip p99 <200ms (EU↔KR), incl. gRPC forwarding
- [ ] Single-region failure auto-failover verified (RTO <5min, RPO <30s)
- [ ] KeyPackage cross-region replication + consume integrity verified (no double-consume)
- [ ] Cross-region synthetic monitoring operational (10-min EU↔KR round-trip)
- [ ] Data residency verified: no PII leaves home_region (only ciphertext envelopes + public KeyPackages cross regions)
- [ ] Edge Worker smart routing (Cloudflare) operational
- [ ] threat-model-checker pass on T7 (regional jurisdiction attacker) + §3.5 multi-region threats
- [ ] infra-test gate green for all multi-region Terraform/Helm (skill: infra-test)

## Notes
- See prd.md §4A (multi-region architecture), §15.4 Phase 6 for full requirements
- Requires infra-lead + terraform-author + k8s-manifest-author + ci-pipeline-author
- Cross-region integration tests must cover the split-brain / replication-timing scenarios in prd.md §3.5
- This phase is split out from Phase 5 (Hardening) per prd.md §15.4 — the STATUS set previously stopped at phase-5
