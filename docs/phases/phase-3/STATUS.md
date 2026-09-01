# Phase 3: Backend Services & API

## Status: COMPLETE (cycle 21)

## Definition of Done
- [x] MLS Delivery Service (envelope routing, fan-out) — REST API axum adapter: AppState, messaging routes, `AuthenticatedDevice` extractor, `ApiError`, 512KB body limit — cycle 12, commit a31ff1a
- [x] KeyPackage Service (upload, fetch, last-resort) — key-package routes (part of cycle 12's axum adapter, extended cycle 34 for cross-region replication)
- [x] Auth Service (OPAQUE endpoints) — real opaque-ke server-side register/login in `powehi-opaque` — cycle 18, commit 7c2a429
- [x] WebSocket hub for real-time delivery — envelope delivery notifications — cycle 16, commit 9c9d886
- [x] Media Service (encrypted blob upload/download via R2) — `powehi-r2` adapter — cycle 21, commit 2527650
- [x] Rate limiting on all public endpoints — tower_governor + governor, `TrustedProxyKeyExtractor` — cycle 19, commit 0a738e6
- [x] security-auditor pass on all backend code — PASS at cycle 12 (REST API adapter) and GREEN at cycle 14 (composition root); re-audited on every subsequent backend change per `CLAUDE.md`'s review-gate rule

## Notes
- See prd.md Phase 3 section for full requirements
- Requires backend-lead + rust-crate-builder + api-designer + db-schema-author
- Composition root wiring (Postgres + Redis outbound adapters into
  `bin/powehi-server`, DI for `AppState`) landed cycle 14, commit c46eec3
- This file was left at "Pending"/all-unchecked long after the phase actually
  completed. Backfilled at cycle 409 from `.claude/memory/project-context.md`'s
  Phase checklist; no functional change.
