# Powehi — Project Context (autonomous dev anchor)

> Source of truth for the `powehi-dev-v1` cron loop: current state + phase checklist.
> Full architecture: `docs/prd.md`. Agent system: `docs/orchestration.md`.

## What this is
E2EE zero-knowledge web messenger. The server NEVER sees plaintext. Rust hexagonal
backend + React 19 / WASM frontend + 3-tier multi-region infra. Protocols: MLS
(RFC 9420), OPAQUE (RFC 9807), Web Push (RFC 8291).

## Non-negotiables (NEVER violate — these gate every commit)
- Server NEVER sees plaintext message content.
- No homegrown crypto. Only `openmls`, `opaque-ke`, RustCrypto (rule: crypto-libraries-pinned).
- Crypto code MUST pass the `crypto-reviewer` agent before commit.
- Architectural / new-metadata changes MUST pass `threat-model-checker`.
- Backend handlers MUST pass `security-auditor`.
- No plaintext logging of content / PII / ciphertext (rule: no-plaintext-logging).
- Every layer has a test gate (rule: testing-conventions).

## Current state (2026-09-03, cycle 425 — STABILIZATION: fix red CI on main (orphan-sweep test bug) + archive sweep, commit d02c816)

- Mode selection: counter 424→425, 425 % 5 == 0 → STABILIZATION.
- **CI check first (STABILIZATION step 1) found main red**, not green as
  usual: `gh run list --limit 5` showed the cycle-424 commit's `CI — Rust`
  run (`33717662456`) as `failure`. Per CLAUDE.md's explicit rule ("if red
  on main, fix the root cause, push, verify green before anything else"),
  fixed this before any other stabilization work.
- **Root cause (`gh run view --log-failed`):** the "Integration Tests
  (Docker)" job — real Postgres+MinIO via testcontainers, which cycle 424
  could not run locally (no Docker in this sandbox), so its two new tests
  had only ever been compile-checked, never executed for real — failed 2 of
  34 `powehi-r2::r2_media_it` tests:
  `sweep_orphaned_storage_objects_pre_sample_cap_bounds_damage_below_min_sample`
  (`assert_eq!` left=16 right=15) and
  `sweep_orphaned_storage_objects_ratio_guard_aborts_on_suspiciously_high_orphan_rate`
  (survivor-list mismatch, 11 keys vs. expected 1).
- **Diagnosed as a test-helper bug, not a production bug:** both new tests
  generate S3 keys with an unpadded decimal loop index
  (`ratio-orphan-{i}`/`pre-sample-orphan-{i}` for `i in 0..N`), then assert
  on `list_keys(&h.s3, key)` — a shared helper
  (`r2_media_it.rs:250`) that does a **prefix** `list_objects_v2`, not an
  exact-key lookup (its own doc comment says "List object keys under
  `prefix`"). `"ratio-orphan-1"` is a string-prefix of `"ratio-orphan-10"`
  through `"-19"`, so the per-key survival assertion picked up 11 sibling
  keys instead of 1 — exactly matching the CI failure's printed arrays.
  Confirmed by reading the helper (not guessed): every other call site in
  the file passes either a UUID-based `blob.storage_key` or a small set of
  non-numeric-suffix keys (`cap-orphan-a`/`-b`), so only these two new,
  cycle-424-added tests hit the collision. `sweep_orphaned_storage_objects`
  itself (`powehi-r2/src/lib.rs:606-740`) — the actual production sweep
  logic, ratio guard, and pre-sample cap fixed last cycle — was read in full
  and is unaffected; nothing about the security-relevant logic reviewed
  RED→GREEN last cycle needed to change.
- **Fix:** zero-padded both loops' index format specifier to `{i:02}` (60
  and 20 items respectively, both `< 100`, so 2 digits is sufficient for no
  key to ever be a proper string-prefix of a sibling key). Test-only change,
  `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs`, 1 file.
- Not crypto (no `.rs` crypto/MLS/OPAQUE/WASM file touched), not
  architectural (test-only, zero production code changed — confirmed via
  `git diff --stat`), not a backend handler/infra change — `crypto-reviewer`
  /`threat-model-checker`/`security-auditor` correctly not invoked, same
  precedent as cycles 399/400/404/406/414's test-only diffs.
- Verified before commit: `cargo test -p powehi-r2 --test r2_media_it
  --no-run` compiles clean (still no Docker in this sandbox to run the
  `#[ignore]`d tests locally); `cargo build --workspace` clean; `cargo
  clippy -p powehi-r2 --all-targets -- -D warnings` clean; `cargo fmt --all
  --check` clean; `cargo test --workspace` (non-ignored) 0 failures.
  **Verified the actual fix against real CI**, not just local compilation:
  pushed (`d02c816`), watched `gh run watch 33729955446 --exit-status` to
  completion — `CI — Rust` (Format/Clippy/Test/Integration Tests all green,
  including the previously-failing r2 testcontainers job) and `CI —
  Live-backend E2E` both green.
- **Archive sweep (this cycle's other STABILIZATION item):** this file had
  been flagged as overdue for archival since cycle 420 (exceeds the Read
  tool's pagination cap on the first read attempt — confirmed again this
  cycle, 45148 tokens for the first 742/1576 lines against a 25000 cap).
  Moved cycles 402-421 (everything before this file's own cycle-424 section)
  to `.claude/memory/archive/project-context-cycles-402-421.md` — mirrors
  the cycle-390/cycle-420-precedent pattern (this repo's 5th such archive
  round: 20-277, 279-319, 320-339, 340-371, 372-401, now 402-421). Live file
  now holds only: header/non-negotiables, this cycle-425 entry, and
  cycle-424 (kept as immediate prior-cycle context, most likely to be
  referenced next cycle) as "Previous state".
- No feature/phase-checklist work this cycle (STABILIZATION, no new
  features) — phase-1..6 checklist state unchanged from cycle 424.
- Target dir hygiene (STABILIZATION, due this cycle):
  `du -sh target/` = 19G, under the 20G prune threshold — pruned only 0-byte
  `.rmeta` stubs (routine step, none found this time), no further action.
- Security sweep (STABILIZATION, due this cycle): `cargo deny check` clean
  (advisories/bans/licenses/sources all ok); `gh issue list --state open`
  empty. No crypto/architecture/handler diff this cycle to route through
  `crypto-reviewer`/`threat-model-checker`/`security-auditor`.
- **Process note:** this cycle reinforces cycle 424's own lesson from the
  opposite direction — a diff that compiles and passes every *locally
  runnable* check (unit tests, clippy, fmt) can still be red in real CI
  when the only broken tests require infrastructure (Docker) unavailable in
  this sandbox. Pushing without a way to run the Docker-gated integration
  suite locally is an accepted, unavoidable gap in this environment, not a
  process failure — but it means **always checking `gh run list` at the
  very start of the next cycle**, not assuming a clean local
  build+test+clippy+fmt pass means CI is green too.
- **Next cycle candidates:**
  1. Both review agents' owner-sentinel design idea from cycle 424 (write a
     deployment UUID to `media/{region_id}/.owner` at boot, verify before
     deleting) — a real scoping/design task, not carried as "just implement
     it."
  2. prd.md §3.3 cross-reference for the region_id-in-storage-key metadata
     (currently only in §9.4.3) — small, mechanical doc fix, good filler
     task if nothing else is queued.
  3. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) remains a human/crypto-lead policy call,
     not a blind retry.
  4. Carried: prd.md §6.4's cross-region abuse-signal propagation
     ("차단된 IP/사용자 → 전 리전 전파") documented-but-unimplemented —
     worth a threat-model-checker-gated scoping pass before committing to
     size.
  5. This file (1576 lines pre-archive) will grow again — next archive
     sweep due whenever it again hits the Read tool's pagination cap on
     first read (was line ~742 this cycle at the 25000-token cap).

## Previous state (2026-09-03, cycle 424 — FEATURE: R2 orphan-object sweep + close 2 RED review findings, commit 27647b0)

- Counter jumped 421→424 (cycles 422/423 have no commits in `git log`) —
  but this time, unlike prior "skipped commit" incidents, the missing
  cycles' real work was NOT lost: it was sitting uncommitted in the
  working tree at this cycle's start (R2 orphan-sweep feature, config
  validation, migration 0017, Helm changes), clearly a coherent,
  substantially-complete implementation of the orphan-object sweeper
  that cycles 419/420/421 had all flagged as a "next cycle candidate."
  Its own inline comments claimed a threat-model-checker RED finding and
  a security-auditor finding had already been found-and-fixed at "cycle
  422" — **treated that claim as unverified** (same discipline as cycle
  418's precedent for interrupted-session diffs) rather than trusting it.
- Read every file in the diff before touching anything, confirmed
  `cargo build/test/clippy/fmt` all clean on the as-found diff, then ran
  a **fresh** `security-auditor` + `threat-model-checker` pass (in
  parallel) rather than accepting the diff's self-reported review
  history. **Both came back RED**, proving the "already reviewed" claim
  in the diff's own comments was not reliable:
  - security-auditor RED: (F1, HIGH) Helm's
    `POWEHI__MEDIA_ORPHAN_SWEEP_ENABLED: {{ ... | default true | quote }}`
    kill switch was silently inert — Sprig's `default` treats boolean
    `false` as empty, so `mediaOrphanSweepEnabled: false` rendered as
    `"true"` (reproduced with `helm template`). (F2, MEDIUM) the
    cumulative orphan-ratio circuit breaker's 80% threshold missed a
    ~50/50 orphan rate (two environments sharing a bucket+region_id),
    and up to 49 objects could be deleted before the guard had enough
    samples (50) to evaluate at all. (F3, MEDIUM) `region_id` had zero
    format validation despite the whole region-prefix isolation
    guarantee depending on it never containing `/`. (F4, LOW) failed
    deletes didn't consume the blast-radius budget (counted successes,
    not attempts).
  - threat-model-checker RED: the region-prefix scoping
    (`media/{region_id}/{uuid}`) only isolates *distinct regions*
    sharing one bucket — it does nothing for **two environments sharing
    the same region_id AND bucket**, which is exactly this repo's actual
    `values-staging.yaml`/`values-prod-eu.yaml` (both `region:
    eu-frankfurt`, both leaving `r2Bucket` unset until real Cloudflare
    values are wired in — confirmed by reading both files). prd.md's own
    new paragraph overclaimed "구조적으로 막음" (structurally prevented)
    for a guarantee that doesn't cover this case, and separately claimed
    "새로운 영구 메타데이터 카테고리 없음" (no new metadata) when
    `region_id` embedded in the object key/presigned URL path *is* new
    metadata (low sensitivity, but a real T5/T7 delta) — a documentation
    drift is exactly the kind of thing this gate exists to catch.
- **Fixed all of it before committing** (not reverted, not shipped as-is
  — CLAUDE.md's "never weaken a security non-negotiable to make
  progress" bar):
  1. Helm: removed the broken `| default true`, now
     `{{ .Values.config.mediaOrphanSweepEnabled | quote }}` (values.yaml
     already supplies a real default). Verified with `helm template
     --set config.mediaOrphanSweepEnabled=false/true` against all 3 real
     overlays — renders correctly both ways.
  2. Ratio breaker: threshold 80%→50%
     (`ORPHAN_RATIO_ABORT_THRESHOLD_PERCENT`), plus a new
     `ORPHAN_PRE_SAMPLE_MAX_DELETES = 5` absolute cap applied via an
     `effective_cap` computed before the delete loop whenever
     `aged_checked_total < ORPHAN_RATIO_ABORT_MIN_SAMPLE` — bounds
     pre-evidence damage to 5 objects/run instead of up to 49. New
     integration test
     `sweep_orphaned_storage_objects_pre_sample_cap_bounds_damage_below_min_sample`.
  3. `region_id` charset validation added to `AppConfig::validate()`
     (non-empty, `[a-z0-9-]+` only) — checked first, unconditionally,
     before every other guard that uses it. New `ConfigError::RegionIdInvalid`.
  4. Budget now tracks *attempted* deletes (`attempted_deletes_total`),
     not just successes, so a run where every `DeleteObjects` call fails
     still respects the cap.
  5. **Closed the actual cross-environment gap** (not just documented
     it): `AppConfig::validate()` now also rejects `r2_bucket` left at
     its compiled dev default (`"powehi-media"`, now
     `DEV_R2_BUCKET_DEFAULT`) whenever `region_id != "local"` — new
     `ConfigError::R2DevDefaultBucketInNonLocalRegion`, mirroring the
     existing `r2_endpoint` guard right above it. This makes any real
     deployment that forgot to set `r2Bucket` fail to start rather than
     silently sharing storage with another environment. Added matching
     warning comments to `values-staging.yaml`/`values-prod-eu.yaml`/
     `values-prod-ap.yaml` (all three, since prod-ap could hit the same
     class of mistake even though it doesn't currently share a
     region_id) explaining the guard's real limits: it catches "forgot
     to set it," not "set two environments to the same real bucket by
     mistake" — that residual gap is accepted as operational discipline
     (both reviewers agreed after the guard was added: not blocking,
     comparable to existing unguarded shared-DATABASE_URL/Redis risk
     elsewhere in the repo).
  6. Fixed the `delete()`-ordering doc-comment inaccuracy (it deletes
     the S3 object first, then the Postgres row — an earlier version of
     the trait doc comment and prd.md both had this backwards) in both
     `media_repo.rs` and prd.md.
  7. Rewrote prd.md's whole orphan-sweep addendum to be accurate: states
     the real new-metadata delta (region_id in storage key) instead of
     denying one, scopes the region-prefix guarantee correctly
     (cross-region only, not cross-environment-same-region), and updates
     the safety-mechanism numbers (50%/50-sample ratio guard, new
     5-object pre-sample cap, actually-working kill switch).
  8. Proactively also fixed a security-auditor-flagged nit found only in
     the **second** (re-verification) pass: `load()`'s
     `.set_default("r2_bucket", "powehi-media")` used a hardcoded literal
     instead of the new `DEV_R2_BUCKET_DEFAULT` const (unlike the
     `r2_endpoint` default right above it, which already used its own
     const) — a silent-desync risk where changing the literal in one
     place wouldn't update the other. Fixed to use the const.
- **Re-ran both review agents fresh on the fixed diff** (not just
  trusted my own fix reasoning) — both returned **GREEN**. Each
  independently traced the fixed code paths (ratio-guard math,
  effective_cap ordering, region_id validation placement,
  `helm template` re-render) rather than re-reading the first pass's
  notes. Non-blocking follow-ups both flagged, **deferred, not fixed
  this cycle** (see next-cycle candidates): (a) the residual
  same-bucket-same-region_id-by-mistake gap noted above; (b) prd.md §3.3
  (the canonical metadata-exposure index) doesn't yet have a bullet for
  the new region_id-in-storage-key metadata, only §9.4.3 (the detailed
  addendum) does; (c) a structural fix idea from both reviewers
  independently (owner-sentinel object: write a deployment UUID to
  `media/{region_id}/.owner` at boot, have the sweep verify it before
  deleting anything) that would close the residual gap without relying
  on operational discipline — a real design task, not a quick fix.
- Verified before commit: `cargo build --workspace` clean, `cargo test
  --workspace` all green (0 failed across every crate, r2_media_it.rs's
  34 tests — including 2 new ones — compile and collect correctly but
  are `#[ignore]`d, no Docker in this sandbox; CI runs them for real),
  `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  fmt --all --check` clean, `helm lint` clean on the base chart + all 3
  overlays. Both fresh review passes independently also ran `cargo
  audit`/`cargo deny check`/`pnpm audit`/`conftest` as part of their own
  verification — all clean, nothing this cycle's diff introduced.
- Crypto (no `.rs`/WASM crypto/MLS/OPAQUE file touched) —
  `crypto-reviewer` correctly not invoked. Architectural + new
  server-visible metadata (new background job, bucket-wide LIST
  capability requirement, region_id embedded in storage keys) —
  `threat-model-checker` invoked, twice (RED then GREEN), correctly.
  Backend handlers + infra — `security-auditor` invoked, twice (RED
  then GREEN), correctly.
- **Process note reinforced this cycle:** an interrupted session's own
  inline comments claiming "reviewed, findings fixed" are not evidence
  a review actually happened rigorously — this cycle's fresh passes
  found real, reproducible RED findings (the Helm kill-switch bug was
  confirmed by literally running `helm template` and seeing `"true"`
  come out for a `false` input) despite the diff's own comments citing
  specific "cycle 422" finding numbers as already resolved. Always
  re-run the required review agents fresh on inherited/interrupted work
  before committing, never treat embedded review claims as sufficient.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:**
  1. project-context.md is now well past due for archival (flagged since
     cycle 420, still not done — file exceeds the Read tool's pagination
     cap on the first read attempt). Cycle 425 is a STABILIZATION cycle
     (425 % 5 == 0) — do the archive sweep then, same as cycle 390's
     precedent.
  2. Both review agents' owner-sentinel design idea (see above) — a real
     scoping/design task for a future cycle, not carried as "just
     implement it."
  3. prd.md §3.3 cross-reference for the region_id-in-storage-key
     metadata (currently only in §9.4.3) — small, mechanical doc fix,
     good filler task if nothing else is queued.
  4. Carried from cycle 419/420/421 and now finally addressed this
     cycle's main item — the orphan-object sweeper. No longer carried.
  5. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) remains a human/crypto-lead policy
     call, not a blind retry.
  6. Carried: prd.md §6.4's cross-region abuse-signal propagation
     ("차단된 IP/사용자 → 전 리전 전파") documented-but-unimplemented —
     worth a threat-model-checker-gated scoping pass before committing
     to size.

