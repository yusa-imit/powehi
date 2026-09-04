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

## Phase status
All 6 phases in `docs/phases/phase-{1..6}/STATUS.md` show every DoD item checked
(`[x]`) as of cycle 425/426 — confirmed by grepping each STATUS.md fresh, not from
memory. There is no phase-checklist "next item" left to pull from; FEATURE-mode work
now comes from each cycle's "Next cycle candidates" list below (review-agent-flagged
follow-ups, prd.md drift, scoping tasks) rather than an unchecked phase DoD box.

## Current state (2026-09-05, cycle 436 — FEATURE: R2 orphan-sweep observability (owner-mismatch + ratio-guard counters), commit c727c53)

- Mode selection: counter 435→436, 436 % 5 != 0 → FEATURE.
- **CI check found main red first**: `gh run list --limit 5` showed the
  cycle-435 memory-only commit's `CI — Rust` run (`33881237625`) as
  `completed`/`failure`. Investigated via `gh run view --log-failed`
  before assuming a code regression — the failure was in the
  "Integration Tests (Docker)" job at the `docker pull postgres:16-alpine`
  step: `Error response from daemon: ... read tcp ...: connection reset by
  peer` against `registry-1.docker.io`, i.e. a transient Docker Hub
  network blip in the runner, not caused by the pushed commit (which only
  touched `.claude/memory/project-context.md` and `deny.toml`, both
  already independently green on the prior push). `gh run rerun --failed`
  confirmed this: the rerun completed `success` with no code change.
  FEATURE-mode step 2 ("if red on main, switch to STABILIZATION") was
  judged satisfied by fixing/confirming the actual root cause (a rerun,
  not a code change) rather than mechanically flipping modes for an
  infra flake — proceeded with FEATURE mode.
- Picked next-cycle candidate #3 (carried since ≥ cycle 434, "still not
  scoped"): the residual gap where the *winner* of a legitimate
  (non-racing) owner-sentinel arbitration in the R2 orphan sweep
  (`verify_region_ownership`, prd.md §9.4.3, cycle 426) can keep deleting
  a colliding-but-still-live sibling environment's media forever, while
  the *loser* only gets a `tracing::error!` log line
  (`error_kind = "gc_orphan_owner_mismatch"`) — no metric, so the
  "permanent, loud" detection the doc comment promises was only actually
  loud if an operator had already built a log-based alert. Scoped this
  cycle's fix narrowly: the underlying architectural gap is explicitly
  accepted risk in prd.md §9.4.3 (full fix = distinct real buckets per
  environment, an operational-discipline requirement, not a code fix) —
  what was actually unscoped/missing was making the *existing* detection
  operationally actionable.
- **Fix** (`crates/adapters/outbound/powehi-r2/src/lib.rs` +
  `Cargo.toml`): added `metrics = { workspace = true }` (already a pinned
  workspace dep, used elsewhere by `powehi-rest-api`'s
  `http_metrics.rs`/`routes/auth.rs` via the same
  `counter!("x_total", "label" => v).increment(1)` pattern) and emitted
  two new counters alongside the existing log lines, purely additive (no
  control-flow/threshold/deletion-logic change):
  - `media_orphan_sweep_owner_mismatch_total{region_id}` next to
    `owner_matches()`'s existing `tracing::error!`.
  - `media_orphan_sweep_ratio_guard_total{region_id}` next to the
    existing `tracing::warn!` in the ratio-guard circuit-breaker branch.
  `region_id` label confirmed by security-auditor to be a small
  operator-set Helm enum (`eu-frankfurt`/`ap-seoul`, gated by
  `configmap.yaml`'s `required "values.region is required"`), never
  user/request-derived — same cardinality class as the existing
  `http_requests_total{method,status}` labels.
- Build/test gate: `cargo build -p powehi-r2 --all-targets`,
  `cargo test -p powehi-r2 --lib` (18/18 green), `cargo clippy -p
  powehi-r2 --all-targets -- -D warnings` (clean), `cargo fmt -p powehi-r2
  --check` (clean), `cargo deny check` (clean — no new external crate,
  only a new intra-workspace dep edge), full `cargo build --workspace` +
  `cargo test --workspace` (all green, 0 failures — `cargo nextest` still
  not installed in this environment, used the documented `cargo test
  --workspace` fallback per cycle 435's precedent).
- **security-auditor: PASS**, no changes required (backend adapter change,
  not crypto/architectural, so `crypto-reviewer`/`threat-model-checker`
  correctly not invoked per routing rules) — independently verified
  `region_id`'s source, confirmed bounded cardinality, confirmed no
  control-flow change by diffing against `git diff`, confirmed metric
  naming/dependency conventions match existing precedent.
- Committed `c727c53` (`feat(r2): emit Prometheus counters for
  orphan-sweep owner-mismatch and ratio-guard trips`), pushed. CI status
  on this commit pending confirmation as of this write — verify before
  relying on this cycle's "green" claim in a future cycle if not already
  confirmed.
- Target dir hygiene: not checked (FEATURE mode; last STABILIZATION pass
  cycle 435 already brought target/ to 7.5G/22GiB free).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. **Downgraded from "not scoped" to "done, monitoring-only":** the
     owner-mismatch/ratio-guard signals are now Prometheus-alertable
     (`media_orphan_sweep_owner_mismatch_total`,
     `media_orphan_sweep_ratio_guard_total`). The underlying architectural
     gap itself (winner-keeps-destroying-live-sibling) remains accepted
     risk per §9.4.3 — no further code action expected here; a genuine
     next step would be wiring an actual Alertmanager/Grafana rule on
     these two metrics, which is an infra-lead/ops task, not a routine
     backend cycle.
  4. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.

## Previous state (2026-09-04, cycle 435 — STABILIZATION: disk-hygiene cargo clean + dead deny.toml license-allowance cleanup, commit 4e7e1f6)

- Mode selection: counter 434→435, 435 % 5 == 0 → STABILIZATION.
- CI check: `gh run list --limit 5` green on `main` (last 2 pushes both
  `completed`/`success` on both `CI — Rust` and `CI — Live-backend E2E`).
  `gh issue list --state open`: empty.
- **Disk was critical again at session start** (same standing operational
  flag cycle 434 raised): `df` showed only 6.3 GiB free on the 228 GiB
  volume (97% full), powehi's own `target/` at 24G. A 2-day-mtime prune
  (cycle 434's emergency threshold) only freed ~1G this time — most of
  the bloat was **duplicate hash-variant `.rlib`s from repeated recent
  rebuilds** (e.g. 9 separate `libaws_sdk_s3-*.rlib` copies at 127M each,
  1.1G just for that one crate), not stale-old artifacts, so mtime-based
  pruning couldn't touch them. Ran a full `cargo clean` instead (source
  code untouched, fully reversible via rebuild, matches the STABILIZATION
  target-hygiene mandate's spirit when duplication rather than age is the
  driver) — reclaimed 24.8 GiB (85999 files). Full rebuild from clean
  finished at only 7.5G total, host disk now at 22 GiB free / 89% — well
  under the 20G prune-threshold and no longer critical. Other
  `~/codespace/*` project directories are still the bulk of host usage
  (~65G+, out of this repo's control) — same standing note as cycle 434,
  still nothing actionable from within this repo.
- Full sweep after the clean, all green: `cargo build --workspace`
  (58.84s clean build), `cargo test --workspace` (0 failures across every
  crate — `cargo nextest` isn't installed in this environment, used the
  documented `cargo test --workspace` fallback), `cargo clippy --workspace
  --all-targets -- -D warnings` (clean), `cargo fmt --all --check`
  (clean), `cargo audit` (0 advisories, 664 crates), frontend `pnpm test
  --run` (1582/1582 green, 111 files), `tsc -b`/`biome check` (clean, 179
  files).
- **Concrete fix, found via the sweep, not pre-planned:** `cargo deny
  check` was emitting `warning[license-not-encountered]` for two
  allow-listed SPDX licenses — `"OpenSSL"` and `"Unicode-DFS-2016"` — that
  no crate in the current 664-crate tree actually uses. Root-caused both:
  `openssl-probe` (the only openssl-named crate present) is
  `MIT OR Apache-2.0`, not `OpenSSL` — the stack is all-rustls, nothing
  ever pulled in a real OpenSSL-licensed crate; `unicode-ident` relicensed
  upstream off `Unicode-DFS-2016` onto `Unicode-3.0` (already separately
  allow-listed) some versions back. Removed both dead entries from
  `deny.toml`'s `[licenses] allow` list — same precedent as `aa1d88e`
  (cycle 270, dead `cargo-audit` ignores). Removing an *allow* entry only
  tightens the policy (a future dep needing either license now hard-fails
  CI instead of silently passing) — no way to weaken the gate this way.
  `cargo deny check` clean before *and* after (this was a warning, not a
  failure — housekeeping, not a break-fix), `license-not-encountered`
  count 2→0.
- **security-auditor: PASS** (dependency-audit is explicitly in this
  agent's remit per its own description) — verified the diff is exactly
  the 2 deletions, confirmed both entries are genuinely dead via
  `cargo metadata` + re-running `cargo deny check` with the change
  stashed/restored, confirmed monotonic-tightening direction (no
  `[licenses] exceptions` or `deny` table that could interact), flagged
  two non-blocking observations (this was warning-hygiene not a CI
  break-fix; the AGPL-3.0-only workspace makes the OpenSSL-license
  fail-closed behavior specifically well-justified given historical
  OpenSSL/GPL advertising-clause friction). Not crypto/architectural/a
  backend handler — `crypto-reviewer`/`threat-model-checker` correctly
  not invoked, consistent with the routing rules.
- Committed `4e7e1f6` (`chore(deps): remove dead license allowances from
  deny.toml`), pushed, confirmed `CI — Rust` (`33880772879`) completed
  `success` on the pushed commit before writing this entry.
- Target dir hygiene: already covered above (the `cargo clean` *was* this
  cycle's hygiene action, done early because it was blocking rather than
  as the routine end-of-cycle step) — final state 7.5G / 22 GiB free, no
  further action needed.
- **Next cycle candidates (carried from cycle 434, still accurate):**
  1. Host disk is still the dominant risk — other `~/codespace/*`
     projects (not powehi) are ~65G+ of the 228 GiB volume; a future
     cycle can still get blocked fast since powehi's own `target/` alone
     regrows several GB per build cycle. Not actionable from this repo;
     keep flagging to a human rather than touching other projects' files.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still not scoped: the residual gap where the winner of a
     *legitimate* (non-racing) ownership claim can still delete a
     colliding environment's live media forever (§9.4.3, "won't fix,
     documented" candidate).
  4. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.

## Previous state (2026-09-04, cycle 434 — FEATURE: finished + hardened + committed cycle 433's cross-region abuse-signal propagation, commit 325ad1e)

- Mode selection: counter 433→434, 434 % 5 != 0 → FEATURE.
- **Session start found a large uncommitted working tree**, not a clean
  slate: cycle 433 (never recorded in this memory file — its own "chore:
  update session memory" write apparently never happened, same failure
  mode cycle 430 found for cycle 429) had already fully implemented next
  cycle candidate #3 (prd.md §6.4 cross-region abuse-signal propagation)
  across 17 files — new `powehi-domain::abuse` module (`AbuseSubject`/
  `AbuseReason`/`AbuseSignal`), new `AbuseSignalStore` outbound port, a new
  `PropagateAbuseSignal` gRPC RPC (proto + server handler + client
  broadcast), a `RedisCache` impl of the store, a testcontainers IT file,
  and prd.md updates that already read as if a prior threat-model-checker/
  security-auditor pass had happened (citing "cycle 433 F2/F3/F4" findings
  baked into the doc). Treated this as real, high-quality in-progress work
  to verify and land — not something to discard — per the standing
  "investigate unfamiliar state before overwriting" discipline.
- **Verified the inherited work from scratch** rather than trusting the
  doc's self-description: read every changed file in full, then ran
  `cargo build --workspace` (clean), `cargo test --workspace` (0 failures,
  784+ tests), `cargo clippy --workspace --all-targets -- -D warnings`
  (clean), `cargo fmt --all --check` (clean), `cargo deny check` (clean —
  new deps `governor 0.6`/`sha2` both fine).
- **Disk was the real first blocker, not the code**: `cargo build` failed
  immediately with `No space left on device` — `df` showed 131 MiB free on
  a 228 GiB volume (99.9% full), and it wasn't just powehi's `target/`
  (24G) — five other project directories under `~/codespace/` totalled
  ~65G more. Pruned only powehi's own `target/` (0-byte `.rmeta` stubs,
  `debug/incremental`, and `.rlib`/`.rmeta`/`.o`/`.d` older than 2 days —
  tighter than STABILIZATION's normal 7-day window because this was an
  active build-blocking emergency, not routine hygiene) to free ~7G and
  unblock the build. **Disk stayed critically tight all cycle** (bounced
  between ~500 MiB and ~3 GiB free after every build/test run) — had to
  re-prune `target/` three more times mid-cycle. Flagged as a carried
  candidate below since this will keep recurring every cycle until fixed
  at the host level (out of this repo's control).
- **Ran all three required review agents in-session before committing**
  (not just trusting cycle 433's doc claims of prior review — no proof
  those reviews ran in a session that actually gated a commit, and the
  work was still uncommitted):
  - `crypto-reviewer` on `AbuseSubject::from_ip`'s SHA-256 construction
    (`crates/domain/powehi-domain/src/abuse.rs`): **pass** — correct
    RustCrypto usage (`Sha256::new`→`update`→`finalize().into()`), sound
    domain separation (prefix + address-family tag prevents v4/v6
    preimage collisions), correct IPv4-mapped-IPv6 canonicalisation
    (`to_ipv4_mapped()`, not the overly-permissive `to_ipv4()`),
    constant-time comparison correctly judged unnecessary (unkeyed hash,
    no secret comparison). Required: elevate the already-documented
    plain-SHA256-vs-HMAC limitation to a blocking gate before this
    primitive is ever wired to a real caller (not just "follow-up"), and
    add two lines to prd.md about IPv6 targeted-confirmation and the
    digest being a stable global pseudonym. Both applied (prd.md §3.3).
  - `threat-model-checker` on the `PropagateAbuseSignal` RPC end-to-end:
    **yellow/mergeable** — mTLS origin-region binding verified correct
    (can't be forged), TTL clamp verified correct (two independent
    layers), fail-open policy verified intentional and correct given
    layer-1 `tower-governor` survives Redis outage. Required before
    merge: (a) correct prd.md/code claims that the rate limiter "prevents
    unbounded key growth" — it only bounds *call frequency*, not the
    limiter's own key-space, which needs separate GC; (b) extend the F3
    accepted-risk writeup (§3.5.1) to explicitly cover
    `AbuseSubject::IpHash`, which is *worse* than `User` because it has
    no `home_region` to check — a compromised region can mesh-wide block
    an entire CGNAT/carrier IP range. Both applied.
  - `security-auditor` on `propagate_abuse_signal` + the Redis adapter:
    **pass with 2 must-fix items**, both applied: (1) `governor`'s
    `DefaultKeyedRateLimiter` map was never reaped — unbounded memory
    growth, reachable via the `tls_required=false` fail-open path where
    `origin_region` is attacker-chosen — added a periodic `retain_recent()`
    GC task (`RegionGrpcServer::abuse_signal_limiter_handle()` exposes a
    cloned `Arc` before the server is moved into `RegionServiceServer::new`,
    mirroring the existing `HandleRateLimiter` GC pattern in
    `bin/powehi-server/src/main.rs`); (2) `governor = "0.6"` was pinned
    literally in two crates (`powehi-rest-api`, `powehi-grpc`) — promoted
    to `[workspace.dependencies]` in root `Cargo.toml`. Input validation,
    log-hygiene (no digest/UUID/peer-text ever logged), Redis key/value
    construction, and TTL clamping were all independently confirmed
    correct with no changes needed.
- **Also fixed, flagged by both crypto-reviewer and security-auditor as a
  nit**: two `.expect()` calls in `RegionGrpcServer::new`'s quota
  construction (rule: crates-naming, no unwrap/expect in lib code) —
  replaced with a `const NonZeroU32` (compile-time match+panic, not a
  runtime call) and `Quota::per_minute()` (a `const fn`, mathematically
  identical to the original `with_period(1s).allow_burst(60)` — verified
  the equivalence by hand before switching: `per_minute(60)` replenishes
  60s/60 = 1 token/sec with burst 60, exactly what the doc comment already
  claimed).
- Re-verified build/test/clippy/fmt clean after all fixes (same commands
  as above, all green again) before committing. **This primitive still
  has zero production callers** — no route handler triggers
  `broadcast_abuse_signal` or queries `is_blocked_or_allow` yet, so
  today's actual security-relevant exposure is unchanged from cycle 433's
  own assessment (RPC surface registered on the live gRPC listener, but
  inert). Wiring it in is explicitly gated on resolving F3 (now including
  the `IpHash` extension) and the HMAC-vs-SHA256 gate per this cycle's
  prd.md edits — do not wire without re-reading those first.
- Committed as `325ad1e` (`feat(grpc): cross-region abuse-signal
  propagation primitive`), pushed, and confirmed both `CI — Rust` and
  `CI — Live-backend E2E` completed `success` on the pushed commit
  (`33866084630`/`33866084596`) before writing this memory entry — not
  left as an unconfirmed claim like cycle 431's did.
- **Archive sweep (routine, done alongside this cycle's work since the
  live file was getting long):** moved cycles 430-431's full "Previous
  state" sections into `.claude/memory/archive/project-context-cycles-425-428.md`,
  renamed to `.claude/memory/archive/project-context-cycles-425-431.md`
  (7th archive round). Live file now holds only header/non-negotiables,
  this cycle-434 entry, and cycle-432 (kept as immediate prior-cycle
  context) as "Previous state".
- **Next cycle candidates (carried/updated):**
  1. **New, operational (not code):** host disk is at ~99-100% full
     system-wide (228 GiB volume), not just powehi's `target/` — a future
     cycle (any mode) may start completely blocked on `cargo build`
     again. Pruning powehi's own `target/` buys a few GB but the volume
     itself needs attention outside this repo's scope (other project
     directories under `~/codespace/` are the bulk of the usage) — flag
     to a human rather than silently deleting other projects' files.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still not scoped: the residual gap where the winner of a
     *legitimate* (non-racing) ownership claim can still delete a colliding
     environment's live media forever (§9.4.3, "won't fix, documented"
     candidate).
  4. New: wiring `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     into a real caller (`powehi-rest-api`'s `HandleRateLimiter` trip
     points, or a route handler querying `is_blocked_or_allow`) is
     explicitly BLOCKED until F3 (including the `IpHash` extension from
     this cycle) and the HMAC-vs-plain-SHA256 gate (also this cycle) are
     resolved — do not casually wire this up as a "quick" next-cycle task
     without re-reading both prd.md sections first.

## Previous state (2026-09-04, cycle 432 — FEATURE: §3.3 cross-reference for media storage_key region_id metadata)

- Mode selection: counter 431→432, 432 % 5 != 0 → FEATURE.
- CI check (FEATURE step 2): `gh run list --limit 3` green on `main`
  (`33826979798`/`33816380358`/`33815946137` all `completed`/`success`).
  `gh issue list --state open`: empty.
- Phase 1-6 checklist: still all `[x]` — picked next-cycle candidate #1 from
  cycle 431's list (the other filler task; #2/#3/#4 still need a
  human/crypto-lead policy call or a threat-model-checker-gated scoping
  pass and aren't a fit for a routine cycle).
- **Fix:** `docs/prd.md` §3.3 ("서버가 불가피하게 알게 되는 것") never had its
  own bullet for the media storage_key's `{region_id}` prefix or the
  `{region_id}/.owner` sentinel object — both were already fully documented
  in §9.4.3 (added cycle 426, itself already threat-model-checker-reviewed
  there) but §3.3's own enumeration list was missing the cross-reference,
  so a reader scanning only §3.3 (the canonical "what the server
  unavoidably learns" list) would miss this category. Added one bullet to
  §3.3 summarizing the exposure and pointing to §9.4.3 for full detail
  (owner-sentinel guarantee scope, deletion safeguards) — verified via
  `grep -n "region_id" docs/prd.md` and reading §9.4.3 in full before
  writing, to match existing bullets' style/precision rather than
  re-describing the mechanism from scratch.
- Doc-only change, no `.rs` file touched, no new architecture or new
  server-visible metadata (this metadata already exists in code since
  cycle 426 and was already threat-model-checker-reviewed there — this
  cycle only adds a cross-reference in a different section) — consistent
  with cycles 425/428/429/430/431's precedent, no crypto-reviewer /
  threat-model-checker / security-auditor invocation needed. No build/test
  gate applies (docs-only). Handled directly (single-agent, well under the
  20-tool-call delegation threshold).
- `gh issue list --state open`: empty (checked above).
- Target dir hygiene: not checked (FEATURE mode).

(cycles 425-431: see `.claude/memory/archive/project-context-cycles-425-431.md`,
now extended with cycles 429/430/431's full entries.
cycle 424 and earlier: see `.claude/memory/archive/project-context-cycles-402-421.md`,
now extended with cycle 424's full entry.)
