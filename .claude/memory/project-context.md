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

## Current state (2026-09-16, cycle 502 — FEATURE: withMlsCommitLock AbortSignal support + trackedGroupCount test hook (carried F9/F10), commit 1837da7)

- Mode selection: counter 501→502, 502 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on main (cycle 501's push; one `cancelled` run on the
  same commit was a redundant duplicate trigger, not a failure — the
  `success` run for that commit's CI — Rust and the CI — Live-backend
  E2E both passed). `gh issue list --state open`: same 5 open issues,
  none newly bug-labeled. Working tree clean at session start.
- Picked carried candidate #2 from cycle 501's list: F9 (acquisition
  timeout/AbortSignal for `withMlsCommitLock`) and F10 (export a test
  hook to directly assert the 128-group eviction cap), both small,
  scoped, frontend-only, zero new UI attack surface — deliberately did
  NOT touch (e)/(g) (the real Remove-UI blockers, still fully open) or
  the device_id-to-MLS-leaf binding design call (crypto-lead-scoped).
- **What shipped** (`app/src/lib/mlsCommitLock.ts`): `withMlsCommitLock`
  now takes an optional third `signal?: AbortSignal` param, passed
  through to the underlying `createLimiter` call (which already
  supported an abort-while-queued contract, previously unused by this
  module). A caller still QUEUED behind a holder that never settles can
  now give up waiting instead of queuing forever — `fn` is never
  invoked in that case, and the holder's slot is NOT freed (only a
  still-waiting caller can give up, not a running one). Also added
  `trackedGroupCount()`, a read-only export returning `locks.size`, for
  direct test assertions of the `MAX_TRACKED_GROUPS` cap.
- **crypto-reviewer: first pass needs-rework, re-review PASS** (this
  file touches the MLS commit-lock primitive gating merge/stage/confirm
  exclusivity, matching the routing precedent from cycle 501). The
  reviewer ran the module in isolation (`/tmp`, deleted after) to
  measure real interleavings rather than just reading code, confirming
  no live bug: exclusivity, FIFO order, `entry.active` bookkeeping, and
  no permanent-wedge risk all held under abort injected at every tick
  boundary. What needed fixing was documentation/test accuracy, not
  runtime behavior:
  - **F-A**: the new docstring claimed the signal "has no effect once
    fn has started running" — actually measured to go dead ONE TICK
    EARLIER, at slot acquisition (dequeue), because the F1 `safeFn =
    () => Promise.resolve().then(fn)` normalization wrapper inserts its
    own microtask between acquisition and the real `fn()` call. Fixed
    the docstring to say "acquires the group's slot," not "fn starts."
  - **F-B**: the "abort after running has no effect" test used a fresh,
    uncontended group — `createLimiter`'s immediate-acquire fast path
    never registers an abort listener at all, so the test passed even
    with the abort-listener-removal logic deleted (verified: reviewer
    instrumented `addEventListener` call count = 0 on that path).
    Fixed by rewriting the test to actually hold the group first via a
    separate holder task, so the signal-bearing caller genuinely queues
    and registers a listener before being dequeued.
  - **F-C**: the queued-abort test's comment claimed "abort does not
    free the holder's slot" but nothing asserted it — the follow-up
    call in that test only ran AFTER the holder had already resolved
    normally, so a bug that freed the slot on abort would have gone
    undetected (mutation-tested by the reviewer: manually adding
    `release()` to the abort path flipped this test from pass to fail
    only after the fix). Fixed by queuing a third caller WHILE the
    holder is still unresolved, right after the abort, and asserting it
    has not started for several ticks before releasing the holder.
  - Re-review: **PASS**, mutation-tested. 3 non-blocking notes carried
    forward (not required): the acquisition→fn gap is actually 2
    microtasks not 1 (doc credits only `safeFn`, technically
    incomplete but not wrong in direction); the "no effect" test
    validates the weaker after-fn-ran claim since the stronger
    inert-from-dequeue instant isn't observable via the public API;
    `trackedGroupCount()`'s `toBe(128)` assertion depends on shared
    module-singleton state and file test order (would break under
    `--shuffle`/`.concurrent`, not used by this repo's vitest config).
- No `threat-model-checker`/`security-auditor` run: no new
  server-visible metadata, no backend/infra touched — matches the
  established routing precedent (crypto-reviewer alone for a
  crypto/MLS-adjacent frontend-only primitive change with no threat-
  model-boundary shift).
- **Full gate**: `pnpm exec tsc -b` clean. `pnpm exec biome check`
  clean on both changed files (2 auto-format passes applied and
  re-verified, both whitespace/wrapping only). `pnpm exec vitest run`:
  113 files / 1675 tests, all green (was 1672 — +3 new AbortSignal
  tests; the F10 eviction-cap assertion was added inline to an existing
  test, not a new one). Rust untouched this cycle (frontend-only
  diff) — `cargo build --workspace` not re-run; no regression risk
  since zero `.rs` files changed (confirmed via `git diff --stat`
  showing only the two `app/src/lib/mlsCommitLock.*` files).
- Committed `1837da7` (`feat(frontend): add AbortSignal support +
  test-only eviction-cap hook to withMlsCommitLock`), 2 files changed
  (132 insertions, 12 deletions). Pushed clean (`66b8700..1837da7 main
  -> main`).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated from cycle 501's list):**
  1. **Resolved this cycle**: F9 (AbortSignal support) and F10 (eviction-
     cap test hook), both from cycle 501's crypto-reviewer pass.
  2. Unchanged, still the real gate before any Remove UI can be safely
     built: (e) incoming-commit-silently-discards-staged-commit and (g)
     stale-local-epoch-undetectable-via-CAS in `mls_group.rs`'s status
     list are BOTH still fully OPEN, both independently cause a
     permanent unrecoverable group fork under `max_past_epochs(0)`.
     Also still undesigned: the T3 local trust anchor for picking
     *which* leaf to remove (prd.md §3.3 names two ways forward — bind
     `device_id` into the MLS credential, or lean on the §5.6 safety
     number — a product/crypto-lead decision). A production Remove UI
     should select from `mlsGroupMembers()`'s roster directly (leaf
     index + sigKeyHex), NOT from `PendingRemovalBanner`'s
     server-supplied device_ids — see `mls_group.rs`'s "Caller
     contract" section for why.
  3. Carried, unchanged: renaming `prod-ap-seoul` (cross-cutting
     Terraform/DNS/CD rename, a policy call — not attempted) and the
     origin-direct-ingress bypass gap threat-model-checker flagged at
     cycle 500 (`smart-router`'s `index.ts` `"XX"` fallback routes to EU
     when `request.cf` is absent — verify whether Hetzner origins are
     actually network-restricted to Cloudflare-only ingress).
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a real
     client polls it.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-16, cycle 501 — FEATURE: MLS commit-lock primitive + GET /epoch client wrapper, issue #2 prereq, commit c3519b9)

- Mode selection: counter 500→501, 501 % 5 != 0 → FEATURE. `gh run list
  --limit 3` all green on main (cycle 500's push). `gh issue list
  --state open`: same 5 open issues (#1 SPA deploy, #2 MLS Remove/PCS,
  #3 WS client, #4 load testing, #5 prod-ap-seoul PIPA).
- Picked up issue #2 (P0-blocker) via the carried candidate list. An
  Explore-agent survey first (don't skip this next time either) found the
  situation was narrower than the issue title suggests: the Rust MLS
  Remove commit primitive (`stage_remove_member`/`confirm_remove_member`/
  `abort_remove_member` in `crates/client/powehi-crypto-wasm/src/
  mls_group.rs`) and its WASM/Comlink exports already existed,
  unit-tested, since an earlier cycle. But that module's own doc comment
  explicitly says **"do not wire this trio into a production UI yet"**
  pending open items (a) epoch reconciliation, (e) an incoming commit can
  silently discard a locally-staged commit, (f) no mutual exclusion
  between the poll loop and a future UI flow, (g) a stale local epoch
  undetectable via the server CAS. Deliberately did NOT build a
  production Remove UI this cycle — building it while (e)/(g) stay open
  risks a permanent, unrecoverable group fork under `max_past_epochs(0)`.
  Scoped instead to closing (a) and partially closing (f), i.e. safe
  prerequisite infra with zero new UI attack surface.
- **`app/src/lib/mlsCommitLock.ts` (new)**: per-group async mutex
  (`withMlsCommitLock(groupId, fn)`), built on the existing
  `concurrencyLimiter.ts` `createLimiter`. Bounded to 128 tracked groups,
  idle-LRU eviction (never evicts a busy lock). Wired into
  `useMessages.ts`'s existing Commit-merge path (`mlsProcessCommit` + the
  self-eviction check, deliberately including the post-merge ack+retry —
  documented tradeoff, not an oversight).
- **`app/src/api/groups.ts`**: added `getEpoch(token, groupId)` wrapping
  the already-existing `GET /v1/groups/:id/epoch` endpoint (added cycle
  499, commit 2ab7ad9). No production caller wired yet — scoping only.
- **`crates/client/powehi-crypto-wasm/src/mls_group.rs`**: doc-only
  updates to the remove-member status list — (a) → PARTIALLY CLOSED
  (endpoint+wrapper exist, no caller), (f) → PARTIALLY CLOSED (lock
  exists, poll loop uses it, but no second/UI caller yet so the mutual-
  exclusion guarantee doesn't hold in practice), (g) got a note that the
  pre-stage drain and the stage/confirm/abort must happen inside ONE
  `withMlsCommitLock` acquisition (the lock is non-reentrant — a naive
  drain-then-reacquire implementation would deadlock).
- **Two review passes, both required by CLAUDE.md for this diff**:
  - `threat-model-checker`: **YELLOW** (documentation-only, not
    blocking). Confirmed T1-T7 unchanged, zero new metadata exposed
    (`getEpoch` has 0 call sites). Flagged F1 (the lock span includes
    unbounded network I/O — the ack call has no timeout — a future
    concern once a UI caller actually contends for the lock, since a
    malicious DS could then stall a Remove attempt at the acquisition
    step) and F2 (item (a)'s original "CLOSED" label was inconsistent
    with (f)'s honest "PARTIALLY CLOSED — one caller only" framing).
    Both addressed in doc updates (see above) before commit.
  - `crypto-reviewer`: **first pass was needs-rework** — found a real,
    reproducible bug (F1, verified via a probe test that was deleted
    after confirming): `withMlsCommitLock`'s underlying
    `createLimiter` executor is `fn().finally(release)`; a `fn` that
    throws SYNCHRONOUSLY (not `async () => { throw }`, a genuine sync
    throw) or returns a non-Promise value never reaches `.finally`, so
    `release` never runs — the capacity-1 mutex wedges PERMANENTLY for
    that group's remaining process lifetime. Fixed by normalizing via
    `const safeFn = () => Promise.resolve().then(fn)` before handing it
    to the limiter; pinned with two new regression tests. Also flagged
    doc-accuracy findings F2-F4 (over-claimed "closes item (f)"/"item
    (a) CLOSED" language; non-reentrancy undocumented despite item (g)
    implying a drain-then-reacquire pattern that would deadlock; "no
    UI-initiated MLS flow exists yet" was false — `AcceptInviteModal.tsx`
    and `CreateGroupModal.tsx` both call MLS-mutating worker methods
    today, just safely, since the poll loop can't bind to a
    not-yet-open group) — all fixed. Plus low-severity F5 (`Number.
    isInteger` → `Number.isSafeInteger`, server returns u64) and F6
    (`resp.json()` needed the same `.catch(() => ({}))` fail-closed
    pattern `throwOnError` already uses). **Re-review after fixes: PASS.**
  - Non-blocking carried findings for a future cycle (crypto-reviewer's
    own triage, not urgent): F8 (ack+retry inside the lock span — fine
    today, revisit once a real competing caller exists to measure
    contention), F9 (no acquisition timeout/AbortSignal — a crashed
    worker wedges the lock forever, future UI caller should apply its
    own timeout), F10 (the 128-cap eviction test doesn't assert
    `locks.size` directly — no export exists to check it), F11 (lock key
    is `groupId` alone, not `(identityId, groupId)` — intentional,
    over-serializes safely, now documented).
- **Full gate, all green**: `cargo build --workspace`, `cargo fmt --all
  --check`, `cargo clippy --workspace --all-targets -- -D warnings` all
  clean. `cargo test --workspace` (nextest not installed in this
  sandbox, documented fallback used): every crate `0 failed`, same
  171/58/235(2 ignored)/62/12/120/10/8/4/4/18/20/158/3/10/13/38/3 counts
  as cycle 500 baseline — no regression (this cycle's Rust changes were
  doc-comment-only). `cargo deny check`: `advisories ok, bans ok,
  licenses ok, sources ok`. Frontend: `pnpm exec tsc -b` clean; `pnpm
  exec biome check` — 4 pre-existing unrelated `app/src-tauri/gen/
  schemas/*.json` errors only (same baseline noted since ≥cycle 472);
  `pnpm exec vitest run`: 113 files / 1672 tests, all green (was 1667 —
  +9 new `mlsCommitLock.test.ts` tests, +2 new `groups.test.ts` `getEpoch`
  tests after the F5/F6 fixes, net +5 shown live but 1672 is the final
  post-fix count).
- Committed as `c3519b9` (feature commit only this cycle — this memory
  update is a separate `chore:` commit per convention). 6 files changed:
  `mlsCommitLock.ts`+test (new), `groups.ts`+test, `useMessages.ts`,
  `mls_group.rs`.
- Target dir hygiene: not checked this cycle (FEATURE mode; hygiene step
  is STABILIZATION-only per the cycle instructions).
- **Next cycle candidates (carried/updated from cycle 500's list):**
  1. **Partially addressed this cycle** (issue #2): closed (a), partially
     closed (f) as prerequisite infra. Still the real remaining work:
     (e) incoming-commit-silently-discards-staged-commit and (g)
     stale-local-epoch-undetectable-via-CAS are BOTH still fully OPEN
     and BOTH independently cause a permanent, unrecoverable group fork
     under `max_past_epochs(0)` — closing them is the real gate before
     any Remove UI can be safely built. Also still undesigned: the T3
     local trust anchor for picking *which* leaf to remove (prd.md §3.3
     names two ways forward — bind `device_id` into the MLS credential,
     or lean on the §5.6 safety number — a product/crypto-lead decision,
     not something to default into). A production Remove UI, when it's
     finally safe to build, should select from `mlsGroupMembers()`'s
     roster directly (leaf index + sigKeyHex), NOT from
     `PendingRemovalBanner`'s server-supplied device_ids — see
     `mls_group.rs`'s "Caller contract" section for why.
  2. Carried non-blocking crypto-reviewer findings from this cycle: F8
     (narrow the lock span to exclude the ack once a real competing
     caller exists to measure against), F9 (acquisition timeout/
     AbortSignal for `withMlsCommitLock`), F10 (export a test hook or
     otherwise directly assert the 128-group eviction cap holds).
  3. Carried, unchanged: renaming `prod-ap-seoul` (cross-cutting
     Terraform/DNS/CD rename, a policy call — not attempted) and the
     origin-direct-ingress bypass gap threat-model-checker flagged at
     cycle 500 (`smart-router`'s `index.ts` `"XX"` fallback routes to EU
     when `request.cf` is absent — verify whether Hetzner origins are
     actually network-restricted to Cloudflare-only ingress).
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a real
     client polls it.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-16, cycle 500 — STABILIZATION: archive this file (cycles 453-484), reconcile prd.md PIPA/KR-residency doc drift with actual deployed topology (issue #5), full green sweep)

- Mode selection: counter 499→500, 500 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` all green on main (cycle 499's push). `gh issue list
  --state open`: same 5 open issues (#1 SPA deploy, #2 MLS Remove/PCS,
  #3 WS client, #4 load testing, #5 prod-ap-seoul PIPA), none
  `bug`-labeled. Working tree clean at session start.
- **This file itself had been flagged as this cycle's #1 STABILIZATION
  task since cycle 499's own candidates list** ("well past ~3050 lines
  — cycle 500 is the archive point, same pattern as cycles 360/485").
  Archived cycles 453-484 (2203 lines of history) to
  `.claude/memory/archive/project-context-cycles-453-484.md`, following
  the exact split precedent cycle 485 set (archive older `## Previous
  state` sections verbatim, keep the "Archive index" list at the
  bottom, add one new line to it). File went from 3132 → 930 lines
  (then this entry). Verified the split boundary was exact (no line
  lost or duplicated) by diffing section headers before cutting.
- **Second task: GitHub issue #5** (P1/infra/compliance — `prod-ap-seoul`
  is Hetzner Singapore, not Korea, so prd.md's compliance-matrix claims
  of "KR 리전 저장" are false). Traced the issue's 4 suggested items
  before acting:
  1. "Decide the interim posture" — already decided and implemented:
     `infra/cloudflare/workers/smart-router` unconditionally 503s any
     `request.cf.country === "KR"` request (`PIPA_REGION_PENDING`).
     Not touched this cycle.
  2. "Rename the env" — a real Terraform/DNS/CD-pipeline rename
     (`prod-ap-seoul` → `prod-ap-singapore` or similar) is a
     cross-cutting, hard-to-reverse infra change affecting live prod
     naming; deliberately NOT attempted this cycle (same category as
     this file's other carried human/policy-call items like PQ
     hybrid) — left as a candidate, not resolved.
  3. "Make the guard mechanical" — confirmed, not just asserted: read
     `router.ts`/`index.ts` and their test files. The guard reads
     `request.cf.country` (CF-trusted, unspoofable), not the
     client-supplied `CF-IPCountry` header; `index.test.ts` has an
     explicit test proving a spoofed `CF-IPCountry: DE` header cannot
     bypass a real `cf.country=KR`. `router.test.ts` unit-tests
     `resolveTarget("KR")` and `AP_COUNTRIES` excluding KR directly.
     This item was already done and tested — no code change needed,
     confirmed via reading, not assumed from memory.
  4. "Reconcile prd.md's KR 리전 저장 claim" — this was the real gap.
     Fixed 4 locations: §1's Data Residency bullet (line 61), §12A's
     compliance matrix (was line 1999, false "KR 사용자 데이터는
     AP-Seoul에만 저장"), §15.2's compliance matrix (was line 2182,
     same false claim), and §4A.6's data-residency requirements table
     (added a caption clarifying its KR column is the target
     architecture for a future real KR DC, not current state — did NOT
     rewrite the table itself, since it correctly describes what
     *should* happen once a KR region exists). All 3 corrected claims
     now say explicitly: no KR PII is stored anywhere today, the
     smart-router 503s all KR traffic, cites GitHub #5 and
     `infra/cloudflare/workers/smart-router` as evidence.
- **threat-model-checker: YELLOW.** Confirmed no code/crypto/data-flow
  changed, T1-T6 impact matrix unchanged, doc posture strictly
  strengthened (previously falsely claimed compliance, now accurately
  labeled "미충족 (accepted risk)"). Not GREEN because it caught a
  residual inconsistency this cycle's first pass had missed: §4A.6's
  table still read as unconditional present-tense "KR 리전에 저장" with
  no caveat, and line 61's Data Residency bullet still claimed PIPA
  "준수" (compliance) outright. Fixed both before committing (see above
  — the §4A.6 caption and the line-61 rewrite were both added in
  response to this finding, not the initial pass). Also flagged an
  unrelated, pre-existing, NOT-introduced-by-this-diff gap for the
  future: `index.ts`'s `country = cfProps?.country ?? "XX"` fallback
  routes to EU (not blocked) when `request.cf` is absent, so the "전면
  차단" (total block) claim depends on all ingress actually routing
  through the Cloudflare Worker — origin-direct access would bypass it
  unless separately network-restricted. Not verified this cycle (infra
  topology check, not a doc-accuracy question); added as a candidate.
- **Full gate** (docs-only change, but ran the complete sweep per
  STABILIZATION's mandate): `cargo clippy --workspace --all-targets --
  -D warnings` clean. `cargo fmt --all --check` clean. `cargo test
  --workspace`: every crate `0 failed` (171/58/235(2 ignored)/62/12/120/
  10/8/4/4/18/20/158/3/10/13/38/3 passed across crates, matching cycle
  499's counts — no regression). `cargo deny check`: `advisories ok,
  bans ok, licenses ok, sources ok`. `pnpm exec tsc -b` clean. `pnpm
  exec biome check`: 4 pre-existing unrelated `app/src-tauri/gen/
  schemas/*.json` errors only (same as noted since ≥cycle 472, not a
  regression — confirmed by re-checking, not assumed from memory).
  `pnpm exec vitest run`: 112 files / 1649 tests, all green. `pnpm
  audit --prod`: no known vulnerabilities. No local `cargo-audit`
  binary in this sandbox; `cargo deny check`'s advisory-DB scan is the
  substitute, as in prior cycles without it installed.
- No `crypto-reviewer`/`security-auditor` run: no crypto/MLS/OPAQUE
  code touched, no backend handler changed — this cycle is a memory
  archive (mechanical, no code) plus a docs-only compliance-accuracy
  fix, matching the established routing precedent for doc-only changes
  (`threat-model-checker` alone, since it touches the threat-model
  document itself).
- Committing this file's own update together with the doc fix and
  archive as part of this cycle's single commit set (memory archive +
  prd.md fix are one logical STABILIZATION unit, unlike FEATURE mode's
  separate feature-then-memory commits).
- Target dir hygiene: `target/` at 18G (up from ~15-16G recently,
  still under the 20G threshold — no pruning triggered). 0-byte
  `.rmeta` prune ran first per the mandated step order (found none to
  delete this cycle).
- **Next cycle candidates (carried/updated from cycle 499's list):**
  1. **Resolved this cycle**: this file's archive-point overflow
     (cycles 453-484 archived). Watch for it crossing ~2500-3000 lines
     again in a future STABILIZATION cycle (next multiple of 5 after
     it does).
  2. **Partially addressed this cycle** (issue #5): doc drift reconciled,
     mechanical guard confirmed already-done-and-tested. Still open:
     renaming `prod-ap-seoul` (cross-cutting Terraform/DNS/CD rename,
     a policy call — not attempted) and the origin-direct-ingress
     bypass gap threat-model-checker flagged (`index.ts`'s `"XX"`
     fallback routes to EU when `request.cf` is absent — verify
     whether Hetzner origins are actually network-restricted to
     Cloudflare-only ingress, or whether this is a real gap).
  3. Carried unchanged: admin-initiated MLS Remove UI step (b) — design
     how a client uses `GET /v1/groups/:id/epoch` (poll-before-retry?
     what does a `RegionMismatch` 502 mean for reconciliation?) and
     wire `app/src/api/groups.ts`'s consumer. FEATURE-mode-scale,
     crypto-lead-scoped.
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a
     real client polls it (steady expected-5xx stream would pollute
     §13 SLO/alerting) — cheap, no other callers yet.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue
     #2's `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-15, cycle 499 — FEATURE: add `GET /v1/groups/:group_id/epoch`, region-authority fail-closed, commit 2ab7ad9)

- Mode selection: counter 498→499, 499 % 5 != 0 → FEATURE. `gh run list`
  green on main before starting (cycle 498's push). Working tree clean at
  session start (no orphaned WIP, unlike several recent cycles).
- **Picked candidate #2 from cycle 498's list, scoped narrowly**: rather
  than attempt the full admin-initiated MLS Remove UI (blocked on epoch
  reconciliation), picked the small concrete sub-task cycle 498 had
  already identified: expose the server's `groups.epoch` counter via a
  read endpoint, so a future client has something to bound a `sendCommit`
  `expected_epoch` against. Did NOT attempt the reconciliation design
  itself or wire any client consumer this cycle (no `app/src/api/groups.ts`
  change) — deliberately step (a) only.
- **What shipped**: `GroupUseCase::get_epoch(caller, group_id) -> Epoch`
  (fail-closed membership guard, same non-existence-oracle contract as
  `list_members`), `GET /v1/groups/:group_id/epoch` REST handler
  (`GroupEpochResponse { epoch: u64 }`), wired into `lib.rs`'s
  `api_routes` block (same `api_governor` rate-limit tier as its siblings).
- **security-auditor: needs-rework on the first pass, PASS after fixes**
  (backend handler, matches routing precedent). Findings and fixes:
  - **F1 (MEDIUM, blocker)**: a group row synced into a non-home region via
    `SyncGroupMembership` is created with `epoch: Epoch(0)` and never
    updated after (`upsert_members`'s `ON CONFLICT DO NOTHING`) — a
    non-home-region caller would get a stale/zero epoch back as `200 OK`
    with no authority indicator, a false-trust signal indistinguishable
    from a genuinely fresh group. Fixed: `GroupService::get_epoch` now
    compares `group.home_region != self.local_region` and returns
    `DomainError::RegionMismatch` (existing variant, already mapped to
    `502 region_mismatch`) instead of ever answering with that value. Guard
    order matters and was verified correct: the region check runs strictly
    after the membership check, so a non-member can never use this to
    probe "does this group exist in some other region" (would have been a
    group-existence-plus-home-region oracle otherwise).
  - **F2 (LOW/MEDIUM) + F3 (LOW), fixed together**: the original impl did
    `list_members` (O(group size) list allocation for an O(1)-sized
    response — worst amplification ratio of any `/v1/groups/*` endpoint)
    followed by a separate non-transactional `find_by_id`, reopening a
    TOCTOU window `list_members`'s own design explicitly avoids elsewhere.
    Fixed: added `GroupRepository::get_epoch_if_member(group_id,
    device_id) -> Option<Group>`, a single fused JOIN query
    (`groups g JOIN group_members m ON m.group_id = g.id WHERE g.id = $1
    AND m.device_id = $2`) that does the membership check and the read in
    one round trip. `Ok(None)` covers "no such group" and "not a member"
    identically — stronger than before, since there's no longer a second
    code path where those two cases could theoretically diverge. Had to
    add this method to 6 other `GroupRepository` fakes across the
    workspace (`grpc/server.rs`, `ws-hub` tests,
    `auth_service.rs`/`media_service.rs`/`messaging_service.rs`'s test
    modules) — all fail-closed (real membership checks in 3, `Ok(None)` or
    `unimplemented!()` in the rest, none unconditionally grant access).
  - **F6 (INFO)**: fixed a doc typo (`GroupUseCase::advance_epoch` doesn't
    exist; corrected to `GroupRepository::advance_epoch`).
  - **F4 (LOW)**: agreed with threat-model-checker's parallel finding
    (same review cycle) that this needed a `prd.md` §3.3 entry — added.
  - **F5** (log volume) and **F7** (no consumer wired yet) left as
    informational, matching the auditor's own severity call — F7 is
    intentional this cycle (step (a) only, see above).
  - **Re-verification pass caught doc drift from the two parallel reviews**:
    threat-model-checker's prd.md §3.3/§3.5.1 additions (written before
    F1's fix landed) still said the stale/zero epoch "may be returned
    without an authority indicator" — no longer true once `RegionMismatch`
    fail-closed shipped. Fixed both paragraphs to say the integrity risk is
    closed and only an availability limitation (non-home-region members
    can't use the endpoint at all) remains. Also fixed an inaccurate
    "no TOCTOU window" claim in `group_service.rs`'s `FakeGroupRepo` test
    comment (its two lock acquisitions are in fact separate statements;
    harmless only because tests are single-threaded) — this repo treats
    comments as normative, so a false claim was worth removing even though
    it was purely cosmetic.
  - **security-auditor's own new observations (not required this cycle,
    tracked for the future consumer-wiring cycle)**: this is the first
    code path in the whole workspace that actually produces
    `DomainError::RegionMismatch` (previously only the error-mapping and
    its own unit test existed) — so the `502` REST path opens in
    production for the first time here. Auditor flagged that `502` may be
    semantically wrong (a deterministic client-side "wrong region" isn't a
    gateway failure; `421 Misdirected Request` fits closer) and that a
    polling peer-region member would generate a steady 5xx stream that
    could pollute `§13` SLO/alerting despite being expected behavior —
    both flagged as pre-existing/shared-mapping concerns out of this
    diff's scope, to revisit whenever step (b) actually wires a consumer.
- **threat-model-checker: YELLOW, conditions applied**. Verdict: no
  confidentiality invariant weakened (server learns nothing new — the
  epoch value already flowed client→server via `AddMemberRequest.epoch`),
  no out-of-scope-list migration, write path untouched, existing
  fail-closed pattern reused correctly, `None → Unauthorized` default
  already guarded (not a `0`-default oracle). Conditioned GREEN on two
  `prd.md` doc-parity additions (this repo's established convention:
  every newly-client-readable server-held field gets a §3.3 entry, per
  the `/members` precedent from cycle 454) — added both, then corrected
  per security-auditor's re-verification note above.
- **Full gate**: `cargo build --workspace` and `cargo build --workspace
  --all-targets` clean. `cargo clippy --workspace --all-targets -- -D
  warnings` clean (multiple times, after this cycle's own review-fix
  round too). `cargo fmt --all --check` clean (auto-fixed once via
  `cargo fmt --all`, re-verified). `cargo test --workspace`: 0 failed
  throughout (application 171, up from 167; rest-api 158, up from 154;
  postgres integration tests unchanged runnable count, +1 new
  Docker-gated `#[ignore]` test, confirmed compiles via `cargo build -p
  powehi-postgres --tests` — no local Docker in this sandbox to actually
  run it). `cargo audit`/`cargo deny check`/`pnpm audit --prod` all clean
  (run by security-auditor as part of its pass).
- Committed `2ab7ad9` (`feat(backend): add GET /v1/groups/:id/epoch,
  fail-closed to home region`), 16 files changed (495 insertions, 0
  deletions — no line removed anywhere in this diff). Pushed clean
  (`f0fe588..2ab7ad9 main -> main`). CI triggered immediately after push;
  not watched to completion before this memory entry was written — verify
  `gh run list` next cycle if this session ends first.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated from cycle 498's list):**
  1. **Narrowed, not resolved** (was candidate #2): admin-initiated MLS
     Remove UI is still blocked on the `sendCommit`/`expectedEpoch`
     reconciliation design, but the "expose server's `groups.epoch`"
     sub-step is now done. A future crypto-lead-scoped cycle should design
     step (b): how a client actually uses this endpoint (poll before
     retry? what to do when a `RegionMismatch` 502 means "can't reconcile
     from here at all"?) and wire `app/src/api/groups.ts`'s
     `getEpoch`/consumer.
  2. New, from security-auditor's own observation this cycle: reconsider
     whether `DomainError::RegionMismatch` should map to `421 Misdirected
     Request` instead of `502 region_mismatch` before any real client
     starts polling it (a steady expected-5xx stream from peer-region
     members would pollute §13 SLO/alerting) — cheap to fix now, before
     the mapping has other callers to keep compatible.
  3. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  4. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s rejection
     latency — informational until a real Remove UI exists.
  5. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  6. Carried: PQ hybrid Phase A prerequisite (blocked on openmls upstream).
  7. Carried, BLOCKED: `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring needs F3 + HMAC-vs-plain-SHA256 gate resolved first.
  8. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
     retention window (separate item — not the same as this cycle's new
     `groups.epoch` §3.3 entry).
  9. Carried: `mls_group_members` `isSelf` leaf-index hardening; issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  10. **This file is now well past ~3050 lines — cycle 500 (1 cycle away,
      the next multiple of 5) is the STABILIZATION archive point, same
      pattern as cycles 360/485.**

## Previous state (2026-09-15, cycle 498 — FEATURE: found + finished cycle 497's uncommitted MLS pending-commit-cleanup fix, fixed crypto-reviewer's needs-rework verdict, commit da96dee)

- Mode selection: counter 497→498, 498 % 5 != 0 → FEATURE. `gh run list`
  green on main before starting.
- **Session opened with 6 modified files already in the working tree**
  (PendingRemovalBanner.tsx, useCryptoWorker.ts/.test.ts, crypto.worker.ts,
  mls_group.rs, wasm_exports.rs) — no memory entry describes cycle 497 at
  all, meaning that session was cut short before EITHER its end-of-cycle
  memory commit OR its own feature commit. Same "session cut short" pattern
  this file has now flagged four times (445/494/495/496) — this is the
  first time it left a real, substantial UNCOMMITTED diff behind rather
  than just an uncommitted memory-file edit. Read the diff in full before
  acting (doc comments in it self-identified as "cycle 497", confirming
  provenance) rather than assuming it was safe to discard or blindly
  commit.
- **What the found diff did**: fixed a real bug — a successful merge of a
  PEER's Commit (via either the one-shot `mls_process_commit` or an
  incoming Welcome/Add flow) makes openmls internally call
  `clear_pending_commit`, which silently invalidates any commit THIS
  device had separately staged via `mls_remove_member_stage` but not yet
  confirmed. Before the fix, that left a dangling
  `pending_own_commit_hashes[group_id]` entry naming a commit that can
  never be merged. Fixed for the one-shot path
  (`mls_process_commit_inner`). Also (JS side): a compensating
  `mlsRemoveMemberAbort` when `mlsRemoveMemberStage` resolves in WASM but
  the required Dexie persist then rejects, so the group isn't left
  durably wedged in `PendingCommit`. Extensive stale-doc-comment cleanup
  in `mls_group.rs`/`crypto.worker.ts` converting a stale "(a)/(b)/(c)"
  MLS-Remove-wiring blocker list into a verified "(a)-(g)" list (closes
  item (d) — persist-failure-after-successful-stage — for the "call"-
  resolved case; leaves the ambiguous "call"-phase-timeout variant open,
  correctly).
  All tests green as found: 234 Rust, 1647 frontend, tsc/biome clean.
- **Before committing, ran the mandatory `crypto-reviewer` pass (this diff
  touches MLS/WASM) — verdict: needs-rework, 2 HIGH + 1 MEDIUM + 2 LOW.**
  This file's non-negotiables gate a commit on this passing, so did NOT
  commit the found diff as-is; fixed all 5 findings before committing:
  - **F1 (HIGH)**: the compensating `raw.mlsRemoveMemberAbort(...)` call
    had no `withTimeout` — violated this file's own "a crypto-worker call
    must never hang forever" invariant, and the dominant trigger reaching
    that catch block (a "persist"-phase timeout) is exactly the situation
    where the worker channel is already suspected wedged, so the abort
    call itself would very plausibly also hang, turning a bounded
    rejection into a permanent hang for the wrapped call. Fixed: wrapped
    in `withTimeout(..., "mlsRemoveMemberAbort", "call")`.
  - **F2 (HIGH)**: the comment justifying skipping a post-abort flush
    ("abort restores in-memory state to exactly what's already durably on
    disk, nothing new to persist") is false whenever `withTimeout` let the
    caller give up on the ORIGINAL failed persist's `doFlush` without
    actually cancelling it (documented `doFlush` behavior) — that
    abandoned write can still land on disk AFTER the abort, durably
    writing the wedged `PendingCommit` state to disk with nothing JS-side
    able to detect it on reload. Fixed: after a successful abort, issue a
    FRESH `runOnChain(() => withTimeout(doFlush(...)))` (failure
    swallowed, logged, original persistError still rethrown) — relies on
    `doFlush`'s existing generation-based supersede check to guarantee the
    fresh, later-issued write can never durably lose to the earlier
    abandoned one. Reviewer independently re-derived the race proof across
    every interleaving and confirmed it holds.
  - **F3 (MEDIUM)**: the two-phase `mls_confirm_incoming_commit` merge site
    has the IDENTICAL dangling-`pending_own_commit_hashes` hazard as the
    one-shot path, but the diff only fixed the one-shot path — violates
    this codebase's own "one construction path" rule (two merge sites,
    one of them silently exempt). Fixed: split into
    `mls_confirm_incoming_commit_inner` (mirrors `mls_process_commit_inner`'s
    pattern) which now also clears the entry on success; added a mirrored
    regression test using the real `inspect_incoming_commit` primitive +
    manual `INSPECTED_COMMITS` insert (JsValue-constructing wasm exports
    can't be called from native tests).
  - **F4/F5 (LOW)**: softened an absolute "on every ERROR path, no merge
    happened" doc claim to scope it to errors this crate's in-memory
    `OpenMlsRustCrypto` provider can actually produce, footnoting two
    openmls-0.8.1 internal counterexamples the reviewer found by reading
    vendored source; added a NOTE documenting that the compensating-abort
    window itself still shares the same unrelated-stage-destruction risk
    it was scoped to avoid elsewhere (unreached today, ties to blocker
    item (f)).
  - Re-review after fixes: **PASS**, all 5 confirmed resolved (reviewer
    re-ran both test suites independently rather than trusting the
    diff), no security invariant weakened. Noted 4 non-blocking residuals
    for future reference (a narrow crash window between stale/fresh
    writes, worst-case rejection latency now ~4x
    `CRYPTO_CALL_TIMEOUT_MS` ≈ 60s for this one failure path, an F4
    wording nit, an optional test gap) — added a one-line latency-caveat
    comment for the first one since it was cheap; left the rest as
    recorded observations, not required changes.
  - Added tests: 1 new Rust test (two-phase confirm mirror, 235 total,
    was 234), 2 new frontend tests (F1 hang-guard via fake timers, F2
    post-abort-flush-attempted via call-count assertion; 38 total in
    `useCryptoWorker.test.ts`, was 36; 1649 total frontend, was 1647).
- **Full gate after fixes**: `cargo test -p powehi-crypto-wasm --lib`
  235/235, `cargo fmt --check` clean. `pnpm exec vitest run` 1649/1649,
  `pnpm exec tsc -b` clean, `pnpm exec biome check` clean (2 files
  auto-formatted, applied via `biome check --write` + `cargo fmt`, both
  re-verified clean after).
- Committed `da96dee` (`fix(crypto): clear dangling pending own-commit
  entry on peer merge; guard compensating abort`), 6 files changed
  (1045 insertions, 101 deletions — the bulk of this diff was written by
  the found cycle-497 session; this cycle's own contribution was the
  crypto-reviewer fix cycle: F3's new inner-fn split + test, F1/F2's
  TS fixes + 2 tests, F4/F5's doc edits). Pushed clean
  (`088e218..da96dee main -> main`). CI running as of this entry (`gh run
  list` showed 3 in-progress checks right after push) — verify green
  next cycle if this session ends before confirming.
- **Lesson for next time a bare working tree with real diffs is found at
  session start**: do not assume "no memory entry = safe to discard" —
  this diff was real, tested, substantial work. Reading the diff's own
  doc comments (they self-dated "cycle 497") was what established
  provenance and trustworthiness before deciding to build on it rather
  than reverting it.
- Target dir hygiene: not checked (FEATURE mode; Rust build ran via
  `cargo test`/`cargo fmt` but no explicit `du -sh target/` this cycle —
  next STABILIZATION cycle, still cycle 500, should check).
- **Next cycle candidates (carried/updated from cycle 496's list, mostly
  unchanged — this cycle fixed a review-blocking bug, not a candidates-list
  item):**
  1. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     PendingRemovalBanner cross-check (crypto-lead design call).
  2. Carried unchanged: admin-initiated MLS Remove UI, blocked on the
     `sendCommit`/`expectedEpoch` gap named in `mls_group.rs`'s now-
     verified (a)-(g) list — item (a) is now understood to be a small
     concrete task (expose the server's `groups.epoch` counter via an
     endpoint) rather than an undesigned one; a future crypto-lead-scoped
     cycle should start there.
  3. New from this cycle's review: consider whether
     `mlsRemoveMemberStage`'s worst-case ~60s rejection latency (4x
     `CRYPTO_CALL_TIMEOUT_MS` across call/persist/abort/post-abort-flush)
     needs a UI-level timeout budget once a real Remove UI is built —
     informational only, not actionable until that UI exists.
  4. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  5. Carried: PQ hybrid Phase A prerequisite (blocked on openmls upstream).
  6. Carried, BLOCKED: `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring needs F3 + HMAC-vs-plain-SHA256 gate resolved first.
  7. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
     retention window.
  8. Carried: `mls_group_members` `isSelf` leaf-index hardening; issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  9. **This file is now well past ~2950 lines — cycle 500 (2 cycles away,
     next multiple of 5) is the STABILIZATION archive point, same pattern
     as cycles 360/485.**

## Previous state (2026-09-15, cycle 496 — FEATURE: wire the already-existing `GET /v1/groups/:id/members` endpoint into `PendingRemovalBanner` as a partial local staleness cross-check (issue #2), commit 7dc8d2e)

- Mode selection: counter 495→496, 496 % 5 != 0 → FEATURE. `gh run list
  --limit 5` all green on main (cycle 495's push). Working tree opened
  with cycle 495's own memory-update entry written but never committed
  (the file already had the full cycle-495 recap in it, no `chore:`
  commit after `5b46068`) — same "session cut short before its
  end-of-cycle step" pattern this file has flagged repeatedly (cycles
  445/494). Committed it first as `6361565` before starting this
  cycle's own work, so a future session doesn't lose it. Flag this
  again if seen a third time — the end-of-cycle memory commit is not
  optional even when a session is running low.
- **Scoped the item deliberately, not just picked the top of the
  candidates list.** The obvious next step for issue #2 (per its own
  GitHub comment history — read in full this cycle) is "admin-initiated
  Remove UI": the crypto primitives (`mlsRemoveMemberStage/Confirm/Abort`)
  have existed since commit b737b2c, but nothing in the app calls them.
  Traced why no prior cycle wired it: `mls_remove_member_stage`'s own
  doc comment (`wasm_exports.rs`) explicitly says its `priorEpoch`
  "must not be passed as sendCommit's expected_epoch" because "the
  server epoch and the local MLS epoch diverge from the very first
  member add in this codebase today" and reconciling them is
  "explicitly OUT OF SCOPE ... tracked as a follow-up." Confirmed this
  is real, not stale caution: `AddMemberModal.tsx` only calls the REST
  `addMember` (hardcoded `epoch: 0`), never `cryptoWorker.mlsAddMember`
  — so the server's `groups.epoch` counter has never actually been
  advanced by anything reachable from today's UI, while a client's own
  local MLS epoch (wherever `mlsAddMember`/`mlsRemoveMemberStage` get
  called, e.g. `AcceptInviteModal.tsx`) is independently real. Attempting
  the full Remove-commit UI this cycle would have meant either (a)
  designing epoch reconciliation from scratch in one session — the kind
  of "human/crypto-lead policy call" this file already carries as a
  separate blocked item for PQ hybrid, not something to rush — or (b)
  wiring `sendCommit` with a value explicitly documented as unsafe to
  use that way. Declined both; picked a different, still-real, properly
  bounded piece instead: `crates/adapters/inbound/powehi-rest-api/src/routes/groups.rs:192-197`'s
  `list_members` handler doc comment says outright it exists as "one
  half of the local cross-check for the server-reported pending-removals
  signal (prd.md §5.4)" and was completely unused by the frontend —
  a small, honest, additive piece with a backend contract already
  spelled out, not a design decision I'd be making up on the spot.
- **What shipped**: `listMembers(token, groupId)` added to
  `app/src/api/groups.ts` (`GET /v1/groups/:groupId/members`).
  `PendingRemovalBanner.tsx` now fetches it unconditionally alongside
  `listPendingRemovals` (unconditional + parallel, not gated on
  `pending.length > 0` — gating it would have made the mere existence
  of the request an observable signal that this group has a pending
  removal, a metadata leak; security-auditor confirmed this was the
  right call, not just an incidental choice) and flags a pending
  device_id absent from the current members list as informational
  "may be stale" (`data-testid="pending-removal-stale-{deviceId}"`) —
  never gates or disables the confirm action. Respects the endpoint's
  documented truncation contract: when `truncated: true`, the
  cross-check is skipped entirely for that fetch (never treats
  truncated-absence as meaningful, per `MembersResponse`'s own Rust doc
  comment's explicit warning against exactly that false-eviction
  direction). Delegated implementation to `frontend-lead` (background
  agent), verified the diff myself afterward rather than trusting the
  report blind.
- **Honest scope, stated in both the code and here**: this is a
  same-trust-domain defense-in-depth check, NOT a T3 mitigation
  (prd.md §3.5.1) — `listPendingRemovals` and `listMembers` are both
  served by the same server, so a fully malicious/colluding server can
  forge both consistently and this check catches nothing in that case.
  It only catches server-side INCONSISTENCY between its own two data
  sources (a pending-removal entry for a device that was never a
  member, or one already removed). The other, real half of the T3
  cross-check — binding `device_id` to the client's own MLS
  ratchet-tree leaves — does not exist yet (no authenticated binding
  between an MLS leaf/credential and a server `device_id` anywhere in
  this codebase); that's explicitly called out as unimplemented in the
  backend handler's own doc comment and NOT attempted this cycle.
  Neither the component doc comment nor this entry oversells it.
- **security-auditor: PASS, 2 LOW findings, both fixed before commit**
  (not crypto/architectural — matches the established routing
  precedent for a frontend-only REST-client change with no
  crypto/WASM/backend touch): (1) `listMembers`'s response was cast via
  `as` with no runtime validation — a malformed/missing `device_ids`
  would have silently become e.g. a char-set `Set` from
  `new Set(someString)`, and a missing `truncated` would have defaulted
  falsy (the FALSE-EVICTION direction the backend doc explicitly warns
  against). Fixed: `device_ids` is now validated as a string array
  (throws `invalid_members_response` otherwise, which the component's
  existing catch-and-skip-cross-check path already handles correctly —
  no new fallback logic needed), and a missing/non-`false` `truncated`
  now defaults to `true` (the safe direction) instead of `false`. (2)
  The 4 new cross-check tests mocked `listMembers` without asserting
  which `(token, groupId)` it was called with — a stale-closure
  regression that cross-checked group A's pending list against group
  B's membership would have passed silently. Fixed: added
  `toHaveBeenCalledWith` assertions to all 4. Also fixed an
  informational finding (truncation test used an unrealistic
  `deviceIds: []` — real truncation is always a length-`MAX_MEMBERS_RESPONSE`
  prefix, never empty — changed to a populated-but-still-absent-target
  list matching the real contract) and added 3 new `groups.test.ts`
  cases for the new validation logic. security-auditor separately
  confirmed via mutation testing (temporarily removing the
  `!membersTruncated` guard, temporarily fail-opening on fetch failure)
  that the new tests are non-tautological — both mutations were caught
  by exactly the intended test.
- No `crypto-reviewer`/`threat-model-checker` run: no crypto/WASM
  surface touched, and the diff explicitly does not shift any
  threat-model boundary (no new T3 mitigation claimed) — matches
  security-auditor's own routing recommendation in its report.
- **Full gate**: `pnpm exec tsc -b` clean. `pnpm exec biome check`
  clean (2 files auto-formatted, whitespace-only, confirmed via diff
  before re-checking). `pnpm exec vitest run` (full suite): 1642/1643
  passed, 1 failure in `ChatLayoutPoll.test.tsx` (poll-voters assertion)
  — confirmed unrelated: that file has zero git diff, is untouched by
  this cycle's changes, and passes 20/20 in isolation when re-run alone
  — a pre-existing test-isolation flake, not a regression from this
  diff. Backend untouched this cycle (frontend-only change,
  `list_members`'s handler was read-only reference), not re-run.
- Committed `7dc8d2e` (`feat(frontend): wire GET /v1/groups/:id/members
  into PendingRemovalBanner as a partial staleness cross-check (issue
  #2)`), 4 files changed, pushed clean (`6361565..7dc8d2e main ->
  main`). CI watched after push — see next cycle's entry or `gh run
  list` for outcome if this session ended before confirming.
- Target dir hygiene: not checked (FEATURE mode, frontend-only cycle,
  no Rust build artifacts touched).
- **Next cycle candidates (carried/updated):**
  1. **Partially addressed this cycle** (carried since cycle 480's
     list, PendingRemovalBanner local cross-check hardening): the
     REST-endpoint half now exists and is wired. Still open: the
     device_id-to-MLS-leaf binding half (would likely require changing
     what identity data an MLS credential carries at KeyPackage
     creation time — a structural crypto change affecting join/Welcome
     flows broadly, genuinely a crypto-lead design call, not a
     follow-on glue task).
  2. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): admin-initiated MLS
     Remove UI, blocked on designing epoch reconciliation between the
     client's local MLS epoch and the server's `groups.epoch` counter.
     Traced this cycle in more depth than before: the backend already
     has a CORRECT CAS mechanism for this
     (`messaging_service.rs::send_commit` →
     `commit_ledger.rs::commit_epoch_and_save` →
     `group_repo.rs::advance_epoch`, tested and used by the receive
     path's `sendCommit` calls) — the actual gap is narrower than "no
     mechanism exists": it's that `AddMemberModal.tsx`'s Add flow
     never calls `mlsAddMember`/`sendCommit` at all (REST-only,
     hardcoded `epoch: 0`), so the server's epoch counter has never
     been exercised by anything reachable from today's UI. A future
     crypto-lead-scoped cycle should start by tracing whether
     `AcceptInviteModal.tsx`'s `mlsAddMember` call (the one real
     production call site) already reconciles correctly or has the
     same gap, before attempting the Remove-side wiring.
  3. New, optional, informational (carried from cycle 495, unchanged):
     `rustls`'s default `aws-lc-rs` crypto provider compiled in but
     unused at runtime — `default-features = false` would shrink SBOM.
  4. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  5. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  7. Carried (unchanged from cycle 480's list): `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; GitHub issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  8. Growing: this file is now well past ~2800 lines — good
     STABILIZATION candidate for cycle 500 (next multiple of 5) to
     archive at, same pattern as cycles 360/485.

## Previous state (2026-09-15, cycle 495 — STABILIZATION: fix RUSTSEC-2026-0285 (rustls TLS 1.3 boundary bug) via dependency bump, harden `GroupRepository::save`'s blind upsert against epoch downgrade with a new integration test, commits 90dd021/5b46068)

- Mode selection: counter 494→495, 495 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` all green on main (cycle 494's push). `gh issue list
  --state open`: same 5 open issues as prior cycles (#1 SPA deploy, #2
  MLS Remove/PCS — large multi-cycle FEATURE item, #3 WS client, #4
  load testing, #5 prod-ap-seoul PIPA), none `bug`-labeled, none
  stabilization-sized — none picked. Working tree clean at session
  start (no orphaned WIP).
- **Picked a concrete item off the carried candidates list** rather than
  a vague sweep: "`GroupRepository::save` blind `ON CONFLICT DO
  UPDATE`" has been carried unactioned since ≥cycle 480's list. Traced
  it fully before acting: confirmed via grep that `PgGroupRepository`
  is the only non-test `GroupRepository` impl and every `save` call
  site in the whole repo is inside a `#[cfg(test)]`/test-fake module —
  it is dead in production today. The real MLS-Commit epoch-advance
  path already uses the correct CAS primitive
  (`advance_epoch`/`CommitLedger::commit_epoch_and_save`, explicitly
  documented in `powehi-grpc/src/server.rs` as the only safe one). The
  port trait doc's own claim that `save` is "still needed to persist an
  epoch advance on commit" turned out stale/false. So `save` was a live
  landmine in the API surface, not an active bug — a future caller
  reaching for the obviously-named "save a group" method could silently
  downgrade a group's epoch.
- **Fix, following the exact precedent set for `PgDeviceRepository::save`
  and `user_id` in cycle 445**: added `WHERE groups.epoch <=
  EXCLUDED.epoch` to `save`'s `ON CONFLICT DO UPDATE`
  (`group_repo.rs`) — Postgres skips the entire UPDATE (leaving every
  column, including `home_region`, untouched) whenever the incoming
  epoch would regress the stored one. This is a monotonic guard, not a
  full CAS (no caller-supplied `expected` to race against) — documented
  as such in both the SQL comment and the port trait doc, which was
  also corrected to drop the stale "needed to persist an epoch advance"
  claim.
- **security-auditor: PASS-with-nits on the first draft.** Confirmed the
  guard SQL is correct and race-safe under READ COMMITTED (Postgres
  re-evaluates `DO UPDATE ... WHERE` against the post-lock row version,
  no TOCTOU against `advance_epoch`'s CAS). Two cheap findings fixed in
  this cycle: (1) the port doc's "monotonic-safe" phrasing understated
  that `<=` (not `<`) means an EQUAL-epoch save still fully applies,
  including rewriting `home_region` — `save` remains a live
  home-region-repoint primitive for any non-decreasing epoch, not an
  inert no-op; clarified in both the SQL comment and port doc, and
  added an explicit equal-epoch boundary case to the new test. Two
  findings left as-is per the auditor's own low/informational call: (a)
  `save` returns `Result<(), _>` so a guard-skipped no-op is
  indistinguishable from an applied write — no caller today depends on
  telling them apart, changing the signature would ripple across every
  `GroupRepository` test fake for a method with zero production
  callers, not worth it this cycle; (b) `create_with_creator`/
  `upsert_members` still bind `group.epoch.0 as i64` (wraps negative)
  instead of `i64::try_from` like `save`/`advance_epoch` — pre-existing,
  unreachable today (both call sites pass hardcoded `Epoch(0)`), no
  `CHECK (epoch >= 0)` constraint exists.
- **New integration test** (Docker-gated,
  `pg_security_it.rs::save_never_downgrades_an_existing_groups_epoch`):
  proves all three epoch boundaries — a lower-epoch save is a full
  no-op (epoch AND home_region both survive unchanged), an equal-epoch
  save still fully applies, and a genuinely-higher-epoch save applies
  normally. Compiles clean (verified via `cargo build --tests -p
  powehi-postgres`); actually runs in CI's `--run-ignored all` step,
  not just locally.
- **Also fixed, found during the mandated `cargo audit`/`cargo deny
  check` security sweep**: RUSTSEC-2026-0285 (rustls <0.23.45, TLS 1.3
  handshake messages incorrectly accepted across encryption level
  boundaries, severity 5.3 medium). Not cosmetic — `rustls` 0.23.40 was
  pulled in by `tokio-rustls`→`tonic` (the real gRPC transport carrying
  inter-region mTLS traffic per prd.md), not just a dev/test-only path
  (a second copy also comes in via `testcontainers`'s `ureq`, which
  *is* dev-only, but that wasn't the blocking one). Fixed via `cargo
  update -p rustls --precise 0.23.45` — single targeted bump, not a
  broad `cargo update`. `cargo audit` and `cargo deny check` both clean
  after (664 crates, `advisories ok, bans ok, licenses ok, sources
  ok`). security-auditor separately noted (informational, not
  blocking) that the bump transitively pulled `aws-lc-rs`/`aws-lc-sys`
  forward too since `rustls`'s default crypto provider is `aws-lc-rs`,
  but `powehi-grpc/src/tls.rs` explicitly installs
  `ring::default_provider()` — so `aws-lc-rs` is compiled into the
  binary but unused at runtime; `default-features = false` on the
  `rustls` dep would shrink the SBOM/image surface, left as an optional
  future hardening, not applied this cycle (scope creep beyond the
  actual vulnerability fix). Confirmed separately that
  `app/src-tauri`'s own `Cargo.lock` has no `rustls` entry at all — not
  affected, no change needed there.
- **Full gate**: `cargo build --workspace` clean (both before and after
  the rustls bump). `cargo build --workspace --tests -p powehi-postgres`
  clean (confirms the new test compiles). `cargo clippy --workspace
  --all-targets -- -D warnings` clean. `cargo fmt --all --check` clean.
  `cargo test --workspace`: all 45 test-result lines `ok`, 0 failed (run
  twice — once before the rustls bump as a baseline, once after — no
  regression from either change; new test correctly shows `ignored,
  requires Docker` locally). `cargo audit`: 0 vulnerabilities (was 1
  before the fix). `cargo deny check`: `advisories ok, bans ok, licenses
  ok, sources ok` (was `advisories FAILED` before the fix). Frontend
  untouched this cycle, not re-run (Rust-only change).
- No `crypto-reviewer`/`threat-model-checker` run: no crypto/MLS/OPAQUE
  code touched, no new server-visible metadata or architectural
  shift — this hardens an existing DB write path's failure mode, it
  doesn't add one. `security-auditor` run instead (backend/DB change),
  matching the established routing precedent.
- Committed as two separate commits (distinct concerns): `90dd021`
  (`fix(deps): bump rustls to 0.23.45, fix RUSTSEC-2026-0285`), 1 file
  (`Cargo.lock`); `5b46068` (`fix(backend): guard GroupRepository::save
  against epoch downgrade`), 3 files (`group_repo.rs` ×2 — src and port
  trait — plus `pg_security_it.rs`). Both pushed clean (`fe89b4d..5b46068
  main -> main`). Watched CI to completion after push — **all 3 checks
  (`CI — Rust`, `CI — Frontend`, `CI — Live-backend E2E`) green on
  `5b46068`**, confirmed before ending the cycle.
- Target dir hygiene: `target/` at 15G (up from 12G at session start,
  under the 20G threshold — no pruning triggered), 0-byte `.rmeta`
  prune ran first per the mandated step order.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle** (carried since ≥cycle 480's list):
     `GroupRepository::save`'s blind `ON CONFLICT DO UPDATE`. Now
     monotonic-epoch-guarded, with a regression test. Two related,
     lower-priority informational items surfaced during the fix (not
     applied, not urgent): `save`'s `Result<(), _>` return type can't
     distinguish a guard-skipped no-op from an applied write; the
     pre-existing unreachable `as i64` cast in
     `create_with_creator`/`upsert_members` vs. `save`/`advance_epoch`'s
     `i64::try_from`.
  2. New, optional, informational (security-auditor note, not applied):
     `rustls`'s default `aws-lc-rs` crypto provider is compiled into the
     binary but unused at runtime (`powehi-grpc/src/tls.rs` explicitly
     installs `ring::default_provider()` instead) — `default-features =
     false` on the `rustls` workspace dependency would shrink the
     SBOM/image surface. Cheap if a future cycle touches TLS/deps again.
  3. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): epoch reconciliation
     between the client's local MLS epoch and the server's
     `groups.epoch` counter, and `mls_confirm_incoming_commit`
     handle-consumption-before-`MLS_CTX`-resolution ordering.
     FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass).
  4. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  5. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  7. Carried (unchanged from cycle 480's list, see cycle 480's own
     section — now archived — for full text if needed): `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; `PendingRemovalBanner`
     local cross-check hardening; GitHub issues #1/#3/#4/#5; prd.md §10
     REST API doc drift; `pending_removals` forged-signal defense;
     unconsumed `RemovalRequired` WS event; `key_packages.device_id` FK
     doc drift.
  8. Growing again: this file is approaching ~2600 lines — watch for it
     crossing the ~2500-line point a future STABILIZATION cycle should
     archive at (same pattern as cycles 360/485).

## Previous state (2026-09-13, cycle 494 — STABILIZATION (forced by red CI, counter said FEATURE): fix Docker Hub's removal of `minio/minio` breaking 2 of 3 CI checks, fix a frontend `tsc -b` type-inference break in a test mock, commit 2fa6184)

- Mode selection: counter 493→494, 494 % 5 != 0 → nominally FEATURE, but
  `gh run list --limit 5` showed all 3 checks (`CI — Rust`, `CI —
  Frontend`, `CI — Live-backend E2E`) failing on the last push to main
  (86d4f66) — FEATURE mode's own step 2 applied, ran as STABILIZATION.
  Working tree was clean at session start (no orphaned WIP).
- **Found an unlogged prior cycle first**: `86d4f66` (`feat(crypto,frontend):
  wire MLS Commit processing into the receive path (issue #2)`) sat on
  `main` with no `chore: update session memory` commit after it and no
  entry in this file — the session that produced it evidently ended before
  its end-of-cycle step. Read the commit message in full before doing
  anything else (see the new entry immediately below this one for what it
  actually contains) so this cycle's CI fix wouldn't be evaluated against
  the wrong baseline. This file's mandatory end-of-cycle memory update
  step is not optional even when a session is cut short — flag it if seen
  again.
- Root cause #1 (`CI — Rust`'s Integration Tests job + `CI — Live-backend
  E2E`, both red): `docker pull minio/minio:RELEASE.2025-02-28T09-55-16Z`
  failed with "repository does not exist or may require 'docker login'".
  Verified directly against the registry (not just the CI log): `curl
  https://hub.docker.com/v2/repositories/minio/minio/` returns `{"message":
  "object not found"}` — Docker Hub's entire `minio/minio` repository has
  been removed upstream (not just this tag), so **no tag** would have
  pulled; a "just bump the pin" fix (the usual move for this class of CI
  break, e.g. cycles 479/481's Tauri lockfile drift) would not have worked
  here. Confirmed the replacement home via `quay.io/api/v1/repository/minio/minio`
  — alive, and the exact pinned tag (`RELEASE.2025-02-28T09-55-16Z`) still
  exists there byte-for-byte (same `manifest_digest`). `minio/mc` (used by
  docker-compose's `minio-init`) was removed from Docker Hub the same way;
  `quay.io/minio/mc:latest` exists.
- The complication: `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs`
  used `testcontainers_modules::minio::MinIO` (0.15.0, confirmed via
  crates.io API to be the latest stable release — no newer version fixes
  this), whose `Image::name()` is hardcoded to the dead `"minio/minio"`
  string with no override hook; `.with_tag(...)` only changes the tag, not
  the repository. Fetched the modules crate's actual source (not
  docs.rs — 0.27.3's testcontainers docs failed to build, its
  `GenericImage` API summary came from a different route) to get its exact
  runtime shape: `ready_conditions()` waits for `"API:"` on **stderr**
  (the test file's own doc comment had this wrong as "stdout" — also
  corrected), `cmd()` is `["server", "/data"]`, `env_vars()` sets
  `MINIO_CONSOLE_ADDRESS=":9001"`. Replaced the `MinIO` struct with a
  hand-built `testcontainers::GenericImage::new("quay.io/minio/minio",
  MINIO_TAG)` reproducing that exact shape (`ContainerAsync<MinIO>` →
  `ContainerAsync<GenericImage>` in both the `Harness` struct field and
  `start_minio_with_bucket`'s return type). Verified by actually compiling
  (`cargo build -p powehi-r2 --tests` and `cargo clippy -p powehi-r2
  --tests --all-targets -- -D warnings`, both clean) — no local Docker in
  this sandbox to actually start the container, so the registry-API
  cross-check above is the closest available confirmation short of CI
  itself; watched CI to completion after push rather than assuming green
  (see below). Also repointed `docker-compose.yml`'s `minio`/`minio-init`
  services and `ci-rust.yml`'s pre-pull step at `quay.io`.
- Root cause #2 (`CI — Frontend`'s Bundle budget check, red, independent
  of the MinIO issue): `pnpm --filter app build` (`tsc -b && vite build`)
  failed with 3 `TS2345` errors in `useMessages.test.ts` — a real type bug
  in 86d4f66's own diff, not a flake. `mockWorker.mlsProcessCommit` was
  declared as `vi.fn(async () => ({ newEpoch: 2 }))`: the 0-arg initial
  stub fixed the mock's *inferred* type to a 0-parameter function, so a
  later `.mockImplementation(async (_identityId, _groupId, bytes) =>
  ...)` call (correctly typed against the REAL 3-parameter
  `mlsProcessCommit(identityId, groupId, commitBytes)` signature in
  `crypto.worker.ts:892`) became un-assignable — TS function subtyping
  rejects a source function that declares MORE parameters than the
  inferred target signature provides, since the target's callers would
  otherwise pass it `undefined` for the missing ones. This only surfaced
  now because `mlsProcessCommit` is the only mock in this file whose
  initial `vi.fn()` stub is later overridden via `.mockImplementation`
  with explicit parameter types (the others only use
  `.mockResolvedValue`/`.mockRejectedValueOnce`, which don't force a
  signature check against the stub). Fixed by typing the initial stub
  with the real 3-parameter signature so inference matches.
- **Full gate**: `cargo build --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --all --check` all clean.
  `cargo test --workspace` (nextest not installed in this sandbox,
  documented fallback used): every crate `0 failed` (`powehi-r2`: 55
  ignored, Docker-gated, expected; `powehi-crypto-wasm`: 232 passed/2
  ignored). `cargo audit`: 664 crates scanned, clean. `cargo deny check`:
  `advisories ok, bans ok, licenses ok, sources ok`. Frontend: `pnpm exec
  tsc -b` clean, `pnpm --filter app build` succeeds end-to-end (matches
  CI's actual failing step, not just `tsc --noEmit`), `pnpm exec biome
  check --write` on the touched test file (1 pure-formatting fix, no
  logic change), full `biome check` shows the same 4 pre-existing
  unrelated `app/src-tauri/gen/schemas/*.json` errors noted since ≥cycle
  472 (no regression), `pnpm exec vitest run`: 112 files/1631 tests green
  (unchanged from 86d4f66's own baseline). Validated both edited YAML
  files parse (`python3 -c 'import yaml; yaml.safe_load(...)'`).
- No `crypto-reviewer`/`threat-model-checker`/`security-auditor` run:
  matches the established precedent for CI/registry-config fixes (cycles
  479/481) — no crypto/MLS/OPAQUE logic touched (the r2 test-harness edit
  only changes which registry a throwaway container pulls from, not any
  adapter or crypto code), no server-visible metadata change, no backend
  handler logic changed (the mock-type fix is test-only).
- Committed `2fa6184` (`fix(ci,frontend): repoint MinIO at quay.io, fix
  mlsProcessCommit mock type inference`), 4 files changed
  (`.github/workflows/ci-rust.yml`, `app/src/hooks/useMessages.test.ts`,
  `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs`,
  `docker-compose.yml`), pushed clean (`86d4f66..2fa6184 main -> main`).
  Watched CI to completion after push (see below for result) rather than
  assuming green from local checks alone, given the Docker-dependent fix
  couldn't be locally verified end-to-end.
- Target dir hygiene: not checked in depth (STABILIZATION mode, but the
  fix itself is the mandated priority-1 action this cycle — CI-red always
  comes before target-dir hygiene per this file's own STABILIZATION step
  order).
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle**: CI red on main (Docker Hub `minio/minio`/
     `minio/mc` removal + frontend `tsc -b` mock-type break). If CI shows
     red again on a MinIO-touching job, don't assume this is the same
     class recurring — the registry move is a one-time upstream event,
     not a periodic drift like the Tauri lockfile class (cycles 479/481).
  2. **Resolved this cycle** (retroactively, see the entry below): the
     "wire MLS commit-processing into the receive path" item that had
     been carried as issue #2's single largest remaining piece since
     ≥cycle 466's list. Confirm via a fresh read of issue #2 in a future
     cycle whether it should now be closed or whether the entry below's
     "capability shifts... accepted as the necessary cost" framing implies
     follow-up hardening work first.
  3. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  4. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  5. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  6. New, from 86d4f66's own commit message (not yet independently
     verified this cycle — read it before acting): prd.md §3.1/§3.4 and
     ADR-0005 were updated to document two capability shifts the receive-
     path wiring introduces — the Delivery Service's envelope ordering
     becoming a permanent content-loss lever under `max_past_epochs(0)`,
     and a compromised member device (not the server) now being able to
     silently add/remove other members with no application-level policy
     gate. `threat-model-checker` graded this YELLOW (documented, not
     RED) per that commit's own claim — worth an independent re-check in
     a future cycle rather than trusting the prior session's self-report
     indefinitely.
  7. Carried (unchanged from cycle 480's list, see cycle 480's own
     section — now archived — for full text if needed):
     `mls_confirm_incoming_commit` handle-consumption-before-`MLS_CTX`-
     resolution ordering; epoch reconciliation; `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; `PendingRemovalBanner`
     local cross-check hardening; GitHub issues #1/#3/#4/#5; prd.md §10
     REST API doc drift; `pending_removals` forged-signal defense;
     unconsumed `RemovalRequired` WS event; `key_packages.device_id` FK
     doc drift; `GroupRepository::save` blind `ON CONFLICT DO UPDATE`.

## Previous state (2026-09-12, cycle unknown — likely 486-493, exact number lost: no memory entry was ever written for this cycle, discovered retroactively at the start of cycle 494 — FEATURE: wire MLS Commit processing into the receive path, issue #2, commit 86d4f66)

- **This entry is reconstructed entirely from `git show 86d4f66`'s commit
  message** (reproduced/condensed below), not from this session's own
  work — flagged here so a future reader doesn't mistake it for
  first-hand cycle-494 testimony. The session that did this work ended
  before running its end-of-cycle memory-update step, so cycle 494 opened
  with `main` one full FEATURE-mode commit ahead of this file's last
  entry and no record of what happened in between (see cycle 494's entry
  above for how that was discovered and handled).
- Per the commit message: closed the largest remaining piece of issue #2
  (P0-blocker: no MLS Remove path, PCS unattainable). `useMessages.ts` now
  merges peer Commit envelopes for its own group via the
  `mlsProcessCommit`/`mlsGroupIsActive` WASM exports, in the same poll
  cursor as Application decrypt, with bounded per-group head-of-line
  ordering between the two envelope types. Self-eviction surfaced via a
  new dismissable banner (previously `console.error` only); the group/DM
  Safety Number now recomputes on every merged Commit instead of only on
  mount or a local memberCount change.
- Two distinct own-commit sentinels (`MLS_OWN_COMMIT_ERROR`,
  hash-verified/safe-to-ack; `MLS_OWN_COMMIT_PENDING_ERROR`, openmls's own
  forgeable pre-merge signal, must NOT auto-ack) replaced the single prior
  `MlsError::OwnCommit`. `mlsGroupIsActive` reads openmls's own
  group-active state instead of the leaf-index-based `isSelf`, which has
  a false negative on a "kick and replace" Commit reusing the evicted
  device's leaf for a new member.
- Per the commit message, a fresh `crypto-reviewer` pass found 2 blocking
  findings, both fixed before commit: a per-sender deferred-Commit cap
  that fired before checking shared-pool room (silently dropping a lone
  legitimate committer's backlog), and Proposal envelopes left
  permanently unacked on an incorrect RFC 9420 §12.4 justification. A
  `threat-model-checker` finding was also fixed: the Safety Number
  recompute trigger was gated on `chat.isGroup`, excluding DMs even
  though prd.md models a DM as a 2-member MLS group.
- Per the commit message: documented two capability shifts in prd.md
  §3.1/§3.4 and ADR-0005 (see cycle 494's candidate list item 6 above) —
  `threat-model-checker` graded YELLOW (documented, not RED), not
  independently re-verified this cycle.
- Per the commit message: `cargo test --workspace` 232/232 in
  `powehi-crypto-wasm`, 0 failures workspace-wide; `pnpm vitest run`
  112/112 files, 1631/1631 tests (up from 1615/1627 baseline);
  clippy/fmt/tsc/biome clean AT THE TIME OF THAT COMMIT — cycle 494's
  entry above found `tsc -b` (the actual `pnpm --filter app build` step,
  not `tsc --noEmit`) broken on this exact commit when CI ran it, so
  whatever local check produced "tsc clean" in this message either used a
  different invocation or the type-checker's mock-inference issue was
  narrowly missed.
- Committed `86d4f66`, pushed to main. Per the commit message, a progress
  comment was intended for issue #2 — not independently verified this
  cycle; check issue #2's comment history in a future session.

## Previous state (2026-09-11, cycle 485 — STABILIZATION: archive stale memory (carried candidate since cycle 480), fix a real bare-`var(--photon)` CSS bug flagged since cycle 452, full security sweep clean)

- Mode selection: counter 484→485, 485 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` all green on `main` (cycle 484's push, all 3 checks
  `success`). `gh issue list --state open`: same 5 open issues as prior
  cycles (#1 SPA deploy, #2 MLS Remove/PCS — large multi-cycle FEATURE
  work in progress, #3 WS client, #4 load testing, #5 prod-ap-seoul
  PIPA), none `bug`-labeled, none stabilization-sized — none picked.
  Working tree clean at session start (no orphaned WIP this time, unlike
  most recent cycles).
- **Memory archiving** (carried candidate since ≥cycle 480's list,
  "growing... good STABILIZATION candidate"): this file had grown to
  3035 lines, well past the ~2385-line point cycle 360 last archived at.
  Split at the cycle 452/453 boundary (same "keep the last ~15-20 cycles
  inline" precedent as every prior archive): cycles 443-452 (the oldest
  6 entries) moved verbatim to
  `.claude/memory/archive/project-context-cycles-443-452.md` (806
  lines), leaving cycles 453-484 (16 entries) inline. Added an "Archive
  index" section listing all 8 archive files by cycle range so a future
  session can find any older entry without grepping blind. File is now
  2246 lines (this entry included).
- **Real fix, not just housekeeping**: grepped for the bare `var(--photon)`
  CSS custom property this pointer has carried as a known cosmetic bug
  since ≥cycle 452's list. Confirmed `app/src/index.css` only ever
  defines scale tokens (`--photon-50`…`--photon-700`), never a bare
  `--photon` — so `LinkedDevicesPanel.tsx`'s current-device lock icon and
  `PendingRemovalBanner.tsx`'s shield icon were silently getting an
  invalid custom-property value (CSS spec: invalid `var()` with no
  fallback makes the whole declaration's computed value invalid, so the
  `color` prop had no effect instead of erroring). Cross-checked
  `docs/design/powehi-design-system/project/README.md`'s hard brand rule
  ("the lock icon is always photon blue, `#A8C8FF`, regardless of
  surface") against `colors_and_type.css`'s token table — `#A8C8FF` is
  exactly `--photon-300`. Fixed both call sites to `var(--photon-300)`;
  `Icon.test.tsx` already asserts `color` is passed through verbatim as
  the `stroke` attribute, so no test needed the token value itself
  updated, just confirmed no other file referenced the bare form.
- **Full gate**: `cargo build --workspace`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo fmt --all --check` all clean.
  `cargo test --workspace`: 45/45 test-result lines `ok`, 0 failed (no
  crate touched this cycle — ran as the mandated stabilization-cycle
  full-suite check, not because Rust code changed). `cargo audit`: 664
  crates scanned, exit 0, no advisories. `cargo deny check`: `advisories
  ok, bans ok, licenses ok, sources ok`. Frontend: `pnpm exec tsc
  --noEmit` clean; `pnpm exec biome check` — both edited files clean
  after `--write` auto-fixed a line-length wrap `color={...}` triggered
  (JSX prop split across lines), remaining 4 errors are the same
  pre-existing unrelated `app/src-tauri/gen/schemas/*.json` issues noted
  since ≥cycle 472; `pnpm vitest run`: 112 files/1615 tests green,
  unchanged from baseline (no regression from the color-token swap).
- No `crypto-reviewer`/`threat-model-checker`/`security-auditor` run:
  pure CSS custom-property value fix in two already-reviewed React
  components, no crypto/MLS/OPAQUE code, no server-visible metadata, no
  backend/infra touched — matches the established routing precedent for
  cosmetic-only frontend diffs.
- Committed (pending push at cycle end), 2 files changed
  (`LinkedDevicesPanel.tsx`, `PendingRemovalBanner.tsx`) plus the memory
  archive split as a separate `chore:` commit per this file's own
  end-of-cycle convention.
- Target dir hygiene: `target/` at 9.9G (well under the 20G threshold,
  0-byte `.rmeta` prune ran, no further pruning triggered).
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle** (carried since ≥cycle 452's list): bare
     `var(--photon)` CSS token bug. Both call sites now use the correct
     `--photon-300` scale token.
  2. **Resolved this cycle** (carried since ≥cycle 480's list): this
     file's size — archived cycles 443-452, back down to a manageable
     length. Watch for it growing past ~2300-2500 lines again in future
     cycles and repeat the same split.
  3. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): the MLS commit-processing
     consumer-loop wiring into `useMessages.ts`/`useWelcomePoller.ts` —
     genuinely FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass), not a stabilization-sized fix.
  4. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  5. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  7. Carried (unchanged from cycle 480's list, see cycle 480's own
     section — now archived — for full text if needed):
     `mls_confirm_incoming_commit` handle-consumption-before-`MLS_CTX`-
     resolution ordering; epoch reconciliation; `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; `PendingRemovalBanner`
     local cross-check hardening; GitHub issues #1/#3/#4/#5; prd.md §10
     REST API doc drift; `pending_removals` forged-signal defense;
     unconsumed `RemovalRequired` WS event; `key_packages.device_id` FK
     doc drift; `GroupRepository::save` blind `ON CONFLICT DO UPDATE`.

## Archive index
Cycles 20-277: `.claude/memory/archive/project-context-cycles-20-277.md`
Cycles 279-319 (+cyclelog): `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
Cycles 320-339: `.claude/memory/archive/project-context-cycles-320-339.md`
Cycles 340-371: `.claude/memory/archive/project-context-cycles-340-371.md`
Cycles 372-401: `.claude/memory/archive/project-context-cycles-372-401.md`
Cycles 402-421: `.claude/memory/archive/project-context-cycles-402-421.md`
Cycles 425-431: `.claude/memory/archive/project-context-cycles-425-431.md`
Cycles 443-452: `.claude/memory/archive/project-context-cycles-443-452.md`
Cycles 453-484: `.claude/memory/archive/project-context-cycles-453-484.md`
