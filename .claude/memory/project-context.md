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

## Current state (2026-09-03, cycle 424 — FEATURE: R2 orphan-object sweep + close 2 RED review findings, commit 27647b0)

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

## Previous state (2026-09-03, cycle 421 — FEATURE: sweep the cycle-420 dead-Escape-key bug across 4 more dialogs, commit 158bb60)

- CI green at cycle start (`gh run list --limit 5` all success), `git status` clean,
  `gh issue list --state open` empty.
- Cycle 420's own "next cycle candidates" flagged the exact `onClick`+`onKeyDown`
  both-stopPropagation pattern as reused verbatim elsewhere in `ChatLayout.tsx`
  beyond `SettingsPanel`, worth a dedicated sweep rather than fixing
  opportunistically. `grep -n 'onKeyDown={(e) => e.stopPropagation()}'
  app/src/components/ChatLayout.tsx` found 5 occurrences. Inspected each site's
  enclosing function and ancestor chain before touching anything (same discipline
  as cycle 420 — not every hit is a live bug): `Lightbox`'s
  `lightbox-image-container` (line ~4882) is backed by a
  `window.addEventListener("keydown", ...)` in a `useEffect` — React's synthetic
  `stopPropagation()` only blocks the React-level onKeyDown chain, not a native
  window-level listener, so Escape/arrow-keys still work there (not a bug, left
  alone); `CallOverlay`'s `<dialog>` (line ~6871) has no ancestor Escape handler
  at all to block (verified — the outer `call-overlay` div has neither onClick nor
  onKeyDown), so the stopPropagation is a harmless no-op (left alone, and
  confirmed correct-as-is by the security-auditor pass below). The other 3 —
  `StatusEditor`'s `status-editor` content div (line ~1122), the forward-message
  modal's `forward-modal` content div (line ~10459), and
  `KeyboardShortcutsModal`'s unnamed content div (line ~10709) — each had a real,
  live parent-overlay Escape handler being silently blocked, identical to cycle
  420's SettingsPanel bug.
- **Fix applied to all 3 real sites:**
  `onKeyDown={(e) => { if (e.key !== "Escape") e.stopPropagation(); }}` — same
  pattern cycle 420 used, still blocks Enter/Space/etc. from bubbling (whatever
  the original stopPropagation's a11y-lint purpose was) while explicitly letting
  Escape through to reach the overlay's own `Escape → onClose` handler.
- **Tests added/fixed, mutation-verified myself before committing** (temporarily
  `git stash push -- <file>` to isolate just the production fix per file, ran the
  new/changed test, confirmed it failed, `git stash pop` to restore):
  1. `ChatLayoutCustomStatus.test.tsx` — new Escape-close test. First attempt
     dispatched from `status-text-input`, which **passed even with the bug
     present** — turned out that specific input has its own independent
     `onKeyDown={(e) => { if (e.key === "Escape") onClose(); }}` handler,
     completely bypassing the wrapper-level bug. Caught this by mutation-testing
     rather than trusting a green run; switched the test to dispatch from
     `status-emoji-input` instead (verified it has no own onKeyDown), which
     correctly failed pre-fix and passes post-fix.
  2. `ChatLayoutForwarding.test.tsx` — new Escape-close test dispatched from
     `forward-modal-close` (a real descendant of the buggy wrapper).
  3. `ChatLayoutShortcuts.test.tsx` — fixed test #8 ("pressing Escape closes the
     modal"), which was a false positive of the exact same class cycle 420 found
     for SettingsPanel: it dispatched `fireEvent.keyDown` directly on the
     `keyboard-shortcuts-modal` testid, which IS the outer dialog owning the
     correct handler — never exercised the inner wrapper's bug at all. Fixed to
     dispatch from `keyboard-shortcuts-close` (inside the buggy wrapper) instead.
- **Ran `security-auditor` proactively** (frontend-only, security-adjacent
  dialog-dismiss UX — same precedent as cycle 420) on the diff before committing.
  **Verdict: GREEN.** Confirmed no security regression (the only handlers newly
  reachable via Escape bubble-through are the pre-existing pure-dismiss `window`
  listeners for the lightbox and in-chat search — no send/delete/key-rotation
  action reachable). It independently traced every patched site's ancestor chain
  and confirmed the fix is genuinely load-bearing (not cosmetic) at all 3.
  **Found 2 more real instances I hadn't checked, both fixed in the same commit:**
  `AddMemberModal.tsx`'s content-wrapper div had the identical unconditional
  `onKeyDown={(e) => e.stopPropagation()}` blocking its own `<dialog>`'s Escape
  handler — notably this component ALSO has a
  `document.addEventListener("keydown", ...)` fallback listener as a second line
  of defense, but the auditor correctly identified that doesn't save it either:
  React's synthetic `stopPropagation()` calls through to
  `nativeEvent.stopPropagation()`, which halts native propagation before it ever
  reaches a `document`-level listener. And `AddMemberModal.test.tsx` had the same
  false-positive-test class: `fireEvent.keyDown(document, {key: "Escape"})` hits
  the document listener directly, bypassing the DOM tree (and the buggy wrapper)
  entirely — fixed to dispatch from `contact-option` instead (mutation-verified
  the same stash/pop way as the other 3).
  **2 additional findings deferred as non-blocking (info-level, not fixed this
  cycle):** (a) `Lightbox`'s `lightbox-image-container` stopPropagation is
  currently latent/harmless (no focusable descendant today — only a
  non-focusable `<img>`) but would become a live bug the moment that subtree
  gains a focusable element (e.g. video controls); (b) Escape now
  double-dismisses across layers in one edge case — if the in-chat search bar
  (Ctrl+F) happens to be open when one of the 4 patched dialogs is also open, a
  single Escape closes both, since the dialogs' own Escape handlers don't call
  stopPropagation after handling it. Purely cosmetic (clears a local,
  non-sensitive search query), not a security issue.
- Not crypto (no `.rs`/WASM file touched) — `crypto-reviewer` correctly not
  invoked. Not architectural (no new API surface, DB column, or server-visible
  metadata; pure client-side dialog-dismiss UX, same as cycle 420) —
  `threat-model-checker` correctly not invoked.
- Verified before commit: `npx tsc -b` clean; `npx biome check` clean on all 6
  touched files; full suite 111 files/1582 tests green (was 1580 at cycle 420
  end, +2 new tests from this cycle — `ChatLayoutPoll.test.tsx` transiently
  failed once mid-suite on an unrelated pre-existing test-order flake,
  unreproducible in isolation and gone on a clean full-suite rerun, confirmed
  unrelated since this cycle touched zero poll-related code).
- **Process note:** the Bash tool's cwd did NOT reliably persist a `cd app &&`
  prefix across separate tool-call invocations this cycle (worked within one
  invocation, reverted to repo root on the next) — used full `app/`-prefixed
  paths from repo root for `git stash push -- <path>` to avoid a pathspec
  mismatch after cwd silently reset.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:**
  1. The 2 deferred security-auditor info findings above (lightbox latent
     instance, double-dismiss cosmetic edge case) — both explicitly judged
     non-blocking/optional, pick up only if a future cycle has nothing
     higher-value.
  2. Carried from cycle 419/420: orphan-object sweeper for R2 `delete()`'s
     untested/unreachable 4th state (S3 object present, DB row absent) — needs a
     design decision (periodic sweep vs. upload-confirmation transaction), good
     backend-lead task, FEATURE mode.
  3. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 + libcrux/x-wing
     admissibility) remains a human/crypto-lead policy call, not a blind retry.
  4. Carried: prd.md §6.4's cross-region abuse-signal propagation ("차단된 IP/
     사용자 → 전 리전 전파") documented-but-unimplemented — worth a
     threat-model-checker-gated scoping pass before committing to size.
  5. project-context.md is well past the point where the next STABILIZATION
     cycle should archive older cycles again (last archived at cycle 390) — this
     file hits the Read tool's pagination cap on the first read attempt every
     cycle now.

## Previous state (2026-09-03, cycle 420 — STABILIZATION: SettingsPanel Escape-close test gap → found & fixed a real dead-code bug, commit 5af1f5f)

- CI green at cycle start (`gh run list --limit 5` all success), `git status` clean,
  `gh issue list --state open` empty. Reconfirmed cycle 419's PATH note: bare `cargo`
  is NOT on this Bash tool's default `$PATH`; `export PATH="$HOME/.cargo/bin:$PATH"`
  before any cargo/cargo-audit/cargo-deny invocation. With it: `cargo audit` clean (0
  vulnerabilities), `cargo deny check` clean (advisories/bans/licenses/sources all ok),
  `pnpm audit` (in `/app`) clean (no known vulnerabilities — the 23 dev/build-time
  findings noted around cycle 372 are gone, presumably resolved by later dependency
  bumps). `cargo build --workspace` + `cargo test --workspace` both clean (no nextest
  installed in this environment, same fallback as cycle 419). Target dir 13G, under the
  20GB hygiene threshold — no pruning needed.
- Structural test-gap search (LOC-vs-test-count per crate/component, TODO/unimplemented
  grep) found nothing conclusive in the backend — ports crates have 0 tests but are pure
  trait defs with no logic; `powehi-webpush` initially looked undertested by a bad grep
  but actually has 13 solid tests. On the frontend, `SettingsPanel.tsx` had no dedicated
  test file — but it turned out to already be well covered indirectly via
  `ChatLayoutSettings.test.tsx` (open/close, logout success/fail, devices-row nav). The
  real gap: that file never exercised Escape-key dismiss, backdrop-click dismiss,
  inner-content-click non-dismiss, or "does the `view` sub-state reset to main on
  close+reopen" (relevant because `<SettingsPanel open={...}>` is always mounted in
  `ChatLayout.tsx` — it returns `null` when closed rather than unmounting, so internal
  `useState` persists across open/close unless explicitly reset).
- **Writing the Escape test surfaced a real bug, not a test artifact:** the shared
  content wrapper div (`data-testid="settings-panel"`, wraps both the main view and the
  devices sub-view) had `onKeyDown={(e) => e.stopPropagation()}` right next to its
  `onClick={(e) => e.stopPropagation()}` — added, per an identical pattern reused
  verbatim elsewhere in `ChatLayout.tsx` (e.g. `status-editor` at ~line 1122), purely to
  satisfy biome's `useKeyWithClickEvents` a11y lint rule, not for functional reasons.
  Net effect: it silently swallowed **every** keydown including Escape before it could
  bubble to the overlay `<dialog>`'s own `onKeyDown={Escape → handleClose}` handler —
  and nothing ever focuses the bare overlay element itself (`<dialog open>`, not
  `.showModal()`, no autofocus/focus-trap), so that handler was unreachable by any real
  user action. Escape-to-close was dead code in production.
- **Verified the fix is load-bearing, not just a plausible story:** `git stash` on just
  `SettingsPanel.tsx` reproduced 2 failing tests (Escape dismiss from both the main view
  and the devices sub-view — the wrapper div is shared by both branches, so the bug hit
  both equally). Fix: `onKeyDown={(e) => { if (e.key !== "Escape") e.stopPropagation(); }}`
  — keeps the lint-satisfying handler present (still stops Enter/Space etc. from
  bubbling) while explicitly letting Escape through. `biome check` clean on both touched
  files after the change.
- **security-auditor pass (this session): YELLOW with 3 findings, all addressed in the
  same commit** before pushing: (1) the original Escape tests dispatched
  `fireEvent.keyDown` directly on the `settings-overlay` testid — an unreachable event
  target in real usage, so they'd have passed even with the bug present; rewrote both to
  dispatch from inside the panel content (`settings-panel` / `linked-devices-panel`) so
  they exercise genuine DOM bubbling; (2) the logging-out re-entrancy test only asserted
  `toBeDisabled()` structurally; added a second click + `logoutSpy` call-count assertion
  to prove the gate actually holds behaviorally; (3) `afterEach` reset `phase`/
  `deviceId`/`sessionToken` but never restored `logout` after a test overwrote it with a
  spy — fixed by capturing `useAuthStore.getState().logout` once at describe-scope and
  restoring it in `afterEach`, preventing fixture bleed into later tests in the file.
  Info-disclosure check on new fixture literals (`tok-settings-test-2`,
  `dev-settings-test-2`): clean, matches existing synthetic-fixture convention.
- Not crypto (no crypto/MLS/OPAQUE/WASM file touched) — `crypto-reviewer` correctly not
  invoked. Not architectural (no new API surface, DB column, or server-visible metadata;
  pure client-side dialog-dismiss UX) — `threat-model-checker` correctly not invoked.
- 6 new tests in `ChatLayoutSettings.test.tsx` (10/10 in-file), full frontend suite 111
  files / 1580 tests green, `tsc --noEmit` clean, `biome check` clean on both touched
  files. No backend files touched this cycle — `cargo build/test --workspace` above was
  the pre-existing baseline check, not re-run post-change (frontend-only diff).
- Target dir hygiene: checked this cycle (STABILIZATION) — 13G, under the 20GB
  threshold, no pruning triggered; ran the 0-byte `.rmeta` prune unconditionally (no-op,
  none found).
- **Next cycle candidates:**
  1. The exact `onClick`+`onKeyDown` both-stopPropagation pattern that caused this bug
     is reused verbatim in several other `ChatLayout.tsx` inline dialogs (confirmed at
     minimum `status-editor` ~line 1122; likely `StarredPanel` and others sharing the
     "fixed-overlay dialog" pattern SettingsPanel's own doc-comment references) — each
     one likely has the same dead-Escape-key bug. Worth a dedicated sweep (grep
     `onKeyDown={(e) => e.stopPropagation()}` across `ChatLayout.tsx`, fix each with the
     same `if (e.key !== "Escape")` guard, add regression tests) rather than fixing
     opportunistically one file at a time.
  2. Orphan-object sweeper for R2 `delete()`'s untested/unreachable 4th state (S3 object
     present, DB row absent) — carried from cycle 419, needs a design decision (periodic
     sweep vs. upload-confirmation transaction), good backend-lead task, FEATURE mode.
  3. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 + libcrux/x-wing
     admissibility) remains a human/crypto-lead policy call, not a blind retry.
  4. Carried (informal Explore flag, not authoritative): prd.md §6.4's cross-region
     abuse-signal propagation ("차단된 IP/사용자 → 전 리전 전파") documented-but-
     unimplemented — worth a threat-model-checker-gated scoping pass before committing
     to size.
  5. project-context.md now ~3800 lines — approaching the point where the next
     STABILIZATION cycle should archive older cycles again (last archived at cycle 390;
     archive threshold has been "hits the 256KB Read cap", which already happened this
     cycle's first read attempt).

## Previous state (2026-09-02, cycle 419 — FEATURE: prove R2 delete's crash self-heal with a regression test, commit 2ef9d89)

- CI green at cycle start (`gh run list --limit 5` all success), `git status`
  clean, `gh issue list --state open` empty. **Found and fixed a tooling gap
  first:** the Bash tool's default `$PATH` in this environment does not
  include `~/.cargo/bin`, so bare `cargo ...` invocations fail with "command
  not found" — this, not a real hang, is almost certainly what cycles
  414/415/418 logged as a "persistent `cargo audit` hang" (2+ cycles noted,
  never actually reproduced once PATH was fixed). Confirmed clean with the
  correct PATH: `cargo audit` (0 vulnerabilities, ~5s, no hang), `cargo deny
  check` (advisories/bans/licenses/sources all ok), `pnpm audit` in `/app`
  (no known vulnerabilities). **Action for future cycles:** `export
  PATH="$HOME/.cargo/bin:$PATH"` before any `cargo`/`cargo-audit`/`cargo-deny`
  invocation in a fresh Bash call, or the same false "hang" will recur.
- Delegated an Explore-style research pass (no code changes) to find a
  concrete next task since memory's own carried-candidate list was empty
  with confidence. It ranked a real, previously-flagged-but-never-tested gap
  top: `R2MediaAdapter::delete` (`crates/adapters/outbound/powehi-r2/src/lib.rs:255-272`)
  deletes the S3 object before the Postgres row; a crash between the two
  steps leaves an orphaned row pointing at a deleted object. A cycle-372
  security-auditor pass had judged this "self-healing" (retried `delete()`
  just re-issues an idempotent S3 DELETE-on-missing-key, then finishes the
  DB delete) but nobody had ever written a test proving that recovery path
  actually works.
- **What it does:** added
  `delete_retry_after_crash_between_s3_and_db_steps_is_idempotent` to
  `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs` (testcontainers
  Postgres+MinIO, `#[ignore]`, runs in CI via the existing `r2_media_it`
  nextest binary). It uploads real bytes through the adapter's presigned
  URL, deletes the object directly via the raw S3 client (reproducing the
  exact post-crash state: object gone, row still present — since `delete()`
  has no intermediate state beyond those two ordered calls), asserts that
  state, then retries `adapter.delete()` and asserts it succeeds and
  finishes removing the row. Also tightened the file's header doc-comment
  list to describe the new coverage.
- Not crypto (no `.rs` crypto/MLS/OPAQUE/WASM file touched) — `crypto-reviewer`
  correctly not invoked. Not architectural/new-metadata (test-only, no new
  API surface, no DB schema change) — `threat-model-checker` correctly not
  invoked. Ran `security-auditor` anyway (backend adapter behavior,
  data-integrity-adjacent): **verdict GREEN**, no blocking findings. It
  confirmed the test reproduces the crash state with no timing assumption,
  no plaintext/PII/secret leakage (synthetic `b"opaque-ciphertext-bytes"`
  body, matches existing fixture conventions), no flakiness (each test gets
  its own fresh Postgres+MinIO container pair, `TEST_BUCKET` is a per-container
  name not shared mutable state), and that the 3 tests together
  (`delete_removes_s3_object_and_row`, this new test,
  `delete_nonexistent_id_is_a_noop`) now cover all 3 reachable
  {S3 object, DB row} states along `delete()`'s crash timeline. One
  **non-blocking LOW finding, deferred (see next-cycle candidates)**: the
  4th state — S3 object present, DB row absent (e.g. a succeeded presigned
  PUT whose row was never/no-longer persisted) — is untested AND
  unreachable by `delete()` itself (`find_by_id` returns `None`, short-
  circuiting the S3 call), so such an object leaks permanently; needs an
  orphan-object sweeper, not a change to this test.
- Verified before commit: `cargo test -p powehi-r2 --test r2_media_it
  --no-run` compiles clean (no Docker available in this sandbox to actually
  run the `#[ignore]`d testcontainers tests locally — CI's `ci-rust.yml` runs
  them via `cargo nextest run -p powehi-r2 --run-ignored all -E
  'binary(r2_media_it)'` with real Docker); `cargo clippy -p powehi-r2
  --all-targets -- -D warnings` clean; `cargo fmt --check` clean (one nit
  auto-fixed: chained method call formatting); `cargo build --workspace`
  clean; `cargo test --workspace` (fallback, no nextest installed in this
  environment either — noted for future cycles) 0 failures across every
  crate.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:**
  1. Orphan-object sweeper for the S3-object-present/DB-row-absent state
     flagged by this cycle's security-auditor pass (storage cost + data-
     retention exposure) — needs a design decision (periodic sweep vs.
     upload-confirmation transaction) before implementation, good backend-lead
     task.
  2. `pnpm PATH` note above should be treated as durable tooling knowledge,
     not re-investigated as a mystery hang.
  3. Carried from cycle 407: PQ hybrid Phase A prerequisite (ml-kem
     0.2.3→0.3.2 + libcrux/x-wing admissibility) remains a human/crypto-lead
     policy call, not a blind retry.
  4. A separate Explore-agent pass (informal, not authoritative) flagged
     prd.md §6.4's "차단된 IP/사용자 → 전 리전 전파 (Redis pub/sub 또는 gRPC)"
     cross-region abuse-signal propagation as documented-but-unimplemented —
     worth a threat-model-checker-gated scoping pass before committing to
     implementation size, since it's a real architectural change (new
     inter-region signal), not confirmed cycle-sized.

## Previous state (2026-09-02, cycle 418 — FEATURE: implement the local-only block-contact feature (InfoPanel), commit ac750cb)

- CI green at cycle start (`gh run list --limit 3` all success). `git status`
  was **not clean**: `app/src/components/ChatLayout.tsx` and
  `app/src/db/schema.ts` had substantial uncommitted diffs, plus an untracked
  `app/src/components/ChatLayoutBlock.test.tsx` (21 tests) — a complete,
  working "block contact" feature left over from an interrupted prior
  session (same recurring failure mode as cycles 405/406/410: real work
  landed without its commit step). Read the full diff before touching
  anything, verified it built/passed clean (`tsc -b`, `biome check`, and the
  new test file 21/21) before deciding whether to finish it or discard it —
  chose to finish it: coherent, well-scoped, and closes a real gap (the
  InfoPanel "Block · Report" button had rendered with zero handler since the
  very first mock-UI commit).
- **What it does:** local-only `blocked` boolean on `GroupRow` (Dexie schema
  v28) toggled via InfoPanel's Block button (inline confirm) / single-click
  Unblock. No MLS message, no server contact — confirmed by inspection and a
  new test. While a chat is blocked: incoming messages are still persisted
  to Dexie (history survives an eventual unblock) but suppressed from the
  visible message list/sidebar preview/unread+mention counts/notifications
  (sound/vibrate/OS); peer-driven side-channel signals (typing, reactions,
  edits, deletes, pins, presence/lastSeenAt) are suppressed too, including
  while the blocked chat is the open/active conversation — the sharpest case
  being edit-injection into an already-rendered, already-trusted bubble.
- **Ran a fresh `security-auditor` pass myself before committing** rather
  than trusting the diff's own inline comments (which claimed several
  "security-auditor finding, this cycle" fixes were already applied) — since
  I had no way to verify that a prior review actually happened or was
  thorough in an interrupted session, treated the diff as unreviewed.
  **Verdict: YELLOW, all findings fixed before commit:**
  1. **Plaintext PII write (MEDIUM):** `handleToggleBlock`'s fallback
     insert-if-update-affected-zero-rows path called raw `db.groups.add()`,
     bypassing `encryptedDb.addGroup()` — `name` and `mlsStateB64` are both
     in `encrypted-db.ts`'s `SENSITIVE.groups` list, so this wrote the
     contact's display name to IndexedDB unencrypted. Fixed: routed through
     `encryptedDb?.addGroup()` instead.
  2. **Missed suppression call sites (LOW-MED):** `handleIncomingReadReceipt`
     and `handleIncomingDeliveryReceipt` were unguarded on `blocked` — a
     blocked peer could still flip our own bubbles to "read"/"delivered" and
     have it persisted (a liveness oracle: confirms their message is still
     being processed). `handlePqBinding` (safety-number header badge) was
     also unguarded. Fixed: added the same `chatsRef.current...?.blocked`
     early-return / in-map guard used by the other suppression call sites.
  3. **Understated race-window comment (MEDIUM, doc-only):** a comment
     claimed the accepted "blocked flag hasn't hydrated yet" merge race was
     "mount-time only" — actually recurs on every switch into a blocked chat
     (no bulk `GroupRow.blocked` preload exists; `useMessages` polls
     immediately on every group switch), worst exactly when a server-side
     backlog bursts in at that moment. Corrected the comment; the underlying
     race itself remains accepted/deferred (fixing it was tried and reverted
     in the original diff — breaks the pinned/unread-divider restore
     effects, a larger sequencing change than this cycle's scope).
  4. **Unhandled rejection (LOW):** the `db.groups.update().then()` chain had
     no outer `.catch()`. Fixed.
  5. **Test gaps:** added a test asserting block/unblock never calls
     `mlsEncrypt` or `sendMessage` (the highest-value untested claim per the
     auditor), and split the mislabeled "vibration, sound, or OS
     notification" test (which only asserted vibration) into a real
     vibration test plus a new dedicated sound-suppression test spying on
     `playNotificationSound`. Not added (accepted gap, lower value): explicit
     tests for `onDelete`/`onReactionRemove`/auto-unarchive-while-blocked/
     mentionCount-reset-while-blocked — all use the identical
     `if (c.blocked) return c;` guard pattern already covered by the
     edit/reaction/pin/presence tests in the suite, judged low marginal
     value for this cycle.
- Not crypto logic (no `.rs`/WASM file touched) — `crypto-reviewer`
  correctly not invoked. Not server-visible metadata (the `blocked` flag
  never leaves the client — confirmed as part of the security-auditor pass)
  — `threat-model-checker` correctly not invoked. Not a backend handler or
  infra change, but proactively ran `security-auditor` anyway given the
  feature is explicitly about suppressing peer-visible-state/information —
  same precedent as cycle 408's frontend-only-but-security-adjacent routing.
- Verified before commit: `npx tsc -b` clean; `npx biome check` clean on all
  3 touched files; `npx vitest run src/components/ChatLayoutBlock.test.tsx`
  23/23 (21 original + 2 added); full suite 111 files/1575 tests green (was
  111/1573 before this cycle's 2 added tests — pre-existing file/test count
  from the interrupted session's own work, not a regression); `git diff
  --stat` confirmed only the 3 intended files before `git add`.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** none carried with confidence. The persistent
  `cargo audit` hang (noted cycles 414/415, 2+ cycles running) is still
  worth a real investigation if a future cycle has spare time. The PQ Phase
  A prerequisite decision (ml-kem 0.2.3→0.3.2 + libcrux/x-wing
  admissibility, open since cycle 407) remains a human/crypto-lead policy
  call, not a blind retry. Otherwise repeat the fresh-scan approach (`cargo
  deny check`/`pnpm audit`/`gh issue list`/delegated Explore scan) next
  cycle.

## Previous state (2026-09-02, cycle 415 — STABILIZATION: real-socket integration coverage for powehi-ws-hub's connection loop, commits 432336f + c8178d7)

- CI green (`gh run list --limit 5` all success), `git status` clean at cycle
  start. `cargo deny check` clean, `pnpm audit` (app/) clean. `cargo audit`
  still hangs indefinitely at "Scanning Cargo.lock for vulnerabilities" in
  this shell environment (progressed past the old "Updating crates.io index"
  hang point this cycle, but still never produced a final result across 3
  more attempts, including a manual background-kill wrapper) — not a
  blocker, `cargo deny check`'s `advisories ok` covers the same RustSec DB;
  this is now confirmed persistent across cycles 414→415, worth a future
  cycle actually investigating the root cause (proxy/network config?) rather
  than re-attempting blindly. `cargo test --workspace` (748+ tests) and
  `npx vitest run` (110 files/1552 tests) both green at cycle start; `tsc -b`
  and `biome check .` clean.
- **Delegated a fresh STABILIZATION-focused gap scan to an Explore agent**
  (test-coverage-at-assertion-level, security-adjacent gaps, `#[allow(...)]`
  suppressions, doc/code drift) rather than repeating the same TODO/glyph
  greps cycles 413/414 already drained. It returned 5 ranked candidates but
  **3 of the top 4 turned out to be stale/wrong on verification** — the
  agent searched only within individual route files under
  `powehi-rest-api/src/routes/*.rs` and missed that this crate's actual test
  home is one giant `#[cfg(test)] mod tests` in `src/lib.rs` (not
  co-located per-route): `key_package.rs`'s ownership-check/malformed-input
  paths, `auth.rs`'s revoke-device anti-oracle, `media.rs`'s upload
  size-bound, and `messaging.rs`'s TTL-range/`since_id`-without-`since`
  guards were ALL already covered there (`upload_key_packages_cross_
  device_returns_401`, `revoke_non_owned_device_returns_401`,
  `media_upload_size_too_large_returns_400`,
  `poll_with_since_id_but_no_since_returns_400`, etc. — all found via grep
  before writing any code). **Lesson for future scans: a file having no
  local `#[cfg(test)]` module does NOT mean the route is untested in this
  codebase — always grep the crate's `lib.rs` test module by handler/
  behavior name before trusting a "zero coverage" claim.**
- **The one candidate that held up: `powehi-ws-hub/src/handler.rs`'s
  `handle_socket` connection loop had zero coverage through a real socket.**
  `filter_notification` and `PingRateLimiter` were already thoroughly unit-
  tested (confirmed by reading the file), but three loop-level behaviors
  were untested: (1) fail-closed empty-groups path when `GroupRepository::
  list_groups_for_device` errors, (2) `RecvError::Lagged` handling on a
  stalled receiver (skip missed frames, keep connection alive — not
  disconnect), (3) missing-`Authorization`-header 401 rejection at the wire
  level (previously only unit-tested at the `extract_device_id` function
  level, never through an actual upgrade attempt).
- **Fix:** new `crates/adapters/inbound/powehi-ws-hub/tests/websocket_loop.rs`
  — a real integration test spinning up `axum::serve` on a
  `TcpListener::bind("127.0.0.1:0")` and connecting a real
  `tokio-tungstenite` WS client. Added `tokio-tungstenite = "0.24"` as a
  crate-local `[dev-dependencies]` entry (already resolved transitively at
  this exact version via axum 0.7's own `ws` feature per
  `cargo tree -i tokio-tungstenite -e normal` — zero new package entries in
  `Cargo.lock`, confirmed by diff). 3 tests: `membership_load_failure_
  upgrades_but_delivers_nothing` (dispatches a notification for a foreign
  group after a simulated DB-error membership load, asserts no frame within
  300ms, THEN a positive-control self-addressed `MemberAdded` barrier frame
  to prove the connection was alive/responsive rather than hung — added
  after security-auditor flagged the bare timeout-only version as a
  deadline-based negative assertion that could pass vacuously on a loaded
  CI runner); `lagged_receiver_stays_connected_and_keeps_receiving` (floods
  562 synchronous `hub.dispatch()` calls with no `.await` in a
  `#[tokio::test(flavor = "current_thread")]` test to deterministically
  starve `handle_socket`'s task of any chance to drain the ring buffer,
  forcing a real `RecvError::Lagged`, then asserts the connection survives
  and still delivers one final in-scope notification);
  `upgrade_without_authorization_header_returns_401` (wire-level auth-bypass
  coverage, `testing-conventions.md`'s explicit "auth bypass impossible"
  gate — added at security-auditor's suggestion since the crate's HTTP
  harness was new this cycle and the check was "nearly free").
- **Mutation-tested both original findings myself before committing** (same
  discipline as cycle 406's lesson): temporarily changed the `Lagged` arm
  from `continue` to `break` in `handler.rs` — confirmed
  `lagged_receiver_stays_connected_and_keeps_receiving` fails with a
  `Protocol(ResetWithoutClosingHandshake)` panic; temporarily changed the
  fail-closed `Err(_) => Vec::new()` branch to `.unwrap()` — confirmed
  `membership_load_failure_upgrades_but_delivers_nothing` fails via a
  propagated panic. Reverted both (`git diff` confirmed zero net change to
  `handler.rs`) before writing the real tests.
- **security-auditor: PASS, 5 low/informational findings, 3 fixed before
  commit.** Fixed: (1) unused direct `http = "1"` dev-dependency (dead
  weight + version-skew footgun since tungstenite's own `http` re-export
  already provided `HeaderValue`) — removed; (2) the fail-closed test's
  doc-comment over-claimed "zero notifications until reconnect" when a
  self-addressed `MemberAdded` legitimately still gets through by design
  (matches `handler.rs`'s own documented race-acceptance comment) — reworded
  to be precise, and added the positive-control barrier frame described
  above; (3) added the wire-level 401 test (finding #5, "nearly free").
  **Not fixed, judged acceptable:** un-aborted `axum::serve` background task
  per test (each `#[tokio::test]` gets its own runtime, dropped at test end —
  auditor confirmed nothing outlives the test); `.unwrap()` on the spawned
  serve task (diagnostics-only concern, test-only code).
- Not crypto logic (no `.rs` file under `powehi-crypto-wasm`/`powehi-mls`/
  `powehi-opaque` touched) — `crypto-reviewer` correctly not invoked; not
  architectural (test-only, zero production code changed in `handler.rs` —
  confirmed via `git diff --stat` showing only `Cargo.toml`/`Cargo.lock`/the
  new test file) — `threat-model-checker` correctly not invoked;
  `security-auditor` invoked proactively (backend-adapter-adjacent + new
  Cargo dependency) even though not strictly a "handler" change, consistent
  with cycle 403's precedent for security-adjacent-but-not-strictly-gated
  diffs.
- **Process gap this cycle: forgot to run `cargo fmt` before the first
  commit (432336f)** — CI's Format check job caught it immediately (`cargo
  fmt --check` failed on 4 long function signatures/match arms in the new
  test file). Fixed with a second commit (c8178d7, `cargo fmt` applied,
  re-verified tests still pass) rather than amending, since 432336f was
  already pushed. **Lesson: run `cargo fmt --check` (not just `clippy`/
  `test`) as a standard pre-commit step for every Rust diff, especially
  longer integration-test files with multi-arg function signatures that are
  likely to trip fmt's line-length wrapping.** Watched both CI runs
  (`33581768868` CI—Rust, `33581768872` CI—Live-backend E2E) to green via
  `gh run watch --exit-status` before ending the cycle, not just push-and-
  assume.
- Target dir hygiene (STABILIZATION, due this cycle): `du -sh target/` = 12G,
  under the 20G prune threshold — pruned only 0-byte `.rmeta` stubs (routine
  step), no further action needed. Re-check again around cycle 420.
- **Next cycle candidates:** none carried with confidence. The Explore
  agent's fresh-scan pattern (cycles 413/414/415) is now hitting diminishing
  returns — 3 of its last 5 candidates were stale re-discoveries of
  already-tested code, only findable-as-real by manually grepping `lib.rs`'s
  test module first. A future cycle should either (a) explicitly instruct
  the scanning agent to check `src/lib.rs`'s test module by behavior name
  before reporting a "no coverage" finding in `powehi-rest-api`, or (b) pick
  a different crate/layer to scan (frontend hooks/stores, `powehi-grpc`,
  `powehi-postgres` adapter edge cases) rather than re-scanning
  `powehi-rest-api` again. The PQ Phase A prerequisite decision (ml-kem
  0.2.3→0.3.2 + libcrux/x-wing admissibility, open since cycle 407) remains
  a human/crypto-lead policy call, not a blind retry. The persistent
  `cargo audit` hang (noted above, now 2 cycles running) is worth a real
  investigation if a future cycle has spare time — e.g. checking for a
  proxy env var, DNS issue, or trying `cargo audit --db <local-path>` to
  skip the network fetch entirely.

## Previous state (2026-09-02, cycle 414 — FEATURE: add missing Icon.tsx test coverage, commit ce4e6d0)

- CI green (`gh run list --limit 5` all success), `git status` clean at cycle
  start. Repeated the now-standard fresh-scan approach since no candidate was
  carried with confidence from cycle 413: `gh issue list --state open` empty;
  `cargo deny check` clean (advisories/bans/licenses/sources all ok, same
  libcrux/hpke-rs-via-openmls_rust_crypto baseline noted in cycle 413, nothing
  new); `pnpm audit` (app/) clean. `cargo audit` itself hung indefinitely on
  the RustSec advisory-db git fetch step in this environment (no output after
  the "Updating crates.io index" line across 3 separate invocations, no
  `timeout` binary available on this macOS shell to bound it) — not treated as
  a blocker since `cargo deny check`'s `advisories ok` already covers the same
  RustSec DB. Note for a future cycle: `cargo`/`rustc`/etc. are not on PATH by
  default in this shell (`~/.cargo/bin` missing) — had to `export
  PATH="$HOME/.cargo/bin:$PATH"` manually before any cargo command worked.
- **Delegated a fresh-gap scan to an Explore agent** (same pattern as cycle
  413, given how thoroughly prior cycles have mined the obvious candidates).
  It ruled out: remaining raw glyphs in JSX (none — only comment/JSDoc arrows
  remain, the star glyph was already fixed cycle 413); hardcoded hex colors in
  components (these are DESIGN.md's literal brand-required values, not a
  token-bypass bug); `unimplemented!()`/`.unwrap()` in `crates/` (all confined
  to `#[cfg(test)]` modules, verified per-file); recently-added modules
  (`leader_lock.rs`, `mediaTransfer.ts`, `concurrencyLimiter.ts`,
  `notificationSound.ts`, `useVoiceRecorder.ts`) already have matching test
  coverage. **Found:** `app/src/components/Icon.tsx` — the app-wide SVG icon
  lookup primitive (single component, ~40-entry path table) — had **zero
  co-located test file**, unlike every other component in
  `app/src/components/` (the project's own `react-hooks-only.md` convention:
  "co-locate component, styles, and tests"). Specifically untested: the `if
  (!path) return null` fallback for an unrecognized icon name, and the
  `size`/`color`/`className`/`style` prop pass-throughs.
- **Fix:** new `app/src/components/Icon.test.tsx`, 6 tests — known-name
  render (correct `viewBox`/default `stroke="currentColor"`), unknown-name
  returns `null`, default `size=20` vs. custom `size` prop, custom `color`
  prop overrides `currentColor` on `stroke`, `className`/`style` pass-through,
  and a known SVG path element actually renders (`<polyline>` for `check`).
  Pure test-only addition — `Icon.tsx` itself untouched, zero production code
  changed.
- Not crypto logic (no `.rs`/WASM file touched) — `crypto-reviewer` correctly
  not invoked; not architectural (no behavior/metadata change, pure test
  addition) — `threat-model-checker` correctly not invoked; not a backend
  handler or infra change — `security-auditor` correctly not invoked.
  Consistent with prior test-only cycles (399, 400, 404, 406) that also
  correctly skipped review.
- Verified before commit: `npx tsc -b` clean; `npx biome check
  src/components/Icon.test.tsx` clean; `npx vitest run
  src/components/Icon.test.tsx` (6/6) then full suite — 110 files / 1552
  tests green (was 109/1546 — +1 file/+6 tests, exactly this cycle's new
  file, no other test count changed); `git status` confirmed only the one
  new file before `git add`.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** none carried with confidence — same pattern as
  recent cycles, this one came from a delegated Explore scan rather than a
  pre-existing queue. Next cycle should repeat the fresh-scan approach
  (`cargo deny check`/`pnpm audit`/`gh issue list`/TODO grep/delegated Explore
  scan) — note `cargo audit` may need investigation (hung 3x this cycle on
  advisory-db fetch; `cargo deny check` is a working substitute for the
  advisory coverage in the meantime). The PQ Phase A prerequisite decision
  (ml-kem 0.2.3→0.3.2 + libcrux/x-wing admissibility, open since cycle 407)
  remains a human/crypto-lead policy call, not a blind retry.

## Previous state (2026-09-02, cycle 413 — FEATURE: fix raw ★ glyph in Starred-panel empty state, commit 3228333)

- CI green (`gh run list --limit 5` all success — last run was cycle 411's
  memory-update commit), `git status` clean at cycle start. Cycle 412 appears
  to have been skipped entirely (counter jumped 411→413 with no cycle-412
  commit anywhere in `git log` — unlike cycles 405/406/410's "skipped memory
  commit but real code landed" pattern, this one has no orphaned diff either;
  nothing to backfill, just noting the gap for continuity).
- Cycle 411 carried no confident "next cycle candidate" — repeated its
  recommended fresh-scan: `gh issue list --state open` empty; `cargo audit`
  clean (no vulnerabilities); `cargo deny check` clean (advisories/bans/
  licenses/sources all ok — noted in passing that `libcrux-sha3`/`hpke-rs`
  appear in the dependency tree, but traced via `cargo tree -i` to
  `openmls_rust_crypto 0.5.1` — the *current, already-pinned* openmls 0.8.1's
  own crypto backend, not a new/uncovered addition; unrelated to cycle 407's
  rejected 0.9.0-bump libcrux/x-wing concern, which was about NEW transitive
  additions from a version bump, not this pre-existing baseline); `pnpm
  audit` (app/) clean; repo-wide TODO/FIXME/`unimplemented!()` grep found
  nothing new beyond the pre-verified `#[cfg(test)]` mock impls (cycle 407).
  Phase checklist fully `[x]` since cycle 54, phase-1..4 STATUS.md already
  synced (cycle 409).
- **Delegated a fresh-gap scan to an Explore agent** (broader than a manual
  grep sweep, given how thoroughly prior cycles have already mined the
  obvious candidates) rather than digging through the whole codebase myself.
  It found: (1) `ChatLayout.tsx`'s Starred Messages panel empty-state hint
  text embedded a literal Unicode `★` glyph directly in chrome copy
  ("Hover a message and click ★ to star it.") — DESIGN.md's hard rule is no
  emoji/raw glyphs in UI chrome, and this exact panel already uses the
  `Icon name="star"` SVG component two lines above (header icon) and at the
  real star-toggle button elsewhere — this one spot was the inconsistent
  holdout; (2) `SettingsPanel.tsx` (and 9 other components) use a manual
  `<dialog open>` + custom Escape/backdrop-click handlers instead of the
  native `showModal()` API — investigated myself before deciding: this is a
  **consistent, deliberate app-wide pattern across all 10 dialog usages**
  (`AcceptInviteModal`, `AddMemberModal`, `ChatLayout` x4, `CreateGroupModal`,
  `InviteModal`, `RecoveryPhraseModal`, `SettingsPanel`), not an isolated
  oversight — likely intentional given jsdom's incomplete `<dialog
  showModal()>` support would complicate every one of these components'
  existing Vitest suites. Correctly rejected as a candidate: not an actual
  gap, and even if it were, a 10-component pattern change is not a
  single-cycle-sized fix.
- **Fix (`app/src/components/ChatLayout.tsx`, Starred Messages empty state):**
  replaced the literal `★` character with `<Icon name="star" size={11} />`
  rendered inline via a flex span, matching the header icon's usage of the
  same `Icon` component two lines above. No test in
  `ChatLayoutStarred.test.tsx` asserted on the literal copy text (confirmed
  via grep before editing), so this was a safe swap with no test-fixture
  update needed.
- Not crypto logic (no `.rs`/WASM file touched) — `crypto-reviewer`
  correctly not invoked; not architectural (pure UI copy/icon swap, no
  behavior or metadata change) — `threat-model-checker` correctly not
  invoked; not a backend handler or infra change — `security-auditor`
  correctly not invoked. Consistent with prior UI-copy/design-compliance-only
  cycles that also correctly skipped review.
- Verified before commit: `npx tsc -b` clean; `npx biome check
  src/components/ChatLayout.tsx` clean; `npx vitest run
  src/components/ChatLayoutStarred.test.tsx` (14/14) then full suite — 109
  files / 1546 tests green (unchanged count, no test added/removed — pure
  copy/markup fix); `git diff --stat` confirmed only the one intended file
  changed (+12/-2 lines).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** none carried with confidence — this cycle's
  item came from a delegated Explore scan rather than a pre-existing queue,
  and that scan's only other candidate (native `<dialog showModal()>`
  migration) was explicitly rejected as not-a-gap/too-large above. Next
  cycle should either repeat the fresh-scan approach (`cargo audit`/`cargo
  deny check`/`pnpm audit`/`gh issue list`/TODO grep, now also trying a
  delegated Explore-agent scan if the manual sweep comes up empty again) or
  pick up the PQ Phase A prerequisite decision IF a human/crypto-lead has
  made the ml-kem 0.2.3→0.3.2 + libcrux/x-wing admissibility policy call
  since cycle 407 — otherwise still not a blind-retry candidate.

## Previous state (2026-09-01, cycle 411 — FEATURE: finish an interrupted act()-warning cleanup sweep across 13 frontend test files, commit 31d241c)

- Cycle counter incremented to 411 (410 was skipped without a matching commit —
  see below). CI green (`gh run list --limit 3` all success), but `git status`
  at cycle start was **not clean**: 6 test files (`AcceptInviteModal.test.tsx`,
  `ChatLayout.test.tsx`, `ChatLayoutGroupReactions.test.tsx`,
  `ChatLayoutMediaGallery.test.tsx`, `ChatLayoutSlowMode.test.tsx`,
  `useMediaSend.test.ts`) already had uncommitted, coherent `act()`-wrapping
  fixes for React "not wrapped in act(...)" warnings — clearly a real, in-
  progress cycle-410 fix that was interrupted before its commit step (same
  failure mode cycle 407 backfilled for cycles 405/406: a real diff landing
  without the matching commit). Read and verified all 6 diffs before touching
  anything further: coherent single-purpose pattern (wrap a raw
  `useAuthStore.setState(...)`/DOM `.click()`/unflushed async effect in
  `act()`), `tsc -b` clean, full suite 109 files/1546 tests green — confirmed
  this was finished-and-correct work, not garbage, so treated it as a real
  candidate to complete rather than reverting it.
- **Found the fix was only partially applied:** a repo-wide `npx vitest run`
  still printed the identical warning class in ~14 more files. Rather than
  commit the partial 6-file fix alone, treated the mechanical act()-wrapping
  sweep as this cycle's item and finished it end-to-end (matches this
  project's established pattern of fully closing a gap in one cycle rather
  than re-splitting it — e.g. cycle 401's JS-glue-coverage closure).
- **Delegated to `frontend-lead`**, which first did a precise per-file warning
  count and found only 7 of the ~18 remaining candidate files actually had any
  occurrences (11 already clean) — then fanned out 4 parallel background
  sub-agents, one per file/group: `useMessages.test.ts` (91→0, root cause:
  unwrapped `useAuthStore.setState` in 2 stacked `afterEach`s exercised via
  `useSyncExternalStore`), `ChatLayoutTimeGrouping.test.tsx` (121→0, root
  cause: unwrapped `render()`/`vi.advanceTimersByTime()` calls plus an
  unwrapped `afterEach` fake-timer flush that fires the 30s disappearing-
  message `sweep()` interval), `usePersistentMessages.test.ts` (135→0, root
  cause: unwrapped `afterEach` `setState` + one test needing real
  `setTimeout` ticks to drain `fake-indexeddb`'s macrotask-based, not
  microtask-based, internal scheduling), and a 4-file batch —
  `LinkedDevicesPanel.test.tsx`, `useMediaReceive.test.ts`,
  `useWelcomePoller.test.ts`, `ChatLayoutTheme.test.tsx` (24+13+9+7→0
  combined) — all via the same unwrapped-`setState`/unflushed-async-effect
  pattern. Two of the four sub-agents hit their 30-turn limit right before
  finishing final verification; resumed both via `SendMessage` to the same
  agent id (standard pattern for long agent runs, per cycle 403's precedent)
  and got complete final reports from both.
- **Independently re-verified after all 4 sub-agents reported done (not just
  trusted their individual reports):** a fresh full-suite `npx vitest run`
  still showed 51 residual "not wrapped in act" occurrences — 50 in
  `ChatLayoutSlowMode.test.tsx` (one of the *original* 6 "already fixed"
  files — it had only been partially fixed before this cycle started) and 1
  in `ChatLayoutTheme.test.tsx`. Fixed both myself rather than re-delegating:
  (1) `ChatLayoutSlowMode.test.tsx`'s `afterEach` called
  `vi.runOnlyPendingTimersAsync()` unwrapped, which flushes the countdown
  badge's pending 1s interval tick and races a `setState` outside `act()`
  after almost every test in the file — wrapped it in `act()`; (2)
  `"slow-mode section is NOT shown for DM chats"` never flushed `InfoPanel`'s
  async `getVerifiedContact()` mount effect before asserting — added the same
  `await act(async () => { ... })` flush the file's other DM-chat-adjacent
  tests already used. Re-ran the full suite after these two fixes: 0
  remaining occurrences, 109 files/1546 tests green, `tsc -b` clean, `biome
  check .` clean (177 files).
- **13 files touched in total, all test-only** (the original 6 partial fixes
  + 7 more from the delegated sweep, one of the 6 — `ChatLayoutSlowMode
  .test.tsx` — touched twice, first by the earlier interrupted cycle then
  again by me to close the last 2 test cases): +288/-118 lines, zero
  assertions/test-counts/production code changed anywhere in the diff (only
  `act()`/`await act(async () => {})` wrapping added or an occasional
  synchronous `it()` callback converted to `async`).
- Not crypto logic (zero `.rs`/WASM files touched) — `crypto-reviewer`
  correctly not invoked; not architectural (no behavior/metadata change, pure
  test-harness correctness) — `threat-model-checker` correctly not invoked;
  not a backend handler or infra change — `security-auditor` correctly not
  invoked. Consistent with prior test-only cycles (399, 400, 404) that also
  correctly skipped review.
- Target dir hygiene: not checked (FEATURE mode).
- **Cycle 410 was silently skipped without a commit** (its work is what this
  cycle found already sitting uncommitted in the working tree and finished).
  Lesson, same as cycle 407's for 405/406: don't let the memory-update +
  commit step get skipped even under time/turn pressure — the "next cycle
  candidates" list and the skipped-cycle detection this cycle relied on both
  depend on every cycle actually landing its commit.
- **Next cycle candidates:** none carried with confidence — this cycle's item
  came from finding leftover uncommitted work, not from the prior fresh-scan
  list (cycle 409's candidates: none). Next cycle should repeat the
  fresh-scan approach (`cargo audit`/`cargo deny check`/`pnpm audit`/`gh issue
  list`/TODO grep/STATUS.md doc-drift check) if no candidate is found waiting.
  The PQ Phase A prerequisite decision from cycle 407 (ml-kem 0.2.3→0.3.2 +
  libcrux/x-wing admissibility) is still open but explicitly flagged as
  needing a human/crypto-lead policy call, not a blind retry.

## Previous state (2026-09-01, cycle 409 — FEATURE: write dev-setup README + sync stale phase 1-4 STATUS.md, commit 965a41e)

- CI green (`gh run list --limit 5` all success), `git status` clean at cycle
  start. Repeated cycle 408's fresh-scan approach since no candidate was
  carried with confidence: `gh issue list --state open` empty, `cargo audit`
  clean (652 crates, 0 vulnerabilities), `cargo deny check` clean
  (advisories/bans/licenses/sources all ok), `pnpm audit` (app/) clean, and a
  repo-wide TODO/FIXME/`unimplemented!()` grep turned up nothing new (the
  `powehi-rest-api` hits are pre-verified `#[cfg(test)]` mock trait impls,
  per cycle 407).
- Widened the scan to doc/process drift (this file's own FEATURE-mode step 1
  says to read "the ACTIVE phase's `docs/phases/phase-N/STATUS.md`") and
  found `docs/phases/phase-{1,2,3,4}/STATUS.md` were **still "Status:
  Pending" with every DoD item unchecked**, even though this file's own
  Phase checklist has marked all of Phase 1-4 `[x]` (with commit hashes)
  since cycle 54 — only phase-5/phase-6 STATUS.md had ever been kept in
  sync. Verified this wasn't just staleness masking a real gap: cross-checked
  every phase-1..4 DoD line against the commit references already recorded
  in this file's Phase checklist, and specifically checked "development
  environment setup documented" (Phase 1) — `README.md` was in fact still
  just a bare `# POWEHI` title, a genuine unmet DoD item, not a false
  negative.
- **Fix:** wrote a real `README.md` (architecture summary, prerequisites
  table incl. exact pinned versions — Rust 1.96.0 from `rust-toolchain.toml`,
  pnpm 10.28.2 from `package.json`'s `packageManager`, wasm-pack 0.13.1 from
  `.github/actions/install-wasm-pack`, `docker compose` for local Postgres/
  Redis/MinIO — and the build/test/lint commands already listed in
  `CLAUDE.md`). Then rewrote `docs/phases/phase-{1,2,3,4}/STATUS.md` to
  `Status: COMPLETE (cycle N)` with every DoD item checked and cited against
  the commit hash already on file in this document's Phase checklist,
  matching the detail level phase-5/phase-6 already used. Pure
  documentation — zero code changed, nothing in `crates/` or `app/src`
  touched.
- Not crypto, not architectural, not a backend/infra handler change —
  `crypto-reviewer`/`threat-model-checker`/`security-auditor` correctly not
  invoked (same precedent as cycle 296/320's pure docs/memory-only cycles).
  No build/test run needed for a docs-only diff; `git status` confirmed only
  the 5 intended markdown files changed before commit.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** none carried with confidence again — repeat the
  fresh-scan approach (`cargo audit`/`cargo deny check`/`pnpm audit`/`gh
  issue list`/TODO grep, now also including a STATUS.md/doc-drift check) if
  cycle 410 also finds no queued item. The PQ Phase A prerequisite decision
  from cycle 407 (ml-kem 0.2.3→0.3.2 + libcrux/x-wing admissibility) is still
  open but explicitly flagged as needing a human/crypto-lead policy call, not
  a blind retry.

## Previous state (2026-09-01, cycle 408 — FEATURE: forwards now carry the target chat's disappearing-TTL, commit 5b619e7)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle
  start. All 6 phase checklists in this file are fully `[x]` (last item closed
  cycle 54); `gh issue list --state open` empty; `cargo audit`, `cargo deny
  check`, and `pnpm audit` (app/) all clean. No new candidate surfaced by any
  of those — as cycle 407 anticipated, did a fresh gap scan instead: grepped
  for `TODO`/`FIXME`/`unimplemented!()` across `crates/` and `app/src`. The
  only non-test hit was a documented, explicitly-tracked follow-up inside
  `ChatLayout.tsx`'s `sendForwardToOne` doc-comment: forwarding a text
  message into another chat always sent `ttlSeconds: undefined` to the REST
  API and a raw (non-JSON) MLS payload, ignoring whatever disappearing-message
  timer was actually configured on the *target* chat — so a forward into a
  TTL-enabled chat silently became permanent for both the peer and (after an
  earlier persistence fix) the sender's own Dexie copy. Picked this as the
  cycle's item.
- **Fix (`app/src/components/ChatLayout.tsx`, `sendForwardToOne` +
  `appendForwardOptimistic`):** now reads the target group's persisted
  `disappearingTtlSeconds` via `encryptedDb.getGroupDisappearingTtl()` (the
  existing helper in `encrypted-db.ts` built for exactly this — not a raw
  `db.groups.get()`, and not the in-memory `disappearingTtl` state, which only
  ever tracks the currently *active* chat). When set: wraps the plaintext in
  the same `{type:"text",text,ttl}` JSON payload `sendMessage` uses (so the
  peer derives its own expiry), passes it as `sendMessageApi`'s server-visible
  `ttlSeconds` arg, and threads a single `expiresAt` timestamp into BOTH the
  optimistic bubble (`appendForwardOptimistic` gained an `expiresAt` param) and
  `persistOutgoing` — so the "Disappearing" badge shows immediately, the
  in-memory expiry sweep (which filters on `msg.expiresAt`) can reap it, and
  the sender's Dexie copy is swept by `purgeExpired` too. Media forwards
  remain untouched (already-documented, larger, separate persistence gap).
  Media-only, TTL-free forwards keep the old raw-string payload — no behavior
  change there.
- **security-auditor: GREEN** on the diff (spawned proactively — this is a
  frontend-only change, not a backend handler, so not a mandatory gate per
  this file's non-negotiables, but the change alters what's sent over the
  wire so worth checking). 4 non-blocking findings, all fixed before commit:
  (1) optimistic bubble wasn't getting `expiresAt` even though the Dexie row
  was — fixed by threading `expiresAt` into `appendForwardOptimistic`; (2)
  `expiresAt` was anchored post-server-ACK instead of at compose time like
  `sendMessage` — fixed by computing it once right after the TTL lookup
  resolves, before the optimistic append; (3) raw `db.groups.get()` bypassed
  the existing `encryptedDb.getGroupDisappearingTtl()` helper — switched to
  it; (4) new test didn't decode the MLS plaintext to confirm the JSON `ttl`
  wrapper reached the wire — left as-is (the existing `mlsEncrypt` mock in
  this test file returns a fixed ciphertext regardless of input, so decoding
  it wouldn't actually verify the payload; would need a mock rewrite out of
  scope for this fix).
- Not crypto logic (no `.rs`/WASM file touched) — `crypto-reviewer` correctly
  not invoked. Not architectural / no new server-visible metadata (reuses the
  exact same `sendMessageApi` `ttlSeconds` param `sendMessage` already sends
  for regular messages, just now also from the forward path) —
  `threat-model-checker` correctly not invoked.
- Tests: added one new test (`ChatLayoutForwarding.test.tsx`) covering the
  server-visible `ttlSeconds` arg, the persisted Dexie `expiresAt`, and the
  on-screen "Disappearing" badge after switching to the target chat; fixed
  one pre-existing test's timing assumption (`mlsEncrypt` call count checked
  synchronously post-click — now needs a `waitFor` since the TTL lookup adds
  an async Dexie hop before encryption). Full suite: 109 files / 1546 tests
  green (was 1545); `tsc --noEmit` clean; `biome check .` clean (177 files).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** none carried with confidence — this cycle's own
  gap scan (audits, `gh issue list`, TODO/FIXME grep) came up empty aside from
  the item just closed. Next cycle should repeat the same fresh-scan approach
  (`cargo audit`/`cargo deny check`/`pnpm audit`/`gh issue list`/TODO grep)
  rather than assume a candidate is waiting. The PQ Phase A prerequisite
  decision from cycle 407 (ml-kem 0.2.3→0.3.2 + libcrux/x-wing admissibility)
  is still open but explicitly flagged as needing a human/crypto-lead policy
  call, not a blind retry.

## Previous state (2026-09-01, cycle 407 — FEATURE: evaluate openmls 0.9.0 for ADR-0003 Phase A, spike blocked and documented, commit TBD)

- CI green (`gh run list --limit 3` all success), `git status` clean at
  cycle start. Found cycles 405/406 had landed real commits (`8d3e147`,
  `cdbb752`) but skipped their "End of Cycle" memory-update step —
  backfilled both as `Previous state` entries below before starting new
  work (see those entries for what each cycle actually did).
- With the two long-carried "next cycle candidates" (pnpm audit, JS-glue
  `*_finish` coverage) now closed by 405/406, and the e2e logout round
  trip closed by 404, re-scanned for fresh work: `gh issue list` empty,
  workspace `cargo clippy --workspace --all-targets` / `cargo doc
  --workspace --no-deps` both clean (no warnings anywhere), no stray
  `unimplemented!()`/TODO in production code (the ~40 `unimplemented!()`
  hits in `powehi-rest-api/src/lib.rs` are `#[cfg(test)]` mock/stub trait
  impls for unrelated handler tests, not production gaps — confirmed by
  reading context around them). This pushed the search toward the one
  remaining long-blocked candidate: **PQ hybrid Phase A** (ADR-0003),
  gated on `openmls` shipping a stable native PQ ciphersuite.
- **`WebSearch` + `crates.io` API check found `openmls` 0.9.0 published
  2026-08-25 (6 days before this cycle)** — the first potential trigger
  event for ADR-0003 Phase A since the ADR was written. Read the upstream
  changelog: 0.9.0 does add a native PQ ciphersuite
  (`MLS_256_MLKEM1024_AES256GCM_SHA512_MLDSA87`) but at 256-bit level, not
  the 128-bit `MLS_128_MLKEM768...MlDsa65` suite the ADR names as its
  exact trigger, and it sits behind openmls's own
  `draft-ietf-mls-pq-ciphersuites` Cargo feature — openmls itself doesn't
  consider the wire format interop-stable. Judged the full 7-item Phase A
  checklist (native ciphersuite wiring across WASM/domain/REST-API/DB/UI)
  far too large and risky for a single cycle regardless; scoped this
  cycle down to just the mechanical prerequisite — bumping the `openmls`
  *dependency* to 0.9.0 while keeping the classical ciphersuite
  unchanged, to unblock a future cycle's actual Phase A work.
- **Delegated the dependency-bump spike to `crypto-lead` (background
  agent).** It correctly stopped short of making the change: bumping
  `openmls` 0.8.1 → 0.9.0 forces `openmls_traits` 0.5→0.6, which forces
  `openmls_rust_crypto` 0.6.0, whose `hpke-rs-rust-crypto 0.7.0`
  dependency requires `ml-kem 0.3.2` **unconditionally** (no feature
  gate — pulled in even without enabling the PQ ciphersuite feature) —
  conflicting with this repo's own deliberate `ml-kem = "=0.2.3"` exact
  pin (cycle-92 risk item Y-6, closed specifically to prevent silent
  `ml-kem` drift from shifting FIPS 203/NIST ACVP KAT output for the
  already-live `POWEHI_PQ_KEM_EXT_TYPE` KeyPackage extension in
  `kem.rs`). The same 0.9.0 tree also pulls in the `libcrux-*` crate
  family and `x-wing 0.1.0` — **neither is on
  `crypto-libraries-pinned.md`'s approved list** (openmls, opaque-ke,
  RustCrypto, `ml-kem`, `getrandom`) — so even a PQ-feature-disabled
  0.9.0 bump would need an explicit `deny.toml`/rules-file admissibility
  ruling. Correctly treated as "a design decision, not an API
  adaptation" per this cycle's own instruction to the agent, reverted its
  `Cargo.toml` edit, left the working tree clean. Captured baselines for
  whoever picks this up next: `cargo test --workspace` 748 passed/0
  failed/64 ignored; `wasm-pack test --node
  crates/client/powehi-crypto-wasm` 9/9 — both at the *current* (0.8.1)
  pin, useful as a regression baseline for a future bump attempt.
- **Wrote the ADR-0003 status update myself** (not the agent's draft
  verbatim, but the same substance) at
  `docs/decisions/0003-pq-migration.md`'s Decision section: records
  openmls 0.9.0 was evaluated and NOT adopted, the exact two-part
  blocker (ciphersuite-name/security-level mismatch +
  ml-kem/libcrux/x-wing dependency conflict), and that Phase A now needs
  two prior decisions sequenced before the bump itself — (1) wait for the
  exact 128-bit suite / IETF draft finalization vs. consciously adopt the
  256-bit draft suite early with crypto-reviewer sign-off, and (2) a
  crypto-reviewer-gated `ml-kem` 0.2.3→0.3.2 migration with KAT
  re-validation plus a libcrux/x-wing admissibility ruling.
- **Also found and fixed a genuinely stale comment** (not the field I
  first guessed): initially edited `Cargo.toml`'s
  `rust-version = "1.87"` toward 1.91 assuming it tracked the toolchain,
  then caught my own mistake before committing — that field is
  deliberately the real MSRV floor for `is_multiple_of` (cycle-92
  Y-ACVP-1), unrelated to which toolchain CI actually runs; reverted it
  (confirmed via `git diff Cargo.toml` showing no change). The actual
  staleness crypto-lead flagged was `.github/workflows/release.yml`'s
  comment claiming "Toolchain version 1.87.0 matches Dockerfile,
  rust-toolchain.toml and Cargo.toml rust-version" directly above a
  `toolchain: "1.96.0"` pin two lines later — fixed the comment to state
  the true relationship (toolchain pinned above the MSRV floor, not
  equal to it).
- Verified before commit: `python3 -c "import yaml; yaml.safe_load(...)"`
  confirms `release.yml` still parses; `git diff --stat Cargo.toml`
  empty (confirms the revert); `cargo build --workspace` clean (no code
  touched, comment/docs-only diff, sanity-checked anyway since
  `Cargo.toml` was transiently edited during the mistaken-then-reverted
  MSRV change).
- **Not crypto logic** (no `.rs`/WASM file touched — `Cargo.toml` diff is
  net-zero, the actual diff is 2 doc/comment files) — `crypto-reviewer`
  correctly not invoked for this cycle's landed change (it WAS invoked,
  correctly, as part of the background spike that did NOT land — that's
  consistent, review gates apply to changes that ship, and this cycle's
  ADR-documentation of a rejected spike is not itself a crypto change).
  Not architectural (no behavior/metadata change, pure documentation of
  an already-true dependency-resolution fact) — `threat-model-checker`
  correctly not invoked.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates:** the two-part PQ Phase A prerequisite
  decision documented above (needs a human/crypto-lead policy call on
  ml-kem 0.2.3→0.3.2 + libcrux/x-wing admissibility before any further
  openmls-bump attempt — NOT a good candidate to just retry blindly);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself gated
  on Phase A, now also gated transitively on the same ml-kem question);
  no other carried candidates remain open as of this cycle — the next
  cycle should do a fresh gap scan (test coverage, `pnpm audit`/`cargo
  audit` re-check, `gh issue list`) rather than assume a candidate is
  waiting, since this cycle's sweep found the well-known list fully
  drained.

## Previous state (2026-09-01, cycle 406 — FEATURE: close OPAQUE *_finish success-path + wrong-password JS-glue coverage, commit cdbb752)

- **Memory-update commits were skipped for cycles 405 and 406 at the time**
  (both left real code commits on `main` — `8d3e147`, `cdbb752` — but no
  matching `chore: update session memory` commit followed). Backfilled here
  by cycle 407 from `git show --stat`/full commit messages before starting
  new work, per the standing "End of Cycle" requirement neither cycle
  completed. Lesson for future cycles: don't skip the memory-update step
  even under time pressure — it's what keeps the "next cycle candidates"
  list trustworthy for the following cycle's picks.
- Picked cycle 401/404's carried candidate (needs test-only
  server-simulation `#[wasm_bindgen]` exports in `wasm_exports.rs`,
  explicitly out of scope for the earlier Node-glue test file per its own
  header comment): `opaqueWasmZeroize.node.test.ts` could only exercise the
  real wasm-bindgen JS copy-back glue for `*_start` success and `*_finish`
  error paths (no JS-reachable OPAQUE server to complete a round trip
  against). Added a default-off `test-server-sim` Cargo feature gating a
  new `test_server_sim.rs` module — JS-callable, handle-based wrappers
  around the same opaque-ke server-simulation logic
  `wasm_bindgen_tests.rs` already used natively. Enabled only by the
  test-only `build:wasm:node` script; the production `build:wasm`
  (`--target web`) script passes no `--features` flag — verified by a
  build + byte-level scan that zero test-only symbols reach the shipped
  artifact.
- New tests: `*_finish` success-path zeroize for registration and login
  (real client<->server round trip through the test-server-sim feature),
  plus a wrong-password negative control using EQUAL-length passwords with
  an in-test positive-control leg first — same mutation-testing lesson
  cycle 398 learned (unequal lengths, or a bare negative-only assertion,
  can pass for the wrong reason under an eager-scrub-before-use
  regression); both failure modes mutation-tested and confirmed caught.
- **crypto-reviewer: YELLOW, fixes applied, re-verified.** Required
  changes: export-key comparisons made boolean-only (no-plaintext-logging
  — raw key bytes must never render in a failure-assertion log), and the
  wrong-password test given an in-test positive control so `toThrow()`
  can't pass for an unrelated reason.
- Verified: `wasm_exports.rs`, `opaque.rs`, and `PasswordScrubGuard` itself
  untouched (production crypto logic diff is zero — only new test-gated
  module + Cargo feature + build script); 181 native tests unchanged,
  `wasm-pack --node` suite unchanged, full Vitest suite 109 files/1545
  tests (+4 over cycle 404's 1541); production `build:wasm` output
  independently verified clean of test-only exports.
- Not architectural (test-only feature-gated module, zero production
  behavior change) — `threat-model-checker` correctly not invoked; not a
  backend handler or infra change — `security-auditor` correctly not
  invoked (crypto-reviewer covered this diff directly, consistent with
  cycles 398/401's identical routing for the same file).
- Target dir hygiene: not checked (FEATURE mode).
- **This closes the last "JS-glue coverage" gap carried since cycle
  396/398/401/404** — no longer a next-cycle candidate.

## Previous state (2026-09-01, cycle 405 — STABILIZATION: resolve 23 pnpm audit vulnerabilities via in-range update, commit 8d3e147)

- CI green, `git status` clean at cycle start. Ran the STABILIZATION
  security sweep (`counter % 5 == 0`): `pnpm audit` in `app/` surfaced 23
  findings — 1 critical (vitest's UI-server arbitrary file read/exec,
  reachable via `infra/cloudflare/workers/smart-router`'s own vitest dep,
  resolved by 3.2.4 despite an already-wide `^3.2.1` range not having
  picked it up yet), 10 high (undici/ws/sharp bundled inside wrangler's
  miniflare; vite dev-server `fs.deny` bypass; postcss/nanoid
  path-traversal and infinite-loop bugs), 12 moderate/low.
- **Fix:** `pnpm update -r` re-resolved every workspace package within its
  existing caret range and rewrote `package.json` ranges to match (e.g.
  `wrangler ^4.20.0` → `^4.127.1`, `vite ^6.3.5` → `^6.4.3`) — also pulled
  in same-range bumps to production deps (react, react-dom, dexie,
  zustand) alongside dev-tooling (wrangler, vitest, vite, playwright,
  tailwind). No crypto package or Rust/WASM code touched; verified the
  Comlink worker boundary (`comlink@4.4.2`, version unchanged) and the
  Dexie storage layer's encrypt-before-write ordering are unaffected
  regardless of the dexie patch bump. `pnpm audit` now reports zero
  vulnerabilities.
- **security-auditor: GREEN.** Verified: `tsc`, `biome`, full Vitest suite
  (109 files/1541 tests) and `smart-router`'s own vitest (27 tests) all
  green, production build succeeds under the bundle budget script.
- Not crypto logic (no `.rs`/WASM file touched) — `crypto-reviewer`
  correctly not invoked; not architectural — `threat-model-checker`
  correctly not invoked.
- **This closes the "frontend `pnpm audit`'s 23 dev/build-time findings"
  candidate** carried unresolved (not urgent) since cycle 401 — no longer
  a next-cycle candidate.
- Target dir hygiene: due this cycle (STABILIZATION) — not recorded at
  memory-backfill time (cycle 407); if this matters, re-check `du -sh
  target/` fresh rather than trusting this gap.

## Previous state (2026-09-01, cycle 404 — FEATURE: exercise the real logout button in the live-backend auth e2e round trip, commit 9bb974b)

- CI green (`gh run list --limit 3` all success), `gh issue list --state
  open` empty, `git status` clean at cycle start. Picked cycle 403's own
  top "next cycle candidate," verified still accurate before starting: the
  e2e register→logout→login Playwright round-trip, re-scoped as "extend
  `app/e2e-live/auth.spec.ts` (which already drives a real backend per
  `ci-e2e-live.yml`) with an explicit logout-button click between a
  reload-based re-sign-in and a third sign-in" rather than the larger
  carried candidate of wiring a real backend into `playwright.config.ts`'s
  `webServer` from scratch (that infra already exists in the separate
  `playwright.live.config.ts` + `ci-e2e-live.yml`'s `playwright-live-backend`
  job, confirmed by reading both files first).
- **Investigated whether inserting logout between the existing reload and
  re-sign-in made sense, concluded it didn't:** read `auth.spec.ts`'s own
  comment — `page.reload()` already clears the in-memory session token
  (auth.ts's initial phase is "login" with no persisted token), so the app
  is already on the login screen immediately after reload; a logout-button
  click has nothing to do there. Instead added the logout step as a THIRD
  leg of the same test, after the existing reload+sign-in already
  succeeded: register → reach chat → reload → sign in (existing, proves
  IndexedDB persistence across a real page refresh) → **click the sidebar
  Settings icon → Log out (new) → sign in again (new)** — this is the part
  that actually exercises `SettingsPanel.tsx`'s "Log out" button, which
  cycle 403 found had zero UI callers anywhere before that cycle.
- **Traced `dropDbKey()`/`clearSessionState()` before writing the
  assertion, to confirm a real sign-in after logout should behave the same
  as after a reload:** `crypto.worker.ts`'s `dropDbKey()` just sets an
  in-memory worker-module `let dbKey = null` (not a DB wipe — the name is
  about the derived key, not the IndexedDB data); `clearSessionState()`
  calls `wasm.mls_clear_session()` to drop in-WASM-heap MLS/OPAQUE session
  state. Neither touches the IndexedDB-persisted device_id/MLS identity
  that `signIn()`'s real OPAQUE login round trip depends on — so a
  logout→sign-in round trip should succeed for the same reason a
  reload→sign-in round trip does, and CI confirmed this (see below).
- **New helper `logOut(page)` in `app/e2e-live/helpers.ts`:** clicks the
  `Settings`-labeled sidebar `IconBtn` (aria-label sourced from `IconBtn`'s
  `label` prop, confirmed via `ChatLayout.tsx:1638`), asserts
  `settings-panel` is visible, clicks `settings-logout-btn`
  (`SettingsPanel.tsx`'s testid from cycle 403), then asserts the login
  heading + handle textbox are back — mirroring the existing
  `registerAndReachChat`/`signIn` helpers' style and doc-comment
  conventions in the same file. **Changed `app/e2e-live/auth.spec.ts`:**
  added the `logOut` import, extended the single test's name and header
  comment, appended `await logOut(page); await signIn(page, handle,
  password);` after the pre-existing reload+sign-in — net diff 2 files,
  +43/-4 lines, no other test file touched.
- **No local docker** in this environment (`docker: command not found`) —
  could not spin up the `playwright-live-backend` stack
  (Postgres/Redis/MinIO/real axum server) locally to pre-validate before
  pushing, unlike a normal frontend-only change. Ran what COULD be checked
  locally first (`npx tsc -b` clean, `npx biome check e2e-live` clean, 3
  files) then pushed and used `gh run watch --exit-status` on the actual
  `CI — Live-backend E2E` run as the real validation gate, same pattern
  cycle 402 used for its wasm-pack installer change.
- **Verified via CI, not just pushed-and-assumed:** watched all 3 workflows
  to completion — `CI — Live-backend E2E` (run 33415997383) GREEN in
  3m43s, full job log shows `Run live-backend Playwright E2E` succeeded
  (the step that actually executes this cycle's new logout+re-sign-in
  assertions against the real backend, proving the round trip genuinely
  works, not just that the test file parses); `CI — Rust` GREEN; `CI —
  Frontend` GREEN (its own `vitest`/`wasm-build`/`wasm-test` jobs
  unaffected — this diff never touched `app/e2e/` or any Vitest file).
- **No review agent invoked, judged correctly out of scope:** this diff is
  test-file-only (`app/e2e-live/*.spec.ts` + `helpers.ts`), touches zero
  production code — `SettingsPanel.tsx`'s logout button and
  `crypto.worker.ts`'s `dropDbKey`/`clearSessionState` were already
  reviewed (security-auditor, cycle 403) when they were introduced/wired
  up; this cycle only adds live-backend E2E coverage of that
  already-reviewed path. Not crypto logic implementation (no `.rs`/WASM
  file touched) — `crypto-reviewer` correctly not invoked; not
  architectural (no new server-visible metadata, no new endpoint, no
  behavior change to any handler) — `threat-model-checker` correctly not
  invoked; not a backend handler or infra change — `security-auditor`
  correctly not invoked. Consistent with prior test-only cycles (e.g.
  cycle 399/400's rustdoc-only fixes) that also correctly skipped review.
- Target dir hygiene: not checked (FEATURE mode; last checked cycle 400
  STABILIZATION at 9.4G, next scheduled recheck cycle 405 — this cycle).
- **Next cycle candidates:** the `*_finish` success-path + wrong-password
  JS-glue coverage (needs test-only server-simulation `#[wasm_bindgen]`
  exports in `wasm_exports.rs`, route to crypto-lead, carried many cycles);
  PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself gated on
  Phase A); frontend `pnpm audit`'s 23 dev/build-time findings
  (vitest/wrangler/vite transitive, not urgent, not re-checked this
  cycle); Helm wiring bundle mentioned in cycles before 401 was already
  confirmed closed (cycle 401 note) — no longer a candidate, not re-listed.

## Previous state (2026-08-31, cycle 403 — FEATURE: wire sidebar Settings icon to a real logout/linked-devices panel, commit 355d8a1)

- CI green (`gh run list --limit 3` all success), `gh issue list --state
  open` empty, `git status` clean at cycle start. This cycle's candidate
  wasn't from the carried "next cycle candidates" list (all of those were
  still blocked/oversized or not urgent — see below) — instead found a new,
  well-scoped gap while re-reading `app/src/store/auth.ts` and grepping for
  UI call sites: `useAuthStore().logout()` (fully implemented since early
  cycles, store-tested in `auth.test.ts` — awaits `clearSessionState()` then
  `dropDbKey()` on the crypto worker, in that order, before resetting auth
  state) had **zero callers anywhere in `app/src/components/`** — confirmed
  via `grep -n "\.logout(\|onClick.*[Ll]og"` across all components, no
  hits. The sidebar's "Settings" icon button existed (`ChatLayout.tsx`'s
  `Sidebar`, `<IconBtn icon="settings" onClick={onSettings} .../>`) but its
  `onSettings` prop was wired to `() => undefined` at the `<Sidebar>` call
  site — a literal no-op. Also found `LinkedDevicesPanel.tsx` (device list +
  revoke, fully built and tested) was similarly never mounted anywhere.
  **Net effect before this cycle: a signed-in user had no UI path to log
  out at all.**
- **Delegated to `frontend-lead`** (ran in background, hit its 40-turn
  limit once mid-task — resumed via `SendMessage` to the same agent id to
  finish verification, per the standing pattern for long agent runs).
  **New file `app/src/components/SettingsPanel.tsx`:** a fixed-overlay
  dialog (same pattern as `ChatLayout.tsx`'s existing `StatusEditor`),
  opened from the Settings icon, with two rows: "Linked devices" (drills
  into the existing `LinkedDevicesPanel` as a sub-view, reusing it
  unmodified) and "Log out" (calls `useAuthStore().logout()`, disables
  itself while in flight). **Changed `app/src/components/ChatLayout.tsx`:**
  +1 import, +1 `useState` (`settingsOpen`), `onSettings={() => undefined}`
  → `onSettings={() => setSettingsOpen(true)}`, renders
  `<SettingsPanel open={settingsOpen} onClose={...} />` alongside the
  existing `StatusEditor`/`KeyboardShortcutsModal` — net diff on this file:
  +8/-1, no other line touched. **New file
  `app/src/components/ChatLayoutSettings.test.tsx`:** Vitest + Testing
  Library, mocks the crypto worker proxy and the `listDevices` API call at
  the boundary (never imports real crypto into the component test, per
  `.claude/rules/react-hooks-only.md`) — asserts the icon opens the panel,
  close dismisses it, the logout button calls a mocked
  `useAuthStore.getState().logout`, and the devices row navigates into
  `LinkedDevicesPanel`.
- Design-system compliance verified independently (not just trusting the
  agent): the "Linked devices" row icon uses `var(--photon-300)` (`#a8c8ff`,
  the "encryption/lock" designated color per `DESIGN.md`'s hard brand rule
  "lock icon always photon blue" — grepped `index.css` to confirm the token
  resolves to the correct hex), "Log out" uses the pre-existing `var(--flare)`
  danger-red token (already used identically in `Login.tsx`/
  `LinkedDevicesPanel.tsx`'s own error states, not a new color introduced),
  no emoji, dark-first `var(--bg-surface)`/`var(--border-soft)` reused
  throughout — zero new hardcoded colors.
- **security-auditor: YELLOW, 1 MEDIUM finding, applied before commit
  (not deferred).** Routed here rather than crypto-reviewer/
  threat-model-checker since no crypto/WASM file was touched and no new
  server-visible metadata or endpoint was introduced (both existing
  triggers correctly not invoked) — but flagged this as security-adjacent
  since it's the first real UI path that can invoke session/key-material
  teardown, so ran security-auditor as a prudent gate rather than skipping
  review entirely. **Finding (MEDIUM): `handleLogout`'s original
  `try/finally` (no `catch`) meant a rejected `dropDbKey()` (uncaught
  inside `logout()`, unlike the deliberately-swallowed `clearSessionState()`
  rejection) would leave the user silently still fully authenticated —
  live `sessionToken`, DB key possibly still resident — with the button
  just quietly re-enabling and no signal to the user at all; also the
  original doc comment inaccurately implied `logout()` never rejects.**
  Fixed: added a `catch` setting a `logoutFailed` state that renders a
  visible "Log out failed — reload to clear this session" message instead
  of silently going idle; corrected the misleading comment to document the
  swallowed-vs-unswallowed distinction explicitly. Added a 5th test
  (`ChatLayoutSettings.test.tsx`) proving a rejected `logout()` renders the
  new `settings-logout-error` testid. **2 informational findings, not
  applied — genuinely low-risk, documented rather than fixed:** the
  "Linked devices" row wasn't `disabled` during a concurrent logout
  (benign — own-account data over an already-authenticated endpoint,
  fixed anyway alongside the main finding since it was a one-line
  `disabled={loggingOut}` addition, cheap); `LinkedDevicesPanel`'s
  pre-existing (not this diff's) indefinite-spinner-if-`sessionToken`-null
  edge case is unreachable today (every `login()` call site supplies a
  token) — left as-is, correctly out of scope.
- Not crypto logic (zero `.rs`/wasm files touched, `logout()`/
  `LinkedDevicesPanel`'s underlying API calls were pre-existing and
  already reviewed in prior cycles, this diff only adds a UI trigger) —
  `crypto-reviewer` correctly not invoked; not architectural (no new
  server-visible metadata, no new endpoint — `listDevices` already
  existed and was already called by the now-mounted `LinkedDevicesPanel`)
  — `threat-model-checker` correctly not invoked.
- Verified independently before commit (not just trusting the agent's
  report): `git diff --stat` confirmed the exact file set (3 files, no
  stray changes); `cd app && npx tsc -b` clean; `npx biome check` — 1
  formatting error surfaced by my own added failure-path test/JSX (a
  multi-line JSX text node biome wanted joined), fixed via
  `--write`, re-checked clean, 177 files; `npx vitest run` full suite
  109 files / 1541 tests green (+1 file over cycle 402's presumed count,
  +5 tests: 4 from the agent's original test file + 1 I added for the
  logout-failure path); re-ran just the new test file standalone to
  confirm a pre-existing, unrelated `act(...)` warning in the full-suite
  log (generic "TestComponent" name, not present when the new file runs
  alone) wasn't coming from this diff.
- Target dir hygiene: not checked (FEATURE mode; last checked cycle 400
  STABILIZATION at 9.4G, next scheduled recheck cycle 405).
- **Next cycle candidates:** the `*_finish` success-path + wrong-password
  JS-glue coverage (needs test-only server-simulation `#[wasm_bindgen]`
  exports in `wasm_exports.rs`, route to crypto-lead, carried many cycles);
  the e2e register→logout→login Playwright round-trip — **now unblocked on
  the UI side** (a real logout button exists for the first time this
  cycle), still needs a real axum server + Postgres/Redis wired into
  `playwright.config.ts`'s `webServer` OR could instead extend
  `app/e2e-live/auth.spec.ts` (which already drives a real backend per
  `ci-e2e-live.yml`) with an explicit logout-button click between the
  reload and the re-sign-in, which would be a much smaller, single-cycle-
  sized version of this long-carried candidate — route to frontend-lead,
  worth prioritizing next; PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B, itself gated on Phase A); frontend `pnpm audit`'s 23
  dev/build-time findings (vitest/wrangler/vite transitive, not urgent, not
  re-checked this cycle).

## Previous state (2026-08-31, cycle 402 — FEATURE: pin wasm-pack installer by version+SHA-256 across all 4 CI call sites, commit 2c81dc1)

- CI green (`gh run list --limit 3` all success), `git status` clean at
  cycle start. Picked cycle 401's own top "next cycle candidate"
  (crypto-reviewer Finding 3): all 4 `curl .../init.sh -sSf | sh`
  wasm-pack install steps (3 in `ci-frontend.yml`'s `vitest`/`wasm-build`/
  `wasm-test` jobs, confirmed by cycle-401's memory; **found a 4th
  previously-missed site** in `ci-e2e-live.yml` via a repo-wide grep before
  starting — cycle 401's "all 3 CI jobs" phrasing undercounted by one, this
  cycle's grep-first approach caught it) had no version pin and no
  checksum verification — a curl-pipe-to-shell supply-chain gap.
- **Fix:** new composite action `.github/actions/install-wasm-pack/
  action.yml` — downloads a pinned wasm-pack v0.13.1 release tarball
  directly from GitHub Releases (`x86_64-unknown-linux-musl`, matching all
  4 call sites' `runs-on: ubuntu-latest`), verifies its SHA-256 via
  `sha256sum -c -` under `set -euo pipefail`, extracts, and installs the
  binary with `install -m 0755` — no content is ever piped into an
  interpreter. **Independently obtained the checksum myself, not
  copied from anywhere:** downloaded the actual release asset via `curl`
  and computed its SHA-256 via `shasum -a 256` (macOS has no `sha256sum`)
  before hardcoding it into the action; also noticed and confirmed via the
  GitHub API that the wasm-pack project moved from the `rustwasm` org to
  `wasm-bindgen` (the current `rustwasm.github.io` installer script's own
  `UPDATE_ROOT` already pointed there) — the new pinned URL uses
  `github.com/wasm-bindgen/wasm-pack/releases/...`. All 4
  `- name: Install wasm-pack\n  run: curl ... | sh` steps replaced with
  `uses: ./.github/actions/install-wasm-pack`.
- **security-auditor: GREEN** (routed here, not crypto-reviewer — this is
  CI/infra config, zero crypto logic touched). Verified independently:
  checksum mismatch reliably fails the job (`sha256sum -c -`'s two-space
  text-mode record format, tested both directions); single-arch pin is
  safe (grepped both workflow files, confirmed no arm64/self-hosted
  runner exists anywhere); GitHub Releases + hardcoded checksum is an
  adequate trust anchor, arguably better than adding a third-party
  `jetli/wasm-pack-action`-style dependency that would itself need
  SHA-pinning; composite actions can't declare their own `permissions:`
  (GitHub Actions limitation, not a gap) but both workflows already
  declare `permissions: contents: read` at the top level; local path
  refs (`./.github/actions/...`) correctly don't need SHA-pinning since
  they resolve from the same checked-out commit, unlike the other
  external actions in these files which remain SHA-pinned with version
  comments. **1 advisory applied (cheap):** added an inline comment
  noting the x86_64/`ubuntu-latest` architecture coupling so a future
  runner-arch change fails loudly instead of silently. **1 own catch,
  fixed before commit (not from the review):** the action's original doc
  comment cited a specific GitHub issue number
  (`rustwasm/wasm-pack#1440`) I had fabricated by pattern-matching, not
  verified — caught this myself re-reading the file before commit and
  removed the fabricated citation (kept the accurate plain-English
  description of the risk instead), per the standing rule to never
  present unverified specifics as fact.
- Verified independently (functional test, not just review-trusted):
  locally reproduced the exact download+checksum+extract sequence the
  composite action runs (`curl -fsSL -o` the pinned URL, `shasum -a 256`
  compare, `tar -xzf`, confirmed `wasm-pack` binary present in the
  extracted dir) — proved the pin resolves and the checksum matches
  before ever pushing to CI. `python3 -c "import yaml; yaml.safe_load(...)"`
  confirmed all 3 touched/added YAML files parse. Post-push: watched all 3
  CI workflows to completion via `gh run watch --exit-status` rather than
  polling status repeatedly (a `gh run list` "duration" column was
  observed frozen at a few seconds across 3 separate re-checks ~90s apart
  — likely a display/caching quirk of `gh run list`, not a stuck job;
  `gh run watch` gave a reliable blocking wait instead) — `CI — Frontend`
  all 6 jobs green (including the 3 that now use the new composite
  action), `CI — Rust` success, `CI — Live-backend E2E` success (the 4th,
  previously-missed call site).
- Not crypto logic (no `.rs`/`.ts` crypto code touched) —
  `crypto-reviewer` correctly not invoked; not architectural/new
  server-visible metadata (CI-internal tooling change only) —
  `threat-model-checker` correctly not invoked.
- Target dir hygiene: not checked (FEATURE mode; last checked cycle 400
  STABILIZATION at 9.4G, next scheduled recheck cycle 405).
- **Next cycle candidates (unchanged from cycle 401's list, this cycle's
  pick fully closes the wasm-pack-installer-pin gap across all 4 sites):**
  the `*_finish` success-path + wrong-password JS-glue coverage left out
  of cycle 401's new test file (needs either test-only
  server-simulation `#[wasm_bindgen]` exports in `wasm_exports.rs` — a
  production-file change, route to crypto-lead — or judged not worth the
  risk, since the equivalent mutation is already killed Rust-side); the
  e2e register→logout→login Playwright round-trip against a real backend
  (needs a real axum server + Postgres/Redis wired into
  `playwright.config.ts`'s `webServer`, route to backend-lead +
  infra-lead jointly, carried since cycle 394 — note this is distinct
  from `ci-e2e-live.yml`'s existing live-backend E2E job, which already
  exists and is green); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B, itself gated on Phase A); frontend `pnpm audit`'s 23
  dev/build-time findings (vitest/wrangler/vite transitive, not urgent,
  not re-checked this cycle).

## Archived history (cycles 20-277, 279-339, 340-371, 372-401, and legacy cycle-log entries)

> Cycles 20-277 were moved to `.claude/memory/archive/project-context-cycles-20-277.md` in
> cycle 320 (2026-07-19 STABILIZATION). Cycles 279-319, plus the old non-chronological
> "Cycle log (recent)" section (cycles 215-262 and a stray 315 entry that cycle 320's pass
> missed), were moved to `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
> in cycle 340 (2026-08-23 STABILIZATION). Cycles 320-339 were moved to
> `.claude/memory/archive/project-context-cycles-320-339.md` in cycle 360 (2026-08-25
> STABILIZATION). Cycles 340-371 were moved to
> `.claude/memory/archive/project-context-cycles-340-371.md` in cycle 390 (2026-08-30
> STABILIZATION) — that file had grown to 3397 lines / 259.7KB, over the Read-tool 256KB
> cap. Cycles 372-401 were moved to
> `.claude/memory/archive/project-context-cycles-372-401.md` in cycle 420 (2026-09-03
> STABILIZATION) — this file had grown to 3814 lines / 275KB, over the cap again (first
> read of the cycle hit it). Only the last ~14 cycles are kept inline above. Read the
> archive files directly (with offset/limit) for older-cycle detail.

## Phase checklist (prd.md §15.4; per-phase DoD in docs/phases/phase-N/STATUS.md)

### Phase 1 — Foundation & DevOps Skeleton  ← ACTIVE
- [x] Cargo workspace + hexagonal crate skeleton (domain → ports → application → adapters → bin), prd.md §6.1 — commit 940a065
- [x] powehi-domain (zero external deps) + powehi-port-inbound/outbound trait stubs — commit 940a065
- [x] React 19 + Vite 6 scaffold under `/app` — commit 312864d (pnpm workspace, Tailwind v4, Vitest, Biome, design tokens)
- [x] WASM build pipeline (empty `powehi-crypto-wasm` compiles to wasm32-unknown-unknown) — commit f498ae1
- [x] CI: GitHub Actions (fmt, clippy, nextest, biome) — commit 35ac5b9
- [x] Terraform base (Hetzner k3s) skeleton — commit d87891f (modules/hetzner-k3s, envs/{dev,prod-eu,cloudflare}, infra-test manual pass)
- [x] `cargo nextest` 100% on skeleton; hexagonal dependency direction holds — cycle 8 (verified: 21/21 domain tests pass; domain←ports←application; adapters→ports only, NOT application)

### Phase 2 — Crypto Core MVP  ← COMPLETE (cycle 11)
- [x] `powehi-crypto-wasm` w/ openmls; OPAQUE register/login; MLS group round-trip; Comlink worker; forward-secrecy invariant test; crypto-reviewer pass
  - [x] OPAQUE registration/login (opaque-ke 3.0, draft-irtf-cfrg-opaque-16): registration_start/finish + login_start/finish/full; 2 tests green — cycle 8
  - [x] MLS group create/encrypt/decrypt (openmls 0.8.1 + openmls_rust_crypto): roundtrip + forward-secrecy invariant; 2 tests green — cycle 8
  - [x] Crypto-reviewer: YELLOW (no RED). Warnings: opaque-ke 3.x vs rule 4.x (follow-up needed), max_past_epochs(0) now explicit, identity binding documented — cycle 8
  - [x] Comlink worker / wasm-bindgen exports — cycle 10 (commit b5c58b0): wasm_exports.rs + crypto.worker.ts; zeroize on export_key; Biome fixed; 30/30 tests green; crypto-reviewer YELLOW (waiver for opaque-ke 3.x recorded in crypto-libraries-pinned.md)
  - [x] WASM compilation test (wasm-pack --target web) — cycle 11: wasm-pack 0.15 success, 1.5MB binary, CI job added to ci-frontend.yml

### Phase 3 — Backend Services & API  ← ACTIVE
- [x] REST API axum adapter: AppState, auth/messaging/key-package routes, AuthenticatedDevice extractor, ApiError, 512KB body limit, 10 tests — cycle 12 (commit a31ff1a); security-auditor PASS
- [x] Composition root: wire Postgres + Redis outbound adapters into bin/powehi-server; DI wiring for AppState — cycle 14 (commit c46eec3); security-auditor GREEN
- [x] WS hub: real-time push via WebSocket (envelope delivery notifications) — cycle 16 (commit 9c9d886); security-auditor PASS
- [x] OPAQUE auth adapter: real opaque-ke server-side register/login in powehi-opaque — cycle 18 (commit 7c2a429)
- [x] Rate limiting (tower_governor 0.4 + governor 0.6, TrustedProxyKeyExtractor) — cycle 19 (commit 0a738e6)
- [x] Media (R2 upload/download via powehi-r2 adapter) — cycle 21 (commit 2527650)

### Phase 4 — Frontend & Integration
- [x] Login/Chat UI; Dexie encrypted storage; crypto worker hook — cycle 23 (commit 786cf6f)
- [x] Service Worker push; Playwright E2E; bundle budget (<200KB init, <800KB WASM) — cycle 24 (commit 600c2b3)
- [x] Safety Numbers UI — prd.md §5.6; WASM SHA-512 derivation; Dexie v2 verifiedContacts; SafetyNumbers component; crypto-reviewer PASS; security-auditor GREEN — cycle 43 (commit 68ce879)
- [x] Dexie AES-GCM-256 encryption layer — `EncryptedPowehiDb` + `encryption.ts`; key in crypto worker; schema v3 (no exportKeyB64); crypto-reviewer + security-auditor GREEN — cycle 47 (commit 380ef49)
- [x] Region-Aware Client — `GET /v1/region/detect` + Zustand region store + sidebar data residency badge; prd.md §7.6; security-auditor PASS — cycle 52 (commit b5513b1)
- UI MUST follow the design system — invoke `/powehi-design` or read `DESIGN.md` first. Brand non-negotiables (dark-first, cream text, dual-light orange=action / photon-blue=encryption, lock always photon-blue) are hard rules. Map `colors_and_type.css` → Tailwind v4 OKLCH.

### Phase 5 — Hardening
- [x] Observability: Prometheus metrics on internal admin port (127.0.0.1:9090); zero-knowledge counters; security-auditor PASS — cycle 28
- [x] SLSA L3 reproducible builds; cosign + Rekor; threat-model-checker pass; load test (10k concurrent WS); PQ migration doc — cycle 29 (commit 75e6c6f)
- [x] CSP + Trusted Types + SRI 100%: security_headers.rs axum middleware; CF Worker addSecurityHeaders; Cloudflare Pages _headers CSP (worker-src blob:, wasm-unsafe-eval, TT, COOP); Vite SRI plugin with build-fail guard — cycle 53 (commit 07e260a)

### Phase 6 — Global Infrastructure
- [x] gRPC mesh + mTLS: powehi-proto (protox 0.7), RegionGrpcServer, RegionGrpcRouter, TlsConfig, CircuitBreaker, security hardening — cycle 32 (commit 563ae8e)
- [x] AP-Seoul Tier 1 Terraform + Helm chart + synthetic checks + infra-test gate — cycle 33 (commit d92e4aa)
- [x] Cloudflare Edge Worker smart routing — TypeScript Worker + PIPA guard + HEALTH_KV failover + Terraform KV/route — cycle 34 (commit 5b7d855)
- [x] KeyPackage cross-region replication integrity — ConsumeKeyPackage RPC implemented, CAS double-consume prevention, 5 integrity tests — cycle 34 (commit 5b7d855)
- [x] Cross-region p99 <200ms live measurement + gRPC forwarding synthetic — `cross-region-p99.js` extended: gRPC HealthCheck p99 threshold; ZK guard; plaintext guard; try/finally — cycle 37 (commit 9efedcb)
- [x] Data residency verification — prd.md §4A.6: 3 compile-time gRPC PII-exclusion tests + `data-residency-check.sh` 4-layer static audit; security-auditor PASS — cycle 54 (commit e0cc130)

## Notes for the autonomous dev
- Implement ONE checklist item per cycle. Flip `[ ]` → `[x]` here when done.
- Delegate domain work via Task to the project's subagents: crypto-lead, backend-lead,
  frontend-lead, infra-lead; reviewers crypto-reviewer / security-auditor / threat-model-checker.
- Use skills: add-rust-crate, add-mls-test, new-api-endpoint, verify-reproducible-build,
  threat-model-update, infra-test.
- Review is part of writing: implement → run the relevant review agent → fix → commit.

