# Powehi — Project Context Archive (cycles 425-428)

> Archived from project-context.md at cycle 430 (STABILIZATION archive sweep).
> Live state: `.claude/memory/project-context.md`. Earlier archives: `archive/project-context-cycles-402-421.md` and older.

## Previous state (2026-09-04, cycle 428 — FEATURE: real MinIO conditional-write claim-race test, closes cycle-427's next-cycle candidate #1 / cycle-426's Y2)

- Picked up next-cycle candidate #1 (carried since cycle 426 as Y2): the
  three existing owner-sentinel tests never exercised
  `verify_region_ownership`'s actual conditional-PUT race-loss branch
  (`Err(e)` matching `PreconditionFailed`/`ConditionalRequestConflict`) —
  one races nobody (first-run claim), the other pre-writes `.owner` before
  calling sweep so `read_owner_sentinel` short-circuits before the PUT is
  ever attempted. Y2 as originally framed assumed the blocker was the
  pinned MinIO image (`RELEASE.2022-02-07T08-17-33Z`, believed too old for
  AWS's `If-None-Match: *` conditional-write wildcard).
- **Investigated before writing any test** (WebSearch + `gh issue view`/`gh
  pr view` on `minio/minio`, not assumed): the `RELEASE.2022-02-07` tag
  named in this repo's own doc comments was stale — the actual resolved
  dependency (`testcontainers-modules` 0.15.0, checked by reading its
  vendored source under `~/.cargo/registry/src`) defaults to
  `RELEASE.2025-02-28T09-55-16Z`, and had been silently used by every
  owner-sentinel test since cycle 426 without anyone noticing the comment
  was wrong. Confirmed via `minio/minio` GitHub history that `*`-wildcard
  `If-None-Match`/`If-Match` support landed in PR #19682 (merged
  2024-05-07) — well before the actual pinned default — and that the one
  open compatibility report (#20346) was a reporter-side `minio-go` client
  bug (an old client version double-quoting the header value), not a
  server-side gap; MinIO's server has supported the real AWS wildcard
  semantics correctly since mid-2024.
- **Fix:** pinned the MinIO tag explicitly via `.with_tag(MINIO_TAG =
  "RELEASE.2025-02-28T09-55-16Z")` in both container-start call sites
  (`crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs`) instead of
  relying on the crate's implicit default — makes the dependency intentional
  and immune to a future silent `testcontainers-modules` bump, and corrected
  the stale module-doc-comment claim.
- **New test:** `sweep_orphaned_storage_objects_owner_sentinel_claim_race_is_mutually_exclusive`
  — two independent Postgres pools (distinct `local_owner_id` each, modeling
  two separately-provisioned environments rather than one environment's own
  replicas racing on boot, which cycle 426's F2 fix already covers) share
  ONE MinIO bucket+region_id and race `sweep_orphaned_storage_objects`
  concurrently via `tokio::join!` against a freshly empty `.owner` prefix.
  Asserts exactly one side claims ownership and deletes the real orphan, the
  other refuses and deletes nothing (`swept_a + swept_b == 1`), and that the
  R2 sentinel's final content matches whichever Postgres pool actually won.
  Factored `start_postgres()`/`start_minio_with_bucket()` helpers out of
  `setup_with_max_deletes` (no behavior change to existing tests) so the new
  test can compose two Postgres pools with one shared MinIO instance without
  duplicating container-start boilerplate.
- **Verified against real CI, not just local compilation** (same discipline
  as cycle 425): no Docker in this sandbox, so `cargo test -p powehi-r2
  --test r2_media_it --no-run` (compiles clean) + `cargo build --workspace`
  + `cargo test --workspace` (0 failures) + `cargo clippy -p powehi-r2
  --all-targets -- -D warnings` + `cargo fmt --all --check` were the only
  local checks possible. Pushed (`372df4e`), watched `gh run watch
  33781183409 --exit-status` to completion — all jobs green, and
  `gh run view --log` confirms the new test actually executed and **PASSed**
  in the real "Integration Tests (Docker)" job (`PASS [6.850s] (28/38)
  ...claim_race_is_mutually_exclusive`), alongside the 3 pre-existing
  owner-sentinel tests all still passing. This is the first real evidence
  (not just code-review reasoning) that the conditional-write race guard
  actually holds under genuine concurrency against a real MinIO backend.
- Test-only change (no production `.rs` logic touched — `verify_region_ownership`
  itself is unmodified this cycle) — `crypto-reviewer`/`threat-model-checker`/
  `security-auditor` correctly not invoked, same precedent as cycle 425's
  test-only diff.
- Phase 1-6 checklist: no change — all items already `[x]`; this cycle's
  work again came from the next-cycle-candidates backlog.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. New, informational from this cycle: consider a mock-`S3Client` unit
     test to close coverage on the Y1 self-verify mismatch/vanished branches
     specifically (object disappears between the claim PUT and the
     self-verify re-read) — the new claim-race test covers the `Err(e)`
     race-loss branch for real now, but not that specific narrower
     mismatch/vanished-on-success sub-case; non-blocking, no existing mock
     harness for `S3Client` in this crate yet, would be new infra.
  2. prd.md §3.3 cross-reference for region_id-in-storage-key metadata
     (carried since cycle 424, still not done — good filler task).
  3. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  4. Carried: prd.md §6.4 cross-region abuse-signal propagation
     (documented-but-unimplemented) — worth a threat-model-checker-gated
     scoping pass.
  5. Carried, still not scoped this cycle: the residual gap where the
     winner of a *legitimate* (non-racing) ownership claim can still delete
     a colliding environment's live media forever — only a real close via
     distinct buckets (operational) or moving `owner_id` into the
     storage-key path itself (bigger migration).

## Previous state (2026-09-03, cycle 427 — FEATURE: R2 owner-sentinel claim-path hardening, closes cycle-426's Y1+Y3 next-cycle candidates)

- Picked up next-cycle candidates #1 (security-auditor Y1) and #3 (Y3) from
  cycle 426's owner-sentinel review, both in the same method so fixed
  together: `R2MediaAdapter::verify_region_ownership`
  (`crates/adapters/outbound/powehi-r2/src/lib.rs`).
- **Y1 fix:** the claim-success path (`Ok(_) => Ok(true)` after the
  conditional `put_object`) no longer trusts the SDK's 2xx blindly — it now
  re-reads `owner_key` via `read_owner_sentinel` and compares against
  `local_owner_id` via `owner_matches`, same as every other path in this
  method. Closes the theoretical gap where a non-conforming S3-compatible
  endpoint silently ignoring `If-None-Match: *` could let two racing
  claimants both observe success and both conclude ownership. `None` on
  re-read (object vanished between write and read) fails closed to
  `Ok(false)`.
- **Y3 fix:** the claim-race-loss detection now matches
  `Some("PreconditionFailed") | Some("ConditionalRequestConflict")` via
  `matches!`, not just `PreconditionFailed` — AWS returns
  `409 ConditionalRequestConflict` (not `412 PreconditionFailed`) to the
  losing side of a genuinely concurrent conditional `PutObject`, so both
  codes are benign race-losses for this specific call site and belong in
  the fail-closed-but-quiet branch rather than the generic-error branch.
- Verified before commit: `cargo build -p powehi-r2` clean; `cargo test
  --workspace` all green (0 failed); `cargo clippy --workspace
  --all-targets -- -D warnings` clean; `cargo fmt --all --check` clean. No
  new dependency, no migration change, no test file touched this cycle —
  the two prior owner-sentinel `#[ignore]`d testcontainers tests already
  exercise the happy claim path (now implicitly covers the Y1 self-verify
  read too); no Docker in this sandbox to run them.
- Not crypto (no `.rs` crypto/MLS/OPAQUE/WASM file touched) —
  `crypto-reviewer` correctly not invoked. Not a new architectural change or
  new server-visible metadata (same mechanism, same `.owner` object,
  already threat-modeled in cycle 426 — only the internal verification
  logic changed) — `threat-model-checker` correctly not invoked this cycle.
  Backend adapter touching a security-critical claim path —
  `security-auditor` invoked (first two attempts hit transient `529
  Overloaded` from the API, both auto-retried; third attempt succeeded on
  retry, one more retry with an explicit Sonnet model override after a
  same-cycle 529 streak). **Verdict: PASS/GREEN**, no blocking findings.
  Confirmed Y1 introduces no new TOCTOU (re-read window compares against a
  private per-environment random UUID, not attacker-controlled input) and
  Y3's widened match doesn't swallow a real error into the benign-race
  branch (both codes are AWS's documented outcomes for a losing concurrent
  conditional `PutObject` on this exact call site). One informational,
  non-blocking note: the two new branches (self-verify mismatch/vanished on
  success, and the `ConditionalRequestConflict` arm specifically) aren't
  exercised by the existing testcontainers tests — would need either a
  non-conforming S3 backend or a genuine concurrent-write race to trigger,
  which the MinIO harness doesn't simulate. Same category of accepted gap
  as cycle 426's own Y2 (MinIO version predates conditional-write support)
  — reasoned through via code review, not left silently unconsidered.
- Phase 1-6 checklist: no change — all items already `[x]`; this cycle's
  work again came from the next-cycle-candidates backlog.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. security-auditor Y2 (carried from 426): bump the MinIO testcontainers
     image past `RELEASE.2022-02-07` so the owner-sentinel tests can
     exercise real conditional-write races, not just read/mismatch paths.
  2. New, informational from this cycle's review: consider a mock-`S3Client`
     unit test to close coverage on the Y1 self-verify mismatch/vanished
     branches and the Y3 `ConditionalRequestConflict` arm specifically —
     non-blocking, no existing mock harness for `S3Client` in this crate
     yet, would be new infra.
  3. prd.md §3.3 cross-reference for region_id-in-storage-key metadata
     (carried since cycle 424, still not done — good filler task).
  4. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  5. Carried: prd.md §6.4 cross-region abuse-signal propagation
     (documented-but-unimplemented) — worth a threat-model-checker-gated
     scoping pass.
  6. Carried, still not scoped this cycle: the residual gap where the
     winner of a *legitimate* (non-racing) ownership claim can still delete
     a colliding environment's live media forever — only a real close via
     distinct buckets (operational) or moving `owner_id` into the
     storage-key path itself (bigger migration).

## Previous state (2026-09-03, cycle 426 — FEATURE: R2 orphan-sweep owner-sentinel, closes cycle-424's #1 next-cycle candidate)

- Picked up the top "next cycle candidate" carried since cycle 424: both
  review agents had independently proposed an "owner-sentinel" design
  (write a deployment-scoped id to `media/{region_id}/.owner` in R2, verify
  it before the orphan sweep deletes anything) to narrow the residual
  same-bucket-same-region_id gap left after cycle 424's fixes — a real
  scoping/design task, not a quick patch, per that cycle's own note.
- **Design implemented:** new Postgres table `media_region_owner
  (region_id PK, owner_id UUID, claimed_at)` — migration
  `crates/adapters/outbound/powehi-postgres/migrations/0018_media_region_owner.sql`
  + rollback. New `R2MediaAdapter::verify_region_ownership` (called at the
  top of `sweep_orphaned_storage_objects`,
  `crates/adapters/outbound/powehi-r2/src/lib.rs`): each environment
  persists a random owner_id in its own Postgres (atomic
  `INSERT ... ON CONFLICT (region_id) DO UPDATE ... RETURNING owner_id`,
  one round trip, correct under concurrent same-environment replica boot),
  then races to claim `{region_prefix}.owner` in R2 with a conditional
  (`If-None-Match: *`) PUT the first time it runs; every subsequent sweep
  re-reads and compares, returning `Ok(0)` (fail closed, deletes nothing)
  on mismatch. The `.owner` key itself is excluded from orphan-candidate
  scanning (it has no `media_blobs` row by design). Three new
  `#[ignore]`d testcontainers tests in
  `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs`: claims the
  sentinel + still sweeps a real orphan on the first run; refuses to
  delete (and never overwrites the foreign marker) when `.owner` already
  belongs to another environment; never sweeps its own sentinel even when
  aged past the grace cutoff.
- **First-draft review caught a real gap in the design, not just the code**
  (both `security-auditor` and `threat-model-checker`, run in parallel,
  fresh — not trusted from memory): the naive GET→(absent)→unconditional-PUT
  claim path had its own TOCTOU — two environments racing to claim the same
  *empty* prefix on their respective first-ever sweeps could both observe
  "absent" and both PUT, both concluding ownership in the same run (the
  exact mutual-destruction case the mechanism exists to prevent). Separately,
  both reviewers flagged that my own doc comments/migration comments
  **overclaimed** — "closes the residual gap structurally" — when the
  mechanism only eliminates *mutual* destruction; the environment that wins
  a legitimate (non-racing) claim can still delete a colliding environment's
  live media as "orphans" forever, since its own Postgres genuinely has no
  row for them. threat-model-checker: YELLOW pending both fixes. security-auditor:
  YELLOW pending the race fix (F1, medium-high) plus two minor items — F2
  (INSERT-then-SELECT could race a concurrent replica's uncommitted insert;
  fixed via the atomic upsert above) and F3 (mismatch log carried neither
  UUID, making the failure mode undiagnosable — both UUIDs are
  server-generated random v4 with no PII/content linkage, so logging them
  is not a no-plaintext-logging violation).
- **Fixed before committing** (not shipped with a known race, not just
  documented as an accepted gap): claim path now reads first, and on
  "absent" does a conditional PUT (`if_none_match("*")`); on the resulting
  `PreconditionFailed` (a racing claimant won), re-reads and compares
  instead of assuming loss. Mismatch log now includes both
  `local_owner_id`/`remote_owner_id`. Reworded every doc comment (lib.rs,
  migration SQL, test-file section header) from "closes ... structurally"
  to "NARROWS, does not close" — explicit about what is and isn't
  protected. Rewrote `prd.md` §9.4.3: new sub-bullet under the existing
  "region-prefix 스코핑의 실제 보증 범위" bullet describing the owner
  sentinel's real guarantee scope (eliminates mutual destruction + gives
  the loser a loud detection signal; does NOT stop the winner from
  deleting a live loser's media; distinct real buckets remain a hard
  requirement — "one-directional protection + detection, not isolation"),
  plus a sentence on the `.owner` object's own metadata delta (random
  UUID, no user linkage, no new confidentiality delta since a
  bucket-write attacker is already in scope elsewhere).
- **Re-ran both review agents fresh on the fixed diff** (cycle 424's own
  precedent — never trust self-fix reasoning alone): both returned
  **GREEN**. security-auditor confirmed the conditional-write fix is sound
  (`PreconditionFailed` is unmodeled in aws-sdk-s3 1.133's `PutObjectError`,
  correctly read via `.as_service_error()` + `ProvideErrorMetadata::code()`
  from the `Unhandled` variant's metadata — the SDK's own prescribed
  pattern) and the atomic upsert is correct Postgres (`DO UPDATE SET
  region_id = EXCLUDED.region_id` forces `RETURNING` on conflict, takes
  the row lock so a concurrent uncommitted insert blocks rather than
  racing, no clobber). threat-model-checker confirmed prd.md's new text
  matches the code line-for-line and doesn't contradict the parent bullet.
  **Non-blocking follow-ups, deferred (see next-cycle candidates):**
  security-auditor Y1 (the `Ok(_) => Ok(true)` claim-success path doesn't
  self-verify the PUT was actually honored — a non-conforming S3-compatible
  endpoint that silently ignores `If-None-Match` would silently reopen the
  race; cheap fix is a post-PUT re-read+compare), Y2 (the test harness's
  pinned `minio:RELEASE.2022-02-07` image predates MinIO's conditional-write
  support, so the 3 new tests exercise the read/mismatch paths but not the
  conditional-PUT race path itself — the fix is currently unverified
  in-repo, only reasoned through), Y3 (AWS's `409
  ConditionalRequestConflict` code isn't matched alongside
  `PreconditionFailed` — falls through to the generic error branch, which
  is fail-closed-safe but noisier than necessary).
- Verified before commit: `cargo build --workspace` clean; `cargo test
  --workspace` all green (0 failed, r2_media_it.rs now 24 `#[ignore]`d
  tests, +3 from this cycle, compile-checked only — no Docker in this
  sandbox); `cargo clippy --workspace --all-targets -- -D warnings` clean;
  `cargo fmt --all --check` clean; `cargo deny check` clean (advisories/
  bans/licenses/sources all ok, no new dependency added — `ByteStream`/
  `ProvideErrorMetadata` are both already-vendored `aws-sdk-s3` exports).
- Not crypto (no `.rs`/WASM/MLS/OPAQUE file touched) — `crypto-reviewer`
  correctly not invoked. Architectural + new server-visible metadata (new
  Postgres table, new `.owner` R2 object) — `threat-model-checker` invoked
  twice (YELLOW then GREEN). Backend adapter — `security-auditor` invoked
  twice (YELLOW then GREEN).
- **Process note:** both reviewers independently caught the same class of
  issue from two different angles — security-auditor found the TOCTOU as a
  concrete race-condition bug, threat-model-checker found the *doc
  comments overclaiming what the fix guarantees* as a threat-model-drift
  issue. Neither alone would have forced both the code fix and the honest
  doc language; running them in parallel on both the first draft AND the
  fix (not just the first draft) is what caught it. Reinforces cycle 424's
  lesson from yet another angle: a design that sounds like it "closes a
  gap" needs the same fresh-pair-of-eyes treatment as a bug fix, not just a
  green build.
- Target dir hygiene: not checked (FEATURE mode).
- Phase 1-6 checklist: no change — all items already `[x]` (see "Phase
  status" above); this cycle's work came from the next-cycle-candidates
  backlog, not an unchecked DoD box.
- **Next cycle candidates:**
  1. security-auditor Y1: self-verifying the R2 claim PUT (re-read +
     compare after a successful conditional write) — cheap hardening
     against non-conforming S3-compatible endpoints, not R2 itself.
  2. security-auditor Y2: the MinIO testcontainers image
     (`RELEASE.2022-02-07`) predates conditional-write support — bump it
     (check for `If-None-Match` support in a current MinIO release) so the
     3 new owner-sentinel tests can actually exercise the claim-race path
     for real, not just the read/mismatch paths.
  3. security-auditor Y3 (minor): also match AWS's `409
     ConditionalRequestConflict` code alongside `PreconditionFailed` in the
     claim-race branch — currently falls through to the generic error path,
     fail-closed-safe but unnecessarily noisy.
  4. prd.md §3.3 cross-reference for the region_id-in-storage-key metadata
     (currently only in §9.4.3) — small, mechanical doc fix, carried since
     cycle 424, still not done; good filler task if nothing else is queued.
  5. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) remains a human/crypto-lead policy call,
     not a blind retry.
  6. Carried: prd.md §6.4's cross-region abuse-signal propagation
     ("차단된 IP/사용자 → 전 리전 전파") documented-but-unimplemented —
     worth a threat-model-checker-gated scoping pass before committing to
     size.
  7. The genuinely residual gap this cycle's fix does NOT close (documented
     honestly in prd.md §9.4.3, not silently accepted): the winner of a
     legitimate (non-racing) ownership claim can still delete a colliding
     environment's live media forever. The only real close is distinct
     buckets per environment (operational) or moving `owner_id` into the
     storage-key path itself so colliding environments' objects are never
     literally the same key space (a bigger migration — not scoped this
     cycle).

## Previous state (2026-09-03, cycle 425 — STABILIZATION: fix red CI on main (orphan-sweep test bug) + archive sweep, commit d02c816)

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

## Previous state (2026-09-04, cycle 429 — FEATURE: mocked-S3Client unit tests for verify_region_ownership self-verify branches, closes cycle-428's next-cycle candidate #1)

- Picked up next-cycle candidate #1 from cycle 428: even with the real MinIO
  claim-race test added last cycle, two branches of
  `R2MediaAdapter::verify_region_ownership` (security-auditor Y1, cycle 426)
  remained unexercised by any test — the self-verify-after-successful-claim
  path's **mismatch** (a different UUID already stored) and **vanished**
  (404 on re-read) outcomes. Neither is reachable against a real, conforming
  S3-compatible backend (MinIO/R2 both honor `If-None-Match` correctly), so
  only a mock can trigger them deterministically — exactly why cycle 428
  flagged this as "new infra, no existing mock harness for `S3Client` in
  this crate yet" rather than attempting it inline.
- **Refactor (pure extraction, no behavior change):** split
  `verify_region_ownership` into (1) the Postgres upsert for
  `local_owner_id` (unchanged) calling (2) a new private
  `verify_region_ownership_with_local_id(&self, region_prefix,
  local_owner_id)` holding the exact same S3-only read/claim/self-verify/
  race-loss logic as before, verbatim — done so the S3-only half is
  unit-testable without a real Postgres pool (`PgPool::connect_lazy` never
  connects, same pattern already used by the existing
  `region_prefix_is_scoped_under_media_and_region_id` unit test).
- **New mock infra:** `aws-smithy-http-client`'s `StaticReplayClient` (test-
  util feature) plugged into `S3ConfigBuilder::http_client(...)` — replays
  canned HTTP responses (404 `NoSuchKey`, 200 PUT success, 200 GET with a
  UUID body, 412 `PreconditionFailed`) in FIFO order regardless of actual
  request content. Added `aws-smithy-http-client`, `aws-smithy-types`, `http`
  as **dev-dependencies only** (confirmed via `cargo build -p powehi-r2`
  prod-profile compiling clean without them) — no new production runtime
  dependency, `cargo deny check` clean (advisories/bans/licenses/sources ok).
- **6 new unit tests** in `crates/adapters/outbound/powehi-r2/src/lib.rs`'s
  existing `#[cfg(test)] mod tests`: already-claimed match/mismatch, claim-
  when-absent-then-self-verify-match, the two target branches (self-verify
  **mismatch** and self-verify **vanished**, both asserting fail-closed
  `Ok(false)`), and claim-race-loss via `PreconditionFailed` re-reading the
  winner's id. All pass; full workspace `cargo test --workspace` still 0
  failures (144/44/181/46/... suites all green, r2's own lib tests now 18
  passing incl. the 6 new ones); `cargo clippy -p powehi-r2 --all-targets --
  -D warnings` and `cargo fmt --all --check` both clean.
- **`security-auditor` invoked (backend adapter, security-critical claim
  path touched) — PASS/GREEN**, with an unusually thorough pass: the agent
  diffed the extracted method body byte-for-byte against the original inline
  logic (confirmed identical, no accidental change during the split), then
  did targeted **mutation testing on the real source** (flipped the
  self-verify-vanished return, flipped `owner_matches`'s comparison to
  always-true, removed `PreconditionFailed` from the matched error codes)
  and confirmed every mutation broke the corresponding new test — ruling out
  the failure mode where a mock test is trivially green regardless of the
  logic under test. Also confirmed the 412 + `<Code>PreconditionFailed</Code>`
  XML body genuinely parses through the real AWS SDK's error-metadata path
  (not just assumed from reading the source), and that
  `verify_region_ownership_with_local_id` stayed non-`pub` (no new API
  surface). All mutations reverted before reporting; `git diff --stat`
  confirmed the file matched the intended 220-line diff before commit.
- Not crypto (no `.rs` crypto/MLS/OPAQUE/WASM file touched) —
  `crypto-reviewer` correctly not invoked. Not a new architectural change or
  new server-visible metadata (no new data exposed, no new object/table, the
  extraction doesn't change what's observable externally) —
  `threat-model-checker` correctly not invoked this cycle.
- Verified before commit: `cargo build --workspace` clean, `cargo test
  --workspace` 0 failures, `cargo clippy --workspace --all-targets -- -D
  warnings` clean (confirmed by both the main session and, independently,
  the security-auditor sub-agent), `cargo fmt --all --check` clean, `cargo
  deny check` clean. Pushed (`9f56abd`); `gh run watch` on the resulting `CI
  — Rust` run was in progress as of this memory update — verify it landed
  green before trusting this entry's "all green" claim in a future cycle if
  no completion note follows. **Confirmed at cycle 430's start**: `gh run
  list` showed run `33799167955` as `completed`/`success` — this entry's
  claim held.
- Phase 1-6 checklist: no change — all items already `[x]`; this cycle's
  work again came from the next-cycle-candidates backlog.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. prd.md §3.3 cross-reference for region_id-in-storage-key metadata
     (carried since cycle 424, still not done — good filler task).
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried: prd.md §6.4 cross-region abuse-signal propagation
     (documented-but-unimplemented) — worth a threat-model-checker-gated
     scoping pass.
  4. Carried, still not scoped: the residual gap where the winner of a
     *legitimate* (non-racing) ownership claim can still delete a colliding
     environment's live media forever — only a real close via distinct
     buckets (operational) or moving `owner_id` into the storage-key path
     itself (bigger migration).
  5. This file is 417+ lines (4 "state" sections back to cycle 425) — not
     yet at the prior archival trigger point (~742 lines), but due for an
     archive sweep next STABILIZATION cycle (430) per the established
     rolling pattern (keep only current + immediate-prior cycle, archive
     the rest to `.claude/memory/archive/`).
