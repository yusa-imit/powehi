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

## Current state (2026-09-03, cycle 430 — STABILIZATION: real testcontainers coverage for RedisEventBus::publish + CI filter fix, commits f8d6513 + 251d8d9)

- Mode selection: counter 429→430, 430 % 5 == 0 → STABILIZATION.
- **Process gap found and closed first:** cycle 429's own "chore: update
  session memory" commit had never actually happened — `git status` at this
  cycle's start showed `project-context.md` modified but uncommitted, even
  though cycle 429's code commit (`9f56abd`) was already on `main`. Verified
  that commit's CI run (`33799167955`, `CI — Rust`) as `completed`/`success`
  via `gh run list` (the thing cycle 429's own memory entry said still
  needed confirming) before doing anything else. This cycle's memory commit
  folds in both the missed cycle-429 write and this cycle's own.
- **CI check (STABILIZATION step 1):** green on `main`, no action needed.
  `gh issue list --state open`: empty.
- **Test-gap search:** delegated to a `test-author` sub-agent (hit its
  30-turn limit mid-verification; I finished the last steps myself) after my
  own manual pass kept hitting already-covered code — I nearly duplicated
  ~250 lines of tests for `routes/auth.rs` in
  `powehi-rest-api` before discovering that crate's convention is a single
  central `test_router()` harness in `src/lib.rs` that already integration-
  tests every route handler, including the exact security-invariant case
  (`revoke_device_not_found_returns_401_not_404`) I was about to add —
  reverted that file back to HEAD unchanged. Told the sub-agent about this
  pitfall explicitly so it grepped repo-wide before writing anything.
- **Real gap found and closed:** `RedisEventBus::publish`
  (`crates/adapters/outbound/powehi-redis/src/lib.rs`) had zero integration
  coverage anywhere in the workspace — only pure-function unit tests
  (`event_topic` matching, serde round-trips) existed, none touching a real
  Redis connection or the actual `PUBLISH` wire behavior. Confirmed via
  repo-wide grep for `PgLeaderLock`/`RedisEventBus`/`publish` usage in test
  files before writing anything (same discipline that just saved the
  auth.rs mistake). New file
  `crates/adapters/outbound/powehi-redis/tests/redis_event_bus_it.rs`
  (`#[ignore]`d, testcontainers-based, mirrors `redis_cache_it.rs`'s
  pattern): `publish_is_received_on_the_correct_topic_channel` (independent
  raw `redis::aio::PubSub` subscriber proves the message actually crosses
  the wire, not just an in-process call, and that `event_topic()`'s channel
  name is what a real subscriber must use), `publish_with_no_subscribers_still_succeeds`
  (Redis `PUBLISH` returns a receiver count, not an error, when nobody is
  listening — must not surface as an adapter error), and
  `published_wire_payload_contains_only_opaque_ids` (asserts the literal
  bytes on the wire contain the opaque group/device UUIDs but never the
  strings "content"/"ciphertext"/"plaintext" — rule `no-plaintext-logging`,
  checked on the real wire payload, not a local serialization). Added
  `futures-util = "0.3"` as a **dev-dependency only** (needed for
  `PubSub::into_on_message()`'s `Stream::next()`) — confirmed via
  `cargo build --workspace` (prod profile) compiling clean without it added
  to `[dependencies]`; `cargo deny check` clean.
- **Found and fixed a second, more important gap the new tests exposed:**
  the CI workflow's redis-integration step (`.github/workflows/ci-rust.yml`)
  filtered `-E 'binary(redis_cache_it)'` only — the new `redis_event_bus_it`
  binary compiled but would have **never actually executed** in CI, same
  failure mode as leaving a test file `#[ignore]`d forever. Widened the
  filter to `binary(redis_cache_it) or binary(redis_event_bus_it)`. Verified
  against real CI, not just local compilation (no Docker in this sandbox):
  pushed both commits separately (`f8d6513` tests, `251d8d9` CI fix) so the
  before/after was directly observable — `gh run view --log` on the first
  push confirmed the redis job showed "11 tests... 1 binary skipped" (the
  new binary silently excluded, exactly the gap suspected); the second
  push's log showed "14 tests across 2 binaries" with all three new tests
  individually `PASS`ing against a real ephemeral Redis
  (`publish_is_received_on_the_correct_topic_channel`,
  `publish_with_no_subscribers_still_succeeds`,
  `published_wire_payload_contains_only_opaque_ids`).
- Verified before each commit: `cargo build --workspace` clean; `cargo test
  -p powehi-redis --test redis_event_bus_it --no-run` compiles clean (no
  Docker locally); `cargo test --workspace` 0 failures; `cargo clippy
  --workspace --all-targets -- -D warnings` clean; `cargo fmt --all --check`
  clean (one real formatting diff caught and fixed via `cargo fmt --all`
  before the first commit — a multi-line `.expect()` chain); `cargo deny
  check` clean (advisories/bans/licenses/sources all ok, new dep is
  dev-only).
- Not crypto (no `.rs` crypto/MLS/OPAQUE/WASM file touched) —
  `crypto-reviewer` correctly not invoked. Not architectural / no new
  server-visible metadata (test-only + a CI filter widening, same category
  as prior test-only diffs) — `threat-model-checker`/`security-auditor`
  correctly not invoked, consistent with cycles 425/428/429's precedent for
  test-only changes.
- Phase 1-6 checklist: no change — all items already `[x]`.
- **Target dir hygiene (STABILIZATION, due this cycle):** `du -sh target/` =
  24G, over the 20G prune threshold — pruned 0-byte `.rmeta` stubs (none
  found) and ran the `mtime +7` prune for `.rlib`/`.rmeta`/`.o`/`.d` files
  and stale incremental dirs; size unchanged (24G before and after) because
  every cycle in this sandbox rebuilds recently enough that nothing is
  actually >7 days old yet — expected, not a bug, per the STABILIZATION
  script's own design (keeps the *warm* cache, only prunes genuinely stale
  artifacts).
- **Archive sweep (this cycle's other STABILIZATION item, flagged as due by
  cycle 429's own note #5):** moved cycles 425-428 to
  `.claude/memory/archive/project-context-cycles-425-428.md` (6th archive
  round: 20-277, 279-319, 320-339, 340-371, 372-401, 402-421 [extended with
  422-424], now 425-428). Live file now holds only header/non-negotiables,
  this cycle-430 entry, and cycle-429 (kept as immediate prior-cycle
  context) as "Previous state".
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
     environment's live media forever.
  5. New, informational: `.github/workflows/ci-rust.yml`'s MinIO pre-pull
     step (`docker pull minio/minio:RELEASE.2022-02-07T08-17-33Z`) still
     references the stale tag cycle 428 found and moved away from in the
     actual test code (`RELEASE.2025-02-28T09-55-16Z`) — the pre-pull now
     warms an image the test never uses, wasting a pull but not breaking
     anything (docker will just pull the real tag again on demand). Small
     mechanical fix, good filler task.
  6. New, informational: this cycle's test-author sub-agent hit its 30-turn
     limit mid-verification (it had already found and written the real gap
     correctly; it was still re-running `cargo test --workspace` output
     scanning when it stopped) — if a future cycle delegates similar
     survey-plus-implement work to a sub-agent, budget for it needing a
     `SendMessage` follow-up to finish verification, or give it a tighter
     scope (skip the full-workspace test dump, just target the touched
     crate) to fit in one run.

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

(cycles 425-428: see `.claude/memory/archive/project-context-cycles-425-428.md`.
cycle 424 and earlier: see `.claude/memory/archive/project-context-cycles-402-421.md`,
now extended with cycle 424's full entry.)
