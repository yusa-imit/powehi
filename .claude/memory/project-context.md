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

## Current state (2026-09-13, cycle 494 — STABILIZATION (forced by red CI, counter said FEATURE): fix Docker Hub's removal of `minio/minio` breaking 2 of 3 CI checks, fix a frontend `tsc -b` type-inference break in a test mock, commit 2fa6184)

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

## Previous state (2026-09-11, cycle 484 — FEATURE: land orphaned WIP persisting MLS own-commit recognition across worker reload (issue #2 gap), fix a real crypto-reviewer MEDIUM finding with an epoch-binding redesign before committing, commit 40e3960)

- Mode selection: counter 483→484, 484 % 5 != 0 → FEATURE. Working tree
  was NOT clean at session start — another occurrence of the established
  "orphaned WIP" pattern (cycles 299/458/460/464/466/470/472/478/480):
  substantial, well-documented, well-tested WIP already sitting in
  `crates/client/powehi-crypto-wasm/src/{mls_group,wasm_exports}.rs`, no
  memory entry referenced it (predates this pointer's last update).
- Traced the whole diff before acting: it closed exactly the
  "reload-loses-own-commit-recognition gap" carried since cycle 478's
  list — `own_commit_hashes`/`pending_own_commit_hashes` (used for
  `MlsError::OwnCommit` "Case 2" recognition, i.e. telling a Delivery
  Service re-echo of this device's own already-merged commit apart from
  a real fork) lived only in worker-local `thread_local!` memory, lost on
  every page reload/worker restart. The WIP added both maps to
  `MlsContextState` (`MLS_CONTEXT_STATE_VERSION` 1→2, hard-reject on
  mismatch, no migration path) so they now round-trip through
  export/import, plus an import-time validation dropping any entry whose
  group has no real openmls pending commit.
- `cargo build/test/fmt/clippy` all green as found (227 passed in
  `powehi-crypto-wasm`, +2 from the 225 baseline).
- **crypto-reviewer (fresh pass): PASS-with-nits, one real MEDIUM
  finding, not a nitpick.** Verified against vendored openmls-0.8.1 that
  persisting `own_commit_hashes` is safe (public content hashes, no key
  material, same blob already carries far more sensitive state via
  `provider_state`) and that the version-gate is fail-closed. **The real
  finding**: the import-time validation (`group.pending_commit().is_none()`
  → drop) is EXISTENCE-only, not binding — it can't tell a genuine
  still-pending entry apart from a DIFFERENT, unrelated one. Concrete
  reachable sequence: peer's commit merges first (clears this device's
  original pending commit as a side effect, a pre-existing documented
  race), leaving a stale hash entry; a LATER, unrelated re-stage on the
  same group leaves a NEW real pending commit in place; existence-only
  checking can't distinguish the stale entry from the fresh one, so it
  survives import and could later be wrongly promoted into
  `own_commit_hashes` — misclassifying some future legitimate commit
  (one that happens to match the stale hash) as `MlsError::OwnCommit`
  and silently dropping it.
- **Fixed with an epoch-binding redesign, not a patch.** Added
  `mls_group::PendingOwnCommit { epoch: u64, hash: OwnCommitHash }`,
  replacing the bare hash as `pending_own_commit_hashes`'s value type
  everywhere (`MlsContext` + `MlsContextState`). Stage time
  (`mls_remove_member_stage_inner`) now records the group's `prior_epoch`
  alongside the hash. Import now requires BOTH
  `group.pending_commit().is_some()` AND `pending.epoch ==
  group.epoch().as_u64()` before keeping an entry — sound because
  staging never advances a group's epoch (only merging does), so a
  genuine still-pending entry's epoch always equals the group's current
  epoch, while a stale one that survived an intervening peer merge does
  not (the merge advanced the epoch past it). Also added the same check
  at `mls_remove_member_confirm`'s promotion site as defense-in-depth
  (not currently reachable in-process — `mls_remove_member_stage_inner`
  is the only producer of a pending commit and always overwrites the map
  entry on every call — but keeps the invariant enforced at every
  promotion site, not just import). Added a regression test
  (`test_import_drops_pending_hash_stale_from_a_different_merged_commit`)
  reproducing the exact race via `clear_pending_commit` + a real merge
  (same technique `mls_group.rs`'s existing abandoned-commit tests use)
  — **manually verified it FAILS against the old existence-only check**
  (temporarily reverted, confirmed the assertion fails with the exact
  stale entry surviving, then restored the fix) before treating it as a
  real regression test, not a tautology.
- **Second, independent crypto-reviewer pass: PASS-with-nits, confirmed
  the epoch-binding fix closes the finding correctly, no new gap.**
  Verified against openmls 0.8.1 source directly (not the diff's own
  claims) that `stage_commit` never touches the epoch and
  `merge_staged_commit` clears the pending commit only AFTER advancing
  it — so epochs are monotone and a stale entry's epoch is permanently
  behind the group's current one. Also independently reasoned that the
  in-process version of this race is NOT actually reachable (the only
  local producer of a pending commit always overwrites the map entry),
  confirming the confirm-time check is genuine defense-in-depth, not
  covering a real live gap. Left 3 non-blocking nits, all cheap and
  fixed before commit: (1) documented explicitly in `PendingOwnCommit`'s
  doc comment that the import check authenticates epoch-match but not
  hash-content — a blob-forging attacker isn't newly enabled by this
  change (the confirmed map already had the same gap), and the blob is
  encrypted at rest before this crate ever sees it again, with a
  fail-closed blast radius (dropped legitimate commit, never key
  compromise); (2) added the epoch check at the confirm-time promotion
  site (described above); (3) strengthened the regression test to also
  assert the imported group DOES have a real pending commit post-import,
  so the test can't trivially pass for the wrong reason (no pending
  commit at all).
- **Full gate, re-run after every fix round**: `cargo build --workspace`
  clean, `cargo test --workspace` all green (0 failures, every crate;
  `powehi-crypto-wasm` alone: 228 passed, 2 ignored, up from 227
  pre-fix), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean. Frontend untouched this cycle,
  not re-run (Rust-only WASM crate change, no JS-visible API change).
- No `threat-model-checker` run: matches the established pattern for
  standalone WASM crypto-primitive additions with no server-visible
  metadata and explicitly not wired to any UI/broadcast flow. No
  `security-auditor` run: no backend/infra code touched.
- Committed `40e3960` (`feat(crypto): persist MLS own-commit recognition
  across worker reload (issue #2)`), 2 files changed, pushed clean
  (`0e1fae6..40e3960 main -> main`). `gh run list` showed all 3 checks
  `queued`/`in_progress` immediately after push — confirm green in a
  future session if not already done. Posted a progress comment on issue
  #2 explaining what landed, the MEDIUM finding and its fix, and that
  the consumer-loop wiring itself remains the largest open piece — did
  NOT close the issue.
- Target dir hygiene: not checked in depth (FEATURE mode), spot-checked
  `target/` at 9.9G — well under the 20G threshold.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle** (was carried since ≥cycle 466's list):
     reload-loses-own-commit-recognition gap for `MlsError::OwnCommit`.
     Both maps now durable across export/import.
  2. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): the MLS commit-processing
     consumer-loop wiring into `useMessages.ts`/`useWelcomePoller.ts` —
     genuinely FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass), not a stabilization-sized fix. What remains:
     (a) the epoch-reconciliation design between the client's local MLS
     epoch and the server's `groups.epoch` counter (still separate from
     today's fix — `PendingOwnCommit.epoch` is purely local bookkeeping,
     not a server-epoch concept), and (b) actually calling
     `mlsInspectCommit`/`mlsConfirmIncomingCommit`/`mlsDiscardIncomingCommit`
     from the poller with a real application-level policy check.
  3. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  4. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  5. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  6. Carried, growing: this file is well past the ~192K/2385-line point
     cycle 360 last archived at — good STABILIZATION candidate for a
     future cycle with no more pressing fix on hand (cycles 320-339
     precedent → `.claude/memory/archive/`).
  7. Carried (unchanged from cycle 480's list): `mls_confirm_incoming_commit`
     handle-consumption-before-`MLS_CTX`-resolution ordering; epoch
     reconciliation; `mls_group_members` `isSelf` leaf-index vs
     signature-key hardening; `PendingRemovalBanner` local cross-check
     hardening; GitHub issues #1/#3/#4/#5; prd.md §10 REST API doc
     drift; `pending_removals` forged-signal defense; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift;
     `GroupRepository::save` blind `ON CONFLICT DO UPDATE`; bare
     `var(--photon)` CSS token.

## Previous state (2026-09-11, cycle 481 — STABILIZATION (forced by red CI, counter said FEATURE): stop the Tauri Cargo.lock drift check from blocking main on routine upstream churn, fix a security-auditor-caught lockfile-mutation bug in the same script, commit 85d8603)

- Mode selection: counter 480→481, 481 % 5 != 0 → nominally FEATURE, but
  `gh run list --limit 5` showed `CI — Rust` failing on the last push to
  main (cycle 480's `chore:` commit) — FEATURE mode's own step 2 applied,
  ran as STABILIZATION. Working tree clean at session start.
- Root cause: **the exact same failure class cycle 479 predicted would
  recur** — `bitflags`/`uuid` that time, `toml` 1.1.5→1.1.6 and
  `toml_edit` 0.25.13→0.25.15 this time. Went further than "refresh the
  lockfile again" (a treadmill fix, not a root cause): confirmed by local
  experiment that `cargo generate-lockfile` does NOT preserve
  already-valid pinned versions — it always re-resolves to the CURRENTLY
  latest compatible graph — so the byte-for-byte "Verify Cargo.lock has no
  unresolved drift" CI step is fundamentally time-sensitive and
  **guaranteed** to periodically false-fail purely from upstream
  publishing, unrelated to any real defect. `cargo check --locked`
  (the preceding step) by contrast only requires the lock to satisfy the
  manifest's semver constraints with ANY already-present version — proven
  time-invariant by pinning `bitflags` to an old version and confirming
  `--locked` accepted it while `generate-lockfile` silently bumped it.
- **Fix**: refreshed `app/src-tauri/Cargo.lock` (unblocks CI immediately),
  then added `continue-on-error: true` to the drift-check step so routine
  upstream patch churn can no longer block main, while leaving `cargo
  check --locked`/`cargo audit`/`cargo deny check` fully blocking (the
  deterministic guarantees stay intact). Diff written to
  `$GITHUB_STEP_SUMMARY` for visibility since a continue-on-error step's
  failure doesn't otherwise surface anywhere in the PR checks list.
- **security-auditor: NEEDS-REWORK on the first draft, PASS after fixing
  the 1 blocking finding.** Caught a real, pre-existing bug in the
  original script (not introduced this cycle, but converted from harmless
  to load-bearing by the fix): `cp Cargo.lock /tmp/...; cargo
  generate-lockfile; diff ...` overwrites `Cargo.lock` in place and never
  restores it, so the `cargo audit`/`cargo deny check` steps immediately
  after were reading the runner-local RE-RESOLVED graph, not the committed
  lockfile. Before this cycle that only mattered on the (rare) drift-fail
  path, where the whole job went red anyway; with `continue-on-error`
  making drift routine, this would have made audit/deny **permanently**
  scan a never-committed graph while reporting green — a committed lock
  pinning a vulnerable version could be silently "healed" by
  `generate-lockfile` before audit ever saw it. Fixed: the script now
  restores the committed `Cargo.lock` unconditionally (via `set +e`/`set
  -e` around the diff so the restore always runs, exit code still
  reflects whether drift was found) before falling through to the
  audit/deny steps. Verified end-to-end with a deliberately-corrupted
  lockfile: script exits 1, writes the diff to a fake `$GITHUB_STEP_SUMMARY`,
  and restores the exact pre-run (corrupted, i.e. "as it would be
  committed") content — confirmed byte-for-byte via `grep -c`. Also fixed
  the reviewer's LOW finding: neither `deny.toml` (root or Tauri) had an
  explicit `[sources]` policy, so `unknown-registry`/`unknown-git` sat at
  cargo-deny's default `"warn"` — a lockfile entry repointed at an
  attacker-controlled git URL wouldn't hard-fail. Added `unknown-registry
  = "deny"` / `unknown-git = "deny"` to both files (verified first that
  neither graph has any git dependency today, so this can't spuriously
  break anything). Re-ran `cargo deny check` on both workspaces after:
  `sources ok` on both.
- Also independently caught and fixed my own bug before the reviewer even
  ran: piping `diff -u ... | tee ...` then reading `$?` captures `tee`'s
  exit status, not `diff`'s, unless `pipefail` is set (not guaranteed
  across bash invocations) — rewrote to redirect to a file and capture
  `$?` directly inside a `set +e`/`set -e` bracket instead.
- **Full gate**: `cargo build --workspace`/`cargo test --workspace` all
  green (0 failures, every crate). `cargo fmt --all --check` clean (both
  workspaces). `cargo check --locked --manifest-path
  app/src-tauri/Cargo.toml --all-targets` clean. `cargo deny check`
  (root) and `cargo deny --manifest-path app/src-tauri/Cargo.toml check`
  both `advisories ok, bans ok, licenses ok, sources ok`. Workflow YAML
  syntax validated with `python3 -c 'import yaml; yaml.safe_load(...)'`.
  The full drift-check script manually simulated under `bash -e` for both
  the no-drift and drift-found paths (see above). Frontend untouched, not
  re-run.
- No `crypto-reviewer`/`threat-model-checker` run: CI-config and
  dependency-policy only, no crypto/MLS/OPAQUE code, no server-visible
  metadata, no application-code architecture change.
- Committed `85d8603` (`fix(ci): stop Tauri lockfile drift check from
  blocking main on upstream churn`), 4 files changed
  (`.github/workflows/ci-rust.yml`, `app/src-tauri/Cargo.lock`,
  `app/src-tauri/deny.toml`, `deny.toml`), pushed clean (`3099a70..85d8603
  main -> main`). Watched all 3 checks (`CI — Rust`, `CI — Frontend`, `CI —
  Live-backend E2E`) to completion this session — **all green**, confirmed
  before ending the cycle (not deferred to a future session, unlike most
  prior cycles' CI-verification notes).
- Target dir hygiene: `target/` at 9.9G (well under the 20G threshold), no
  pruning needed.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle**: CI red on main (Tauri Cargo.lock drift,
     2nd occurrence). The recurring FAILURE MODE is now structurally
     closed (non-blocking + restore-after-diff), not just this instance
     patched — future upstream patch bumps will show as an orange
     step + job summary note, not red CI. Don't expect to see this class
     again; if it recurs anyway, something deeper changed (e.g. a real
     manifest/lock mismatch) and deserves fresh investigation, not another
     lockfile refresh.
  2. Carried, unchanged, the single largest remaining piece of issue #2
     (P0-blocker, security, frontend): MLS commit-processing
     consumer-loop wiring into `useMessages.ts`/`useWelcomePoller.ts` —
     genuinely FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass), not a stabilization-sized fix.
  3. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  4. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  5. Carried (cycle 480's optional note, unchanged): prd.md §3.3 doesn't
     yet document the consumed-`key_packages` retention window.
  6. Carried (cycle 480's optional note, unchanged): this file is now
     well past the ~192K/2385-line point cycle 360 last archived at —
     good STABILIZATION candidate for a future cycle with no more
     pressing fix on hand (cycles 320-339 precedent →
     `.claude/memory/archive/`).
  7. Carried (unchanged from cycle 480's list): `mls_confirm_incoming_commit`
     handle-consumption-before-`MLS_CTX`-resolution ordering; epoch
     reconciliation; `mls_group_members` `isSelf` leaf-index vs
     signature-key hardening; `PendingRemovalBanner` local cross-check
     hardening; GitHub issues #1/#3/#4/#5; prd.md §10 REST API doc
     drift; `pending_removals` forged-signal defense; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift;
     `GroupRepository::save` blind `ON CONFLICT DO UPDATE`; bare
     `var(--photon)` CSS token.

## Previous state (2026-09-11, cycle 480 — STABILIZATION: land orphaned WIP adding the consumed-`key_packages` retention sweep, fix 2 security-auditor required findings before committing, commit 8d7e5b0)

- Mode selection: counter 479→480, 480 % 5 == 0 → STABILIZATION.
- `gh run list --limit 5` green on main (cycle 479's push). `gh issue
  list --state open`: 5 open (#1 SPA deploy path, #2 MLS Remove/PCS —
  large multi-cycle FEATURE work in progress since cycle 464, #3 WS
  client, #4 load testing, #5 prod-ap-seoul PIPA) — none labeled `bug`,
  none stabilization-cycle-sized, so none picked this cycle.
- Session opened with a large uncommitted diff already in the working
  tree — no memory entry referenced it, so it predates this pointer's
  last update and was never recorded (same "orphaned WIP" pattern as
  cycles 299/464/470/472/478). Traced it fully before acting on it (the
  cycle-299 lesson: verify the actual data flow, don't just discard):
  it was a complete, well-reasoned consumed-`key_packages` retention
  sweep — closes exactly the "consumed `key_packages` rows never
  garbage-collected" gap this pointer had carried since at least cycle
  478's list (line ~140 above). Same shape as the existing media-blob/
  media-ledger/media-orphan/pending_removals GC jobs: a new
  `GC_LOCK_KEY_PACKAGES` advisory-lock key (0x...0005, distinct from the
  existing 4), `KeyPackageRepository::delete_consumed_older_than`
  (bounded `DELETE ... USING (SELECT ... LIMIT $2)` batch, partial index
  migration `0022` on `(uploaded_at) WHERE consumed`), 4 new `AppConfig`
  fields with bounds validation + tests, and a `tokio::spawn`'d daily
  sweep in `main.rs`. Defaults `key_package_gc_enabled = true` (unlike
  `pending_removal_sweep_enabled`) since a consumed row's only remaining
  reader (`mark_consumed`'s existence check) already treats absence as
  fail-closed, identically to `AlreadyConsumed`.
- Full local gate before delegating review: `cargo build --workspace`
  clean; `cargo clippy --workspace --all-targets -- -D warnings` first
  FAILED — a third fake `KeyPackageRepository` impl
  (`key_package_service.rs`'s `FakeKpRepo`, not touched by whoever wrote
  the orphaned diff) was missing the new trait method, `cargo build`
  alone hadn't caught it since it's test-only code; added the same
  bounded-`retain` fake impl the other two fakes already used, then
  clippy/fmt clean. `cargo test --workspace`: 100% green (no `#[ignore]`
  test regressions; new Docker-gated `pg_security_it.rs` tests compile
  but don't run here, same as every prior cycle touching that file).
  `cargo audit`/`cargo deny check` both clean (664 crates).
- **security-auditor: PASS, with 2 required-before-merge findings, both
  fixed in-cycle** (backend/DB change with a new background job — not
  crypto/architectural, so `crypto-reviewer`/`threat-model-checker`
  correctly not invoked):
  1. The 4 new config fields weren't wired into the Helm chart
     (`configmap.yaml`/`values.yaml`/`values.schema.json`) — for a
     default-`true` destructive job, the kill switch was unreachable in
     any deployed environment without a code revert. Fixed: added all 4,
     following the exact `mediaOrphanSweepEnabled`/
     `pendingRemovalSweepEnabled` precedent (cycle 424's Sprig
     `| default true` boolean-trap avoidance — NOT applied to the
     enabled flag). Verified by rendering: `--set
     config.keyPackageGcEnabled=false` actually propagates `"false"`,
     not silently reverting to `"true"`. `helm lint`/`conftest
     test/verify` all green on all 3 overlays (prod-eu/prod-ap/staging);
     no `kubeconform` locally (same standing gap as every prior infra
     cycle) and no live cluster for `--dry-run=server` (expected, this
     sandbox has none).
  2. Throughput: one 10k-row batch per **daily** tick can't keep up with
     realistic KeyPackage consumption rates (an Add-commit consumes one
     per group-add, several orders of magnitude more frequent than
     `pending_removals`' device-revocation trigger) — the sweep as
     originally written would never close the backlog. Fixed: the
     per-tick handler now loops calling the bounded per-call delete
     (same shape as `MediaService::run_gc_batched`'s keyset-pagination
     loop) until a short return signals the eligible set is exhausted,
     the whole loop sharing the single existing per-tick timeout — so a
     large backlog gets a bounded partial sweep instead of an
     artificially-capped one, and iteration count stays finite because
     every full-batch iteration makes irreversible forward progress.
  Also fixed 2 of the auditor's non-blocking LOW notes since they were
  cheap and the rationale was actively being cited to justify
  default-`true`: (a) both `main.rs`'s job comment and the port trait's
  doc claimed "no code path ever reads it again" — false,
  `mark_consumed`'s `EXISTS` check does; corrected to the accurate
  argument (that read's fail-closed contract is what makes the sweep
  safe, not the absence of any reader). (b) documented that the grace
  period is measured from `uploaded_at`, not from consumption time (no
  `consumed_at` column exists) — harmless per (a), but the original
  wording overstated the guarantee. Left as non-blocking/optional per
  the auditor's own call: fake-repo `retain()` non-determinism vs the
  real SQL's `ORDER BY` (INFO, no real test currently depends on order),
  prd.md §3.3-style documentation of the new retention window (INFO),
  and the pre-existing no-upper-bound gap on `*_timeout_secs` configs
  (not a regression, same as 3 prior sweeps).
- Committed `8d7e5b0` (`feat(backend,infra): add consumed key_packages
  retention sweep`), 14 files (13 modified + migration `0022` new),
  pushed clean (`7ca6319..8d7e5b0 main -> main`). CI (`CI — Rust`/
  `CI — Infra`/`CI — Live-backend E2E`) was in_progress at push time —
  confirm green in a future session if not already done by the time
  this is read.
- Target dir hygiene: `target/` at 9.7G (well under the 20G threshold),
  no pruning needed. Host disk: 43Gi free / 78% full.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle**: "consumed `key_packages` rows never
     garbage-collected" (carried since ≥cycle 478). Closed.
  2. Carried, unchanged, the single largest remaining piece of issue #2
     (P0-blocker, security, frontend): MLS commit-processing
     consumer-loop wiring into `useMessages.ts`/`useWelcomePoller.ts` —
     genuinely FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass), not a stabilization-sized fix.
  3. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  4. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  5. New, optional (security-auditor INFO note, not applied): prd.md
     §3.3 doesn't yet document the new consumed-`key_packages` retention
     window the way it documents `pending_removals`' — same precedent as
     cycle 289's media-GC doc addition; privacy-positive (shortens
     server-held metadata lifetime), cheap if a future cycle touches
     this area again.
  6. New, minor, optional: this file is back up to 2771 lines / 184K,
     approaching the ~192K/2385-line point where cycle 360 last archived
     (cycles 320-339 → `.claude/memory/archive/`). Good STABILIZATION
     candidate for a future cycle with no more pressing fix on hand —
     same pattern, keep the last ~20 cycles inline.
  7. Carried (unchanged from cycle 478's list): `mls_confirm_incoming_commit`
     handle-consumption-before-`MLS_CTX`-resolution ordering; epoch
     reconciliation; `mls_group_members` `isSelf` leaf-index vs
     signature-key hardening; `PendingRemovalBanner` local cross-check
     hardening; GitHub issues #1/#3/#4/#5; prd.md §10 REST API doc
     drift; `pending_removals` forged-signal defense; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift;
     `GroupRepository::save` blind `ON CONFLICT DO UPDATE`; bare
     `var(--photon)` CSS token.

## Previous state (2026-09-11, cycle 479 — STABILIZATION (forced early by red CI, counter said FEATURE): fix Tauri-shell Cargo.lock drift breaking `CI — Rust` on main, plus close GitHub issue #8 (stale doc comment), commit a78cee5)

- Mode selection: counter 478→479, 479 % 5 != 0 → nominally FEATURE, but
  `gh run list --limit 5` showed `CI — Rust` failing on the very last push
  to main (cycle 478's `chore:` commit) — FEATURE mode's own step 2
  ("if red on main, switch to STABILIZATION this cycle") applied, so this
  cycle ran as STABILIZATION despite the counter. Working tree was clean
  at session start (unlike several recent cycles — no orphaned WIP this
  time).
- Root cause (`gh run view <id> --log-failed`): the `tauri-check` job's
  "Verify Cargo.lock has no unresolved drift" step (added cycle 465,
  `.github/workflows/ci-rust.yml:188-193`) regenerates
  `app/src-tauri/Cargo.lock` fresh via `cargo generate-lockfile` and
  diffs it byte-for-byte against the committed one. `bitflags` 2.13.1→
  2.13.2 and `uuid` 1.26.0→1.26.1 were published upstream between the
  last lockfile refresh and this run, so the fresh resolve no longer
  matched — not a manifest change, not a real regression, just the lock
  going stale as upstream ships patch releases. `cargo check --locked`
  itself (the step before) had already passed.
- **Fix**: no local `cargo`/`rustc` on PATH by default — found via
  `~/.cargo/bin` (rustup-managed toolchain). Ran `cargo generate-lockfile`
  from `app/src-tauri/`, producing a 27-line bump/add diff (bitflags,
  uuid, plus a few `available: vX.Y.Z` notices for crates not actually
  bumped — normal `cargo generate-lockfile` chatter, not evidence of a
  wider re-resolve). Verified both CI steps locally before committing:
  `cargo check --locked --manifest-path app/src-tauri/Cargo.toml
  --all-targets` clean, and the exact drift-check recipe (copy committed
  lock → `cargo generate-lockfile` → `diff -u`) produced NO diff against
  the freshly-regenerated file.
- Also fixed GitHub issue #8 (P2, documentation, carried since cycle 465):
  `AppConfig::handle_oracle_secret_token`'s doc comment
  (`crates/infra/powehi-config/src/lib.rs`) still claimed "if empty, a
  random key is generated at startup (per-restart only)" — stale since
  the YELLOW-2 fix landed a `server_config`-table-backed persistent
  fallback (`bin/powehi-server/src/main.rs:122-183`: env var → SHA-256
  derive; else DB read; else generate+`INSERT ON CONFLICT DO NOTHING`+
  re-read-the-winner for concurrent-replica convergence). Read at face
  value the stale comment implied a `replicaCount: 3`+ prod deployment
  would derive a different HMAC key per pod, turning `login_init` into a
  handle-enumeration oracle — a described vulnerability that no longer
  exists in the code. Rewrote the comment to describe the actual
  DB-backed fallback and note the env var is now optional
  (operator-controlled rotation/pinning), not required for correctness.
  Left the issue's optional Helm/README suggestion out: no
  `infra/helm/powehi/README.md` exists yet, and the ExternalSecret
  template's omission of this var is already the intended (safe)
  behavior, not an oversight worth flagging in a template comment.
- No `crypto-reviewer`/`threat-model-checker` run: neither change
  touches crypto/MLS/OPAQUE code or shifts the security posture (a
  dependency-lockfile refresh and a doc-comment-only fix). No
  `security-auditor` run: the config doc-comment edit has zero code
  behavior change; not treated as a "backend handler" change.
- **Full gate**: `cargo build --workspace` and `cargo check -p
  powehi-config` both clean. `cargo test --workspace` all green (0
  failures across every crate; only doc-tests and docker-gated
  testcontainers tests show 0-run/ignored, expected — no docker daemon
  in this sandbox). `cargo fmt --check` clean (both workspace-wide and
  scoped to `powehi-config`). `cargo audit` clean (664 crates scanned,
  no advisories). `cargo deny check` clean (`advisories ok, bans ok,
  licenses ok, sources ok`). Frontend untouched this cycle, not re-run.
- Committed `a78cee5` (`fix(ci): refresh stale Tauri Cargo.lock; fix(docs):
  correct handle_oracle_secret_token comment (issue #8)`), 2 files
  changed, pushed clean (`5732e77..a78cee5 main -> main`). Closed issue
  #8 with a summary comment. Started a background CI watch after push to
  confirm `CI — Rust` actually goes green on the fix commit (not just
  "looks right locally") — check `gh run list --commit a78cee5` in a
  future session if this wasn't already confirmed.
- Target dir hygiene: `target/` at 8.9G (well under the 20G threshold),
  0-byte `.rmeta` prune ran, no further pruning needed.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle**: CI red on main (Tauri Cargo.lock drift).
     No longer a gap. This class of failure (upstream patch releases
     making a byte-for-byte lockfile diff check fail) will very likely
     recur periodically — not a one-time fix, just periodic maintenance;
     don't be surprised to see it again in a future cycle.
  2. **Resolved this cycle**: GitHub issue #8 (stale doc comment). Closed.
  3. Carried, the single largest remaining piece of issue #2 (P0-blocker,
     security, frontend): the MLS commit-processing consumer-loop wiring
     into `useMessages.ts`/`useWelcomePoller.ts`. This is genuinely
     FEATURE-mode-scale work (needs crypto-lead/mls-engineer + a fresh
     crypto-reviewer pass), not a stabilization-cycle-sized fix — do not
     attempt to cram it into a STABILIZATION cycle. Both previously-
     blocking primitive-layer preconditions (own-commit recognition
     covering both pre- and post-merge, pre-merge policy-inspection
     point) are already built (cycles 466-478); what remains is (a) the
     epoch-reconciliation design between the client's local MLS epoch and
     the server's `groups.epoch` counter, (b) a plan for the
     reload-loses-own-commit-recognition gap (the relevant maps are
     worker-local only — needs both added to `MlsContextState` +
     `MLS_CONTEXT_STATE_VERSION` bump), and (c) actually calling
     `mlsInspectCommit`/`mlsConfirmIncomingCommit`/`mlsDiscardIncomingCommit`
     from the poller with a real application-level policy check.
  4. Carried, low-priority hardening: `wasm_exports.rs`'s
     `mls_remove_member_stage_inner` records the pending own-commit hash
     before the export's `u64_to_f64_checked(prior_epoch)` guard; if that
     guard ever rejected (unreachable in practice, epoch ≥ 2^53), the
     commit would be staged and hashed but never returned to the
     caller/broadcast. Fail-safe direction, low priority.
  5. Carried, low-priority hardening: RUSTSEC-2024-0429 (glib unsound)
     isn't enforced by cargo-deny's default policy (root workspace; the
     Tauri shell's own `deny.toml` already documents this class of gap).
  6. Carried (unchanged from cycle 478's list — see that section for full
     text): `mls_confirm_incoming_commit` consumes the `INSPECTED_COMMITS`
     handle before resolving `MLS_CTX`; epoch reconciliation;
     `mls_group_members` `isSelf` leaf-index vs signature-key hardening;
     PQ hybrid Phase A prerequisite; `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring (BLOCKED);
     `PendingRemovalBanner` local cross-check hardening; GitHub issues #1
     (P0-blocker, SPA deployment path), #3 (WebSocket client), #4 (load
     testing), #5 (prod-ap-seoul region/PIPA compliance); prd.md §10 REST
     API doc drift; `pending_removals` forged-signal defense; unconsumed
     `RemovalRequired` WS event; Helm `monitoring.prometheusRule`/
     `serviceMonitor` overlay + CI render job; `key_packages.device_id`
     FK doc drift; consumed `key_packages` rows never garbage-collected;
     `GroupRepository::save` blind `ON CONFLICT DO UPDATE`; bare
     `var(--photon)` CSS token.

## Previous state (2026-09-10, cycle 478 — FEATURE: land orphaned WIP adding MLS post-merge own-commit recognition, "Case 2" of MlsError::OwnCommit (issue #2), fix a real crypto-reviewer finding before committing, commit d23c2a4)

- Mode selection: counter 477→478, 478 % 5 != 0 → FEATURE. `gh run list
  --limit 6` green on `main`. **Working tree was NOT clean at session
  start** — another occurrence of the established pattern (cycles
  458/460/464/466/472): substantial, well-documented, well-tested WIP in
  `crates/client/powehi-crypto-wasm/src/{mls_group,wasm_exports}.rs` + 2
  frontend files (`crypto.worker.ts` doc-only, `useCryptoWorker.test.ts`
  a mock-arity fix) closing the LIMIT cycle 472's landed inspect/confirm/
  discard API explicitly carried: openmls's own own-commit signal
  (`CannotDecryptOwnMessage`/`StageCommitError::OwnCommit`) only fires
  while an own Commit is still at the group's CURRENT epoch, so a
  Delivery Service echo of a commit this device already merged fell
  through to the generic `MlsError::Decrypt`, indistinguishable from a
  real fork.
- Mechanism: `mls_remove_member_stage` hashes (SHA-256) the exact commit
  bytes it returns into a new `pending_own_commit_hashes` map;
  `mls_remove_member_confirm` promotes the entry to `own_commit_hashes`
  on a successful merge; `mls_remove_member_abort` drops it.
  `mls_process_commit`/`mls_inspect_commit` pass the recorded hash into
  `stage_incoming_commit`, which checks it (plain `==`, not
  constant-time — deliberate, both operands are public content hashes)
  BEFORE any deserialization. Neither map is part of the exported
  `MlsContextState` snapshot — deliberately worker-local, lost on
  reload/restart (documented as a real, not-yet-closed limit).
- Read the whole diff file-by-file before treating "land it" as the
  cycle's action. `cargo build/test/fmt/clippy` all green as found (224
  passed/2 ignored in `powehi-crypto-wasm`, +5 from the 219 baseline),
  `pnpm exec tsc --noEmit` clean, `biome check` clean (4 pre-existing
  unrelated errors in `app/src-tauri/gen/schemas/*.json`), `pnpm vitest
  run` 112 files/1615 tests green (unchanged — the TS diff was doc-only
  plus a test mock arity fix).
- **crypto-reviewer (fresh pass): PASS-with-nits, no blocking finding,
  one real (non-nit) bug.** Verified all 4 requested security properties
  against openmls-0.8.1 source directly (not the diff's own claims):
  (1) the plain `==` hash compare is safe — the attacker controls
  `commit_bytes`, not the recorded hash, so extracting the hash via
  comparison timing would require breaking SHA-256 preimage resistance,
  not just observing timing; (2) checking before deserialization
  introduces no bypass (it only ever rejects, never accepts); actually an
  improvement over the existing `content_type` guard's own justification,
  since `framing/validation.rs` proved `CannotDecryptOwnMessage` itself
  fires BEFORE touching the sender ratchet; (3) the stage→pending→
  confirm/abort→promote state machine is sound in the normal path (only
  `stage_remove_member` ever creates an openmls pending commit in this
  crate's production code, so a promotion can never target the wrong
  commit) with one real gap (next point); (4) misclassification is
  airtight under SHA-256 second-preimage resistance, verified the empty-
  input and zero-length edge cases can't produce a false match.
  **Real bug (F1):** `mls_remove_member_abort` called
  `abort_remove_member(...)?` BEFORE removing the pending hash, so a
  failed abort (e.g. a race where a peer's commit got merged first,
  clearing the openmls-level pending commit via its internal
  `clear_pending_commit`) left a stale pending-hash entry that a later
  successful stage+confirm could wrongly promote — misreporting a
  genuine, never-merged commit's later delivery as `OwnCommit` and
  silently dropping it. Also flagged doc-accuracy nits (the "avoids
  consuming a ratchet secret" justification was correct for the
  `content_type` guard but wrong for the own-commit check specifically;
  "exact byte match" language should say "hash match", reducing to
  second-preimage not collision resistance) and test-coverage nits (the
  new wiring test hand-reproduced the stage-time insert instead of
  calling real code; no adversarial-input test for the hash check).
- **Fixed all of it.** F1: `mls_remove_member_abort` now captures the
  abort result in a binding, unconditionally removes the pending hash,
  then returns the captured result. Docs: rewrote the `stage_incoming_commit`
  rationale to correctly attribute the ratchet-secret-avoidance argument
  only to the `content_type` guard, and added the second-preimage-
  resistance framing everywhere "exact byte match" language appeared
  (`MlsError::OwnCommit`'s variant doc, `stage_incoming_commit`,
  `inspect_incoming_commit`, and a test comment) — also restored
  `crypto.worker.ts`'s "BOTH gaps... must be resolved" framing after the
  original WIP had narrowed it to "that gap" (a real regression: the
  reload-loses-recognition-state gap is still open, not just epoch
  reconciliation). Tests: extracted `mls_remove_member_stage_inner`
  (matching this file's existing `_inner` split pattern) so
  `mls_remove_member_stage`'s real stage-time insert is now exercised by
  a native test instead of a hand-copied reproduction; added
  `test_process_incoming_commit_case2_rejects_non_matching_inputs`
  (empty bytes → `Codec`; single-bit-corrupted own commit → `Decrypt`,
  not `OwnCommit`, with an epoch-unchanged assertion so it can't pass for
  the wrong reason).
- **Second, independent crypto-reviewer pass: PASS-with-nits, confirmed
  all fixes correct, no blocking finding remaining.** Re-verified the F1
  fix closes the gap without introducing a new one (traced every
  producer of an openmls pending commit in this crate's production code —
  only `stage_remove_member` — so a stale pending hash can never be
  promoted against the wrong commit), confirmed the `_inner` extraction
  is behavior-preserving (identical error surface via `js_err`), and
  independently re-derived the corrupted-commit test's actual result
  (`Err(Decrypt)`) rather than trusting the assertion. Left 4 small nits,
  none blocking: (1) the corrupted-input test's assertion was `!matches!
  (_, Err(OwnCommit))` rather than pinned to the exact `Decrypt` variant
  — **fixed** before commit (pinned to `Err(Decrypt)` + an epoch-unchanged
  assert); (2) three more stray "exact byte match"/"byte-equality"
  phrases the first fix round missed — **fixed** before commit (all now
  say "hash match"/"hash-equality"); (3)/(4) two low-value informational
  nits (a fail-safe-direction edge case in the u64→f64 epoch guard
  ordering, a slightly-indirect test assertion) — carried, not fixed,
  genuinely cosmetic.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; `powehi-crypto-wasm` alone: 225 passed, 2 ignored, up from
  224 pre-fix), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean. Frontend: `pnpm exec tsc --noEmit`
  clean, `biome check` clean (same 4 pre-existing unrelated errors), `pnpm
  vitest run` 112 files/1615 tests green (unchanged).
- No `threat-model-checker` run: matches the established pattern for
  standalone WASM crypto-primitive additions with no server-visible
  metadata and explicitly not wired to any UI/broadcast flow. No
  `security-auditor` run: no backend/infra code touched.
- **Verified `git diff --cached` actually contained the fixes** before
  committing (the cycle-472 lesson: a prior cycle forgot to re-`git add`
  after editing already-staged files) — confirmed `pending_own_commit_hashes.remove(group_id);`
  present unconditionally and `mls_remove_member_stage_inner` present in
  the staged diff.
- Committed `d23c2a4` (`feat(crypto): add MLS post-merge own-commit
  recognition (issue #2)`), 4 files changed, pushed clean (`fa339b8..
  d23c2a4 main -> main`). `gh run list` showed all 3 checks `in_progress`
  immediately after push — confirm green in a future session if not
  already done. Posted a progress comment on issue #2 explaining what
  landed, the crypto-reviewer findings/fixes, and the 2 gaps still
  blocking consumer-loop wiring — did NOT close the issue.
- Target dir hygiene: not checked in depth (FEATURE mode), spot-checked
  `target/` at 8.9G — well under the 20G threshold.
- **Next cycle candidates (carried/updated):**
  1. Carried, still the natural next step for issue #2: the consumer-loop
     wiring itself into `useMessages.ts`/`useWelcomePoller.ts`. Both of
     its previously-blocking preconditions (own-commit recognition — now
     covering BOTH pre-merge and post-merge — and pre-merge
     policy-inspection point) are built, but wiring still needs (a) the
     epoch-reconciliation design between the client's local MLS epoch and
     the server's `groups.epoch` counter, (b) a plan for the
     reload-loses-own-commit-recognition gap (own_commit_hashes/
     pending_own_commit_hashes are worker-local only — making this
     durable needs both maps added to `MlsContextState`, an
     `MLS_CONTEXT_STATE_VERSION` bump), and (c) actually calling
     `mlsInspectCommit`/`mlsConfirmIncomingCommit`/`mlsDiscardIncomingCommit`
     from the poller with a real application-level policy check.
  2. Carried, low-priority hardening (this cycle's second review pass):
     `wasm_exports.rs`'s `mls_remove_member_stage_inner` records the
     pending hash before the export's `u64_to_f64_checked(prior_epoch)`
     guard; if that guard ever rejected (unreachable in practice, epoch
     ≥ 2^53), the commit would be staged and hashed but never returned to
     the caller/broadcast. Fail-safe direction (missed recognition, not a
     false one), low priority.
  3. Carried, low-priority hardening: RUSTSEC-2024-0429 (glib unsound)
     isn't enforced by cargo-deny's default policy.
  4. Carried (unchanged from cycle 472's list — see that section for full
     text): `mls_confirm_incoming_commit` consumes the `INSPECTED_COMMITS`
     handle before resolving `MLS_CTX`; epoch reconciliation; `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; PQ hybrid Phase A
     prerequisite; `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring (BLOCKED); `PendingRemovalBanner` local cross-check hardening;
     GitHub issues #1, #3, #4, #5, #8; prd.md §10 REST API doc drift;
     `pending_removals` forged-signal defense; unconsumed `RemovalRequired`
     WS event; Helm `monitoring.prometheusRule`/`serviceMonitor` overlay +
     CI render job; `key_packages.device_id` FK doc drift; consumed
     `key_packages` rows never garbage-collected; `GroupRepository::save`
     blind `ON CONFLICT DO UPDATE`; bare `var(--photon)` CSS token.

## Previous state (2026-09-10, cycle 472 — FEATURE: land orphaned WIP adding the MLS two-phase inspect/confirm/discard commit API (issue #2), fix a HIGH-severity crypto-reviewer finding before committing, commit bd7ddde)

- Mode selection: counter 471→472, 472 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on `main`. **Working tree was NOT clean at session
  start** — another occurrence of the established pattern (see cycles
  458/460/464/466 process notes): substantial, well-documented, well-tested
  WIP in `crates/client/powehi-crypto-wasm/src/{mls_group,wasm_exports}.rs`
  + 4 frontend files (`crypto.worker.ts`, `useCryptoWorker.ts` + test +
  mock) implementing own-commit recognition (`MlsError::OwnCommit`) and a
  pre-merge policy-inspection point (`inspect_incoming_commit`/
  `merge_inspected_commit`, `mls_inspect_commit`/`mls_confirm_incoming_commit`/
  `mls_discard_incoming_commit`) — exactly cycle 466's carried candidate #1
  (the two preconditions blocking a commit-processing consumer loop) — but
  never committed.
- Read the whole diff file-by-file before treating "land it" as the cycle's
  action. `cargo build/test/fmt/clippy` all green as found (218 passed/2
  ignored in `powehi-crypto-wasm`, +7 from the 211 baseline), `pnpm exec
  tsc --noEmit`/`biome check` clean (4 pre-existing, unrelated biome errors
  in `app/src-tauri/gen/schemas/*.json`, confirmed untouched by this diff),
  `pnpm vitest run` 112 files/1614 tests green (+3 from 1611).
- **crypto-reviewer (fresh pass): NEEDS-REWORK, one real HIGH-severity
  finding, not a nitpick.** **F1:** `merge_inspected_commit` had NO guard
  against merging a STALE `StagedCommit` — reachable path: inspect commit A
  (staging it), then merge a DIFFERENT commit B via the one-shot
  `process_incoming_commit` (advancing the epoch), then confirm the
  now-stale A. Verified against vendored openmls-0.8.1
  (`processing.rs`/`staged_commit.rs`): `merge_staged_commit` performs NO
  epoch or group-id check before mutating `group_epoch_secrets`,
  `message_secrets`, and the tree/context diff — it would have silently
  rolled the group back onto the wrong branch instead of erroring. The
  diff's own doc comment falsely claimed openmls handles this ("passing one
  from a different group is a caller-contract violation that surfaces as
  `MlsError::Membership`") — it does not. Also 3 medium findings: **F2**
  `mls_import_state` orphaned outstanding `INSPECTED_COMMITS` entries
  (unresolvable, still holding key material, consumes a cap slot
  indefinitely); **F3** `mlsInspectCommit` was excluded from
  `SYNC_FLUSH_ARG_METHODS` in `useCryptoWorker.ts` despite durably consuming
  a forward-secrecy secret at staging time (same category as `mlsDecrypt`,
  which IS in the flush set) — the diff's "strictly weaker" claim was
  unsupported; **F4** (doc-only) comments understated that losing an
  inspected-but-unresolved commit handle to a worker restart is NOT benign
  (the ratchet secret is already gone the moment staging succeeded).
- **Fixed all 4.** F1: added `MlsError::StaleStagedCommit`; `merge_inspected_commit`
  now checks `staged.group_context().group_id() != group.group_id()` and
  `staged.epoch().as_u64() != group.epoch().as_u64() + 1` before calling into
  openmls, plus a new regression test
  (`test_merge_inspected_commit_rejects_stale_staged_commit`) pinning the
  exact inspect-A/merge-B/confirm-A scenario. F2: `INSPECTED_COMMITS.clear()`
  added to `import_mls_context_inner`'s success path. F3: added
  `mlsInspectCommit` to `SYNC_FLUSH_ARG_METHODS`; rewrote its test from
  "resolves even when persist fails" to "RED 3: a failed persist REJECTS
  mlsInspectCommit", added it to the completeness-guard table. F4: rewrote
  both doc comments (Rust + TS) to state the real consequence.
- **Second, independent crypto-reviewer pass: caught a real process defect
  before it could ship — the fixes existed only in the working tree, `git
  diff --cached` still showed the vulnerable code (forgot to re-`git add`
  after editing already-staged files).** Also flagged that F2's fix
  comment's rationale was itself factually wrong (claimed a pre-import
  inspection "can never be resolved" by the old identity_id — false, since
  `import_mls_context_inner` never removes the OLD identity's `MlsContext`
  from `MLS_CTX`; only `mls_clear_session` does). Re-staged all 6 files,
  rewrote the F2 comment to state the real rationale (deliberate
  discontinuity policy, not orphan reclamation), reverified `git diff
  --cached` actually contains `StaleStagedCommit`/`mlsInspectCommit`/the
  `INSPECTED_COMMITS.clear()` call before committing. **Final verdict:
  PASS-with-nits** (2 non-blocking nits: the new test's second assertion
  isn't fully load-bearing — cosmetic; `mls_confirm_incoming_commit`
  consumes the handle before resolving `MLS_CTX`, so an
  unknown-identity/group error after a valid binding check would destroy an
  otherwise-recoverable commit — not reachable today, carried below).
- No `threat-model-checker` run: matches the established pattern for
  standalone WASM crypto-primitive additions with no server-visible metadata
  and explicitly not wired to any UI/broadcast flow. No `security-auditor`
  run: no backend/infra code touched.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; `powehi-crypto-wasm` alone: 219 passed, 2 ignored, up from
  218 pre-fix), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean. Frontend: `pnpm exec tsc --noEmit`
  clean, `biome check` clean (same 4 pre-existing unrelated errors), `pnpm
  vitest run` 112 files/1615 tests green (+1 from 1614).
- Committed `bd7ddde` (`feat(crypto): add MLS two-phase inspect/confirm/
  discard commit API (issue #2)`), 6 files changed, pushed clean (`0188f2a..
  bd7ddde main -> main`). `gh run list` showed all 3 checks `queued`
  immediately after push — confirm green in a future session if not already
  done. Posted a progress comment on issue #2 explaining what landed, the
  HIGH-severity finding and its fix, and what's still needed to wire this
  into the consumer loop — did NOT close the issue.
- Target dir hygiene: not checked in depth (FEATURE mode), spot-checked
  `target/` at 8.5G — well under the 20G threshold.
- **Next cycle candidates (carried/updated):**
  1. **New, real, non-blocking (crypto-reviewer second pass, this cycle):**
     `mls_confirm_incoming_commit` consumes the `INSPECTED_COMMITS` handle
     BEFORE resolving `MLS_CTX` — an `unknown mls identity`/`unknown mls
     group` error (as opposed to a genuine merge failure) after a valid
     `(identity_id, group_id)` binding check would still permanently destroy
     an otherwise-recoverable staged commit. Not reachable today (the
     binding check already requires the same identity/group that was live
     at inspect time), but worth moving the take-after-resolve if this is
     ever wired to a real consumer loop.
  2. Carried, still the natural next step for issue #2: the consumer-loop
     wiring itself into `useMessages.ts`/`useWelcomePoller.ts`, now that both
     of its previously-blocking preconditions (own-commit recognition,
     pre-merge policy-inspection point) are built. What remains is (a) the
     epoch-reconciliation design between the client's local MLS epoch and
     the server's `groups.epoch` counter, and (b) actually calling
     `mlsInspectCommit`/`mlsConfirmIncomingCommit`/`mlsDiscardIncomingCommit`
     from the poller with a real application-level policy check (e.g. only
     accept adds/removes from a recognized admin identity).
  3. Carried, low-priority hardening: RUSTSEC-2024-0429 (glib unsound) isn't
     enforced by cargo-deny's default policy.
  4. Carried (unchanged from cycle 466's list — see that section for full
     text): epoch reconciliation between client MLS epoch and server
     `groups.epoch`; `mls_group_members` `isSelf` leaf-index vs
     signature-key hardening; PQ hybrid Phase A prerequisite;
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` wiring
     (BLOCKED on F3 + HMAC gate); `PendingRemovalBanner` local cross-check
     hardening; GitHub issues #1 (SPA deployment path), #3 (no WebSocket
     client), #4 (load testing never run), #5 (prod-ap-seoul region/PIPA
     compliance), #8 (stale doc comment); prd.md §10 REST API doc drift;
     `pending_removals` forged-signal defense; unconsumed `RemovalRequired`
     WS event; Helm `monitoring.prometheusRule`/`serviceMonitor` overlay +
     CI render job; `key_packages.device_id` FK doc drift; consumed
     `key_packages` rows never garbage-collected; `GroupRepository::save`
     blind `ON CONFLICT DO UPDATE`; bare `var(--photon)` CSS token.

## Previous state (2026-09-09, cycle 470 — STABILIZATION: close the long-carried Tauri-shell cargo-deny/cargo-audit coverage gap (cycle 465 follow-up), commit 59b3e0a)

- Mode selection: counter 469→470, 470 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` green on `main`, working tree clean at session start.
  `gh issue list --state open` had 6 open issues, none labeled `bug`
  (issue #8 is `documentation`) — per STABILIZATION's own instruction to
  fix bug-labeled issues first only when one exists, moved to step 3
  (test/coverage gaps) and picked the top carried candidate from cycles
  465-469: `app/src-tauri/Cargo.lock` (the standalone Tauri `[workspace]`,
  not part of the root Cargo.toml) had zero `cargo audit`/`cargo deny`
  coverage anywhere, locally or in CI.
- Root cause (confirmed by running `cargo deny --manifest-path
  app/src-tauri/Cargo.toml check` directly): cargo-deny resolves its
  config relative to the manifest path, so the root `deny.toml` is never
  discovered for this standalone workspace — it silently fell back to
  cargo-deny's default config (an EMPTY license allow-list), which
  rejected every third-party license in the graph (456 rejection lines).
  `cargo audit --file app/src-tauri/Cargo.lock` by contrast already
  exited 0 (cargo-audit's default policy doesn't fail on non-vulnerability
  warnings) — 7 unmaintained/unsound warnings, no disclosed CVEs.
- **Fix**: added `app/src-tauri/deny.toml` — `[licenses]` allow-list
  copied verbatim from the root file (verified sufficient: every license
  expression in this graph, e.g. `0BSD OR MIT OR Apache-2.0`, `BSD-3-Clause
  AND MIT`, `(MIT OR Apache-2.0) AND Unicode-3.0`, is already satisfiable
  by root's existing MIT/Apache-2.0/BSD-3-Clause/Unicode-3.0/CC0-1.0/etc.
  list — no new license strings needed), `[licenses.private] ignore =
  true` for the crate's own AGPL-3.0-only license (mirrors root's
  precedent), and an `[advisories] ignore` list of the 6 cargo-deny-flagged
  unmaintained IDs (RUSTSEC-2024-0370 proc-macro-error, RUSTSEC-2025-0075/
  -0080/-0081/-0098/-0100 the abandoned `unic-*` family via
  `urlpattern -> tauri-utils`). Wired `cargo-deny` + `cargo-audit` into
  the existing `tauri-check` CI job via `taiki-e/install-action` (same
  unpinned-by-design convention as the existing `nextest` install).
- **security-auditor: PASS-with-nits, all 3 real findings fixed before
  commit.** (1) The deny.toml's advisories comment falsely claimed the
  5 `unic-*` ignores were "Linux desktop toolchain"/"compile-time or
  desktop-shell-only" — the reviewer proved via `cargo tree --target
  aarch64-apple-darwin -i unic-ucd-ident` that `urlpattern -> tauri-utils
  -> tauri` is a normal RUNTIME dependency edge on every target
  (macOS/Windows/iOS/Android too), and that `urlpattern` backs Tauri's
  isolation-pattern/remote-URL capability matching (an origin-authorization
  surface), not inert code — fixed by rewriting the comment to state this
  accurately and separate proc-macro-error's genuinely build-time-only
  case from the unic-* runtime case. (2) `cargo audit` actually reports
  **7** warnings, not 6 — RUSTSEC-2024-0429 (glib 0.18.5 `VariantStrIter`
  unsoundness, UB/possible NULL deref, fixed upstream in glib >=0.20.0 but
  gtk-rs 0.18.x pins the older glib) is real and was undocumented; the CI
  step's comment falsely claimed "all inventoried in deny.toml". Fixed:
  documented RUSTSEC-2024-0429 in deny.toml's advisories comment as a
  known-but-not-cargo-deny-enforced entry (matching the root deny.toml's
  own documented blind spot on `unsound`-category advisories, which
  aren't denied by cargo-deny's default policy) — deliberately did NOT
  add it to the `ignore` list since cargo-deny doesn't flag it (same
  "don't list what isn't actually flagged" convention the root file
  uses), and corrected the CI comment. (3) Cross-workspace waiver leak:
  running `cargo audit --file app/src-tauri/Cargo.lock` from repo ROOT
  cwd would silently apply the ROOT `.cargo/audit.toml`'s 12 ignores to
  this unrelated graph (reviewer verified by testing that injecting a
  config ignoring RUSTSEC-2024-0370 dropped the count 7→6) — no actual
  overlap exists today (verified: repo-root and `app/src-tauri`-cwd runs
  both report the same 7 crates), but it's a live footgun for any future
  root waiver. Fixed by adding `working-directory: app/src-tauri` to the
  CI step and changing the arg to a relative `--file Cargo.lock`, which
  makes cargo-audit look for `app/src-tauri/.cargo/audit.toml` (absent)
  instead of the root one. Re-verified locally after all 3 fixes: `cargo
  deny --manifest-path app/src-tauri/Cargo.toml check` → `advisories ok,
  bans ok, licenses ok, sources ok`; `cd app/src-tauri && cargo audit
  --file Cargo.lock` → exit 0, still 7 (unchanged, correctly scoped) warnings.
- **Full gate**: no Rust source or Cargo.toml/Cargo.lock changed in
  either workspace (only new `deny.toml` + CI YAML), so `cargo build/test`
  were unaffected — reconfirmed anyway: `cargo test --workspace` all
  green (0 failures, every crate, docker-gated testcontainers tests
  correctly `ignored` — no docker daemon in this sandbox), `cargo fmt
  --all --check` clean. `cargo check --locked --all-targets
  --manifest-path app/src-tauri/Cargo.toml` clean. Root `cargo audit`/
  `cargo deny check` (unrelated to this change) also reconfirmed clean.
  Frontend untouched this cycle, not re-run.
- No `crypto-reviewer` run: no crypto/MLS/OPAQUE code touched. No
  `threat-model-checker` run: CI/build-tooling config only, no
  server-visible metadata, no application code touched.
- Committed `59b3e0a` (`fix(ci): add cargo-deny/cargo-audit coverage for
  the Tauri shell lockfile`), 2 files changed, pushed clean (`649057f..
  59b3e0a main -> main`). CI verification for this push is tracked via a
  background monitor started this session — check `gh run list --commit
  59b3e0a` in a future session if this wasn't already confirmed green.
- Target dir hygiene: `target/` at 8.4G (well under the 20G threshold),
  0-byte `.rmeta` prune ran, no further pruning needed.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle** (was cycle 465 candidate #1): Tauri shell
     audit/deny coverage. No longer a gap.
  2. Carried, low-priority hardening (this cycle's review, not fixed —
     accepted as a documented blind spot matching root deny.toml's
     precedent): RUSTSEC-2024-0429 (glib unsound) isn't enforced by
     cargo-deny's default policy; would need `[advisories] unsound =
     "deny"` plus an explicit ignore (or waiting for gtk-rs to ship a
     glib >=0.20-compatible release) to actually gate on it.
  3. Carried (all items below are unchanged from cycle 466's list —
     see that section for full text): the MLS commit-processing
     consumer-loop wiring into `useMessages.ts`/`useWelcomePoller.ts`
     (needs pre-merge policy-inspection point + self-commit recognition,
     GitHub issue #2's largest remaining piece); epoch reconciliation
     between client MLS epoch and server `groups.epoch`; `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; PQ hybrid Phase A
     prerequisite; `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring (BLOCKED on F3 + HMAC gate); `PendingRemovalBanner` local
     cross-check hardening; GitHub issues #1 (SPA deployment path), #3
     (no WebSocket client), #4 (load testing never run), #5 (prod-ap-seoul
     region/PIPA compliance), #8 (stale doc comment); prd.md §10 REST API
     doc drift; `pending_removals` forged-signal defense; unconsumed
     `RemovalRequired` WS event; Helm `monitoring.prometheusRule`/
     `serviceMonitor` overlay + CI render job; `key_packages.device_id`
     FK doc drift; consumed `key_packages` rows never garbage-collected;
     `GroupRepository::save` blind `ON CONFLICT DO UPDATE`; bare
     `var(--photon)` CSS token.

## Current state (2026-09-09, cycle 466 — FEATURE: land orphaned WIP adding the MLS commit-processing consumer primitive (issue #2), fresh crypto-reviewer PASS, commit 7570b3b)

- Mode selection: counter 465→466, 466 % 5 != 0 → FEATURE. `gh run list
  --limit 5` green on `main`. **Working tree was NOT clean at session
  start** — another occurrence of the established pattern (see cycles
  458/460/464 process notes): substantial, well-documented, well-tested
  WIP in `crates/client/powehi-crypto-wasm/src/{mls_group,wasm_exports}.rs`
  + 4 frontend files (`crypto.worker.ts`, `useCryptoWorker.ts` + test +
  mock) implementing `process_incoming_commit` / `mls_process_commit` /
  `mlsProcessCommit` — exactly candidate #1 carried since cycle 464
  ("build the commit-processing consumer... the single largest remaining
  piece of issue #2") — but never committed.
- This is the peer/bystander-side counterpart to the already-landed
  committer-side `stage_remove_member`/`confirm_remove_member`/
  `abort_remove_member` trio (b737b2c): it processes a Commit sent by
  ANOTHER group member and merges it via openmls's `merge_staged_commit`,
  advancing the local epoch so the group doesn't fork. Also fixes the
  carried candidate #3/#4 (`prior_epoch`'s unguarded `u64 as f64` cast) by
  adding a new `u64_to_f64_checked` helper (mirror of the existing
  `f64_to_u64_checked`, JS_MAX_SAFE_INTEGER = 2^53-1 boundary, content-free
  error) used by both `mls_remove_member_stage`'s `priorEpoch` and the new
  `mls_process_commit`'s `newEpoch`.
- Read the whole diff file-by-file before treating "land it" as the
  cycle's action. `cargo build/test/fmt/clippy` all green as found
  (211 passed/2 ignored in `powehi-crypto-wasm`, +7 tests from the 204
  baseline), `pnpm exec tsc --noEmit`/`biome check` clean, `pnpm vitest
  run` 112 files/1611 tests green (+1 from the 1610 baseline).
- **crypto-reviewer (fresh pass): PASS, no blocking findings.** Per
  CLAUDE.md's rule and the now well-established lesson (cycles 459/460's
  orphaned WIP had doc comments that falsely claimed prior review/fixes),
  did NOT trust the diff's own extensive embedded RFC/openmls-internals
  claims — ran a fresh review that independently re-verified every one
  against the vendored openmls 0.8.1 source rather than the diff's
  comments: (1) RFC 9420 §6.3.2 `content_type`-before-decrypt ordering
  confirmed correct in both directions (the new guard in `decrypt_message`
  rejecting a misrouted Commit, and `process_incoming_commit` rejecting a
  misrouted Application message), including that `content_type` is bound
  into the sender-data AAD so a spoofed cleartext field can't be misused —
  it's authenticated, not just trusted. (2) `is_active()` vs
  `is_operational()` gating, `merge_staged_commit`'s internal
  `clear_pending_commit` call, and self-eviction via
  `RemoveOperation::WeWereRemovedBy` all confirmed against
  `processing.rs`/`membership.rs`. (3) Confirmed the diff's own
  self-identified deferred gaps are real and honestly flagged, not
  soft-pedaled: no pre-merge policy-inspection point (any member's Commit
  merges unconditionally, no application-level veto) and
  `StageCommitError::OwnCommit` (openmls's own self-commit detection)
  being collapsed into a generic `MlsError::Decrypt` are both correctly
  called out as blocking for a *future* wiring pass, not for this
  primitive-only change. (4) All 7 new Rust tests confirmed to exercise
  real 3-party `MlsGroup`/`OpenMlsRustCrypto` instances (no mocking) with
  genuine assertions (epoch match, `epoch_authenticator()` cryptographic
  agreement, roster exclusion, end-to-end encrypt/decrypt round-trip,
  and — notably — the own-staged-commit-silently-dropped race actually
  reproduced by execution, not asserted by comment). (5) `mlsProcessCommit`
  correctly added to `SYNC_FLUSH_ARG_METHODS` (mutates durable MLS state
  via merge; a reload right after must not roll back). (6) No plaintext/
  ciphertext/epoch logging introduced. One non-blocking nit (an
  unreachable wildcard match arm could use a clarifying comment) — not
  fixed, purely cosmetic.
- No `threat-model-checker` run: matches the established pattern for
  standalone WASM crypto-primitive additions with no server-visible
  metadata and explicitly not wired to any UI/broadcast flow (same
  reasoning as cycles 458/461/464's primitive-only additions). No
  `security-auditor` run: no backend/infra code touched.
- **Full gate, re-run after review**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean. Frontend: `pnpm exec tsc --noEmit`
  clean, `biome check` clean, `pnpm vitest run` 112 files/1611 tests green.
- Committed `7570b3b` (`feat(crypto): add MLS commit-processing consumer
  primitive (issue #2)`), 6 files changed, pushed clean (`427a9b0..7570b3b
  main -> main`). `gh run list` showed all 3 checks `in_progress`/`queued`
  immediately after push — confirm green in a future session if not
  already done. Posted a progress comment on issue #2 explaining what
  landed, what's verified, and the 3 concrete gaps (policy-inspection
  point, self-commit recognition, epoch reconciliation) still blocking
  wiring into the consumer loop — did NOT close the issue.
- Target dir hygiene: not checked in depth (FEATURE mode), spot-checked
  `target/` at 8.4G — well under the 20G threshold.
- **Next cycle candidates (carried/updated):**
  1. **New, real, the natural next step for this cycle's primitive
     (crypto-reviewer + issue #2 comment, this cycle):** build the
     consumer-loop wiring itself into `useMessages.ts`/
     `useWelcomePoller.ts` — needs (a) a pre-merge policy-inspection point
     (expose the `StagedCommit`'s proposals/committer identity before
     calling `merge_staged_commit`, since right now any member's Commit
     merges unconditionally with zero application-level veto) and (b)
     self-commit recognition (surface openmls's own
     `StageCommitError::OwnCommit` distinctly instead of collapsing it
     into generic `MlsError::Decrypt`, so the consumer loop can skip a
     commit this device itself sent without misreading a real fork as a
     no-op). This is now the single largest remaining piece of issue #2 —
     needs crypto-lead/mls-engineer scope, not a quick patch.
  2. Carried: epoch reconciliation between the client's local MLS epoch
     and the server's `groups.epoch` counter — still needed before
     `prior_epoch`/`newEpoch` can be used for anything server-side; they
     diverge from the first `mlsAddMember` since `group_service.rs::add_member`
     never advances the server counter. Unchanged this cycle (out of scope
     for a primitive-only addition).
  3. Carried, low-priority hardening: `mls_group_members`'s `isSelf` field
     is derived by leaf *index*, not signature key — worth switching if
     ever wired to a UI.
  4. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  5. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried: the `PendingRemovalBanner`'s local cross-check needs either
     (a) binding `device_id` into the MLS credential identity at creation
     time, or (b) leaning on §5.6 safety-number verification (now
     including the group variant) as the real local trust anchor for T3,
     updating the banner's copy accordingly.
  7. Carried: GitHub issue #1, P0-blocker, infra: "Frontend SPA has no
     deployment path (no Pages project, no deploy job)." Needs infra-lead
     scoping.
  8. Carried: GitHub issue #2, P0-blocker, security, frontend — progressed
     this cycle (see candidate #1 above for the concrete next step).
  9. Carried: GitHub issue #3, P1, frontend: "No WebSocket client:
     delivery runs on 3s polling despite a working WS hub."
  10. Carried: GitHub issue #4, P1, infra: "Load testing never run against
      real infra (Phase 5 DoD still open)."
  11. Carried: GitHub issue #5, P1, infra, compliance: "prod-ap-seoul is
      Hetzner Singapore, not Korea — PIPA blocks KR-home PII."
  12. Carried: GitHub issue #8, P2, documentation: "Stale doc comment:
      handle_oracle_secret_token claims a per-restart random key."
  13. Carried, doc-sync only, low priority: prd.md §10's REST API list is
      stale — missing `pending-removals` and `members`.
  14. Carried: the `PendingRemovalBanner` confirm click is still the only
      defense against a forged `pending_removals` signal.
  15. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all).
  16. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  17. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  18. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  19. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  20. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  21. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-09, cycle 465 — STABILIZATION: fix GitHub issue #7, Tauri shell Cargo.lock out of sync + no CI coverage, commit 3ee6bd6)

- Mode selection: counter 464→465, 465 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` green on `main`, working tree clean at session start
  (no orphaned WIP this time). `gh issue list --state open` had 7 open
  issues; per STABILIZATION's own instruction to fix bug-labeled issues
  first, picked issue #7 (`bug`, P2) over the P0/P1 issues that carry
  other labels (`security`, `infra`, `frontend`, `compliance` — none
  labeled `bug`).
- Issue #7: `app/src-tauri/Cargo.lock` (a standalone `[workspace]`, not a
  root workspace member) had no entries for `tauri-plugin-deep-link`/
  `tauri-plugin-notification` even though `Cargo.toml` declares both, so
  any tool that touched the manifest silently rewrote ~1400 lines — no CI
  job built the Tauri shell at all, so the drift went unnoticed, and the
  issue's own evidence traced the rewrite to the local JetBrains Rust
  indexer, not to any build command.
- **Fix**: `cargo generate-lockfile` in `app/src-tauri/`, verified with
  `cargo check --locked --all-targets` (0 errors; regenerated diff was
  +1129/-318, expected size for a from-scratch re-resolve of an
  out-of-date lock, not a red flag). Added a `tauri-check` job to
  `.github/workflows/ci-rust.yml`: installs the Linux WebKit2GTK 4.1/
  appindicator/rsvg/xdo/ssl apt deps + `patchelf`, then (1) `cargo check
  --locked` against the manifest and (2) copies the committed lockfile,
  runs `cargo generate-lockfile` fresh, and `diff -u`s the two — this
  second step is the actual fix for the issue's root cause, since
  `--locked` alone only rejects a lockfile *missing* a manifest
  requirement, not a re-resolve that lands on a different-but-still-valid
  graph (exactly what a repeated JetBrains rewrite would produce, and
  `--locked` would stay silent on it). Also added `publish = false` to
  the crate (it's an internal app shell, never meant for crates.io).
- **security-auditor: PASS, 3 non-blocking findings.** Confirmed the new
  apt-get step has zero `${{ }}` interpolation (no injection surface,
  actually stricter than an existing precedent in `load-test.yml` that
  does interpolate a version var into a shell string) and that action SHA
  pins match every other job. Findings: (1) medium — `cargo audit`/
  `cargo-deny` still don't scan this lockfile at all; `tauri-check` proves
  it compiles, not that it's safe. Investigated: running `cargo audit
  --file app/src-tauri/Cargo.lock` locally found only unmaintained
  (non-vulnerability) warnings, exit 0. Running `cargo-deny check` against
  it with the ROOT `deny.toml` FAILS (AGPL-3.0-only isn't in the root
  license allow-list — it was never meant to cover this crate's own
  license; and several `unic-*` crates pulled in via `tauri-utils` ->
  `urlpattern` are flagged unmaintained with no safe upgrade available) —
  giving this its own `deny.toml`/waiver file with the same rigor as the
  root one is real follow-up work, explicitly NOT attempted this cycle
  (would need per-advisory unreachability tracing like the existing
  `deny.toml`/`.cargo/audit.toml` comments have, not a quick patch).
  (2) low — the regenerated lockfile's dependency churn (111 bumps + 68
  new packages, 379→446) is bigger than "only fixing the lockfile" framing
  suggests; expected for a from-scratch re-resolve of a lock that was
  already badly out of date, not evidence of an unreviewed manifest
  change (Cargo.toml's only diff this cycle is the new `publish = false`
  line). (3) low, fixed this cycle: `--locked` alone doesn't catch a
  valid-but-different re-resolve — addressed by the `diff -u` step above,
  verified locally to be silent (no diff) against the just-regenerated
  lockfile before committing.
- No `threat-model-checker` run: CI/build-tooling config only, no
  server-visible metadata, no application code touched. No
  `crypto-reviewer` run: no crypto/MLS/OPAQUE code touched (the Tauri
  shell itself has none yet).
- **Verified against real CI, not just locally**: pushed, then polled
  `gh run list` until all 3 checks completed — `CI — Rust` (which now
  includes the new `tauri-check` job), `CI — Frontend`, `CI — Live-backend
  E2E` all `success`; confirmed via `gh run view --json jobs` that the
  `Tauri shell (check, locked)` job specifically succeeded, not just the
  workflow overall.
- Closed GitHub issue #7 with a summary of the fix, the verification, and
  an explicit note that the audit/deny coverage gap (finding 1 above) is
  tracked separately, not silently dropped.
- Committed `3ee6bd6` (`fix(ci): sync Tauri shell lockfile, add CI check
  (issue #7)`), 3 files changed, pushed clean (`7d01555..3ee6bd6 main ->
  main`).
- Target dir hygiene: `target/` at 6.2G (well under the 20G threshold,
  down from the 24-26G range cycles 450-460 were watching) — no prune
  needed, ran the 0-byte `.rmeta` cleanup anyway per the standard steps.
- **Next cycle candidates (carried/updated):**
  1. **New, real, non-blocking, medium priority (security-auditor, this
     cycle):** `app/src-tauri`'s `Cargo.lock` still has zero
     `cargo audit`/`cargo-deny` coverage. Needs a dedicated `deny.toml`
     (own license allow-list including AGPL-3.0-only, own advisory
     waivers for the `unic-*` unmaintained crates pulled in via
     `tauri-utils` -> `urlpattern` with no safe upgrade) with the same
     unreachability-tracing rigor as the root `deny.toml`/
     `.cargo/audit.toml` comments — not a quick patch, needs its own
     cycle or plan.
  2. Carried: the commit-processing consumer for issue #2's MLS Remove
     primitive — `useMessages.ts`/`useWelcomePoller.ts` still ack-and-drop
     any Commit-type envelope, which would fork the group if the
     primitive were wired in as-is. Single largest remaining piece of
     issue #2.
  3. Carried: epoch reconciliation between the client's local MLS epoch
     and the server's `groups.epoch` counter — needed before
     `prior_epoch` can be used for anything; they diverge from the first
     `mlsAddMember` since `group_service.rs::add_member` never advances
     the server counter.
  4. Carried, low-priority hardening: `wasm_exports.rs`'s `prior_epoch`
     `u64 as f64` conversion is unguarded — must be fixed before
     `prior_epoch` is used in a server-side precondition (candidate #3).
  5. Carried, low-priority hardening: `mls_group_members`'s `isSelf` field
     is derived by leaf *index*, not signature key — worth switching if
     ever wired to a UI.
  6. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  7. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  8. Carried: the `PendingRemovalBanner`'s local cross-check needs either
     (a) binding `device_id` into the MLS credential identity at creation
     time, or (b) leaning on §5.6 safety-number verification (now
     including the group variant) as the real local trust anchor for T3,
     updating the banner's copy accordingly.
  9. Carried: GitHub issue #1, P0-blocker, infra: "Frontend SPA has no
     deployment path (no Pages project, no deploy job)." Needs infra-lead
     scoping.
  10. Carried: GitHub issue #2, P0-blocker, security, frontend (see
      candidates #2-#5 above for the concrete next steps).
  11. Carried: GitHub issue #3, P1, frontend: "No WebSocket client:
      delivery runs on 3s polling despite a working WS hub."
  12. Carried: GitHub issue #4, P1, infra: "Load testing never run against
      real infra (Phase 5 DoD still open)."
  13. Carried: GitHub issue #5, P1, infra, compliance: "prod-ap-seoul is
      Hetzner Singapore, not Korea — PIPA blocks KR-home PII."
  14. Carried: GitHub issue #8, P2, documentation: "Stale doc comment:
      handle_oracle_secret_token claims a per-restart random key."
  15. Carried, doc-sync only, low priority: prd.md §10's REST API list is
      stale — missing `pending-removals` and `members`.
  16. Carried: the `PendingRemovalBanner` confirm click is still the only
      defense against a forged `pending_removals` signal.
  17. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all).
  18. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  19. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  20. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  21. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  22. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  23. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-09, cycle 464 — FEATURE: land cycles 462/463's orphaned WIP adding an MLS Remove commit stage/confirm/abort primitive (issue #2), fix 3 crypto-reviewer blockers before committing, commit b737b2c)

- Mode selection: counter 463→464, 464 % 5 != 0 → FEATURE. **Working tree
  was NOT clean at session start** — the eighth+ occurrence of the
  now-familiar pattern: substantial, well-documented, well-tested WIP in
  `crates/client/powehi-crypto-wasm/src/{mls_group,wasm_exports}.rs` +
  4 frontend files (`crypto.worker.ts`, `useCryptoWorker.ts` + its test +
  mock) implementing `mls_remove_member_stage/confirm/abort` — the crypto
  primitive layer for the long-carried P0-blocker candidate (GitHub issue
  #2: "Client cannot evict a compromised device: no MLS Remove commit
  path, PCS unattainable") — but never committed.
- Read the whole diff file-by-file before treating "land it" as the
  cycle's action. `cargo build/test/fmt/clippy` all green as found
  (200 passed/2 ignored in `powehi-crypto-wasm`, +7 new tests), `pnpm exec
  tsc --noEmit`/`biome check` clean, `pnpm vitest run` 112 files/1610
  tests green (+10 from the 1600 baseline). Per CLAUDE.md's rule and the
  cycle-460 lesson (an uncommitted diff's own "already reviewed" doc
  comments are not evidence a review actually happened), ran a **fresh**
  `crypto-reviewer` pass myself rather than trusting the WIP's embedded
  claims.
- **crypto-reviewer (fresh pass): NEEDS-REWORK, 3 real blockers, not
  nitpicks.** (1) **F1:** `confirm_remove_member`/`abort_remove_member`
  called `merge_pending_commit`/`clear_pending_commit` unconditionally,
  both of which silently return `Ok(())` when there's nothing staged
  (openmls's own documented no-op-on-`Operational` behavior) — so
  confirm/abort-without-a-stage, AND a second confirm retried after a
  failed merge (the merge transitions state to `Operational` *before*
  attempting the merge, destroying the staged commit either way), both
  silently "succeeded" having done nothing. A TS doc comment in
  `crypto.worker.ts` asserted the opposite ("rejected by the WASM layer"),
  which was false. Fail-open on exactly the operation whose purpose is
  restoring PCS. (2) **F2:** `stage_remove_member` had no guard against a
  non-empty proposal store — `remove_members`'s `commit_builder()` folds
  in *every* queued proposal by default (confirmed against vendored
  openmls 0.8.1 `commit_builder.rs`), not just Adds, so a queued Remove/
  Update/GroupContextExtensions proposal (fed by a future
  `store_pending_proposal` call once a commit-processing consumer exists)
  would silently ride along with what the caller believes is a
  single-target eviction. (3) **F3:** the PCS doc comment cited RFC 9420
  §12.1.3 backwards — claimed removal requires the leaf to end up
  "non-blank" in the tree; actually non-blank is the *precondition on the
  target before* the proposal applies, and the leaf is *blanked* as the
  post-state (confirmed against vendored `public_group/validation.rs` +
  `apply_proposals.rs`). Also flagged 5 non-blocking nits (F4 §12.4 path-
  required-set over-generalization, F5 self-removal-guard doc undersold
  as the *only* protection, F9 all failures collapsing to one
  `MlsError::Membership` string, F10 debug_assert framing, F11 a PCS test
  assertion over-claiming what it proves past openmls's `is_active()`
  guard) plus 2 deferred-to-follow-up items (F6 `isSelf` is index- not
  key-derived; F7 unguarded `u64→f64` on `prior_epoch`).
- **Fixed F1/F2/F3 plus F4/F5/F8/F9/F10/F11**, re-verified by a **second,
  independent crypto-reviewer pass: PASS-with-nits, no blockers.** F1 fix:
  gated both functions on `group.pending_commit().is_none()` →  new
  content-free `MlsError::NoPendingCommit` variant (removed the now-dead
  best-effort `clear_pending_commit` cleanup branch this uncovered). F2
  fix: reject on `group.pending_proposals().next().is_some()` → new
  `MlsError::PendingProposals` variant, before calling `remove_members`.
  F3/F4: rewrote the RFC citations correctly. F5: reframed the
  self-removal check's doc as the function's *only* protection (openmls
  doesn't independently reject self-removal). F8: documented two more
  wiring preconditions the reviewer surfaced (reload wedges a group with
  no JS-side record a stage was outstanding; a failed Dexie persist after
  a successful in-memory stage has no rollback). Added 5 new Rust tests
  (`confirm_without_stage_rejected`, `abort_without_stage_rejected`,
  `confirm_twice_second_call_rejected`,
  `rejects_when_proposals_are_pending` — which also discovered and pins
  that `encrypt_message` itself refuses to run while a proposal is queued,
  confirmed correct by the reviewer against openmls `application.rs`).
  Second pass additionally confirmed F6/F7's deferral is acceptable (both
  unreachable today; F7 must close before `prior_epoch` is ever used
  server-side) and flagged one more cheap nit (`abort_remove_member`'s new
  gate still reports success on an unreachable
  `PendingCommitState::External` no-op) which I folded in as a doc-only
  caveat before committing, since no `external_commit` call exists
  anywhere in this codebase today.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; `powehi-crypto-wasm` alone: 204 passed, 2 ignored, up from
  200 pre-fix), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean. Frontend files were untouched by
  the fix round (confirmed by the second review pass: byte-identical to
  the first pass), so the earlier `tsc`/`biome`/`vitest` green run still
  applies unchanged.
- No `threat-model-checker` run: matches the established pattern for
  standalone WASM crypto-primitive additions with no server-visible
  metadata and explicitly not wired to any UI/broadcast flow (same
  reasoning as cycles 458/461's primitive-only additions). No
  `security-auditor` run: no backend/infra code touched.
- Committed `b737b2c` (`feat(crypto): add MLS Remove commit stage/confirm/
  abort primitive (issue #2)`), 6 files changed, pushed clean (`f4176bb..
  b737b2c main -> main`). `gh run list` showed all 3 checks `queued`
  immediately after push. Posted a progress comment on issue #2
  explaining what landed and what's still needed to actually close it
  (commit-processing consumer, removing the `useMessages.ts`/
  `useWelcomePoller.ts` ack-and-drop of Commit envelopes, epoch
  reconciliation, then UI wiring) — did NOT close the issue, since the
  primitive alone doesn't let a user evict a device yet.
- **Process note, continuing** (now well past double digits of prior
  occurrences): a cycle keeps doing real, reviewed-in-comments work and
  burning its counter slot without committing. This cycle is another data
  point that a landing cycle re-running the review gate fresh is
  necessary, not just cautious — the WIP's own embedded doc comments this
  time didn't claim a prior review had happened (unlike cycle 459's false
  claims), but the code still had 3 real blockers a fresh pass caught.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. **New, real, the natural next step for this cycle's primitive
     (crypto-reviewer + issue #2 comment, this cycle):** build the
     commit-processing consumer — nothing in the app currently handles a
     Commit-type envelope; `useMessages.ts`/`useWelcomePoller.ts` both
     ack-and-drop it today, which would fork the group if this primitive
     were wired in as-is. This is the single largest remaining piece of
     issue #2, needs crypto-lead/mls-engineer scope.
  2. **New, real, needed before `prior_epoch` can be used for anything
     (carried from stage_remove_member's doc comment):** design epoch
     reconciliation between the client's local MLS epoch and the server's
     `groups.epoch` counter — they diverge from the very first
     `mlsAddMember` today since nothing in `group_service.rs::add_member`
     advances the server counter.
  3. Carried, low-priority hardening (crypto-reviewer, this cycle, F7):
     `wasm_exports.rs`'s `prior_epoch` `u64 as f64` conversion is
     unguarded (unlike the existing `f64_to_u64_checked` used for inbound
     values) — must be fixed before `prior_epoch` is ever used in a
     server-side precondition, per candidate #2 above.
  4. Carried, low-priority hardening (crypto-reviewer, this cycle, F6):
     `mls_group_members`'s new `isSelf` field is derived by comparing leaf
     *index*, not signature key, against `own_leaf_index()` — MLS reuses
     blanked leaf indices for new joiners, so this holds "at most one
     `isSelf`" by state-machine accident (openmls's `Inactive` guard on an
     evicted handle), not by construction. Worth switching to a
     signature-key comparison against `own_leaf_node()` if this is ever
     wired to a UI.
  5. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  6. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  7. Carried: the `PendingRemovalBanner`'s local cross-check needs either
     (a) binding `device_id` into the MLS credential identity at creation
     time, or (b) leaning on §5.6 safety-number verification (now including
     the group variant) as the real local trust anchor for T3, updating the
     banner's copy accordingly.
  8. Carried: GitHub issue #1, P0-blocker, infra: "Frontend SPA has no
     deployment path (no Pages project, no deploy job)." Needs infra-lead
     scoping.
  9. Carried: GitHub issue #3, P1, frontend: "No WebSocket client: delivery
     runs on 3s polling despite a working WS hub."
  10. Carried: GitHub issue #4, P1, infra: "Load testing never run against
      real infra (Phase 5 DoD still open)."
  11. Carried: GitHub issue #5, P1, infra, compliance: "prod-ap-seoul is
      Hetzner Singapore, not Korea — PIPA blocks KR-home PII."
  12. Carried: GitHub issue #7, P2, bug: "app/src-tauri/Cargo.lock is out of
      sync with its Cargo.toml; no CI builds the Tauri shell."
  13. Carried: GitHub issue #8, P2, documentation: "Stale doc comment:
      handle_oracle_secret_token claims a per-restart random key."
  14. Carried, doc-sync only, low priority: prd.md §10's REST API list is
      stale — missing `pending-removals` and `members`.
  15. Carried: the `PendingRemovalBanner` confirm click is still the only
      defense against a forged `pending_removals` signal.
  16. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all).
  17. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  18. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  19. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  20. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  21. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  22. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-08, cycle 461 — FEATURE: fix GitHub issue #6, `pnpm build:wasm` wrote to the wrong out-dir and Vite silently substituted a no-op crypto stub, commit 86ccec7)

- Mode selection: counter 460→461, 461 % 5 != 0 → FEATURE. `gh run list
  --limit 5` green on `main`, working tree clean at session start (no
  orphaned WIP — first clean start in a while). `gh issue list --state
  open` was NOT empty this time (8 open issues, several P0/P1) — FEATURE
  mode's own instructions don't mandate an issue sweep, but a P1 bug
  titled "pnpm build:wasm writes to the wrong out-dir; Vite silently
  substitutes a no-op crypto stub" (issue #6) was serious enough (crypto
  silently disabled with zero signal) to pull instead of a project-context
  candidate.
- Root cause confirmed by reading the code directly: root `package.json`'s
  `build:wasm` ran `wasm-pack build ... --out-dir pkg` (relative to the
  crate → `crates/client/powehi-crypto-wasm/pkg/`), but `app/vite.config.ts`'s
  `powehiWasmStub()` plugin looks for `app/src/wasm/powehi_crypto_wasm.js`
  and silently resolves to a no-op stub module when that's missing/stale.
  Only `.github/workflows/ci-e2e-live.yml` happened to build to the right
  place (`--out-dir ../../../app/src/wasm`); the documented root script
  never did. README.md and `opaqueWasmZeroize.node.test.ts`'s comment
  already stated the correct `app/src/wasm` target, so only the script
  itself needed fixing, not those docs.
- **Fix**: (1) aligned `build:wasm`'s `--out-dir` with CI's, verified by
  actually running it (`export PATH="$HOME/.cargo/bin:$PATH"` was needed —
  cargo isn't on the session's default PATH) — produced real artifacts
  directly in `app/src/wasm/`, confirmed `mls_compute_group_safety_number`
  (cycle 458's export) is present in the `.d.ts`. (2) Added a `buildStart`
  hook to `powehiWasmStub` that warns loudly (`console.warn`) when the real
  artifact is missing OR older (mtime) than any `.rs`/`Cargo.toml` under
  the crate (bounded walk, 2000-entry limit, excludes `target`/`pkg`/
  `pkg-node`/`tests`). Manually verified both warning paths fire via a real
  `vite build` (moved `app/src/wasm` aside; then `touch`ed a crate source
  file against a rebuilt artifact).
- **security-auditor: PASS-with-nits, both nits fixed before commit.**
  Confirmed the out-dir math is correct (`../../../app/src/wasm` from the
  crate climbs client→crates→root then descends), confirmed the staleness
  walk's shared `visited` counter genuinely bounds a symlink-loop/
  pathological tree (not just decorative), confirmed no secrets/PII in the
  warning strings, confirmed `powehiWasmStub` having no `apply` restriction
  (unlike `sriPlugin`'s `apply: "build"`) predates this diff (`git log -p`)
  and is out of scope. **Real nit (moderate): CI's `vitest` job
  (`ci-frontend.yml`) only builds `build:wasm:node` (nodejs target →
  `pkg-node`), never `build:wasm` (web target → `app/src/wasm`) — since
  unit tests intentionally mock the Comlink worker boundary per
  testing-conventions.md and never need real wasm — so the new warning
  would otherwise fire on every green CI run and train reviewers to ignore
  it.** Fixed by skipping the warning when `process.env.VITEST` is set
  (Vitest sets this itself); reverified silent under `pnpm vitest run`
  afterward. **Nit (low): the walk didn't exclude `tests/`, so editing only
  wasm-bindgen integration tests (which don't affect the shipped lib
  artifact) could trip a false "stale" warning** — fixed by adding `tests`
  to the directory-name skip list alongside `target`/`pkg`/`pkg-node`.
- **Full gate, re-run after every fix round**: no Rust logic changed (only
  the `wasm-pack` invocation's `--out-dir` flag), so no `cargo
  build/test/fmt/clippy` re-run needed — confirmed by `git status --short`
  showing only `app/vite.config.ts` and `package.json` touched. Frontend:
  `pnpm exec tsc --noEmit` clean, `biome check` clean on `vite.config.ts`,
  `pnpm vitest run` 112 files/1600 tests green both before and after the
  `VITEST`-skip fix (unaffected either way — the warning was never part of
  any assertion).
- No `crypto-reviewer` run: no crypto/MLS/OPAQUE primitive logic touched,
  only the build-tooling path that loads the already-reviewed WASM module
  and a diagnostic `console.warn`. No `threat-model-checker` run: no new
  server-visible metadata, no trust-boundary change — this is dev/build
  tooling visibility, not an architectural change.
- Closed GitHub issue #6 with a summary of the fix and verification
  (`gh issue close 6 --comment ...`) — confirmed fixed, not just filed
  away; the four suggested-work checklist items in the issue are now all
  addressed (out-dir fixed; docs were already correct so nothing to
  change there; stub is loud in dev; staleness check added).
- Committed `86ccec7` (`fix(frontend): point build:wasm at app/src/wasm,
  warn on stub fallback`), 2 files changed, pushed clean (`5089b7c..86ccec7
  main -> main`). `gh run list` showed all 3 checks `in_progress`
  immediately after push — confirm green in a future session if not
  already done.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  3. Carried: the `PendingRemovalBanner`'s local cross-check needs either
     (a) binding `device_id` into the MLS credential identity at creation
     time, or (b) leaning on §5.6 safety-number verification (now including
     the group variant) as the real local trust anchor for T3, updating the
     banner's copy accordingly.
  4. **New, from this cycle's open-issue sweep — GitHub issue #2, P0-blocker,
     security, frontend:** "Client cannot evict a compromised device: no MLS
     Remove commit path, PCS unattainable." Matches long-carried candidate
     (frontend has never constructed/landed a real MLS Remove Commit — see
     old candidates about `removeMember` being server-bookkeeping-only).
     This is the single most-flagged remaining gap across many past cycles;
     worth prioritizing as the next FEATURE-mode item — needs crypto-lead/
     mls-engineer scope (constructing and landing an MLS Remove Commit from
     the frontend crypto worker), not a quick patch.
  5. **New, from this cycle's open-issue sweep — GitHub issue #1,
     P0-blocker, infra:** "Frontend SPA has no deployment path (no Pages
     project, no deploy job)." Needs infra-lead scoping.
  6. **New, from this cycle's open-issue sweep — GitHub issue #3, P1,
     frontend:** "No WebSocket client: delivery runs on 3s polling despite
     a working WS hub." Matches long-carried candidate (the `RemovalRequired`
     WS event has been "still unconsumed" for many cycles because no
     frontend WS client exists at all). Building one would also let the
     `PendingRemovalBanner` (candidate #3) go live-push instead of
     REST-poll-on-mount.
  7. **New, from this cycle's open-issue sweep — GitHub issue #4, P1,
     infra:** "Load testing never run against real infra (Phase 5 DoD still
     open)."
  8. **New, from this cycle's open-issue sweep — GitHub issue #5, P1,
     infra, compliance:** "prod-ap-seoul is Hetzner Singapore, not Korea —
     PIPA blocks KR-home PII." Compliance-sensitive, needs infra-lead +
     likely a real region migration, not a quick fix.
  9. **New, from this cycle's open-issue sweep — GitHub issue #7, P2, bug:**
     "app/src-tauri/Cargo.lock is out of sync with its Cargo.toml; no CI
     builds the Tauri shell."
  10. **New, from this cycle's open-issue sweep — GitHub issue #8, P2,
      documentation:** "Stale doc comment: handle_oracle_secret_token
      claims a per-restart random key."
  11. Carried, doc-sync only, low priority: prd.md §10's REST API list is
      stale — missing `pending-removals` and `members`.
  12. Carried: the `PendingRemovalBanner` confirm click is still the only
      defense against a forged `pending_removals` signal.
  13. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all) — see #6
      above, same root cause.
  14. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  15. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  16. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  17. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  18. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  19. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-08, cycle 460 — STABILIZATION: land cycle 459's orphaned WIP wiring the group safety number into ChatLayout's InfoPanel, fix a real crypto-reviewer NEEDS-REWORK finding, commit 13243fb)

- Mode selection: counter 459→460, 460 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` green on `main`, `gh issue list --state open` empty.
  **Working tree was NOT clean at session start** — the seventh occurrence
  of this pattern (cycles 448/449, 451, 454, 455, 457→458, now 459→460):
  cycle 459 had done substantial, coherent, well-tested work wiring
  cycle 458's candidate #4 (`mlsComputeGroupSafetyNumber` had zero UI
  consumers) into `ChatLayout.tsx`'s InfoPanel, with doc comments citing
  its own in-session "crypto-reviewer, cycle 459" findings F1/F2/F5/B1 as
  already found and fixed — but never committed it.
- Read the whole diff file-by-file, confirmed `cargo build/test/fmt/clippy`
  all green as found (193 passed/2 ignored in `powehi-crypto-wasm`, 0
  failures workspace-wide), `cargo audit`/`cargo deny check` clean,
  `pnpm exec tsc --noEmit`/`biome check` clean, `pnpm vitest run` green
  (112 files/1599 tests) — then, per CLAUDE.md's rule that review gates
  run in-session before commit, did NOT take the diff's own uncommitted
  "already reviewed" doc comments at face value and ran a fresh
  `crypto-reviewer` pass myself (this session's cycle 459 never actually
  committed, so there's no way to confirm the cited review really
  happened as described, or happened correctly).
- **crypto-reviewer (fresh pass): NEEDS-REWORK, and it caught a real bug
  the diff's own comments had claimed was already fixed.** (1) **F1,
  blocking:** the group safety-number effect's re-run trigger
  (`groupMemberIdsKey`, derived from `chat.members`) was dead code for
  every real group — `chat.members` is populated only by the hardcoded
  seed fixture (`ChatLayout.tsx:398`); every runtime group is created by
  `handleNewGroup` with no `members` array, and the only runtime
  membership-mutating path (`handleMemberAdded`, wired to
  `AddMemberModal`'s "Add member" button in the chat header, reachable
  while InfoPanel is open) bumps `chat.memberCount` only. So adding a
  member to a real group never re-triggered the fingerprint recompute —
  the UI kept showing a stale "Membership verified" badge with no MITM
  warning after a real membership change, exactly the tampering event
  this fingerprint exists to catch. The diff's own doc comment claiming
  this was "fixed" per a prior "crypto-reviewer, cycle 459, finding F2"
  was false. (2) **F2, blocking (TDD-law violation):** the diff's
  regression test for a claimed render-timing race (switching from a
  verified DM to a group while InfoPanel is open, asserting BEFORE
  `waitFor`) had a comment claiming this was "confirmed empirically" to
  catch the race — the reviewer mutation-tested it twice (swap the
  render-time reset for an equivalent `useEffect`; delete the reset
  entirely) and the test passed both times, because RTL's `fireEvent`
  wraps every dispatch in `act()`, which flushes all passive effects
  before the assertion runs — no pre-effect-flush commit is ever
  observable through jsdom. The comment's empirical claim was fabricated
  or wrong. (3) F3, non-blocking nit: `chat.isGroup` is a local UI flag
  never derived from real MLS member count/state — if it ever went out
  of sync between two peers' clients, they'd compute different
  domain-separated safety numbers and see a false MITM alarm during an
  in-person comparison. Carried, not fixed this cycle.
- **Fixed F1 and F2, both independently re-verified by a second
  crypto-reviewer pass (PASS-with-nits) via its own mutation tests, not
  just re-reading my diff.** F1 fix: replaced `groupMemberIdsKey` with
  `groupMemberCountKey = chat.isGroup ? (chat.memberCount ?? 0) : 0` in
  the effect's dependency array (`ChatLayout.tsx:5219,5291`), rewrote the
  doc comment to accurately state `chat.members` is dead for real chats
  and that `memberCount`-keying is still incomplete (doesn't cover a
  remote Add via the Welcome poller, a remove, or another member's
  self-Update/key-rotation — those are only caught on the next fresh
  InfoPanel mount for that chat). I mutation-tested this fix myself
  before commit (temporarily hardcoded `groupMemberCountKey = 0`,
  confirmed the new regression test failed; restored the fix, confirmed
  it passed) — the second review agent independently reran the same
  mutation plus a second one (reverting to the literal original buggy
  `chat.members`-based expression) and confirmed both fail without the
  fix. F2 fix: removed the false pre-`waitFor` assertion and its
  fabricated-claim comment from the chat-switch test, renamed it to
  describe only the settled-state guarantee it actually provides, and
  added an honest comment (independently verified true by the second
  review agent's own mutation test) explaining the render-timing half
  isn't unit-testable through this harness. Added a NEW real regression
  test, "recomputes and flags a mismatch after a member is added to an
  already-verified group (F1)": creates a group, verifies its safety
  number, adds a member through the actual `AddMemberModal` flow (not a
  mocked shortcut — only the Comlink worker proxy and the `addMember`
  REST call are mocked, per `testing-conventions.md`'s stated crypto
  boundary), and asserts `mlsComputeGroupSafetyNumber` is called a second
  time and the "Group membership changed since you last verified" MITM
  banner appears. Also applied 2 of the second pass's non-blocking nits
  in-session (N1: comment now explicitly names the remote-Add/remove/
  key-rotation gap instead of a vague "not authoritative" hedge; N2:
  fixed a dangling "see the note above" self-reference).
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate, unchanged from cycle 459's WIP since no Rust logic
  changed this round — only a doc-comment-adjacent test-message tighten
  was already in the WIP as found), `cargo fmt --all --check` clean,
  `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  audit`/`cargo deny check` clean. Frontend: `pnpm exec tsc --noEmit`
  clean, `biome check` clean on all touched files, `pnpm vitest run` 112
  files/1600 tests green (up from 1599 pre-fix — net +1 after removing
  the false-guard assertion but adding the new real regression test; one
  unrelated poll-voters test flaked once, reran green, not a regression).
- No `threat-model-checker` run: client-side-only diff, no new
  server-visible metadata or handler change (both review passes agreed
  this gate doesn't apply here). No `security-auditor` run: no backend/
  infra code touched.
- Committed `13243fb` (`feat(frontend): wire group whole-membership
  safety number into InfoPanel`), 8 files changed, pushed clean
  (`560ebcb..13243fb main -> main`). `gh run list` showed all 3 checks
  (`CI — Rust`, `CI — Frontend`, `CI — Live-backend E2E`) `in_progress`
  immediately after push — confirm green in a future session if not
  already done.
- **Process note, now the seventh time** (cycles 448/449, 451, 454, 455,
  457→458, 459→460): a cycle keeps doing real, reviewed-in-comments work
  and burning its counter slot without committing — and this cycle shows
  why that pattern is actually risky, not just wasteful: the "already
  reviewed" doc comments in the orphaned WIP were themselves wrong (F1
  was claimed fixed but wasn't; F2's empirical claim was fabricated). A
  landing cycle must re-run the required review gate itself rather than
  trusting an uncommitted diff's self-reported review history, exactly
  as this cycle did — this is now validated as necessary, not just
  cautious.
- Target dir hygiene: `target/` at 24G (over the 20G threshold, up from
  23-26G in cycles 450/451/455/460's own pre-prune reading), the
  mtime+7 prune found nothing eligible (all content from active recent
  work) — same as every prior check. Not actionable yet; worth watching
  if it keeps climbing past ~35-40G without anything aging out, since
  cron's own instructions cite a past 49GB/291k-file incident.
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  3. Carried (superseded framing from cycle 456 still applies): the
     `PendingRemovalBanner`'s local cross-check needs either (a) binding
     `device_id` into the MLS credential identity at creation time, or (b)
     leaning on §5.6 safety-number verification (now including this
     cycle's new group variant) as the real local trust anchor for T3,
     updating the banner's copy accordingly.
  4. **New, real, non-blocking (crypto-reviewer, this cycle, finding F3):**
     `chat.isGroup` is a local UI flag that dispatches between the
     pairwise/group safety-number constructions but is never derived
     from or cross-checked against real MLS member count/state. If it
     ever went out of sync between two peers' clients (no known path
     today, but nothing enforces the invariant), they'd compute different
     domain-separated fingerprints and see a false MITM alarm during an
     in-person comparison. Worth deriving from actual member count or
     recording the invariant with an assertion/test.
  5. **New, real, non-blocking (second crypto-reviewer pass, this
     cycle, finding N3):** the render-time state reset for the InfoPanel
     chat-switch case (`ChatLayout.tsx:5180-5187`, cycle 459's original
     F1 fix) has zero direct test coverage — a mutation test proved the
     full test file stays green even with that block deleted entirely.
     `InfoPanel` isn't exported, so a direct-render unit test isn't
     possible today; either export it for testing or explicitly record
     this as an accepted coverage gap rather than leaving it silently
     uncovered.
  6. **New, real but low-urgency (crypto-reviewer, this cycle):** the
     `groupMemberCountKey` re-run trigger added this cycle only catches a
     LOCAL `mlsAddMember`. A remote Add (via the Welcome poller), a
     remove, or another member's self-Update/key-rotation while the
     InfoPanel is open won't trigger a recompute — only closing and
     reopening the panel does (which recomputes unconditionally, so it's
     not silently wrong forever, just not live). Closing this gap needs a
     live epoch/member-count signal read from the worker itself, not a
     UI-local counter.
  7. Carried, doc-sync only, low priority: prd.md §10's REST API list is
     stale — missing `pending-removals` and `members`.
  8. Carried: the `PendingRemovalBanner` confirm click is still the only
     defense against a forged `pending_removals` signal.
  9. Carried: no MLS Remove commit path exists in the frontend at all yet.
  10. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all).
  11. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  12. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  13. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  14. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  15. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  16. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-08, cycle 458 — FEATURE: land cycle 457's orphaned WIP adding an N-party MLS group safety number WASM export, commit c62edf1)

- Mode selection: counter 457→458, 458 % 5 != 0 → FEATURE. **Working tree
  was NOT clean at session start** — same recurring process gap as cycles
  448/449/451/454/455 (now the sixth occurrence): cycle 457 had done
  substantial, coherent, already partially self-reviewed work (its own doc
  comment cited "crypto-reviewer, cycle 457") adding
  `mls_compute_group_safety_number` — an N-party generalization of the
  existing 2-party `mls_compute_safety_number` (prd.md §5.6) — to
  `powehi-crypto-wasm`, plus a thin worker wrapper
  `mlsComputeGroupSafetyNumber` in `crypto.worker.ts`, with 6 new Rust
  unit tests, but never committed it.
- Read the whole diff, confirmed `cargo build/test/fmt/clippy` all green
  on the WIP as found (0 failures across every crate), `pnpm exec tsc
  --noEmit`/`biome check` clean, full `pnpm vitest run` unaffected
  (112 files/1595 tests — the new export has no UI consumer yet, matching
  the pattern of other WASM primitives landing ahead of their frontend
  wiring). Confirmed via grep that `mlsComputeGroupSafetyNumber` is not
  referenced anywhere outside the worker file itself — a pure primitive
  addition, not a partial UI feature.
- **crypto-reviewer (first pass): PASS-with-nits, real findings, not
  nitpicks.** (1) `GROUP_SAFETY_NUMBER_DOMAIN`'s doc wrongly credited the
  member-count field, not the distinct domain string, with preventing a
  2-member group from colliding with the pairwise construction — with
  fixed-32-byte length-prefixed operands the pairwise encoding is already
  injective, so two different domain strings alone are what separates the
  two; count is only defense-in-depth against different-*sized* groups
  colliding with each other. (2) **The real bug**: the 512-member bound
  was enforced by checking `keys.len()` *after* `mls_group_members_inner`
  had already unboundedly collected every member into a `Vec` — so the
  doc's "an unbounded loop can never happen" claim was false; only the
  hashing loop was bounded, not the collection. Fixed by adding a
  dedicated `mls_group_signature_keys_bounded(identity_id, group_id, max)`
  helper that calls `group.members().take(max.saturating_add(1))`
  directly — verified in the re-review (by tracing openmls 0.8.1's actual
  call chain: `MlsGroup::members` → `PublicGroup::members` →
  `TreeSync::full_leaf_members`, which is a lazy `filter_map().map()`
  chain with no intermediate collect) that `.take()` genuinely bounds the
  tree walk itself, not just a post-hoc check. This required removing the
  now-dead `sig_key: Vec<u8>` field from `MlsMemberInfo` (only the new
  helper needed raw key bytes; `mls_group_members`/`mls_group_members_inner`
  — the pre-existing, unrelated export — only ever used `sig_key_hex`, and
  the re-review confirmed that export's diff hunk is net-zero, fully
  unaffected). (3) the "not server-reported data" bound justification
  needed to also note group size is still remotely influenced (members
  join via Commit/Welcome, RFC 9420 §12.1.1/§12.4), and that the eventual
  UI consumer must render "too many members to verify" distinctly from
  "verification failed" — added to the doc comment. (4) missing a
  known-answer test for the group construction (the pairwise one has one;
  without it a refactor could silently change every already-verified group
  safety number with the other, behavior-only tests staying green) — added
  `test_group_safety_number_known_answer` with a frozen 3-key vector,
  cross-checked against an independent Python SHA-512 computation before
  writing it into the test, then re-verified independently by the review
  agent itself. (5) the out-of-bounds test only exercised `max+1` (513)
  rejected, never `max` (512) itself accepted — a `>`→`>=` regression
  would've gone undetected — added
  `test_group_safety_number_accepts_exactly_the_bound`. (6) the
  order-independence test only compared forward vs. exact full reversal of
  a 3-key set — widened to a 4-key genuine shuffle (`[k3,k1,k4,k2]`, not a
  reversal or single swap) plus a separate reversal assertion. (7) nit:
  added an RFC 9420 §7.8 comment noting duplicate signature keys are
  unreachable in valid MLS group state, and mirrored the pairwise
  function's "no timing side-channel — both operands are public keys"
  comment onto the group construction's sort step.
- **crypto-reviewer (re-verify pass): PASS.** Confirmed all 7 findings
  actually resolved (not just claimed) by re-reading the diff and
  independently recomputing the new KAT vector. Flagged one further
  non-blocking nit: `mls_group_signature_keys_bounded` itself had no
  direct test proving truncation against a *real* MLS group (the openmls
  laziness argument was correct but relied on reading library internals
  by hand, not a test) — cheap to add, so added it this cycle rather than
  carrying it: `test_mls_group_signature_keys_bounded_truncates_a_real_group`
  builds a real 2-member group, confirms the unbounded path sees 2
  members, then confirms `mls_group_signature_keys_bounded(..., max=0)`
  (i.e. `take(1)`) truncates it down to exactly 1 — proving `.take()`
  bounds the live iterator, not a post-hoc length check.
- No `threat-model-checker` run: this is a pure client-side crypto
  primitive with no server-visible metadata and no new trust boundary
  (matches the pattern for prior standalone WASM export additions like
  the original pairwise safety number). No `security-auditor` run: no
  backend/handler/infra code touched.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; `powehi-crypto-wasm` alone: 193 passed, 2 ignored, up from
  184 pre-cycle — 9 net new tests), `cargo fmt --all --check` clean,
  `cargo clippy --workspace --all-targets -- -D warnings` clean. Frontend:
  `pnpm exec tsc --noEmit` clean, `biome check` clean on the touched file,
  `pnpm vitest run` 112 files/1595 tests green (unaffected — no frontend
  logic touched beyond the new pass-through worker method).
- Committed `c62edf1` (`feat(crypto): add N-party MLS group safety number
  export`), 2 files changed, pushed clean (`9fcdeb5..c62edf1 main ->
  main`).
- **Process note, now the sixth time** (cycles 448/449, 451, 454, 455,
  457→458): a FEATURE-mode cycle does real, reviewed work and burns its
  counter slot without committing, leaving the next cycle to land it.
  This keeps happening across many different cycles/features — worth
  treating as a structural pattern (e.g. a hard "commit before the turn
  ends" checklist gate) rather than continuing to rely on the next
  cycle's git-status check to catch it.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  3. Carried (superseded framing from cycle 456 still applies): the
     `PendingRemovalBanner`'s local cross-check needs either (a) binding
     `device_id` into the MLS credential identity at creation time, or (b)
     leaning on §5.6 safety-number verification (now including this
     cycle's new group variant) as the real local trust anchor for T3,
     updating the banner's copy accordingly. Not attempted this cycle
     (scope was landing cycle 457's WIP, not starting new UI work).
  4. **New, real, natural next step for this cycle's export:** wire
     `mlsComputeGroupSafetyNumber` into an actual UI surface — likely a
     group-info panel action alongside the existing pairwise safety-number
     verification flow (`computedSafetyNumber` state in `ChatLayout.tsx`
     around line 5088) — since the WASM/worker layer now exists but has
     zero consumers.
  5. Carried, doc-sync only, low priority: prd.md §10's REST API list is
     stale — missing `pending-removals` and `members`.
  6. Carried: the `PendingRemovalBanner` confirm click is still the only
     defense against a forged `pending_removals` signal.
  7. Carried: no MLS Remove commit path exists in the frontend at all yet.
  8. Carried, scoped out: the `RemovalRequired` WS event is still
     unconsumed (no frontend WebSocket client exists at all).
  9. Carried: no `values-prod-*.yaml`/CI overlay flips
     `monitoring.prometheusRule.enabled=true` yet (ops task).
  10. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  11. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  12. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  13. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  14. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-08, cycle 456 — FEATURE: found cycle 454/455's uncommitted WASM WIP (mlsGroupMembers "deviceIdHex") was semantically broken, fixed the naming instead of shipping it, commit 01f77b7)

- Mode selection: counter 455→456, 456 % 5 != 0 → FEATURE. Working tree was
  NOT clean at session start (same recurring gap as cycles 448/449/451/454):
  `crates/client/powehi-crypto-wasm/src/wasm_exports.rs` and
  `app/src/workers/crypto.worker.ts` had uncommitted WIP implementing cycle
  455's candidate #3 (expose a device_id↔leaf mapping from WASM's
  `mls_group_members`, tagged `deviceIdHex`), already unit-tested and
  green on `cargo test -p powehi-crypto-wasm`.
- Read the WIP, then went further: designed and built a full local
  cross-check UI in `PendingRemovalBanner.tsx` (per-row "verified"/
  "not-found"/"unavailable" badge, wired `chat.mlsIdentityId` through
  `ChatLayout.tsx`, 6 new frontend tests, full `pnpm vitest run` green at
  112 files/1601 tests) — this is what candidate #3 asked for.
- **crypto-reviewer: NEEDS-REWORK, a real and serious finding, not a
  nitpick.** `deviceIdHex` was rendered from the MLS `BasicCredential`
  identity bytes, but in this codebase those bytes are
  `SHA-256(recovery_phrase)[0..16]` (`mlsInitIdentityFromPhrase`,
  `Login.tsx:112`) — an ACCOUNT-level label shared by every device restored
  from the same recovery phrase — not the server's per-device `device_id`
  (`crypto.randomUUID()` / `DeviceId::new()` in `auth_service.rs`), which is
  generated completely independently. The two values have no relationship
  at all: comparing them would make the cross-check report "not-found" for
  nearly every legitimate removal (false alarms training users to distrust
  the one real defense against T3), and the mapping isn't even injective
  (all devices from one phrase share one label). Root cause: I built the UI
  on top of a field whose *name* (from the prior cycle's WIP) implied it was
  a device id, without independently verifying that claim against how MLS
  identities are actually derived in this codebase's registration/restore
  flow (`Login.tsx`) before wiring a security-relevant comparison on it.
  **Lesson for future cycles:** when a carried candidate says "expose X so a
  client can join list A against list B", verify both sides' actual value
  semantics (not just their types) before building the join — a plausible
  field name from a previous WIP is not evidence of a real 1:1 relationship.
- **Fix, not abandonment:** reverted `PendingRemovalBanner.tsx` +
  its test + `ChatLayout.tsx` + the `useCryptoWorker` mock back to their
  pre-session state via `git checkout` (clean revert, `pnpm vitest run`
  back to the prior 112 files/1595 tests baseline). Kept and corrected the
  WASM/TS layer: renamed `deviceIdHex`/`device_id_hex`/`member_device_id_hex`
  → `credentialIdentityHex`/`credential_identity_hex`/
  `member_credential_identity_hex` throughout (Rust struct field, helper
  fn, JS object key, all doc comments, all 3 test names AND their assertion
  message strings — crypto-reviewer's re-verify pass caught 6 leftover
  "device id" strings in test messages that a first rename pass missed),
  and rewrote every doc comment to state plainly this is NOT a device_id and
  why. Also applied a non-blocking nit: switched to
  `BasicCredential::try_from(credential.clone()).ok().map(|b| ...)` instead
  of reading `credential.serialized_content()` directly (typed accessor,
  not an internal-representation-detail dependency).
- **crypto-reviewer re-verify pass: PASS** after the 6-string test-message
  fix (only remaining issue from the NEEDS-REWORK round). **threat-model-
  checker: YELLOW → addressed** by NOT shipping the broken cross-check
  (its independent finding: even the intended design — cross-checking two
  *server*-reported signals like `pending-removals` vs `members` — proves
  nothing for T3, since a malicious server can forge both; only a real
  local ratchet-tree trust anchor works, and this diff didn't have one).
  Updated `docs/prd.md` at both §3.3/§5.4 locations that previously said
  the WASM half "doesn't exist yet" — now accurately says a naming-fixed
  field exists but was deliberately NOT wired to the frontend because it
  doesn't solve the join; `pending_removal_sweep_enabled` stays `false`;
  the real reconciliation gap is now understood to be deeper than
  previously scoped (see candidate #3 below, superseding the old one).
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; `powehi-crypto-wasm` alone: 184 passed, 2 ignored), `cargo
  fmt --all --check` clean, `cargo clippy --workspace --all-targets -- -D
  warnings` clean. Frontend: `pnpm exec tsc --noEmit` clean, `biome check`
  clean, `pnpm vitest run` 112 files/1595 tests green (frontend diff was
  fully reverted, so this is the pre-session baseline, confirmed
  unregressed).
- Committed `01f77b7` (`fix(crypto): correct WASM mls_group_members
  identity field naming`), 3 files changed, pushed clean
  (`da1bca5..01f77b7 main -> main`).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3 +
     HMAC-vs-plain-SHA256 gate resolved first.
  3. **Supersedes old candidate #3 (threat-model-checker/crypto-reviewer,
     this cycle):** the `PendingRemovalBanner`'s "local cross-check against
     the server-forged-removal threat (T3)" is NOT achievable by exposing
     any MLS-credential-derived value from WASM, because this codebase has
     no authenticated binding between a device's MLS credential identity
     and its server-assigned `device_id` (RFC 9420 §5.3 leaves that binding
     to an external Authentication Service this codebase doesn't have).
     Two real paths forward, both bigger than a quick follow-up and need a
     plan + threat-model-checker before implementation: (a) change
     registration/restore (`auth_service.rs` + `Login.tsx`) to actually
     bind `device_id` into the MLS credential identity at creation time
     (e.g. use the server-issued `device_id` bytes, or a hash including it,
     as the `BasicCredential` identity instead of the current
     phrase-derived account-level label — has knock-on effects on the
     restore-from-phrase flow, since today's design deliberately makes
     every restored device share one label); (b) give up on a WASM-exposed
     cross-check entirely and instead lean on the already-shipped §5.6
     safety-number verification as the real local trust anchor for T3,
     updating `PendingRemovalBanner`'s copy to point users there instead of
     implying a cross-check exists.
  4. Carried, doc-sync only, low priority: prd.md §10's REST API list is
     stale — missing `pending-removals` and `members`.
  5. Carried: the `PendingRemovalBanner` confirm click is still the only
     defense against a forged `pending_removals` signal — see candidate #3
     above for why the local-cross-check half of the plan needs a redesign,
     not just a WASM export.
  6. Carried: no MLS Remove commit path exists in the frontend at all yet.
  7. Carried, scoped out: the `RemovalRequired` WS event is still
     unconsumed (no frontend WebSocket client exists at all).
  8. Carried: no `values-prod-*.yaml`/CI overlay flips
     `monitoring.prometheusRule.enabled=true` yet (ops task).
  9. Carried: CI has no job rendering the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  10. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  11. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  12. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  13. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-07, cycle 455 — STABILIZATION: finish and land cycle 454's orphaned WIP wiring GET /v1/groups/:group_id/members (cycle 453's candidate #3), commit e710df6)

- Mode selection: counter 454→455, 455 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` green on `main`, `gh issue list --state open` empty.
  **Working tree was NOT clean at session start** — same recurring process
  gap as cycles 448/449/451: cycle 454 had done substantial, coherent,
  already-partially-self-reviewed work (its own code comments cited
  "security-auditor finding, cycle 454") implementing cycle 453's
  candidate #3, but never committed it. Read the whole diff file-by-file
  to confirm coherence before treating "land the WIP" as this cycle's
  action: new `GroupUseCase::list_members` (inbound port + application
  fail-closed guard + 3 unit tests), new `GET /v1/groups/:group_id/members`
  REST handler (`MembersResponse` capped at `MAX_MEMBERS_RESPONSE=512`,
  `truncated` flag, canonical UUID re-sort before truncation,
  `joined_at_epoch` deliberately not serialized), plus mechanical
  test-fake updates in 3 other route test files. The outbound port
  (`GroupRepository::list_members`) and its Postgres impl + testcontainers
  coverage already existed pre-diff (unchanged).
- `cargo build/test/fmt/clippy` all green on the WIP as found (0 test
  failures across every crate), `cargo audit`/`cargo deny check` clean —
  then ran both required review gates on the whole diff before committing
  any of it (backend REST handler + new server-visible metadata surface
  → `security-auditor` + `threat-model-checker`; no crypto/MLS code
  touched so `crypto-reviewer` correctly not invoked).
- **security-auditor: PASS-with-nits, one nit fixed in-session.** Verified
  the fail-closed authz guard is sound (no path returns `Ok` without the
  membership predicate holding; unknown group and non-member both hit
  identical 401 at the response level) and actually has a *narrower*
  TOCTOU window than its own comment claimed — the guard's read IS the
  returned data, so there's no read-then-write gap at all (unlike
  `add_member`/`remove_member`'s real gap). Fixed the stale comment
  (`group_service.rs`) to state this correctly instead of copying the
  sibling's caveat verbatim. Two real-but-non-blocking findings carried
  to next-cycle candidates below (DoS cost-shape, operator-controlled
  truncation evasion) — both explicitly "not new-in-kind" (same shape
  pre-exists in `add_member`/`list_pending_removals`) and their fix is
  scoped as a separate change, not a blocker for this diff. Confirmed no
  new SQL (outbound impl unchanged), no plaintext/PII logging (UUID-only),
  no new `unwrap()`/`expect()` outside tests, same rate-limit bucket
  (`api_governor`) as sibling group routes.
- **threat-model-checker: YELLOW → addressed via prd.md updates (no
  redesign needed).** Hit its 20-turn limit mid-review once; resumed via
  SendMessage to get a final verdict (same pattern that worked well in
  cycle 453 — worth continuing to budget for a resume round rather than
  treating a partial result as done). **Key finding, more significant
  than the task assumed:** this endpoint does NOT yet close the §5.4
  reconciliation gap — it's necessary but not sufficient. The client-side
  half is still missing: `mls_group_members` (WASM,
  `powehi-crypto-wasm/src/wasm_exports.rs`) returns only
  `{leafIndex, sigKeyHex}`, no `device_id`, so there is no key to join the
  new endpoint's `device_id` list against the client's own MLS ratchet
  tree. Also found a real, undocumented region-locality gap:
  `SyncGroupMembership`'s `upsert_members` is add-only (`ON CONFLICT DO
  NOTHING`, never deletes members absent from a snapshot), so a non-home
  region can serve a monotonically-growing stale superset of group
  membership with no region/authoritativeness marker — a removed device
  can appear "still a member" forever from a peer region's perspective.
  Applied all 3 required prd.md edits verbatim as drafted by the reviewer
  (§3.3 residual-risk paragraph at the `pending_removals` entry, §3.5.1
  region-locality paragraph, §5.4 client-policy paragraph) plus the code-
  doc nit qualifying "not a group-existence oracle" as response-level-only
  in both `group.rs` (inbound port) and `groups.rs` (REST handler) doc
  comments. `pending_removal_sweep_enabled` confirmed must stay `false`.
  Did NOT apply the optional §10 API-list sync (already stale in other
  ways too, e.g. missing `pending-removals`; out of scope for this diff,
  carried below).
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean.
- Committed `e710df6` (`feat(security): wire GET
  /v1/groups/:group_id/members local cross-check endpoint`), 8 files
  changed (7 code + `docs/prd.md`), pushed clean (`5210b3b..e710df6
  main -> main`). Both `CI — Rust` and `CI — Live-backend E2E` were
  `in_progress` immediately after push — confirm green in a future
  session if not already done.
- **Process note, now the fourth time** (cycles 448/449, 451, 454 →
  this cycle): a FEATURE-mode cycle keeps doing real, reviewed-in-comments
  work and burning its counter slot without committing. The counter
  advances regardless (454 ran, produced this WIP, but 455 is the one
  that had to land it) — this is a persistent pattern worth a dedicated
  process fix (e.g. an explicit "commit before ending the turn" checklist
  step), not just repeated manual recovery.
- Target dir hygiene: `target/` at 24G (over the 20G threshold), but the
  mtime+7 prune found nothing eligible — same as cycles 450/451, all
  content is from active recent work. Not a concern yet.
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3
     + HMAC-vs-plain-SHA256 gate resolved first.
  3. **New, real, needed before pending_removal_sweep_enabled can ever
     flip to true (threat-model-checker, this cycle):** expose a
     device_id-to-MLS-leaf mapping from the WASM crypto layer
     (`powehi-crypto-wasm`'s `mls_group_members` currently returns only
     `{leafIndex, sigKeyHex}`) so a client can actually join the new
     `GET /v1/groups/:group_id/members` response against its own ratchet
     tree. Without this, the endpoint landed this cycle is necessary but
     not sufficient — reconciliation is still not possible end to end.
  4. **New, real but scoped out (threat-model-checker, this cycle):**
     cross-region member-list staleness — `SyncGroupMembership`'s
     `upsert_members` is add-only and never propagates `remove_member`
     deletes to peer regions; a non-home-region call to the new
     `list_members` endpoint (or the existing gRPC replication path) can
     return a stale superset with no region/authoritativeness marker.
     Needs either delete-propagation in `SyncGroupMembership` or REST-layer
     home-region proxying for this endpoint.
  5. **New, real but non-blocking (security-auditor, this cycle):** the
     new endpoint's 512-item response cap bounds egress only, not DB rows
     read/sorted — a 100k-member group still costs a full fetch+sort per
     request, including on the 401 (non-member) path since the guard reads
     before rejecting. Same shape pre-exists in `add_member`/
     `list_pending_removals`; a real fix needs a bounded/paginated outbound
     query, not just a response-side truncation.
  6. **New, real but non-blocking (security-auditor, this cycle):** the
     new endpoint's threat model assumes a malicious *server* operator,
     but that operator also controls `group_members` rows directly — they
     can insert ≥512 low-UUID bogus members to force `truncated: true` and
     deterministically push a target device out of the visible prefix,
     disabling the cross-check exactly when it's needed. Not an escalation
     (degrades to pre-diff status quo, never a false positive), but worth
     a cursor-based or membership-probe (`?device_id=`) alternative in a
     future cycle.
  7. Carried, doc-sync only, low priority: prd.md §10's REST API list
     (lines ~1015-1024 and around) is stale in general — missing
     `pending-removals` and now `members` too. A dedicated `doc-syncer`
     pass should reconcile the whole list against `lib.rs`'s actual router
     rather than patching one endpoint at a time.
  8. Carried: the `PendingRemovalBanner` confirm click is still the only
     defense against a forged `pending_removals` signal (candidate #3 was
     the first of two prerequisites; #3 above is the remaining piece).
  9. Carried: no MLS Remove commit path exists in the frontend at all yet.
  10. Carried, scoped out: the `RemovalRequired` WS event is still
      unconsumed (no frontend WebSocket client exists at all).
  11. Carried: no `values-prod-*.yaml`/CI overlay flips
      `monitoring.prometheusRule.enabled=true` yet (ops task).
  12. Carried: CI has no job rendering the Helm chart with
      `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`.
  13. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
      having `REFERENCES devices(id)`; the actual schema never had this FK.
  14. Carried, real but scoped out: consumed `key_packages` rows are never
      garbage-collected.
  15. Carried, low-priority hardening: `GroupRepository::save` is a blind
      `ON CONFLICT DO UPDATE` with no production caller today.
  16. Carried, cosmetic: bare `var(--photon)` CSS custom property used
      without a defined token in `LinkedDevicesPanel.tsx`/
      `PendingRemovalBanner.tsx`.

## Previous state (2026-09-07, cycle 453 — FEATURE: wire frontend consumer of GET /v1/groups/:id/pending-removals, cycle 452 candidate #3, commit 60719d3)

- Mode selection: counter 452→453, 453 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on `main`, `gh issue list --state open` empty, working
  tree clean at session start (no orphaned WIP this time).
- Backend has shipped `GET /v1/groups/:group_id/pending-removals` +
  `RemovalRequired` WS event since cycles 448-452, but there was ZERO
  frontend consumer. Delegated to `frontend-lead`: added
  `listPendingRemovals()` to `app/src/api/groups.ts`, and a new
  `PendingRemovalBanner.tsx` component mounted in `ChatLayout.tsx`'s
  group `InfoPanel` (`groupId={chat.mlsGroupId ?? chat.id}`, matching
  the existing `AddMemberModal` resolution pattern). REST-poll only —
  explicitly did NOT build a WebSocket client (none exists yet in the
  frontend at all); consuming the `RemovalRequired` WS event is still
  open (see candidates).
- **threat-model-checker: first pass RED, real findings, not nitpicks:**
  (1) the initial UI ("Remove now" / optimistic list-drop) implied an
  actual MLS Remove had happened; in reality `removeMember` is
  server-side `group_members` bookkeeping only (stops future fan-out),
  does NOT advance the group epoch, and does NOT heal PCS — the revoked
  device keeps its existing group keys until a real MLS Remove Commit
  lands in a client. False security assurance in a security-critical
  UI element. (2) the confirm button rendered in the exact screen
  position the arming "Remove now" button had occupied — a stray
  double-click could fire the action, undermining the "two-step
  confirm" property. (3) missing an inline warning that the signal is
  server-reported and unverified (prd.md §3.5.1 T3: a malicious/
  compromised server can forge arbitrary `(group_id, device_id)` pairs;
  there's no local device-list cross-check yet, so the confirm click is
  currently the *only* defense). (4) required prd.md §3.3/§5.4 updates
  documenting the finalized client policy.
- **Fixed all four, re-verified GREEN** (same agent instance, resumed
  via SendMessage rather than a fresh review — worked well, kept full
  context): relabeled to "Stop delivery" / "Confirm: stop delivery" +
  added an inline sub-label "This does not perform an MLS Remove.";
  added a `CONFIRM_ARM_DELAY_MS = 500` cooldown — the confirm control is
  `disabled` until 500ms after arming, with a test asserting a click in
  that window is a no-op; added a `data-testid="pending-removal-warning"`
  banner line stating the signal is server-reported/unverified; updated
  prd.md at both flagged locations (§3.3 line ~188, §5.4 line ~706) to
  record the finalized 2-step-confirm-with-arm-delay policy, that it
  still lacks a local cross-check, and that `pending_removal_sweep_enabled`
  must stay `false` until one exists.
- Full frontend suite: `pnpm vitest run` — 112 test files / 1595 tests
  passed (up from 1594; net +7 new tests in `PendingRemovalBanner.test.tsx`
  covering empty/fail-closed/per-device confirm-gate/arm-delay/error-scoping,
  +4 new in `groups.test.ts` for `listPendingRemovals`). `biome check` and
  `tsc --noEmit` clean on all changed files.
- No `security-auditor` or `crypto-reviewer` pass run this cycle — no
  Rust/backend/crypto code touched (frontend-only diff), and CLAUDE.md's
  gate list ties those two specifically to backend handlers / crypto
  code; `threat-model-checker` was the applicable gate here (new client
  trust-boundary behavior consuming a previously-undocumented-in-practice
  signal) and it ran to GREEN.
- Committed `60719d3` (`feat(frontend): add confirmation-gated
  pending-removal banner`), 6 files changed (2 new), pushed clean
  (`e5b3960..60719d3 main -> main`).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` — needs F3
     + HMAC-vs-plain-SHA256 gate resolved first.
  3. **New, real (threat-model-checker, this cycle, residual/accepted
     risk, explicitly written into prd.md as an open item):** the
     `PendingRemovalBanner` confirm click is still the *only* defense
     against a forged `pending_removals` signal — no local cross-check
     exists. Wire a group-scoped device-list endpoint (`GET
     /v1/groups/:group_id/members`, mentioned as the missing channel
     in prd.md §3.3) and have the banner cross-check the reported
     device_id against it before/alongside the confirm step.
  4. **New, real (threat-model-checker, this cycle):** no MLS Remove
     commit path exists in the frontend at all yet — `removeMember`
     only stops server fan-out, PCS is never actually healed by this
     UI. A real fix needs the crypto-worker to actually construct and
     land an MLS Remove Commit when a device is confirmed for removal
     (crypto-lead/mls-engineer scope, not a quick frontend patch).
  5. **New, scoped out (this cycle):** the `RemovalRequired` WS event
     is still unconsumed — frontend has no WebSocket client at all.
     Building one (and wiring live push instead of REST-poll-on-mount)
     is a separate, larger task.
  6. Carried: no `values-prod-*.yaml`/CI overlay flips
     `monitoring.prometheusRule.enabled=true` yet (ops task).
  7. Carried: CI has no job rendering the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`
     (ci-pipeline-author follow-up, not urgent).
  8. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
     having `REFERENCES devices(id)`; the actual schema never had this FK.
  9. Carried, real but scoped out: consumed `key_packages` rows are never
     garbage-collected.
  10. Carried, low-priority hardening: `GroupRepository::save` is a
      blind `ON CONFLICT DO UPDATE` with no production caller today;
      worth a doc comment forbidding it from ever advancing epoch.
  11. Minor, noticed this cycle, not fixed (cosmetic, pre-existing):
      `var(--photon)` is used as a bare CSS custom property in both
      `LinkedDevicesPanel.tsx` (pre-existing) and the new
      `PendingRemovalBanner.tsx`, but `app/src/index.css` only defines
      scale tokens (`--photon-50` … `--photon-300` etc.), never a bare
      `--photon`. Not a new bug (matches existing precedent) and
      harmless (undefined var just no-ops the color), but worth adding
      the missing token or fixing both call sites in a future cycle.

## Archive index
Cycles 20-277: `.claude/memory/archive/project-context-cycles-20-277.md`
Cycles 279-319 (+cyclelog): `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
Cycles 320-339: `.claude/memory/archive/project-context-cycles-320-339.md`
Cycles 340-371: `.claude/memory/archive/project-context-cycles-340-371.md`
Cycles 372-401: `.claude/memory/archive/project-context-cycles-372-401.md`
Cycles 402-421: `.claude/memory/archive/project-context-cycles-402-421.md`
Cycles 425-431: `.claude/memory/archive/project-context-cycles-425-431.md`
Cycles 443-452: `.claude/memory/archive/project-context-cycles-443-452.md`
