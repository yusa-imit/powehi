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

## Current state (2026-09-07, cycle 450 — STABILIZATION: finish and land cycles 448/449's orphaned WIP closing the MLS-Remove-notification gap from cycle 447's candidate #8, commit 9796cba)

- Mode selection: counter 449→450, 450 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` green on `main` at session start, `gh issue list
  --state open`: empty. **Working tree was NOT clean at session start**:
  ~2100 uncommitted lines across 21 tracked files + 1 untracked migration
  (`0020_pending_removals.sql`) already sitting there — cycles 448/449 had
  clearly done substantial, coherent, well-tested work implementing cycle
  447's candidate #8 (server-side MLS Remove notification on device
  revocation) but never committed it (counter still advanced 447→448→449,
  so those cycles ran and burned budget without producing the mandatory
  commit — a process gap worth watching for, not just this cycle's fix).
- Rather than discard or ignore this WIP, read the entire diff file-by-file
  to verify it was coherent (it was: new `pending_removals` table +
  `GroupRepository::create/delete/list_pending_removals` + new
  `DomainEvent::RemovalRequired` fanned out over the WS hub + a new `GET
  /v1/groups/:id/pending-removals` endpoint + `AuthService::revoke_device`
  wired to capture group memberships before device deletion and fan out
  the notification, with an incidental clean refactor moving
  invite-revocation from the REST handler into `AuthService::revoke_device`
  itself for correct ordering), confirmed `cargo build/test/fmt/clippy`
  all green, then ran the three mandatory review gates on the *whole* diff
  before committing any of it (treating "finish and land abandoned WIP" as
  the stabilization action, not as new feature work).
- **crypto-reviewer: needs-rework → fixed.** Real findings, not nitpicks:
  (1) the epoch gate on `delete_pending_removal`
  (`created_at_epoch < groups.epoch`) was documented in 3+ places as
  proving "a real MLS Remove Commit was accepted" — false; the server
  cannot see Commit contents (RFC 9420 §6/§12.4), so it only proves *some*
  Commit landed, and an ordinary self-Update (routine, RFC 9420
  §12.1.2/§12.4.3 recommends it for PCS) satisfies it — fixed by
  correcting every overstated comment/port-doc/migration claim to state
  the real, weaker guarantee ("costs one Commit", not "proof of this
  device's Remove"), removing "SECURITY REGRESSION" test labels that
  pinned a control that doesn't exist, and adding new tests
  (`remove_member_erases_the_pending_removal_after_any_unrelated_epoch_advance`
  in group_service.rs + `delete_pending_removal_is_satisfied_by_any_unrelated_epoch_advance`
  in pg_security_it.rs) that lock in the limitation as documented, not
  hidden; (2) `create_pending_removal` ran best-effort *after* the
  irreversible KeyPackage/device deletes — a DB blip there would
  permanently and silently lose the one notification this table exists
  for, with no retry possible (`find_by_id` → `NotFound`) — fixed by
  moving it before the deletes as a hard-fail (`?`) step, matching
  `revoke_device`'s own already-stated ordering discipline (idempotent
  hard-fail steps first, then irreversible deletes); had to rewrite the
  now-stale test `revoke_device_still_succeeds_when_recording_a_pending_removal_fails`
  into `revoke_device_propagates_pending_removal_failure_and_the_device_survives`
  to match; (3) a live, connected revoked-device socket could receive its
  own `RemovalRequired` (WS auth is checked once at upgrade, not
  re-validated per-message, and session invalidation runs after the
  publish) — fixed `filter_notification` in ws-hub/src/handler.rs to
  suppress `RemovalRequired` when `device_id == recipient`, corrected the
  handler's doc comment that had falsely claimed this was impossible, and
  flipped the one test that had pinned the old (wrong) behavior.
- **threat-model-checker: YELLOW → addressed.** Real trust-boundary
  preserved (server still can't construct a Remove — no group state, no
  keys) but this was NOT a pure internal fix: (a) new *permanent* metadata
  category — `pending_removals` rows survive the device row's deletion and
  have no retention cap yet; (b) new server→client "demand" channel that a
  malicious operator could forge to trick honest clients into evicting a
  legitimate device (availability/integrity risk, not confidentiality);
  (c) the fix is currently region-local (not replicated via
  `SyncGroupMembership`, `RemovalRequired` is pod-local-only dispatch), so
  PCS recovery is incomplete across regions. Required prd.md updates before
  merge, applied this cycle: §3.3 new bullet (permanent metadata + no TTL
  yet), §5.4 new item 5 (server forwards a Remove *request*, never
  constructs one, and clients must not blindly auto-execute it — a
  trust-boundary note, not just a mechanism note), §3.5.1 new paragraph
  (region-locality, not yet cross-region replicated).
- **security-auditor: PASS-with-nits, no blockers.** Confirmed SQL
  parameterization clean on all 3 new queries, `GET
  /v1/groups/:id/pending-removals` fail-closed on both explicit
  non-membership and repo-lookup errors (same `?`-propagation pattern as
  `add_member`/`remove_member`), no-plaintext-logging compliant (every new
  log site is UUIDs + fixed categories only), no new `unwrap()`/`expect()`
  outside tests, all 9 non-production `GroupRepository`/`GroupUseCase`
  test-fake implementers correctly updated (confirmed unreachable outside
  `#[cfg(test)]`), and confirmed the invite-revocation test-coverage move
  from routes/auth.rs to auth_service.rs is equivalent-or-better (the new
  service-layer tests assert the ordering invariant, not just the call).
  Ran as a background agent that hit its 30-turn limit before reporting —
  had to `SendMessage` it to resume and force a final verdict; worth
  budgeting review agents more turns or a tighter prompt next time a
  diff is this large (~2100 lines).
- Non-blocking follow-ups flagged by review (not applied this cycle,
  candidates below): expose `created_at_epoch` in the REST response so
  clients can actually reconcile against their own tree state (currently
  UUID-only); add a retention cap/sweeper for `pending_removals` (no GC
  path besides the `groups` cascade); `ORDER BY created_at ASC` in
  `list_pending_removals` has no tiebreaker; a `GroupRepository::save`
  hardening note (blind `ON CONFLICT DO UPDATE`, no production caller
  today, but a future one could violate the "epoch only moves via CAS"
  invariant the whole epoch-gate design depends on).
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate; 49 ignored testcontainers tests, up from 48 — confirms the
  new pg_security_it.rs test registered), `cargo fmt --all --check` clean,
  `cargo clippy --workspace --all-targets -- -D warnings` clean (one
  `cloned_ref_to_slice_refs` lint fixed in a test — `&[device_id.clone()]`
  → `std::slice::from_ref(&device_id)`). `cargo nextest` still not
  installed in this environment — used the documented `cargo test
  --workspace` fallback.
- Committed `9796cba` (`feat(security): notify group members of revoked
  devices' pending MLS Remove`), 23 files changed, pushed. `gh run list`
  showed both `CI — Rust` and `CI — Live-backend E2E` `in_progress`
  immediately after push — confirm green in a future session if not
  already done.
- Target dir hygiene (stabilization mode): `target/` was 23GB (over the
  20GB threshold) but the mtime+7 prune found nothing eligible — everything
  in it is from this cycle's own active build/test work, so no artifacts
  were actually removed. Not a concern yet; revisit if it keeps growing
  past 30GB+ without aging out.
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  3. **New (crypto-reviewer/threat-model-checker, this cycle, real but
     scoped out):** `pending_removals` has no retention cap or sweeper —
     a group whose members never call `remove_member` (or never advance
     the epoch again) accumulates rows forever. Model on the existing
     media-orphan-sweep pattern, or add a TTL.
  4. **New (crypto-reviewer, this cycle, scoped out):** `GET
     /v1/groups/:id/pending-removals` returns device UUIDs only; exposing
     `created_at_epoch` (and maybe `created_at`) would let a client
     actually reconcile the reminder against its own ratchet-tree state,
     which is the only real enforcement path per this cycle's threat
     model finding (server-side epoch gate is a heuristic, not a proof).
  5. **New (threat-model-checker, this cycle, needs a product/frontend
     decision, not just a backend patch):** no frontend consumer of
     `RemovalRequired`/`pending-removals` exists yet, and per prd.md §5.4's
     new trust-boundary note, whatever client eventually consumes it must
     NOT auto-execute a Remove without some verification/confirmation
     step (since the signal is server-forgeable). Needs an ADR once
     frontend wiring for this starts.
  6. **New (crypto-reviewer, this cycle, low-priority hardening):**
     `GroupRepository::save` is a blind `ON CONFLICT DO UPDATE` on
     caller-supplied epoch with no production caller today, but the new
     epoch-gate security reasoning now implicitly depends on "epoch only
     ever moves via `advance_epoch`'s CAS" — worth a doc comment forbidding
     `save` from ever being used to advance epoch, before any future
     caller appears.
  7. Carried: no `values-prod-*.yaml`/CI overlay actually flips
     `monitoring.prometheusRule.enabled=true` yet in a real
     kube-prometheus-stack install (ops/environment-config task).
  8. Carried: CI has no job that renders the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`
     (ci-pipeline-author follow-up, not urgent).
  9. Carried, doc-sync only: prd.md:1373-area documents
     `key_packages.device_id` as having `REFERENCES devices(id)`; the
     actual schema never had this FK (cycle 447 fixed the gap at the
     application layer instead, not the schema).
  10. Carried, real but scoped out (needs a GC/lifecycle decision):
      consumed `key_packages` rows are never garbage-collected.

## Previous state (2026-09-06, cycle 447 — FEATURE: close the device-revocation KeyPackage/invite orphan gap, commit 8ba43e4)

- Mode selection: counter 446→447, 447 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on `main` (cycle 446's push both jobs
  `completed`/`success`). `gh issue list --state open`: empty. Clean tree.
- Carried-candidates pool was thin again (cycle 445's stabilization
  sweep flagged one real, scoped-out item: cycle 445 stab note #6,
  "`PgDeviceRepository::delete` doesn't cascade to `key_packages`").
  Spawned an Explore-style research agent to map the actual device-
  revocation call path before committing to a fix scope (paid off —
  the real bug was bigger than the one-line summary suggested).
- **Root finding**: `AuthService::revoke_device` deleted the `devices`
  row and invalidated cached sessions but never touched the device's
  `key_packages` rows. `KeyPackageRepository::fetch_one`/`count_available`
  filter only on `consumed`, not device liveness, and `key_packages.device_id`
  has no FK at all (unlike every other devices-referencing table). Net
  effect: a revoked device's stale unconsumed KeyPackage could still be
  fetched and used to add that (now-nonexistent) device's MLS credential
  to a group after revocation — a PCS/device-compromise-response gap.
- **Fix, part 1 (pool)**: added `KeyPackageRepository::delete_by_device`
  (port + Postgres `DELETE FROM key_packages WHERE device_id = $1` impl +
  a new non-partial `key_packages(device_id)` index migration
  `0019_key_packages_device_id_idx.sql` — the existing index is partial
  on `WHERE NOT consumed` and can't back a DELETE that must also match
  consumed rows, so every revocation was doing a full seq scan). Wired
  into `revoke_device`.
- **Fix, part 2 (invite path — found by crypto-reviewer, not the
  original scope)**: `InviteService::create_invite` pins a *separate*
  copy of the KeyPackage bytes directly in Redis (`invite:<H(code)>`,
  24h TTL), entirely outside the pool table — part 1 alone left this
  channel still handing out a revoked device's credential for up to
  24h. Added `InviteUseCase::revoke_invites_for_device` (walks the
  existing `invite:device:<uuid>` index, deletes each member + the
  index) and wired it into the REST `revoke_device_handler` (not into
  `AuthService` itself — kept Auth and Invite bounded contexts
  independent, orchestrated at the inbound-adapter composition layer,
  matching this codebase's existing pattern of handlers coordinating
  multiple use cases).
- **Ordering bug caught independently by threat-model-checker AND
  security-auditor AND crypto-reviewer (initial FAIL)**: first draft
  deleted the device row, THEN deleted its KeyPackages — hard-failing
  (`?`) on the KeyPackage step. All three reviewers flagged the same
  failure mode: if KeyPackage deletion fails after the device is
  already gone, the state is unrecoverable (retry hits `find_by_id` →
  `NotFound` before ever reaching the KeyPackage call again), leaving
  orphaned KeyPackages forever — exactly the bug this fix exists to
  close. Fixed by reversing the order (KeyPackage delete → device
  delete); both operations are idempotent, so a failure now leaves the
  device row intact and the whole revocation safely retryable.
- **crypto-reviewer: FAIL → fixed → clean.** Required changes, all
  applied: (1) the ordering fix above; (2) a regression test locking in
  hard-fail-with-device-survival (`FailingDeleteByDeviceKeyPackageRepo`
  fake + `revoke_device_key_package_cleanup_failure_propagates_and_device_survives`);
  (3) the invite-path fix (part 2) — offered as an alternative to
  narrowing the port doc's "can never be handed out again" claim, chose
  to actually close the gap instead. Also applied on top: a port-doc
  note that cross-region `mark_consumed`'s `NotFound` must be treated
  fail-closed identically to `AlreadyConsumed` (a previously-consumed
  id now also reads back `NotFound` post-cleanup). Confirmed no RFC
  9420 race: `fetch_one`'s atomic `UPDATE...RETURNING` means a
  concurrent legitimate Add already has the KeyPackage bytes in hand
  before any delete could matter; Welcome decryption uses the client-
  held init private key, unaffected by the server row's deletion.
  Confirmed zero KeyPackage bytes/credential material read or logged
  by the new code (pure `DELETE`/Redis-key metadata operations).
- **threat-model-checker: GREEN.** T3 (malicious operator) and T4
  (device seizure) rows strengthened — T4 explicitly: revoke is the
  user's only response to a seized device, and this is the first time
  the code actually enforces prd.md's own "KeyPackage = one-time use,
  deleted after" invariant end-to-end. No new server-visible metadata
  (device_id was already stored/indexed). No prd.md edit or ADR needed
  (closes a gap vs. the documented invariant, doesn't introduce a new
  assumption/trade-off). Flagged a pre-existing, unrelated doc-sync gap
  (prd.md:1373 says `key_packages.device_id` has a FK; the migration
  never did) — noted as a future `doc-syncer` candidate, not blocking.
  Also flagged (not blocking, carried below): if §4A.6 cross-region
  KeyPackage replication is ever implemented, `delete_by_device` will
  need mesh fan-out or the T7 gap reopens per-region.
- **security-auditor: PASS-with-nits, addressed.** Confirmed ownership
  check still gates both new deletion calls, fully parameterized SQL,
  no new `unwrap()`/`expect()` in lib code, all 3+2 test-fake
  `impl KeyPackageRepository`/`InviteUseCase` sites found and updated
  (2 more `InviteUseCase` fakes than my own grep first caught —
  `push_subscription.rs`/`region.rs`'s `Null`/`NullUseCase` stubs, only
  surfaced by the compiler; grep alone had missed them). Independently
  confirmed the new index closes a real seq-scan risk (agreed with
  crypto-reviewer's F3). Consumed-KeyPackage-row accumulation (no GC)
  flagged as a separate LOW follow-up, not blocking a test-only-adjacent
  security fix.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures,
  every crate, including the two new REST-handler tests
  `revoke_device_handler_also_revokes_outstanding_invites` and
  `revoke_device_handler_propagates_invite_cleanup_failure`), `cargo
  clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt
  --all --check` clean (`cargo nextest` still not installed in this
  environment — used the documented `cargo test --workspace` fallback,
  same as prior cycles). New Postgres integration test
  (`key_package_delete_by_device_removes_only_that_devices_packages`)
  is `#[ignore]`'d like its siblings — no Docker here, runs in CI's
  Docker job.
- Committed `8ba43e4` (`fix(security): delete a revoked device's
  KeyPackages and outstanding invites`), pushed. 15 files changed
  (5 test-fake update sites the compiler caught, not just the ones a
  first grep found — re-confirm `cargo build --workspace --all-targets`
  after ANY inbound-port trait method addition, don't trust a single
  `grep -rln "impl X for"` pass to find every implementer, since
  `impl Trait for Name { ... }` inside a nested test module can dodge a
  loose grep pattern). Confirm `CI — Rust`'s Docker job actually runs
  and passes the two new `pg_security_it.rs`/behavior-locking tests in
  a future session if not already done by the time this is read.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  3. Carried: no `values-prod-*.yaml`/CI overlay actually flips
     `monitoring.prometheusRule.enabled=true` yet in a real
     kube-prometheus-stack install (ops/environment-config task).
  4. Carried: CI has no job that renders the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`
     (ci-pipeline-author follow-up, not urgent).
  5. **New, from this cycle's threat-model-checker (doc-sync, not
     code):** prd.md:1373 documents `key_packages.device_id` as having
     `REFERENCES devices(id)`; the actual schema never had this FK (the
     bug this cycle fixed at the application layer instead). A
     `doc-syncer` pass should either fix the prd.md text or add the FK
     for real (the latter needs an orphan-row backfill first).
  6. **New, from this cycle's reviews, real but scoped out (needs a
     GC/lifecycle decision, not a quick follow-up):** consumed
     `key_packages` rows are never garbage-collected (only the
     per-device *unconsumed* count is capped at 200). Combined with
     device churn this grows unbounded — a Tiger Style "limit on
     everything" violation. Would need either a periodic sweep (model
     on the existing media-orphan-sweep pattern in
     `bin/powehi-server/src/main.rs`) or a TTL/retention policy.
  7. **New, from this cycle's threat-model-checker, not urgent:** if
     §4A.6 cross-region KeyPackage replication is ever implemented,
     `delete_by_device` needs mesh fan-out (or a `RevokeKeyPackages`
     RPC) or the same T7 gap reopens per-region for replicated pool
     rows.
  8. **New, from this cycle's crypto-reviewer, real but explicitly
     out of scope for this diff:** `revoke_device` never issues an MLS
     Remove proposal/Commit — the server-side routing list (`group_members`
     FK cascade) is cleared, but a revoked device's leaf stays live in
     any existing group's ratchet tree until another member commits a
     Remove. This fix closes "can a revoked device be newly Added"; it
     does not close "is a revoked device still a current group member"
     (RFC 9420 §12.1.3 PCS only recovers after that Remove commits).
     Worth its own cycle: likely needs a server-initiated or client-
     prompted Remove-proposal flow on revocation.

## Previous state (2026-09-06, cycle 446 — FEATURE (redirected to a CI-red bug fix per core law "bugs/CI red before anything else"): fix flaky `created_at` nanosecond-vs-microsecond assertion in cycle 445's new device-upsert test, commit 81c22e2)

- Mode selection: counter 445→446, 446 % 5 != 0 → FEATURE. But `gh run list
  --limit 5` showed the most recent push (cycle 445's memory-chore commit,
  which re-ran cycle 445's own code commit's tests) had **`CI — Rust`:
  failure** — per citadel core law ("Bugs and CI red are fixed before
  anything else, plan or no plan") and this repo's own FEATURE-mode step 2,
  dropped the feature-candidate hunt and fixed the break first instead.
- Root cause (`gh run view <id> --log-failed`): cycle 445's new test
  `device_save_upsert_updates_credential_but_never_reassigns_owner`
  (`crates/adapters/outbound/powehi-postgres/tests/pg_security_it.rs:1638`)
  asserted `found.created_at == device.created_at` — a straight `DateTime<Utc>`
  equality between the in-memory `Device` (nanosecond precision from
  `Utc::now()`) and the value read back from Postgres `TIMESTAMPTZ` (stored
  at microsecond precision, non-lossless round trip). This is flaky, not
  deterministically broken: it only fails when `Utc::now()`'s sub-microsecond
  digits happen to be nonzero (CI hit `...361625Z` vs `...361625989Z`). Not a
  production bug — the adapter/schema behavior is correct; the test's
  assertion was too strict. The exact same pitfall was already solved
  correctly elsewhere in the same file at line 903-905
  (`after.created_at.timestamp_micros() == created_at.timestamp_micros()`),
  cycle 445 just didn't reuse that pattern for its new test.
- **Fix**: changed the one assertion to compare `.timestamp_micros()` on both
  sides instead of the raw `DateTime<Utc>`, matching the established
  in-file convention exactly. One line changed, no production code touched.
- Review routing: test-only fix, zero crypto/architecture/backend-handler
  diff — crypto-reviewer/threat-model-checker/security-auditor correctly
  not invoked (same precedent as e.g. cycle 435's deny.toml-only chore).
- Verification: `cargo build --workspace --all-targets` clean, `cargo test
  --workspace` all green (0 failures across every crate — the fixed test
  itself is `#[ignore]`'d locally, no Docker in this dev environment, same
  standing limitation as every `pg_security_it.rs` test; will actually
  exercise the fix in CI's Docker job), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --all --check` clean.
- Committed `81c22e2` (`fix(test): compare created_at by microsecond
  precision in device upsert test`), pushed, then **watched `gh run list`
  to completion this cycle** (not just triggered-and-assumed): both
  `CI — Rust` and `CI — Live-backend E2E` came back `completed`/`success`
  on the new commit — confirmed green before closing the cycle, not
  deferred to "a future session" like several recent entries had to.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects —
     resolved as of cycle 445 (43 GiB free / 29% full), re-verify if it
     regresses.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. Carried: no `values-prod-*.yaml`/CI overlay actually flips
     `monitoring.prometheusRule.enabled=true` yet in a real
     kube-prometheus-stack install (ops/environment-config task, cycle 444).
  5. Carried: CI has no job that renders the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`
     (ci-pipeline-author follow-up, cycle 444, not urgent).
  6. **New lesson, not a code candidate:** when adding a new
     Postgres-round-trip timestamp assertion in `pg_security_it.rs`, always
     compare via `.timestamp_micros()` (established at line 903-905, now
     also at ~1638) — never assert raw `DateTime<Utc>` equality against a
     value that passed through a `TIMESTAMPTZ` column, since Postgres
     truncates to microsecond precision and `Utc::now()` doesn't.

## Previous state (2026-09-06, cycle 445 — STABILIZATION: add testcontainers integration coverage for `PgDeviceRepository` (test-coverage gap, not a carried candidate), commit 0af42c7)

- Mode selection: counter 444→445, 445 % 5 == 0 → STABILIZATION.
- CI check: `gh run list --limit 3` green on `main` (cycle 444's push
  `completed`/`success` on `CI — Rust`; the one `cancelled` run was
  superseded by the immediate rerun, not a real failure).
  `gh issue list --state open`: empty. Clean working tree at session start.
- Full backend gate run first, before looking for work (stabilization
  order: CI → issues → test gaps → security sweep): `cargo build
  --workspace --all-targets` clean, `cargo test --workspace` all green
  (0 failures across every crate's unit+doc tests), `cargo clippy
  --workspace --all-targets -- -D warnings` clean, `cargo fmt --all
  --check` clean, `cargo audit` 0 advisories (664 crates), `cargo deny
  check` — advisories/bans/licenses/sources all ok. Host disk: 43 GiB
  free / 29% full on the 228 GiB volume — the "97% full / 6.9 GiB free"
  risk carried since cycle 434 has resolved itself (other
  `~/codespace/*` projects presumably cleaned up); dropping that as a
  standing carried candidate.
- Everything green and the carried-candidates pool was already thin
  (cycle 444 said so explicitly), so did a real test-gap sweep per
  testing-conventions.md ("Outbound adapter → testcontainers integration
  test required") instead of mining another security-auditor nit: grepped
  every `powehi-postgres` repo module for `#[cfg(test)]`/testcontainers
  presence and cross-checked against `pg_security_it.rs`'s actual test
  bodies (not just import lines). Found `PgDeviceRepository`
  (`src/device_repo.rs`) was the one repo in that crate with **zero** real
  coverage of its own methods — `pg_security_it.rs`'s `insert_device`
  fixture helper only ever calls `.save()` as setup for other tests;
  `find_by_id`, `find_by_user`, `delete`, and the `ON CONFLICT (id) DO
  UPDATE` upsert clause's `user_id`-exclusion invariant had never been
  exercised against real Postgres. (Every other repo module — group,
  key_package, server_config, user, push_subscription, commit_ledger,
  leader_lock — already had dedicated real-SQL test coverage.)
- **Fix**: added six tests to `pg_security_it.rs` (`#[ignore]`d like the
  rest of the file — no Docker in this environment, run in CI's existing
  `pg_security_it` job via `--run-ignored all`, confirmed that wiring is
  still in place at `.github/workflows/ci-rust.yml:101`): find-by-id
  hit/miss, find_by_user ownership scoping (asserts another user's device
  never leaks into the result), delete + delete-of-unknown-id-is-a-no-op,
  and a security-invariant test that a colliding-id upsert `save` can
  never reassign `user_id` to an attacker-supplied owner.
- **security-auditor: PASS-with-nits, both cheap nits applied in-session.**
  Confirmed no plaintext/PII/secret logging (pure test code, none added),
  fixtures use random/constant bytes not real-looking keys, no SQL
  surface changed (adapter untouched), `expect()` in test code is
  allowed per testing-conventions. Independently verified the
  ownership-reassignment test's own logic is sound (genuinely collides on
  the PK with a distinct `insert_user`-minted `attacker_owner`, and
  `UserId: PartialEq` makes the assertion real) — not just trusting my
  own claim. Two nits applied: (1) documented in a code comment that a
  foreign-owner id collision returns `Ok(())` and silently keeps
  first-writer-wins semantics rather than erroring, since callers must
  not read "save succeeded" as proof of ownership, and noted why today's
  two callers (registration mints a fresh id; recovery-mint rejects a
  known id already owned by someone else) don't hit this; (2) added
  assertions that `created_at` also survives the upsert unchanged and
  that `find_by_user(attacker_owner)` stays empty. One nit intentionally
  NOT applied this cycle (flagged as the one security-relevant gap beyond
  nice-to-have, but out of scope for a test-only diff): `key_packages`/
  `envelopes` have no FK cascade on `device_id`/`recipient_device_id`
  (`migrations/0001_initial.sql`), so `delete` leaves unconsumed
  KeyPackages behind for a revoked device while `push_subscriptions`/
  `group_members` do cascade — a pre-existing schema property, not a
  regression, and fixing/pinning it is a schema-and-behavior decision for
  a future cycle, not a test-only one.
- No `.rs` production code touched (test-file-only diff) — `crypto-reviewer`/
  `threat-model-checker` correctly don't apply (no crypto, no new
  server-visible metadata, no architectural change).
- Re-ran the full gate after the nit-fixes: `cargo fmt --all` (one
  reformat needed, reapplied and reverified `--check` clean), `cargo test
  -p powehi-postgres --test pg_security_it --no-run` (compiles clean),
  `cargo clippy -p powehi-postgres --all-targets -- -D warnings` (clean),
  `cargo test --workspace` (45/45 test result blocks `ok`, 0 `FAILED`).
- Committed `0af42c7` (`test(postgres): add testcontainers coverage for
  PgDeviceRepository`), pushed. Confirm `CI — Rust`'s `pg_security_it`
  Docker job actually runs and passes these six new tests in a future
  session if not already done by the time this is read.
- Target dir hygiene: `target/` at 17G (below the 20G prune threshold,
  no pruning needed) — pruned 0-byte `.rmeta` stubs only.
- **Next cycle candidates (carried/updated):**
  1. **Dropped:** host disk risk (carried since cycle 434) — now 43 GiB
     free / 29% full, no longer a live concern.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. Carried, minor, optional (security-auditor nit from cycle 444, not
     applied): `additionalLabels` schema doesn't constrain label-key/value
     syntax (DNS-1123-ish pattern, 63-char max). Marginal payoff.
  5. Carried, minor, optional: if staging and prod-eu (same
     `region_id=eu-frankfurt`) ever get scraped by the same Prometheus
     instance, `sum by (region_id)` can't distinguish their alerts.
  6. **New, from this cycle's security-auditor review, real but scoped
     out (schema/behavior decision, not a quick follow-up):**
     `PgDeviceRepository::delete` doesn't cascade to `key_packages`
     (`device_id` FK-less) — a revoked device's unconsumed KeyPackages
     stay in the table forever (they're single-use and TTL'd at the
     application layer already via `mark_consumed`/expiry, so this is a
     storage-hygiene gap, not a security bypass, but worth a deliberate
     decision: add an explicit cleanup call in the revoke-device flow, or
     a FK cascade, or document why leaving them is fine).
  7. The candidate pool is otherwise still thin — a future FEATURE cycle
     should keep considering a fresh substantial item from prd.md rather
     than only mining review-agent nits.

## Previous state (2026-09-06, cycle 444 — FEATURE: close cycle 443's candidate #5, declare `additionalLabels` in `monitoring.serviceMonitor`/`monitoring.prometheusRule` values.schema.json, commit 0ffca0f)

- Mode selection: counter 443→444, 444 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 3` green on `main` (cycle 443's push
  `completed`/`success` on both `CI — Rust` and `CI — Infra`).
  `gh issue list --state open`: empty. Clean working tree at session
  start. Checked for real, actionable gaps beyond the carried-candidates
  list before picking one: grepped `crates/` for `unimplemented!()`/
  `TODO`/`FIXME` (all hits are `#[cfg(test)]` mock structs in
  `invite.rs`/`region.rs`, not production code — nothing actionable);
  confirmed all six `docs/phases/phase-{1..6}/STATUS.md` still show
  zero unchecked `[ ]` items (grep count 0 on all six, re-derived fresh
  not from memory).
- Picked cycle 443's candidate #5 (only genuinely actionable, non-blocked
  item left): `values.schema.json`'s `monitoring.serviceMonitor` and
  `monitoring.prometheusRule` objects didn't declare `additionalLabels`
  as a schema property even though both `values.yaml` (empty default)
  and the three overlay files (`release: kube-prometheus-stack`) set it
  — a typo there would validate cleanly and only fail silently at
  runtime (Prometheus Operator's selector/ruleSelector just wouldn't
  match, so scraping/alerting silently doesn't happen) instead of
  failing loud in CI.
- **Fix**: added `additionalLabels: {"type": "object", "additionalProperties":
  {"type": "string"}, "description": "..."}` to both `serviceMonitor` and
  `prometheusRule` in `infra/helm/powehi/values.schema.json`. Pure
  schema-only diff — no template, `values.yaml`, or overlay file touched.
- **Validated locally**: `helm lint` clean on base chart + all three
  overlays (`values-prod-eu.yaml`/`values-prod-ap.yaml`/
  `values-staging.yaml`) with the new schema in place; `helm template`
  → `conftest test -p infra/policy --combine` 7/7 passed on all three
  overlays (0 failures, no regression from the schema-only change, as
  expected since schema doesn't affect rendered output).
- **security-auditor: PASS.** Confirmed the diff is additive-only (no
  `required` touched, no `additionalProperties: false` added/removed, no
  pattern/enum loosened), confirmed via `helm lint` that both the current
  empty-object default and the overlays' `{release: kube-prometheus-stack}`
  value validate cleanly under the new schema, and **ran the actual
  negative case**: `--set monitoring.prometheusRule.additionalLabels.release=123`
  now fails schema validation (`got number, want string`) — confirms the
  original nit (typo silently passing) is genuinely closed, not just
  theoretically addressed. No attack surface: labels are Kubernetes
  metadata only, no secrets/PII/ciphertext ever flow through this field.
  Noted two optional non-blocking nits (label-value pattern/length regex,
  `propertyNames` constraint on keys) — correctly flagged as marginal
  payoff (can't catch a *valid but wrong* value like `kube-prometheus-stak`
  either way) and not applied this cycle.
- No `.rs` file touched — `crypto-reviewer`/`threat-model-checker`
  correctly don't apply; backend build/test gate doesn't apply either
  (same routing precedent as cycles 442/443).
- Committed `0ffca0f` (`fix(infra): declare additionalLabels in
  monitoring.serviceMonitor/prometheusRule schema`), pushed.
- Target dir hygiene: not checked (FEATURE mode); `du -sh target` was
  17G at session start, under the 20G stabilization-mode prune threshold.
- Trimmed this file's tail: dropped cycle-438-and-older "Previous state"
  sections (kept 440-443) to keep the file from growing unbounded —
  older cycle detail is still in git history / GitHub commit messages if
  ever needed.
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. **Downgraded to done:** cycle 443's candidate #5 (schema didn't
     declare `additionalLabels`) is now closed.
  5. Carried, minor, optional (security-auditor nit, not applied):
     if staging and prod-eu (same `region_id=eu-frankfurt`) ever get
     scraped by the same Prometheus instance, `sum by (region_id)` can't
     distinguish their alerts. Not urgent since they're currently
     separate clusters — would need an `env` label or
     `enforcedNamespaceLabel` only if that topology changes.
  6. New, minor, optional (this cycle's own security-auditor nit, not
     applied): `additionalLabels` schema now types values as strings but
     doesn't constrain label-key/value syntax (DNS-1123-ish pattern,
     63-char max) — would catch malformed-but-schema-valid labels in CI.
     Marginal payoff (can't catch valid-but-wrong values like a
     misspelled release name either way); not worth a dedicated cycle.
  7. **The carried-candidates pool is now thin** (mostly non-actionable/
     policy-gated/blocked plus marginal-payoff nits) — a future FEATURE
     cycle should consider scoping a fresh, more substantial item
     directly from prd.md rather than continuing to mine security-auditor
     nits one small schema tweak at a time.

## Previous state (2026-09-06, cycle 443 — FEATURE: enable the media-orphan-sweep PrometheusRule in prod-eu/prod-ap/staging overlays (closes cycle 442's candidate #5), commit 87398b2)

- Mode selection: counter 442→443, 443 % 5 != 0 → FEATURE.
- CI check: `gh run list --limit 5` green on `main` (cycle 442's push
  `completed`/`success` on both `CI — Rust` and the now-present
  `CI — Infra` job). `gh issue list --state open`: empty. Clean working
  tree at session start (no inherited uncommitted work this time).
- Picked cycle 442's candidate #5 (the only genuinely actionable item;
  #1/#2/#4 remain non-actionable-from-this-repo/policy-gated/BLOCKED as
  before): CI's existing `ci-infra.yml` `helm-validate` job already loops
  `helm lint` + `helm template | kubeconform` + `helm template | conftest`
  over `values-prod-eu.yaml`/`values-prod-ap.yaml`/`values-staging.yaml`,
  but none of those three overlays set `monitoring.prometheusRule.enabled`,
  so the new PrometheusRule template (cycle 442) was never actually
  rendered/validated by CI, and a real kube-prometheus-stack install would
  render it without the `additionalLabels.release` its `ruleSelector`
  needs.
- **Fix**: added a `monitoring.prometheusRule` block to all three overlay
  files, mirroring the existing (already-enabled, already-reviewed)
  `monitoring.serviceMonitor` block's shape exactly —
  `enabled: true`, `window: "1h"`, `additionalLabels: {release:
  kube-prometheus-stack}` — same value in all three files, same pattern
  the `serviceMonitor` block in the same file already uses. Pure
  values-file diff, zero template/schema/code changes (those already
  landed cycle 442).
- **Validated locally before delegating review** (not just trusting the
  template renders): `helm lint` clean on all three overlays;
  `helm template ... | grep -c "kind: PrometheusRule"` → 1 for each
  overlay (previously 0 — confirms this closes the actual gap);
  `conftest verify -p infra/policy` (88/88) and `helm template ... |
  conftest test - -p infra/policy --combine` (7/7 per overlay, 0
  failures) — `conftest` happened to be installed locally this session
  (`kubeconform` still wasn't, same gap as prior infra cycles) so this ran
  for real instead of only being deferred to CI.
- **security-auditor: PASS, no required fixes.** Independently re-derived
  rather than trusting this session's own claims: diffed rendered
  manifests at HEAD vs. working tree (73 added lines, 0 removed/modified,
  all originating from `templates/prometheusrule.yaml` — confirms
  no other resource/limits/NetworkPolicy path was touched), confirmed
  both underlying counters carry only the `region_id` label (schema-bound
  enum, no user data), byte-compared all six `release:` lines for exact
  match, confirmed `window: "1h"` and the rendered `for: 0m` both satisfy
  their respective duration-pattern schemas (values.schema.json and the
  real PrometheusRule CRD from the datreeio catalog CI actually fetches),
  and explicitly reasoned about whether staging should get this alert at
  all — concluded **yes, arguably required**: `values-staging.yaml` sets
  `region: eu-frankfurt`, the same region as prod-eu, and the file's own
  cycle-424 comment already documents that a shared bucket between the
  two would let staging's orphan sweep delete prod-eu's live media — the
  owner-mismatch alert is the detection control for exactly that
  misconfiguration, so gating it to prod-only would blind the one
  environment where the risk is documented as live. Two non-blocking
  nits, not applied this cycle (correctly out of scope for a two-line
  enablement diff): (a) if staging and prod-eu ever scrape into one
  Prometheus, `sum by (region_id)` alone can't tell their alerts apart
  (both `region_id="eu-frankfurt"`) — would need an `env` label or
  `enforcedNamespaceLabel` if that topology ever happens; (b)
  `values.schema.json`'s `prometheusRule` object doesn't declare
  `additionalLabels` (same pre-existing omission as `serviceMonitor`) —
  a typo in the release-label value fails silently at runtime, not in CI.
- No `.rs` file touched — pure Helm values diff, so `crypto-reviewer`/
  `threat-model-checker` correctly don't apply (same routing precedent as
  cycle 442's template-authoring commit) and the backend build/test gate
  doesn't apply either; not re-run this cycle.
- Committed `87398b2` (`feat(infra): enable media-orphan-sweep
  PrometheusRule in prod/staging overlays`), pushed. Confirm `CI — Infra`
  green in a future session if not already done by the time this is read.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: host disk risk from other `~/codespace/*` projects — not
     actionable from this repo.
  2. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  3. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  4. **Downgraded to done:** cycle 442's candidate #5 (CI never rendering
     the PrometheusRule template) is now closed — all three overlays
     enable it and CI's existing `ci-infra.yml` loop will render/validate
     it on every future push that touches `infra/helm/**`.
  5. **New, minor, optional (security-auditor nit, not applied this
     cycle):** `values.schema.json`'s `monitoring.prometheusRule` object
     (and `serviceMonitor`, pre-existing) doesn't declare
     `additionalLabels` as a schema property, so a typo in
     `release: kube-prometheus-stack` would validate cleanly and only
     fail silently at runtime (Prometheus Operator's `ruleSelector`
     simply wouldn't pick up the rule) instead of failing in CI. Cheap
     one-line schema addition if a future cycle touches this file again;
     not worth a dedicated cycle.
  6. **New, minor, optional (security-auditor nit, not applied this
     cycle):** if staging and prod-eu (same `region_id=eu-frankfurt`)
     ever get scraped by the same Prometheus instance, `sum by
     (region_id)` can't distinguish their alerts. Not urgent since they're
     currently separate clusters — would need an `env` label or
     `enforcedNamespaceLabel` only if that topology changes.

