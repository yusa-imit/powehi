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

## Current state (2026-08-25, cycle 359 — FEATURE: bind size_bytes into presigned R2 upload signature, commit 62541bb)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. All of
  cycle 358's carried-forward candidates were blocked (PQ hybrid Phase A: openmls PQ
  ciphersuite still not stable — checked `docs/decisions/0003-pq-migration.md`, Phase A
  checklist items all still unchecked) or too large for one safe cycle (media-key
  incoming/outgoing asymmetry — dispatched an Explore agent to scope it first: closing it
  needs WASM to retain a session-lived local-storage key derived from the OPAQUE
  `export_key`, since WASM currently has no thread-local counterpart to `dbKey` at
  `media_encrypt` time — a real new-persistent-secret design decision, correctly deferred
  again rather than rushed). Dispatched a fresh `security-auditor` sweep instead (same
  pattern as cycle 350 when the candidate queue ran dry), scoped to `bin/powehi-server`,
  `application/*/src/*service*.rs`, and outbound adapters.
- **security-auditor found a real MEDIUM bug:** `R2MediaAdapter::presigned_upload_url`
  (`crates/adapters/outbound/powehi-r2/src/lib.rs`) never bound `Content-Length` into the
  SigV4 signature. `size_bytes` is validated server-side (0 < size ≤ `MAX_MEDIA_BYTES` =
  100MB, `media_service.rs::request_upload`) and persisted, but that check was purely
  advisory — a client could declare `size_bytes: 1` then PUT an arbitrarily large body to
  the real presigned URL (15 min TTL), since nothing checked the actual upload length.
  Unbounded R2 storage/egress cost, and `media_blobs.size_bytes` (the only value any GC/
  accounting logic sees) was a client-controlled lie.
- **Fix:** added `.content_length(row.size_bytes as i64)` to the presign builder — R2 now
  rejects (SignatureDoesNotMatch) any PUT whose actual body length differs from the row's
  `size_bytes`. Also closed a related **pre-existing live bug** the same sweep surfaced:
  `content_type` had ALWAYS been a signed header on this presigned URL, but both PUT call
  sites in `app/src/lib/mediaTransfer.ts` (`encryptAndSendMedia`, chunked + non-chunked)
  hardcoded `Content-Type: application/octet-stream` instead of the real `mimeType` param
  — meaning every real upload against actual R2/S3 (not the local dev/test path) would
  already fail with `SignatureDoesNotMatch`. Fixed both call sites to send the real
  `mimeType`.
- **security-auditor: GREEN** (2 non-blocking YELLOW notes, no required fixes — "Ship it").
  Verified EMPIRICALLY, not by reading docs: built a temporary probe against the pinned
  `aws-sdk-s3 1.133.0`/`aws-sigv4 1.4.4` and diffed presigned URLs with/without
  `.content_length()` — confirmed `content-length` genuinely enters `X-Amz-SignedHeaders`
  (not silently dropped by the presign interceptor's default-header suppression), and that
  `content-type` was already signed pre-diff (confirming the second bug was real, not
  theoretical). `i64`↔`u64` cast confirmed lossless (100MB ≪ `i64::MAX`, `size_bytes` is
  `BIGINT` on disk). Confirmed no drift: `ciphertext.length` (the exact post-encryption
  byte count) is what both `requestMediaUpload` and the PUT body use — the signed value
  always equals the real body. Residual gap flagged as pre-existing/out-of-scope, not
  introduced by this diff: `/v1/media/upload-url` has no per-device/per-day byte quota,
  only the shared per-IP `api_governor` rate limit (~4TB/day/IP sustained-worst-case) —
  the diff converts unbounded-per-URL to bounded-per-URL, which is the correct increment;
  a byte quota is a separate MEDIUM finding for a future cycle. No plaintext/PII/ciphertext
  leaked (error paths collapse to static categories; new test fixtures are filler bytes).
  Not architectural, no new server-visible metadata (R2 already saw object size regardless;
  this only makes an already-collected value load-bearing) — `threat-model-checker` not
  required. Not crypto code (S3 request-signing infra, not a message-encryption primitive)
  — `crypto-reviewer` not required.
- 4 new/updated Rust tests in `r2_media_it.rs` (2 new: oversized-body-rejected,
  undersized-body-rejected, both asserting the object never lands in S3; 2 existing tests'
  fixtures corrected to set `blob.size_bytes = body.len()` before save, since content-length
  is now signed and must match the real PUT body) — all `#[ignore = "requires Docker"]`,
  not run locally (no Docker in sandbox), will run in CI's Rust workflow. 2 new Vitest tests
  in `mediaTransfer.test.ts` proving the PUT's `Content-Type` header matches the real
  `mimeType` on both chunked and non-chunked paths — these DID run locally and pass.
  `cargo build/test --workspace` clean (all non-ignored green), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean (1 auto-fix applied
  mid-cycle for the two new tests' `.expect()` line length, no logic change). Frontend:
  105/105 files, 1504/1504 tests green (was 1502). `tsc -b`/`biome check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 360,
  STABILIZATION).
- **Next cycle candidates:** the 2 YELLOW notes from this cycle (both optional, cheap,
  non-blocking — signing `.content_type(&row.content_type)` instead of the caller-supplied
  parameter for extra robustness against a future divergent caller; a `video/quicktime`
  test fixture that isn't in `ALLOWED_CONTENT_TYPES`, cosmetic only); a per-device/per-day
  media upload byte quota (MEDIUM, this cycle's residual finding — no `MediaRepository`
  count method exists yet, would need one, same pattern as `MAX_KEY_PACKAGES_PER_DEVICE`/
  `MAX_OUTSTANDING_INVITES_PER_DEVICE`); closing the incoming/outgoing media-key asymmetry
  (needs a new crypto-reviewed WASM key-export/local-storage-key design — scoped this
  cycle via Explore agent, confirmed genuinely multi-part, not a quick fix); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md archival
  (184KB/2308 lines, under the 256KB Read cap but flagged repeatedly across cycles 355-358
  as increasingly pressing — cycle 360 is STABILIZATION, do it then per precedent from
  cycles 320/340).

## Previous state (2026-08-25, cycle 358 — FEATURE: automate pg_index.indisvalid migration guard, commit d3df0de)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 355/357's carried-forward candidate: the manual runbook step in 0011's OPERATIONAL
  NOTE (security-auditor cycle 353) — if 0011's `CREATE INDEX CONCURRENTLY` on
  `envelopes_recipient_created_id_idx` is interrupted, Postgres leaves an INVALID index
  under that name; `IF NOT EXISTS` then no-ops on a migration retry without rebuilding it,
  and the old `0012` migration would unconditionally drop the only good (two-column)
  fallback index — every poll (every device, ~3s interval) would seq-scan `envelopes`.
- **Fix:** `git mv`'d the old `0012_envelope_poll_created_idx_drop.sql` to
  `0013_envelope_poll_created_idx_drop.sql` (content unchanged), and inserted a new
  `0012_envelope_poll_idx_validity_guard.sql` between 0011 (create) and 0013 (drop) — an
  ordinary transactional migration (`DO $$ ... $$` block, since `CONCURRENTLY` forbids
  running inside a transaction and can't share a file with a conditional check) that
  `RAISE EXCEPTION`s and aborts the whole `sqlx::migrate!().run()` call if
  `pg_index.indisvalid = false` for the new index. Updated 0011's comment to point at the
  fix instead of re-flagging closed work.
- **security-auditor: GREEN.** Verified (not rubber-stamped), including tracing the actual
  deploy path: `run_migrations` is called on every real server boot
  (`bin/powehi-server/src/main.rs`), but confirmed via `git tag` (empty, 667-commit history)
  and `.github/workflows/release.yml`/`cd.yml` (both gated on a `vX.Y.Z` tag that's never
  been pushed) that no real deployed environment has ever recorded the old migration
  version 12 in a persisted `_sqlx_migrations` table — renumbering an unreleased migration
  is safe today. Advisory-only, not blocking: once a real tag/release ships, this
  renumbering pattern must not be repeated (sqlx 0.8.6 would hard-error with
  `VersionMismatch` on a checksum mismatch for an already-applied version — fails loudly,
  not silently, if it ever were unsafe). Also confirmed the `'...'::regclass` cast is safe
  by construction (sqlx runs migrations strictly in order and aborts the whole run on any
  earlier failure, so a catalog row for the index name is guaranteed to exist by the time
  0012 runs, valid or not); no plaintext/PII logging (only index/table names in SQL
  comments and the exception message); no wire-format/API/behavior change
  (`threat-model-checker` correctly not required, diff scoped to `migrations/*.sql` +
  `tests/pg_security_it.rs` only).
- 2 new `#[ignore = "requires Docker (testcontainers)"]` tests in `pg_security_it.rs`:
  `full_migration_run_leaves_new_envelope_index_valid_and_old_index_dropped` (happy-path,
  full `sqlx::migrate!()` run leaves the new index valid + old index gone) and
  `envelope_poll_idx_validity_guard_aborts_on_invalid_index` (reproduces an invalid index
  via a `CREATE UNIQUE INDEX CONCURRENTLY` that fails on a genuine duplicate-key violation
  — the standard reliable way to get Postgres to leave a catalogued-but-invalid index, since
  there's no supported way to directly flip `pg_index.indisvalid` on a healthy one — then
  runs the **actual shipped 0012 SQL** via `include_str!`, string-substituting the index
  name, proving both directions: raises when invalid, passes silently once rebuilt valid).
  Not run locally (no Docker in this sandbox, consistent with prior cycles — will run in
  CI's Rust workflow, which has Docker). `cargo build --workspace` clean, `cargo test
  --workspace` (non-ignored) all green, `cargo clippy --workspace --all-targets -- -D
  warnings` clean, `cargo fmt --check` clean (one auto-fix applied mid-cycle for the two
  new happy-path assertions' line length, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due).
- **Next cycle candidates:** closing the incoming/outgoing media-key asymmetry (cycle 349,
  needs a new crypto-reviewed WASM key-export primitive); PQ hybrid Phase A (still blocked
  on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B 95%-session threshold); cycle 356's YELLOW note (KeyPackage 16KiB cap margin
  narrows under Phase A native PQ — revisit alongside that work, not standalone);
  project-context.md archival (now 2300+ lines — worth archiving older cycle entries in a
  future stabilization cycle, getting more pressing each cycle this is deferred).

## Previous state (2026-08-25, cycle 357 — FEATURE: cross-crate REST/gRPC envelope size-cap sync test, commit 781348e)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 356's top carried-forward candidate:
  threat-model-checker's cycle 355 follow-up — no compiler/test-enforced sync between
  `messaging_service.rs`'s (`powehi-application`, REST ingress) and
  `powehi-grpc/server.rs`'s (cross-region forwarder) deliberately-duplicated
  `MAX_CIPHERTEXT_BYTES`/`MAX_COMMIT_BYTES`/`MAX_WELCOME_BYTES` constants — this exact
  pair had already drifted silently once before (RED-1, cycle 353: a stale generic 1MiB
  gRPC cap outlived a tightened 96KiB REST cap).
- **Fix:** widened the three constants in each crate from private `const` to `pub const`
  (both modules were already `pub mod`, so no new module exposure) and added
  `bin/powehi-server/tests/size_cap_consistency.rs` — the only crate in the workspace
  that already depends on both `powehi-application` and `powehi-grpc` (the composition
  root), so no new cross-crate dependency was introduced. The test file has both a
  `const _: () = assert!(...)` per pair (fails `cargo build`/`cargo check` itself, added
  post-review per the auditor's suggestion — stronger than a runtime test since it can't
  be skipped by filtering `cargo test`) and matching `#[test]` runtime assertions with
  descriptive failure messages.
- **security-auditor: GREEN.** Verified (not rubber-stamped): all six constants are
  literal `usize` byte-size values, not derived from config/env/key material — `pub`
  grants read of a compile-time integer only, no capability; values are already
  black-box discoverable via size probing by any client, so zero information
  disclosure. New test file confirmed pure `assert_eq!`/`assert!` on consts, no I/O/DB/
  testcontainers/fixtures, non-flaky by construction (ran it: 3/3 passed in 0.00s). No
  other code in the diff besides the visibility bump + doc comments + new test file. No
  plaintext/PII/ciphertext logging added (zero log statements in the diff).
- Not architectural, no new server-visible metadata (pure internal visibility change +
  test-only addition, no wire-format/behavior change) — `threat-model-checker` re-run
  not required (it was the one that requested this fix); `crypto-reviewer` not required
  (no crypto code touched).
- `cargo build --workspace` clean, `cargo test --workspace` all green (no regressions,
  new 3 tests pass), `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean (one auto-fix applied mid-cycle for the const-assert
  formatting, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due).
- **Next cycle candidates:** `pg_index.indisvalid` migration guard automation for
  0011/0012 (cycle 355's other follow-up, cheap, low urgency); closing the incoming/
  outgoing media-key asymmetry (cycle 349, needs a new crypto-reviewed WASM key-export
  primitive); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session threshold);
  cycle 356's YELLOW note (KeyPackage 16KiB cap margin narrows under Phase A native PQ
  — revisit alongside that work, not standalone); project-context.md archival
  (now 2200+ lines — worth archiving older cycle entries in a future stabilization
  cycle, getting more pressing).

## Previous state (2026-08-25, cycle 356 — FEATURE: KeyPackage upload per-item size cap, commit d0f0c8e)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 350's last remaining deferred LOW
  finding (the other two from that sweep — broadcast-ack access control, envelope
  pagination/size caps — were closed cycles 350/355): `KeyPackageService::upload`
  capped package *count* per call (50) and per device (200) but not individual byte
  size, inconsistent with `invite_service.rs`'s `MAX_KEY_PACKAGE_BYTES`/
  `auth_service.rs`'s `MAX_MLS_CREDENTIAL_BYTES` precedent.
- **Fix:** added the same `MAX_KEY_PACKAGE_BYTES = 16 * 1024` constant to
  `key_package_service.rs`. `upload()` now rejects the whole batch fail-closed (empty
  or >16KiB on any item) before the per-device count check's DB round trip — no
  partial upload, since `save()` loops individual INSERTs with no transaction.
- **security-auditor: GREEN.** Verified (not rubber-stamped): built a temporary probe
  in `powehi-crypto-wasm` to measure a real `openmls` KeyPackage wire size
  (PQ-hybrid-extension-included, current Phase B interim ciphersuite) at 1,541 bytes —
  16KiB gives ~10.6x headroom, no legitimate-KeyPackage rejection risk; reverted the
  probe, confirmed working tree clean before commit. No bypass path (`save`'s only
  caller is post-check; `upload`'s only production caller is the REST route; gRPC only
  reads/consumes, never writes). Fail-closed whole-batch rejection is the only clean
  choice given `save`'s non-transactional insert loop, consistent with the existing
  count-cap's same all-or-nothing behavior. No plaintext/PII logging (bytes are
  `#[instrument(skip(...))]`, error strings are static categories, `ApiError::from`
  collapses all `InvalidInput` variants to `400 invalid_input` client-side). One
  YELLOW informational, non-blocking: prd.md §5.3's Phase A native-PQ KeyPackage
  estimate (~8000B) + a max-size 4KiB LeafNode credential narrows headroom to ~25% —
  worth revisiting when `POWEHI_PQ_MLS_NATIVE_ENABLED` is ever flipped on, not now.
- Not architectural, no new server-visible metadata (same disclosure precedent as the
  existing `MAX_KEY_PACKAGE_BYTES`/`MAX_MLS_CREDENTIAL_BYTES` caps) —
  `threat-model-checker`/`crypto-reviewer` not required (diff touches no crypto code).
- 4 new tests in `key_package_service.rs` (oversized rejected, at-limit accepted,
  empty rejected, mixed-batch rejects whole batch with zero partial-store state;
  module total 8→12). `cargo test --workspace` all green, `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt` applied (2 lines reformatted, no
  logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — last checked
  cycle 355 at 14GB, well under the 20GB threshold).
- **Next cycle candidates:** the two follow-ups from cycle 355 (cross-crate
  size-cap-drift test between `messaging_service.rs`/`powehi-grpc/server.rs`;
  `pg_index.indisvalid` migration guard automation for 0011/0012) — both cheap, low
  urgency; closing the incoming/outgoing media-key asymmetry (cycle 349, needs a new
  crypto-reviewed WASM key-export primitive); PQ hybrid Phase A (still blocked on
  openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold); this cycle's new YELLOW note (KeyPackage
  16KiB cap margin narrows under Phase A native PQ — revisit alongside that work, not
  standalone); project-context.md archival (166KB→ now larger, worth archiving older
  cycle entries in a future stabilization cycle).

## Previous state (2026-08-24, cycle 355 — STABILIZATION: envelope poll pagination + per-type size caps, commit 97c6c7c)

- CI green (`gh run list --limit 5` all success/cancelled-superseded), `gh issue list
  --state open` empty. **`git status` at cycle start was NOT clean** — found a complete,
  passing, uncommitted working-tree diff spanning what its own doc comments described as
  cycles 351-353 (same "cycle silently fails to commit" pattern as cycles 324/326/330/
  332/341/342). Per CLAUDE.md's investigate-before-discarding guidance, validated rather
  than discarded: `cargo build --workspace` clean, `cargo test --workspace` all green (no
  regressions), `cargo clippy --workspace --all-targets -- -D warnings` clean, frontend
  `pnpm test --run` 105/105 files / 1502/1502 green (was 1498), `tsc -b`/`biome check`
  clean. The diff's doc comments *claimed* prior review cycles already happened but were
  never committed — treated as unverified claims, not fact, and re-reviewed properly
  before this commit (see below). `pg_security_it.rs`'s new pagination test needs
  testcontainers/Docker, unavailable in this session's sandbox — not run locally, will be
  exercised by CI's Rust workflow (which has Docker) on push.
- **What it does:** closes both findings security-auditor deferred from cycle 350:
  1. `find_pending` had no LIMIT/pagination — a device with a large backlog (offline for
     a long time, or a flooded group) could force `poll_envelopes` to serialize an
     unbounded JSON response, risking OOM on the polling device. Fixed: exact
     `(created_at, id)` keyset cursor (`ENVELOPE_POLL_LIMIT=64` rows,
     `ENVELOPE_POLL_MAX_BYTES=4MiB` cumulative raw bytes, at-least-one-row-always-returned
     for a single oversized envelope), backed by a new 3-column index
     (`envelopes_recipient_created_id_idx`, migrations 0011/0012 — `CREATE INDEX
     CONCURRENTLY` first, `DROP INDEX CONCURRENTLY` of the old 2-column index second, so
     the table is never unindexed or lock-held during the build; `-- no-transaction`
     marker required since Postgres forbids `CONCURRENTLY` inside sqlx's default
     migration transaction).
  2. No server-side size cap on message ciphertext beyond the global 512KB body limit
     (inconsistent with `invite_service.rs`'s `MAX_KEY_PACKAGE_BYTES`/`auth_service.rs`'s
     `MAX_MLS_CREDENTIAL_BYTES` precedent). Fixed: per-type caps in
     `messaging_service.rs` — `MAX_CIPHERTEXT_BYTES=96KiB` (Application),
     `MAX_COMMIT_BYTES=64KiB`, `MAX_WELCOME_BYTES=256KiB` — checked before the membership
     DB round-trip in `send_message`/`send_welcome`/`send_commit`. Mirrored in
     `powehi-grpc/src/server.rs`'s cross-region `forward_envelope`/`forward_commit`,
     replacing a single generic 1MiB cap that would have let a compromised peer region
     forward oversized Application/Proposal envelopes and silently invalidate
     `ENVELOPE_POLL_LIMIT`'s documented worst-case-per-poll memory bound.
  REST `poll` endpoint's `PollQuery.since` changed from a Unix-timestamp `i64` to an
  RFC3339 string, plus a new `since_id` field — together they're the keyset cursor pair;
  `since_id` without `since` is rejected fail-closed. Frontend (`useMessages.ts`/
  `useWelcomePoller.ts`) advances the cursor to the last envelope of every fetched page
  unconditionally (even a page the hook doesn't fully act on — wrong group, undecryptable
  Welcome, decrypt-rate-deferred), so the next poll always moves forward; a large backlog
  drains over repeated 3s-interval ticks rather than a single in-tick loop.
- **security-auditor: GREEN.** Verified (not rubber-stamped): the byte-trim loop's
  at-least-one-row guarantee, the keyset cursor's injection-safety and gap/duplicate-
  freedom (checked against the new `find_pending_keyset_cursor_splits_same_timestamp_
  group_safely` testcontainers test — 71+ same-`created_at` envelopes paged across 10
  rounds, zero loss), the 0011/0012 migration's `-- no-transaction` mechanism against
  sqlx's actual vendored source, no bypass of the new size caps from any other route
  handler (invite.rs/push_subscription.rs/region.rs/lib.rs diffs are pure trait-signature
  plumbing for the new `since_id` param, not new call sites), no broken-access-control
  regression from since/since_id (device-scoping WHERE clause is independent of and
  applied before the cursor predicate), no plaintext/PII/ciphertext logging added. One
  non-blocking follow-up: automate a `pg_index.indisvalid` guard between 0011/0012
  instead of relying on the migration's documented manual runbook step for the rare
  interrupted-CONCURRENTLY-build case.
- **threat-model-checker: GREEN, no prd.md changes required.** Envelope ciphertext size
  was already disclosed as server-visible in prd.md §3.3 — the new caps don't add a new
  observable signal, same `MAX_KEY_PACKAGE_BYTES` precedent. Verified the pagination
  cursor can't be used as an existence oracle (a forged `since_id` can only reposition
  within the caller's own already-authorized row set, since the device-scoping filter is
  independent of the cursor predicate) and can't cause a *permanent* skip (only
  latency — draining a large/flooded backlog over multiple poll ticks, not a single-tick
  loop, is a documented availability property, not a correctness regression). Two
  non-blocking follow-ups noted: (a) no compiler-enforced sync between the REST-side
  (`messaging_service.rs`) and gRPC-side (`powehi-grpc/server.rs`) size-cap constants —
  worth a cross-crate test asserting they match, to fail CI instead of requiring a human
  to notice future drift (closing this the same way a future cycle 352-style gap would
  reopen it); (b) `MAX_WELCOME_BYTES=256KiB` is generous on paper but the pre-existing
  (unchanged by this diff) global `MAX_BODY_BYTES=512KB` body limit already truncates a
  raw Welcome to ~143KB before this check is ever reached (JSON-numeric-array ~3.57x
  inflation on a plain `Vec<u8>` field) — a pre-existing availability constraint on
  large-group MLS Welcomes, not introduced or worsened by this diff, flagged for a future
  `serde_bytes`/base64 encoding fix if ever prioritized.
- New/updated tests: `pg_security_it.rs` gained `find_pending_paginates_large_backlog`
  and `find_pending_keyset_cursor_splits_same_timestamp_group_safely` (testcontainers,
  not run locally this cycle — no Docker in sandbox, will run in CI); `messaging_service.rs`
  gained 3 oversized-payload rejection tests + 1 at-limit-accepted test;
  `powehi-grpc/server.rs` gained a per-type-cap-dispatch test (Welcome between the
  Application and Welcome caps is accepted, not rejected at the tighter cap) + an
  oversized-Welcome-rejected test; frontend `useMessages.test.ts`/`useWelcomePoller.test.ts`
  gained cursor-advancement coverage. **Frontend: 105/105 files, 1502/1502 tests green**
  (was 1498). `tsc -b` clean, `biome check` clean.
- Target dir hygiene: pruned 0-byte `.rmeta` stubs; `target/` at 14GB, under the 20GB
  prune threshold, no further action needed. `project-context.md` at 166KB/2059 lines,
  under the 256KB Read cap — no archive needed yet, but getting closer; worth archiving
  older cycle entries (300s) to a separate file in a future stabilization cycle if it
  keeps growing.
- **Next cycle candidates:** the two follow-ups from this cycle's reviews (cross-crate
  size-cap-drift test; `indisvalid` migration guard automation) — both cheap, low
  urgency; `KeyPackageService::upload`'s missing per-KeyPackage size cap (cycle 350's
  other deferred LOW finding, still not picked up — cheap, same pattern as
  `MAX_KEY_PACKAGE_BYTES` in invite_service.rs to copy); closing the incoming/outgoing
  media-key asymmetry (cycle 349, would need a new crypto-reviewed WASM key-export
  primitive); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session threshold);
  project-context.md archival (noted above, not urgent yet).

## Previous state (2026-08-24, cycle 350 — STABILIZATION: fix broken access control in broadcast envelope ack, commit bd82201)

- CI green, `gh issue list --state open` empty, `git status` clean at cycle start. Full
  baseline pass before picking a target: backend `cargo build/test --workspace` green,
  `cargo audit`/`cargo deny check` clean, `cargo clippy --workspace --all-targets -- -D
  warnings` clean; frontend 105/105 files, 1498/1498 tests, `tsc -b`/`biome check` clean,
  `pnpm audit --prod` clean. Dispatched `security-auditor` + `crypto-reviewer` sweeps in
  parallel to find a concrete fix target (crypto-reviewer's sweep returned truncated/
  inconclusive — not resumable, not pursued further since this cycle's fix ended up
  non-crypto anyway).
- **security-auditor found a real HIGH-severity broken-access-control bug:**
  `ack_envelope` (`messaging_service.rs`) hard-deleted any broadcast envelope (group
  Application messages AND MLS Commit envelopes — anything with `recipient == None`) on
  the **first** ack from **any authenticated device**, with zero group-membership check
  and no per-device delivery tracking. Any group member — or any authenticated device
  that obtained/guessed an `envelope_id` — could delete a group message before other
  members polled it (silent censorship), or delete a Commit envelope, which is worse:
  MLS cannot self-heal from a dropped Commit, so this was a permanent group-epoch-desync
  DoS. Two more findings from the same sweep deferred (see below).
- **Fix:** new `envelope_acks(envelope_id, device_id)` table (migration
  `0010_envelope_acks.sql`), same shape/precedent as `media_acks` (cycle 289).
  `EnvelopeRepository` gained `ack_broadcast(envelope_id, device_id, group_member_ids)`;
  `PgEnvelopeRepository`'s impl inserts an ack row then deletes the envelope in the same
  transaction only if every id in `group_member_ids` now has an ack row (SQL
  set-containment `NOT EXISTS` check, atomic). `MessagingService::ack_envelope` now
  calls `check_sender_is_member` before accepting a broadcast ack (closes the actual
  membership hole), then passes the current member list (minus the envelope's own
  sender — see below) to `ack_broadcast`.
- **threat-model-checker caught a RED blocking bug in the first draft:** the initial fix
  passed *all* group members (including the sender) as the required-ack set. But a
  sender never acks their own broadcast — `useMessages.ts` in the frontend documents
  that a sender's own envelope fails MLS decrypt client-side and is deliberately never
  acked, "stays server-side indefinitely." So the all-members-acked condition could
  **never** be satisfied for an ordinary group message → GC unreachable → unbounded
  ciphertext retention / storage DoS, directly contradicting prd.md §11.4's documented
  `Stored_Server → Expired: TTL 도달 (기본 30일)` state. Fixed by excluding the
  envelope's sender from the required-ack set (mirrors `media_service.rs`'s existing
  uploader-exclusion pattern for the exact same reason). Also added the missing default
  30-day retention floor to `delete_expired` for envelopes with `expires_at IS NULL`
  (a backstop for members who leave a group without ever polling, so a straggler
  membership record can't pin an envelope forever) — this path in prd.md §11.4 existed
  in the diagram but was never actually implemented for envelopes before this cycle.
  Re-reviewed: threat-model-checker's second listed concern (new `envelope_acks`
  metadata category, higher-resolution than `media_acks` since it fires on every
  message not just shared media) addressed by adding a `docs/prd.md` §3.3 bullet + a
  §3.4 GC-timing-oracle paragraph extension, same disclosure precedent as
  `media_acks`/cycle 289-290.
- 3 new/updated unit tests in `messaging_service.rs` (non-member ack rejected +
  envelope survives; multi-member ack sequencing proves GC never needs the sender's own
  ack) — `cargo test --workspace` green (was 172 passed in `powehi-application`, still
  172 after edits — net even: 1 test rewritten, 2 added, one pre-existing test's
  assertion target changed from a random non-member device to the actual sole member,
  since acking as a non-member now correctly fails). Also had to add trivial
  `ack_broadcast` stubs to two no-op `EnvelopeRepository` test fakes in
  `powehi-grpc/src/server.rs` (compile-only impact, not exercised). Full
  build/test/clippy/fmt green after the fix.
- **Two more security-auditor findings from the same sweep, deferred as next-cycle
  candidates (documented, not blocking — both lower severity than the one fixed):**
  1. *(MEDIUM-HIGH)* `find_pending` has no `LIMIT`/pagination and `poll_envelopes`
     serializes the whole result into one JSON response — a sustained-send device could
     build a backlog that OOMs the victim's next poll. No per-message size cap beyond
     the global 512KB body limit either. Needs `LIMIT`+keyset pagination on
     `created_at` plus an explicit `MAX_CIPHERTEXT_BYTES` check in `send_message`.
  2. *(LOW)* `KeyPackageService::upload` caps count (50/call, 200/device) but not
     individual KeyPackage size, inconsistent with `invite_service.rs`'s
     `MAX_KEY_PACKAGE_BYTES = 16 KiB` and `auth_service.rs`'s
     `MAX_MLS_CREDENTIAL_BYTES`. Cheap fix, same pattern to copy.
- Target dir hygiene: pruned 0-byte aborted-build `.rmeta` stubs; `target/` at 11GB,
  under the 20GB prune threshold, no further action needed.

## Previous state (2026-08-24, cycle 349 — FEATURE: persist media messages (photo/video/voice) to Dexie, commit 2b05798)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Dispatched an Explore-agent scoping pass first on
  cycle 347's largest carried-forward candidate — the media-message-has-zero-Dexie-
  persistence gap (flagged since cycle 343) — before committing a cycle to it: confirmed
  the R2 blob itself is durable server-side (no client-side blob cache exists), so
  persisting only `blobId+key+iv+thumbnail+mimetype` (never raw bytes) to Dexie is
  sufficient to re-fetch and redecrypt after reload — achievable in one focused cycle,
  not the multi-part effort earlier cycles assumed.
- **Fix:** `MessageRow.mediaJson?: string` (schema v27, `db/schema.ts`) — JSON-encoded
  `MediaPayload`, added to `SENSITIVE.messages` in `encrypted-db.ts` (same transparent
  FieldEncryptor boundary as `pollJson`/`reactionsJson`/`replyToJson`, no new crypto
  primitives). `persistIncoming` (`usePersistentMessages.ts`) threads `msg.media` into
  `mediaJson` on receive. `persistOutgoing` gained an optional `media` param, but the
  actual send call sites (`useMediaSend.ts`, `ChatLayout.tsx`'s `sendForwardToSelected`)
  only ever pass a placeholder text ("Image attachment"/"Video attachment"/"Voice
  message") plus the real ciphertext — **documented architectural asymmetry**: the raw
  AES-256-GCM media key never crosses the WASM→JS boundary on send
  (`encryptAndSendMedia` in `mediaTransfer.ts` returns only an opaque-handle-backed
  result, never key bytes), so a sender has no key to persist for their own
  redisplayable copy. Not a regression — the live pre-reload optimistic bubble for a
  sent attachment never rendered an inline preview either, only this same placeholder.
  Closing the asymmetry would need a new, crypto-reviewed WASM key-export-for-storage
  primitive — explicitly out of scope this cycle. `encryptAndSendMedia`'s signature
  changed `Promise<void>` → `Promise<{envelopeId, ciphertextB64}>` so send call sites can
  persist; no wire-format change, purely a local re-encoding of already-sent bytes.
  ChatLayout's rehydration effect parses `row.mediaJson` back into `ChatMessage.media`.
- Delegated implementation to `frontend-lead` (had to resume it once — its first pass
  cut off mid-task with no tests written yet; the resume completed tests +
  verification).
- **security-auditor: YELLOW, both MEDIUM findings fixed in-cycle:**
  1. *(fixed)* Rehydration's shape validation (`ChatLayout.tsx`) checked only
     `blobId`/`blobHash`/`mediaKey`/`iv`, weaker than the live receive path
     (`useMessages.ts`), which also validates `thumbnail.ct/key/iv` exact lengths
     (≤16384/32/12) and `chunked`⇒`totalSize`/`chunkSize` validity. A malformed-but-
     truthy `thumbnail` on a rehydrated row would crash synchronously inside
     `useThumbnail`'s `thumbnail.key.length` check, uncaught — no ErrorBoundary in the
     tree. Fixed: hoisted both paths' predicates into one shared, exported
     `isValidMediaPayload()` (`useMessages.ts`), used by both the receive path (which
     also got simpler — removed ~35 lines of duplicated inline validation) and
     rehydration. mimeType sanitization (not part of the shared validator, since a bad
     mimeType shouldn't invalidate an otherwise-valid attachment) kept as an explicit
     per-branch step so it isn't silently dropped by the refactor.
  2. *(fixed)* The new rehydration test's headline assertion (`useMediaReceive` called →
     image renders) survived the reviewer's content-substitution mutation (swapping in a
     wrong `blobId`/`mediaKey`/`iv` still passed both checks), since `useMediaReceive`
     was stubbed and its call args never inspected — didn't actually prove the *right*
     key material survived the round trip, only that *some* media object did. Fixed:
     added `expect(useMediaReceive).toHaveBeenCalledWith(expect.objectContaining(media))`.
  3. *(informational, fixed cheaply)* `putMessage`'s redelivery-merge preserve-list
     doesn't carry over `mediaJson` (same as `replyToJson`) — benign since both are
     set-once-at-creation fields, a replayed `persistIncoming` for the same id carries
     the identical value in the fresh row anyway. Added a one-line comment explaining
     the omission is intentional, not an oversight.
  4. *(informational, not fixed)* one harmless redundant-narrowing nit in
     `sendForwardToSelected` (`targetChat.mlsGroupId` re-read into a local before a
     truthiness check inside a `.then` closure) — left as-is, TS's control-flow analysis
     doesn't retain narrowing on an object property across a closure boundary, so it may
     not actually be redundant.
- 1 new test file (`ChatLayoutMediaPersistence.test.tsx`: incoming-media rehydration +
  redisplay, corrupt-JSON safety, shape-invalid safety, outgoing-placeholder-only case)
  plus new/updated tests in `db/schema.test.ts`, `db/encrypted-db.test.ts`,
  `hooks/usePersistentMessages.test.ts`, `hooks/useMediaSend.test.ts`,
  `lib/mediaTransfer.test.ts`. **Frontend: 105/105 files, 1498/1498 tests green** (was
  104/1479). `tsc -b` clean, `biome check` clean (1 import-sort auto-fix applied
  post-review, no logic change). Production build: initial route 165.70 kB gzip / WASM
  642.87 kB gzip (both under prd.md §7 budgets).
- Not architectural, no new server-visible metadata (purely local Dexie persistence of
  data already flowing through existing send/receive paths, confirmed via `git diff
  --stat` — no MLS/OPAQUE/wire-format changes) — `threat-model-checker`/`crypto-reviewer`
  not required, same scoping precedent as `pollJson`/`replyToJson`/`scheduledFor`.
- **Next cycle candidates:** closing the incoming/outgoing media-key asymmetry (would
  need a new crypto-reviewed WASM key-export-for-local-storage primitive — bigger,
  crypto-adjacent, worth its own cycle if ever prioritized); the harmless redundant-
  narrowing nit in `sendForwardToSelected` (cheap, non-blocking); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`, openmls still pinned at 0.8.1 —
  re-checked this cycle); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B
  95%-session threshold).

## Previous state (2026-08-24, cycle 348 — FEATURE: mlsDecrypt cost bound + CI permissions hardening, commits a3eeee8 + 8db1748)

- CI green, `gh issue list --state open` empty at cycle start. Picked up both of cycle
  347's flagged candidates in one cycle: the CI `permissions:` hardening (cheap) and the
  security-auditor F4 unconditional-`mlsDecrypt`-cost gap (the main feature work).
- **CI hardening (a3eeee8):** `ci-frontend.yml`/`ci-rust.yml`/`ci-e2e-live.yml` had no
  top-level or job-level `permissions:` block, so `GITHUB_TOKEN` inherited repo-default
  scope. Added explicit `contents: read` to all three — none of the jobs need more.
- **mlsDecrypt cost bound (8db1748):** every Application envelope for the active group
  unconditionally paid a real `mlsDecrypt` WASM round trip before type dispatch,
  including garbage/tampered ciphertext that would fail to decrypt — the cycle 346
  reaction-rate-limiter only bounds envelopes that decrypt successfully and parse as a
  reaction, so a flooding sender still cost N decrypt attempts regardless. Added a
  coarser per-sender decrypt-attempt budget (100/10s) gating the `mlsDecrypt` call
  itself, layered on top of the existing reaction limiter.
- **security-auditor caught a silent-data-loss bug in the first draft:** dropping
  over-budget envelopes outright would have silently swallowed real text messages behind
  a burst of unrelated traffic (e.g. ~100 presence heartbeats over ~50 minutes with one
  chat left open), since the server's `find_pending` query has no redelivery path other
  than an explicit ack. Fixed: over-budget envelopes are deferred into a bounded local
  queue (500 cap) instead, retried on later poll ticks and merged/deduped by id once the
  sender's window frees up — no data loss, only latency. Also corrected a pre-existing
  inaccurate comment claiming un-acked envelopes are GC'd via server-side TTL (only
  disappearing-message `expires_at` triggers that; otherwise they're redelivered
  indefinitely on a later since-eligible poll).
- Not architectural, no new server-visible metadata (client-side receiver-side
  throttling only, no wire-format change) — `threat-model-checker`/`crypto-reviewer` not
  required, same scoping precedent as the cycle 346 reaction-rate-limit fix.
- **Next cycle candidates carried forward:** the media-message-has-zero-Dexie-
  persistence gap (large, flagged cycle 343 — picked up and closed this cycle, see
  cycle 349 above); PQ hybrid Phase A (still blocked); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 347 — FEATURE: real-browser Dexie.waitFor transaction-liveness test (F3), commit 2eb8ccf)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 346's top carried-forward candidate:
  **F3** — the `Dexie.waitFor`-held `rw` transaction in `markMessageReactionDelta`
  (encrypted-db.ts; async crypto-worker round trip *inside* an IndexedDB transaction) had
  only ever been exercised against `fake-indexeddb` in Vitest, never a real browser
  engine. First flagged cycle 344, deferred 3 cycles running (345, 346).
- **Fix:** new `app/e2e/dexie-transaction-liveness.spec.ts`. Navigates to `/`, then via
  `page.evaluate` dynamically imports `/src/db/encrypted-db.ts`/`/src/db/schema.ts`
  directly from the Vite dev server (no bundling — dev-server-only technique, confirmed
  by security-auditor to have zero prod exposure: prod build emits hashed bundles with
  no `/src/*.ts` route, and the spec lives outside `tsconfig.app.json`'s `include`).
  Constructs a real `PowehiDb` + `EncryptedPowehiDb`, injects a fake `FieldEncryptor`
  (duck-typed against the existing port in encryption.ts) whose `encryptDbField`/
  `decryptDbField` use a real `setTimeout`-based 40ms delay — a genuine macrotask, unlike
  an instantly-resolved Promise — standing in for the crypto-worker's postMessage round
  trip. Fires two concurrent `markMessageReactionDelta` calls from different senders and
  asserts both merge (no clobber, no rejected promise) — same race
  `encrypted-db.test.ts`'s existing fake-indexeddb test covers, but here against a real
  engine's actual IndexedDB transaction-lifetime behavior.
- Added a second Playwright project `webkit-dexie-liveness` (`devices["Desktop Safari"]`)
  in `playwright.config.ts`, scoped via `testMatch` to just this one spec so the rest of
  the suite doesn't pay a second real-browser run per spec; the pre-existing `chromium`
  project still runs it too (plus every other spec, unchanged). `ci-frontend.yml`'s
  `playwright` job now installs both `chromium` and `webkit` browsers (`--with-deps`).
  Installed webkit locally (`pnpm exec playwright install webkit --with-deps`, 76.7 MiB)
  to actually run and verify the test before committing — was not previously present in
  this dev environment (only chromium was, matching what CI installed pre-diff).
- **security-auditor: GREEN**, both informational notes fixed in-cycle (not blocking, but
  cheap):
  1. The reviewer **mutation-tested the test itself** — temporarily removed both
     `Dexie.waitFor` wrappers from `markMessageReactionDelta`, confirmed the spec fails
     with `TransactionInactiveError: Transaction has already completed or failed` on
     *both* chromium and webkit, restored the file via `git checkout`, confirmed all 9
     `Dexie.waitFor` call sites intact. **Not vacuous — catches the exact regression it
     claims to guard**, and notably this proved chromium's real engine *also* reproduces
     the failure, not just webkit.
  2. *(fixed)* the test's `indexedDB.deleteDatabase("PowehiDb")` cleanup resolved on the
     `onblocked` event instead of rejecting — safe today (traced every production
     `new EncryptedPowehiDb(...)` call site, all are post-login, so `page.goto("/")`
     never opens the DB pre-test) but a latent flake if the app ever gains a pre-login
     IndexedDB read, since `schema.ts`'s module-level `db` singleton is the same module
     record the test's dynamic import resolves to. Fixed: `onblocked` now rejects with an
     explicit error instead of silently continuing against potentially-stale state.
  3. *(fixed, doc-only)* both the spec's top comment and the new Playwright project's
     comment overclaimed "WebKit is the historically stricter engine... only a real
     browser can exercise this" as if webkit were required to catch the regression — the
     reviewer's own mutation test (finding 1) showed chromium already catches it too.
     Corrected both comments: webkit is engine-diversity insurance against future
     divergence, not load-bearing for closing F3.
  Also confirmed: no plaintext/key-material/PII leakage (fake encryptor's in-memory Map
  holds only synthetic fixture data, dies with the browser context, never reaches
  traces/screenshots — `ci-frontend.yml`'s `playwright` job has no `upload-artifact` step
  regardless); no supply-chain concern from installing the webkit binary (same pinned
  `@playwright/test` version, same Microsoft CDN chromium already uses, lockfile
  unchanged); `deleteDatabase` can't reach real user data (ephemeral Playwright browser
  profile, storage-partitioned from any developer's real browser profile even when
  attached to a locally-running dev server).
- One pre-existing, unrelated observation the reviewer flagged in passing (not fixed,
  not in scope): `ci-frontend.yml` has no top-level or job-level `permissions:` block, so
  `GITHUB_TOKEN` inherits repo-default permissions — cheap hardening win, worth doing
  next time that file is touched for an unrelated reason.
- Not architectural, no new server-visible metadata (test-only + CI browser-install
  change, no production crypto/backend/MLS/OPAQUE code touched — confirmed via
  `git diff --stat`: only the new spec file, `playwright.config.ts`, and
  `ci-frontend.yml` changed) — `threat-model-checker`/`crypto-reviewer` not required;
  ran `security-auditor` anyway since the diff touches CI infra and exercises the Dexie
  encryption boundary via a new test harness.
- **Frontend: 1473/1473 Vitest tests green** (unchanged — this cycle added no new Vitest
  tests, only a new Playwright spec). **Playwright: 7/7 e2e tests green** (was 5 across 2
  projects — `chromium` only; now 7 across `chromium` + the new `webkit-dexie-liveness`
  project, +1 spec × 2 projects − 0, i.e. +2 total test executions net). `tsc -b` clean,
  `biome check` clean (2 touched files). Production build/bundle budget: not re-checked
  this cycle (no app/src/ production code touched, only e2e/ + config + CI workflow).
- **Next cycle candidates:** the unconditional `mlsDecrypt`-cost gap (cycle 346's
  security-auditor F4 — a flooding sender still forces N decrypt round trips regardless
  of the reaction-callback rate limit; broader mitigation than the lock-contention fix
  already landed, not yet scoped); the media-message-has-zero-Dexie-persistence gap
  (flagged cycle 343, large, needs new schema + threading through send/receive paths,
  worth scoping as its own multi-part effort); the `ci-frontend.yml` missing
  `permissions:` block (flagged this cycle, cheap, low urgency); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 346 — FEATURE: bound reaction/reaction_remove callback rate per sender, commit f86d6e5)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty, `git status`
  clean at cycle start. Picked up cycle 345's top carried-forward candidate: **F1/F7** — no
  inbound rate limit on reaction/reaction_remove envelopes, so a single flooding sender
  (compromised device, or a peer replaying a batch) could force `markMessageReactionDelta`'s
  exclusive Dexie transaction lock (held across 2 sequential crypto-worker round trips) to be
  acquired at unbounded rate, head-of-line-blocking `persistIncoming`'s `putMessage` on the same
  origin. First flagged cycle 344, deferred twice.
- **Fix:** `useMessages.ts` gained a per-sender sliding-window rate limiter — `reactionTimestampsRef`
  (a `Map<string, number[]>`) tracks up to `REACTION_RATE_MAX = 20` timestamps per `senderId`
  within a `REACTION_RATE_WINDOW_MS = 10_000` window. `withinReactionRateLimit(senderId)` is added
  as the last condition (after the existing emoji-allowlist/length checks, so a malformed envelope
  never burns real budget) gating whether `onReactionRef`/`onReactionRemoveRef` fire. Both envelope
  types share ONE budget per sender since both hit the identical costly lock path. Over-budget
  envelopes are still acked (no redelivery loop) — the callback drop is a real, permanent loss for
  that receiver past the ceiling, not a deferral; documented explicitly as an accepted DoS-bound
  tradeoff (≤2 lock acquisitions/sec/sender), not equated with the nearby malformed-envelope
  discard cases. `env.sender` is server-attested (from `Envelope.sender`, never client-supplied in
  the decrypted payload), so the rate-limit key isn't spoofable from the wire.
- **security-auditor: YELLOW, both findings fixed in-cycle:**
  1. *(fixed)* `reactionTimestampsRef` lives for the hook's whole mount (one `useMessages`
     instance per logged-in session — `groupId` just changes which chat it polls), so every
     distinct sender ever seen across every group opened in the tab would linger in the map
     forever, unbounded by current group membership. Fixed: added `sweepStaleReactionRateEntries()`,
     run once per `poll()` tick (not per envelope), deleting any map entry whose timestamps have
     all aged out of the window — bounds the map to currently-active senders.
  2. *(fixed, doc-only)* the original comment justified the callback-drop-but-still-ack behavior by
     analogy to malformed-envelope discarding, which overclaimed equivalence — a legitimate
     tail-of-burst reaction (e.g. rapid-fire reacting during an active group chat) is *valid*
     content lost purely for receiver-side resource protection, with no error/feedback to the
     sender. Rewrote the comment to state this as a deliberate, accepted tradeoff, and to scope
     precisely what's protected: only the exclusive-lock-acquisition rate — NOT the unconditional
     `mlsDecrypt` every Application envelope pays before type dispatch (a flood still costs this
     client N decrypt round trips), and nothing server-side (queue growth/bandwidth unaffected).
  Also requested (point 5 of the review) and added: a test proving a burst of malformed
  (invalid-emoji) reactions does NOT consume the sender's real budget, since the rate-limit check
  is last in the validity `&&` chain — confirms the ordering the reviewer specifically asked about.
- 4 new tests in `useMessages.test.ts`: burst-of-25-caps-at-20 (still acks all 25), per-sender
  isolation (one sender's flood doesn't throttle another sender in the same batch), shared budget
  across reaction/reaction_remove for the same sender (via `vi.useFakeTimers`/`advanceTimersByTimeAsync`
  since the second envelope needs a real poll-interval tick), window-reset after 10s elapses (same
  fake-timer technique), and the malformed-envelope-doesn't-consume-budget test added post-review.
  **Frontend: 1473/1473 tests green** (was 1472, 104 files unchanged — net +5 across the review
  round: +4 initial, +1 for the review's requested test, then 1 initial test's assertion was
  corrected from a bad standalone-budget assumption to the right shared-budget-of-21 total before
  landing). `tsc -b` clean, `biome check` clean (1 formatting auto-fix applied post-review, no
  logic change). Production build: initial route 165.28 kB gzip / WASM 642.87 kB gzip (both under
  prd.md §7 budgets).
- Not architectural, no new server-visible metadata (pure client-side receiver-side throttle on an
  existing envelope type, no wire-format or server-endpoint change) — `threat-model-checker`/
  `crypto-reviewer` not required; consistent with how the identical-class `readByJson`/`putMessage`
  merge fixes (cycles 322/345) and the original reaction-delta-merge fix (cycle 344, which is where
  F1/F7 were first raised) were scoped.
- **Next cycle candidates:** F3 from cycle 344 (Playwright test for real-browser `Dexie.waitFor`
  transaction liveness — WebKit is the historical risk case, still not done); the general
  unconditional-`mlsDecrypt`-cost gap surfaced by this cycle's security-auditor F4 (a flooding
  sender still forces N decrypt round trips regardless of the reaction-callback rate limit — this
  cycle deliberately scoped to the lock-contention vector only, decrypt-cost bounding would be a
  separate, broader mitigation if ever prioritized); the media-message-has-zero-Dexie-persistence
  gap (flagged cycle 343, large, needs new schema + threading through send/receive paths, worth
  scoping as its own multi-part effort); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); the missing `~/.cargo/bin` on `$PATH` noted cycle 345 (worked around inline both
  times it's come up, may be worth a cron-env fix if it recurs a third time — this cycle was
  frontend-only, didn't touch cargo, so not re-verified).

## Previous state (2026-08-23, cycle 345 — STABILIZATION: close putMessage full-row-overwrite gap (F4), commit cb65117)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty, `git status`
  clean at cycle start. Full sweep before picking work: `cargo audit` (652 crates, 0 advisories),
  `cargo deny check` (advisories/bans/licenses/sources all ok), `cargo test --workspace` all green,
  `cargo clippy --workspace --all-targets -- -D warnings` clean, frontend `pnpm test --run`
  1465/1465 green (104 files) pre-cycle, `tsc -b`/`biome check` clean. `target/` 11G, well under
  the 20G hygiene threshold — no pruning needed. `project-context.md` 132KB/1646 lines, under the
  256KB Read cap — no archive needed this cycle. Note: `cargo`/`cargo-audit`/`cargo-deny` were not
  on `$PATH` this session (`~/.cargo/bin` missing from the shell's PATH) — had to `export
  PATH="$HOME/.cargo/bin:$PATH"` explicitly for every cargo invocation this cycle; if this recurs,
  worth checking whether the cron job's shell profile sourcing regressed.
- Picked cycle 344's top carried-forward candidate: **F4**, the `putMessage` full-row-overwrite
  gap — `EncryptedPowehiDb.putMessage` (encrypted-db.ts) did a blind `.put()` with no merge, and
  its 4 call sites (`persistIncoming`/`persistOutgoing`/`persistPollCreate`/
  `persistScheduledCreate` in usePersistentMessages.ts) build fresh `MessageRow` object literals
  with no dedup against an existing row. Dispatched an Explore-agent first to confirm reachability
  before spending a cycle on it (it had been deferred 2+ cycles as "pre-existing, out of scope"):
  confirmed **live, not stale** — `useMessages.ts`'s `onMessageRef.current(...)` (→
  `persistIncoming`) fires before the fire-and-forget `ackMessage(...).catch(() => {})` DELETE; a
  transient ack failure (network blip/5xx/tab-close-mid-request) leaves the envelope un-deleted
  server-side, and the client's redelivery guard (`sinceRef`) is a plain `useRef` that resets on
  reload — so **ack failure + reload while the envelope is still server-side ⇒ the same envelope
  id gets redelivered and replayed through `persistIncoming`**, wiping whatever
  reactions/read-receipts/starred/poll-votes/expiresAt had accumulated on that row since.
- **Fix:** `putMessage` now runs the `get` + merge + `put` inside one Dexie `rw` transaction —
  if an existing row is found, the fresh row's core fields (ciphertext/plaintext/sender/epoch/etc,
  via the existing `encRow` helper) are kept, but `reactionsJson`/`readByJson`/`read`/`delivered`/
  `starred`/`editedText`/`deletedAt`/`scheduledFor`/`expiresAt`/`pollJson` are carried over
  verbatim from the existing row instead of being overwritten to `undefined`. `encRow` (the
  multi-field crypto-worker round trip) now runs *before* the transaction opens, so the `rw` lock
  only spans a synchronous get+put — no `Dexie.waitFor` needed here (unlike
  `markMessageReactionDelta`/`markMessageRead`, which must decrypt-merge-reencrypt a single field
  *inside* the transaction; `putMessage` doesn't need to inspect the existing SENSITIVE values,
  only copy their already-ciphertext bytes across).
- **security-auditor: YELLOW, all 4 findings fixed in-cycle:**
  1. *(MEDIUM, fixed)* `expiresAt` wasn't in the original preserve-list — `persistIncoming`
     recomputes `expiresAt = Date.now() + ttl*1000` at receive time, so a redelivery would have
     silently *restarted* a disappearing message's TTL from a later "now" instead of preserving
     the original expiry. Added to the preserve-list.
  2. *(MEDIUM, fixed)* `pollJson` wasn't preserved either — structurally identical to
     `reactionsJson` (locally mutated post-creation by `markMessagePoll`/`persistPollVote`), so a
     replayed `putMessage` on a poll id would wipe accumulated votes. Added to the preserve-list.
  3. *(LOW, fixed)* the first draft's regression test used an identical replay (same
     ciphertext/plaintext/epoch/receivedAt on both writes) — an implementation that just
     early-returned on `existing` found would've passed vacuously. Strengthened: the replay now
     varies `ciphertextB64`/`expiresAt` and asserts the FRESH `ciphertextB64` wins while the
     ORIGINAL `expiresAt` is preserved — proves both halves of the merge, not just one. Also
     expanded coverage to `delivered`/`editedText`/`deletedAt` (previously untested) and added a
     dedicated `pollJson`-preservation test.
  4. *(LOW, fixed, robustness)* the first draft ran `encRow` *inside* the transaction via
     `Dexie.waitFor`, holding the `rw` lock across N sequential crypto-worker round trips
     (serializes all other message writes behind it, risks Dexie's transaction-timeout abort on a
     slow worker). Moved `encRow` before `db.transaction(...)` opens — the lock now spans only the
     synchronous get+put, matching the pattern `claimScheduledFire` already argues for.
  Also updated `markMessageReactionDelta`'s doc comment, which had explicitly called out this
  exact gap as "pre-existing, out of scope here" — now points at the fix instead of re-flagging a
  closed issue in a future cycle.
- 3 new/strengthened tests in `encrypted-db.test.ts`: the redelivery-merge test (rewritten, now
  non-vacuous, covers 8 preserved fields + 1 fresh-field-wins assertion), a new poll-redelivery
  test, plus the pre-existing "no existing row → plain create" test (unchanged). **Frontend:
  1468/1468 tests green** (was 1465, 104 files unchanged). `tsc -b` clean, `biome check` clean (2
  touched files). Production build: initial route 165.14 kB gzip / WASM 642.87 kB gzip (both under
  prd.md §7 budgets).
- Not architectural, no new server-visible metadata (purely local Dexie merge logic, confirmed via
  `git diff --name-only` — only `app/src/db/encrypted-db.ts`/`.test.ts` touched, no MLS/OPAQUE/
  crypto-library code) — `threat-model-checker`/`crypto-reviewer` not required, same scoping
  precedent as the identical-class `persistReaction`/`persistRead` race fixes (cycles 322/344).
- **Next cycle candidates:** F1/F7 from cycle 344 (peer-driven reaction lock-hold amplification —
  no inbound rate limit on reactions specifically, worth a look if volume ever becomes a real
  concern); F3 from cycle 344 (Playwright test for real-browser `Dexie.waitFor` transaction
  liveness — WebKit is the historical risk case); the media-message-has-zero-Dexie-persistence gap
  (flagged cycle 343, large, needs new schema + threading through send/receive paths, worth
  scoping as its own multi-part effort); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); the missing `~/.cargo/bin` on `$PATH` this session (worked around inline, may be
  worth a cron-env fix if it recurs).

## Previous state (2026-08-23, cycle 344 — FEATURE: close concurrent-reaction persistence race, commit 2b86969)

- All phase 1-6 checklists were already complete going into this cycle; CI green
  (`gh run list --limit 3` all success), `gh issue list --state open` empty. Picked
  up the standing "next cycle candidate" note from cycle 320-343's log: `persistReaction`
  still had the same full-replace-overwrite race that `persistRead`'s `readBy` had
  before cycle 322's fix (concurrent reactions to the same message from different
  devices, each computed from a possibly-stale in-memory snapshot, could have the
  later Dexie write clobber the earlier one's entry).
- Replaced `EncryptedPowehiDb.markMessageReactions(id, reactionsJson)` (full-replace)
  with `markMessageReactionDelta(id, emoji, senderId, action: "add"|"remove")` —
  reads the persisted (encrypted) reaction map, decrypts, merges the single delta,
  re-encrypts, writes back, all inside one Dexie `rw` transaction. Unlike
  `markMessageRead`'s readByJson (unencrypted field, synchronous merge), reactionsJson
  is a SENSITIVE encrypted-at-rest field, so the merge needs two async crypto-worker
  round trips inside the transaction — used `Dexie.waitFor(...)` (documented Dexie API
  for exactly this: keep an IDB transaction alive across a non-Dexie await instead of
  letting it auto-commit early) around both the decrypt and the encrypt calls.
- `usePersistentMessages.ts`'s `persistReaction` signature changed from
  `(targetMessageId, reactions: Record<string,string[]>)` to
  `(targetMessageId, emoji, senderId, action)` — call sites in `ChatLayout.tsx`
  (`handleIncomingReaction`/`handleRemoveReaction`) already computed exactly these
  primitives before building the old full map, so the call sites got simpler, not
  more complex. Optimistic `rows` update recomputes the merge from each row's latest
  functional-update snapshot.
- **security-auditor: YELLOW** (not FAIL — reviewed via Task before commit since this
  touches the Dexie encryption boundary). PASS on all 4 explicitly-asked questions: no
  plaintext/sender-id leakage into logs or thrown errors; `Dexie.waitFor` fails closed
  (rejection/60s-timeout aborts the transaction, no partial/half-merged write can
  land); the race is genuinely closed for reaction-vs-reaction (IDB serializes
  overlapping-scope rw transactions); no auth/authz regression (senderId is still
  `env.sender`, the server-attested device id — a malicious peer still can't forge
  another device's reaction, and can now only ever filter its OWN id out on remove).
  Findings applied this cycle: (F6) bounded reaction `targetMessageId` to `<=36` chars
  in `useMessages.ts` (matches `read_receipt`'s existing bound; auditor's own
  suggested cheapest mitigation for the lock-hold concern below) — done; (F8) fixed
  two stale doc-comment references to the removed `markMessageReactions` name, and
  clarified `markMessageReactionDelta`'s doc comment to not overclaim that the merge
  guarantee extends to `putMessage`'s full-row overwrite path — done. Deferred to a
  future cycle (pre-existing or narrow-impact, not regressions from this diff): (F1)
  the transaction now holds an exclusive lock across TWO crypto round trips on a
  peer-driven (reaction-rate) hot path, with no inbound rate limit today — could
  head-of-line-block `persistIncoming`'s `putMessage` under a reaction burst; (F2)
  optimistic `rows`/`chats` state isn't rolled back if the Dexie transaction aborts
  (self-heals on reload, no capability granted); (F3) the new concurrent-merge test
  runs against `fake-indexeddb`, not a real-browser transaction-liveness check
  (WebKit is the historical risk case for `waitFor`-held transactions) — a Playwright
  assertion would close this; (F4) `putMessage` (full-row upsert, encryption outside
  any transaction) can still wipe `reactionsJson`/`readByJson`/etc. on a duplicate/
  replayed `persistIncoming` for an id that already has reactions — pre-existing,
  same class noted for `readByJson` previously, doc-comment overclaim now fixed but
  the underlying gap remains; (F5) `pendingWriteIds` is a Set not a refcount, so two
  concurrent same-id reaction writes can have the first's `.finally` clear the guard
  while the second is still in flight (pre-existing shape, now more reachable since
  concurrent same-id writes are the scenario this fix targets); (F7) reaction senders
  array has no cardinality bound (pre-existing, cost of the bound now paid inside the
  exclusive lock too — compounds F1 under a compromised-server device-id-minting
  scenario).
- Not architectural, no new server-visible metadata (pure local persistence/merge
  logic for reactions that were already being received over the wire) —
  `threat-model-checker`/`crypto-reviewer` not required, consistent with how the
  identical `persistRead` fix (cycle 322) and the edit/delete/reaction persistence
  work (cycles 252-254) were scoped.
- `tsc -b` clean, `biome check` clean. Frontend `pnpm test --run`: **1465/1465 tests
  green** (104 files) — one `ChatLayoutPoll.test.tsx` failure appeared under one
  full-suite run (`poll.options[0].voters` assertion) but passed both standalone and
  on a second full-suite rerun; pre-existing test-isolation flake under parallel
  load, unrelated to this change (poll code untouched), not investigated further this
  cycle. Test counts: `encrypted-db.test.ts` net +3 (2 new delta-merge/no-op tests
  replacing the 2 old full-replace tests, +1 net), `usePersistentMessages.test.ts` net
  +1 (split one full-map test into an add+merge test and a separate remove test),
  `ChatLayout.test.tsx` unchanged count (existing reaction-persistence tests updated
  to assert the new delta call signature instead of the old full-map argument).
- **Next cycle candidates:** F1/F7 above (peer-driven lock-hold amplification — worth
  a look if reaction volume ever becomes a real concern, currently no inbound
  rate limit on reactions specifically); F3 (Playwright test for real-browser
  `Dexie.waitFor` transaction liveness); F4 (the pre-existing `putMessage`
  full-row-overwrite gap — same class as previously-deferred `readByJson` concern,
  now explicitly documented rather than newly discovered); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold); opaque-ke live-migration
  login-round-trip regression test gap (cycle 318/319, no prod users yet, low
  urgency).

## Previous state (2026-08-23, cycle 343 — FEATURE: persist sender's own copy of forwarded text messages, commit 3fab286)

- CI green (`gh run list --limit 3`), `gh issue list --state open` empty, `git status` clean at
  cycle start. Cycle-340's "next cycle candidates" note claiming "pins/mentions remain
  session-only" was **stale/wrong** — verified via a fresh Explore-agent survey that both
  `GroupRow.pinnedMessageId` (v9) and `GroupRow.mentionCount` (v13) are already fully persisted
  and wired; corrected here so it isn't repeated. Continued searching (Draft — already persisted
  v17; pin/mention — already persisted) and found via direct grep of `persistOutgoing` call
  sites: **only 2 exist in the whole file** (plain `sendMessage`, and cycle-342's `fireScheduled`)
  — `sendForwardToOne` (text-forward path, used by both the single-target and multi-select
  forward-modal flows) never called it at all.
- **What it does:** forwarding a text message to another chat appended an optimistic "me" bubble
  and sent it over MLS, but never persisted the sender's own copy to Dexie — reload silently
  dropped it from the sender's own history (recipient's `persistIncoming` was already correct and
  unaffected). Fixed by chaining `persistOutgoing(envelopeId, mlsGroupId, text,
  uint8ToBase64(ciphertext))` after `sendMessageApi` resolves inside `sendForwardToOne`
  (ChatLayout.tsx). Uses the existing `persistOutgoing` helper — no schema change needed.
  `persistOutgoing` writes to Dexie keyed by its own `groupId` param, not the hook's bound active
  group, so writing under the *target* chat's group (which may differ from the active chat) is
  Dexie-safe — same precedent already documented on cycle-342's `fireScheduled` call.
- **Found and deliberately did NOT fix in this cycle (too large, separate gap):** grepped the
  whole `MessageRow` schema and found **no media field exists at all** — `persistIncoming` only
  ever stores `msg.text` (which is the literal string `"[image]"` for a media message, per
  `IncomingMessage`'s own doc comment), never `msg.media` (blobId/key/iv/thumbnail). This means
  **every media message (photo/video/voice note), sent OR received, has zero Dexie persistence
  for redisplay after reload** — a pre-existing, much bigger architectural gap than any single
  persistence cycle has tackled so far (would need a new encrypted `mediaJson` field, threading
  through `useMediaSend`/`encryptAndSendMedia`/`persistIncoming`, chunked-video handling,
  thumbnail bytes, rehydration UI). Left `sendForwardToSelected`'s media-forward path (which
  calls `encryptAndSendMedia` directly, no persistence hook at all) untouched to avoid an
  inconsistent half-fix — documented inline as a known limitation. **Flagging as the standing
  large-scope candidate for a future cycle or a dedicated multi-cycle push**, not attempted here.
- **crypto-reviewer: YELLOW, both findings fixed in-cycle:**
  1. **Fixed (doc-only):** added a RETENTION NOTE doc comment on `sendForwardToOne` — forwards
     have never carried the target chat's `disappearingTtl` on the wire (pre-existing,
     `sendMessageApi` called with `ttlSeconds: undefined` and a raw non-JSON payload, unlike
     `sendMessage`'s `{type:"text",text,ttl}` shape) — this diff widens that gap from "peer keeps
     it forever" to "sender AND peer keep it forever" (since nothing was persisted pre-diff, there
     was nothing to leave un-purged). Documented as an accepted widening of a known gap, not a new
     class; not fixed (would need the JSON payload shape, bigger scope than this persistence fix).
  2. **Fixed (test):** the reviewer mutation-tested the positive test and found it didn't pin the
     actual ciphertext — a bug that persisted the *source* message's ciphertext under the *target*
     group would have still passed. Strengthened: asserts `row.ciphertextB64 === "3q0="` (the
     mocked `mlsEncrypt`'s fixed `[0xde,0xad]` output) and `!== "Zg=="` (source ciphertext), plus
     `expiresAt`/`replyToJson` both `undefined`.
  3. Non-blocking note left as-is (informational, matches existing `sendMessage` error-handling
     shape): a synchronous throw inside `persistOutgoing` would be swallowed by the outer
     `.catch(() => {})` — acceptable, `putMessage` rejections already route through the opaque
     `writeErrorCount` counter.
- 2 new tests in `ChatLayoutForwarding.test.tsx`: positive (forwards a text message, asserts the
  Dexie row lands under the target group with the correct ciphertext/plaintext/sender, no
  expiresAt/replyTo) and negative (send rejects → `db.messages` for the target group stays empty,
  mutation-tested to confirm it's not vacuous). **Frontend: 1462/1462 tests green** (was 1460,
  104 files unchanged). `tsc -b` clean, `biome check` clean (2 touched files). Production build:
  initial route 164.81 kB gzip / WASM 642.87 kB gzip (both under prd.md §7 budgets).
- Not architectural, no new server-visible metadata (server-visible bytes are byte-identical to
  pre-diff — this only adds a local-only Dexie write) — `threat-model-checker` not required.
  Backend untouched (confirmed via `git diff --name-only`) — `security-auditor` not required
  either (crypto-reviewer's scope covers this diff fully, same class as cycle 342's scheduled-
  send fix).
- `gh issue list --state open` — empty at cycle start. Target dir hygiene: not checked (FEATURE
  mode, backend untouched).
- **Next cycle candidates:** the media-message-has-zero-Dexie-persistence gap surfaced this cycle
  (large, would need new schema + threading through both send and receive paths — worth scoping
  as its own multi-part effort rather than a single cycle); media forwards still unpersisted
  (same root cause, fixed together with the above); the general cross-tab cloned-MLS-sender-
  ratchet property (flagged cycle 342, still not scoped for a single cycle); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-23, cycle 342 — FEATURE: scheduled messages now actually send over MLS when they fire, commit 636996c)

- Cycle 341 apparently ran but never committed (`git status` at cycle start showed a complete,
  uncommitted working-tree diff across ChatLayout.tsx/encrypted-db.ts/usePersistentMessages.ts +
  tests, plus a stray debug scratch file `ZZDebugClaim.test.ts` with console.logs — same
  "cycle silently fails to commit" pattern as cycles 324/326/330/332). Per CLAUDE.md's
  investigate-before-discarding guidance, validated and landed it (like cycle 332) rather than
  redoing from scratch: deleted the scratch debug file, then built on the real diff.
- **What it does:** closes the long-standing gap (flagged since cycles 339/340) that a fired
  scheduled ("send later") message never actually transmitted over MLS — it only cleared the
  local `scheduledFor` flag. `EncryptedPowehiDb.claimScheduledFire(id)` (encrypted-db.ts) reads
  and deletes a scheduled row inside ONE Dexie `readwrite` transaction, gated on `scheduledFor`
  still being set — IndexedDB serializes same-store rw transactions, so this is an atomic claim:
  at most one caller (this tab's overlapping sweep ticks, or another same-origin tab) ever gets
  a defined row back. `ChatLayout.tsx`'s `fireScheduled` sweep (10s interval) now: claims →
  `mlsEncrypt` → `sendMessageApi` → `persistOutgoing`, the same pipeline `sendMessage` itself
  uses, instead of the old "just flip scheduledFor in memory" no-op.
- **crypto-reviewer: 2 rounds, both required since this diff calls `mlsEncrypt` directly.**
  Round 1 verdict **needs-rework**, 6 required changes (the atomic-claim pattern itself was
  GREEN from round 1 — it does correctly prevent double-encrypting the same scheduled message):
  1. **Fixed:** added a fail-closed `if (claimed.groupId !== item.groupId) continue;` before
     encrypting — nothing previously verified the claimed row's groupId matched the chat it was
     scanned from before encrypting under that chat's key material.
  2. **Fixed:** an already-expired-by-fire-time message (elapsed `expiresAt`) now `continue`s
     (drops, matching purge semantics) instead of `Math.max(1, ...)`-clamping to a 1-second TTL
     and sending already-past-retention content.
  3. **Fixed:** the empty `catch` after a failed send previously justified "no retry" with an
     incorrect claim ("would reopen a narrower version of the same TOCTOU race") — corrected to
     state the true reason (RFC 9420 §6.3: re-encrypting the already-claimed plaintext would be
     safe, since each `mlsEncrypt` call advances the sender ratchet; simply not implemented,
     matching `sendMessage`'s own no-retry-UI scope, not a safety requirement).
  4. **Fixed (doc-only):** the claim's doc comments (encrypted-db.ts + ChatLayout.tsx +
     usePersistentMessages.ts) overclaimed that this closes the general cross-tab
     cloned-MLS-sender-ratchet problem and called a generation collision "catastrophic" AEAD
     reuse. Corrected: the claim only closes *this-message* double-firing (scheduled rows are
     local-only pre-fire, so there's no separate device to race); the general cloned-ratchet
     property is pre-existing across every send path in this app (typing/presence/sendMessage),
     unresolved by this change; cited RFC 9420 §6.3.2's per-message `reuse_guard` (a bare
     generation collision isn't automatically nonce reuse).
  5. **Fixed (doc-only):** the TTL-bucket-rounding comment (server-visible retention arg snapped
     UP to nearest `TTL_OPTIONS` member instead of sent exactly) overclaimed it eliminates the
     "this was a scheduled send" fingerprint — corrected to "narrows, does not eliminate" and
     enumerated the residual peer-visible signal (exact `ttl` inside the MLS-encrypted payload,
     no preceding typing/presence traffic, no MLS `padding_size` on this path) as an accepted,
     documented gap.
  6. **Fixed:** `ChatLayoutScheduleSend.test.tsx`'s cross-tab-cancel-race test asserted
     `MOCK_WORKER.mlsEncrypt.mock.calls` never contained the cancelled text — but the real
     `fireScheduled` zeroes its plaintext buffer (`plaintext.fill(0)`) in a `finally` right after
     `mlsEncrypt` resolves, so that assertion was reading an already-zeroed buffer and would
     pass vacuously even if the guard it was testing regressed. Fixed: the mock now pushes a
     manual `new Uint8Array(plaintext)` copy into a module-level `capturedPlaintexts` array
     before returning; the test asserts against that copy instead.
  Round 2 (fresh agent, verifying the fix diff): **GREEN**, all 6 confirmed fixed, plus 2 small
  non-blocking residuals flagged and fixed in the same cycle anyway (cheap): (a) the sweep
  processes claimed items serially, each a full encrypt+network round trip, so reusing the
  sweep's single `now` for later items in the same tick could be stale — now re-reads
  `Date.now()` immediately after each claim; (b) `Math.round` on a sub-second remaining TTL could
  floor to `0` (falsy), silently downgrading a near-expiry disappearing message to a permanent
  one — restored a `Math.max(1, ...)` floor, safe now that the already-expired case is a
  `continue` guard *before* this floor (round 1's fix #2), not the same clamp that caused it.
- Not architectural, no new server-visible metadata (same TTL-rounding/envelope shape every
  other disappearing send already uses) — `threat-model-checker` not required. Backend untouched
  (confirmed via `git diff --name-only`) — `security-auditor` not required either (crypto-
  reviewer's scope covers this diff fully, it's the crypto-adjacent MLS-send path).
- Root-caused and fixed a real test bug hit while validating the dropped cycle's tests: 3 of the
  new "firing" tests failed under `vi.advanceTimersByTime` (sync). Root cause: `claimScheduledFire`
  does a `get()` then `delete()` inside one Dexie transaction; fake-indexeddb settles each
  IDBRequest via a (now-faked, since `vi.useFakeTimers()` globally replaces `setTimeout`) 0ms
  timer — the sync advance doesn't drain newly-scheduled timers between the transaction's two
  dependent awaits, so Dexie sees the transaction go idle after the `get()` and the `delete()`
  then fails, silently no-opping the claim (self-healing but permanently missing the test's
  short real-timer `waitFor` window). Fixed: switched the 4 affected `vi.advanceTimersByTime`
  calls in `ChatLayoutScheduleSend.test.tsx` to `await vi.advanceTimersByTimeAsync(...)`, which
  drains microtasks/newly-scheduled timers between ticks and keeps the transaction alive across
  both awaits. Confirmed via debug instrumentation (removed before commit) that this was purely
  a fake-timers/fake-indexeddb test-environment interaction, not a real-browser bug.
- **Frontend: 1460/1460 tests green** (was 1451 pre-cycle-341's-drop; +9 net: 6 in
  `usePersistentMessages.test.ts` for `claimScheduledFire`, 3 new ChatLayout-level firing/
  cross-tab-cancel tests). `tsc -b` clean, `biome check` clean (5 touched files). Production
  build: initial route 164.78 kB gzip / WASM 642.87 kB gzip (both under prd.md §7 budgets).
- `gh issue list --state open` — empty at cycle start. Target dir hygiene: not checked (FEATURE
  mode, backend untouched).
- **Next cycle candidates:** the crypto-reviewer's 2 residual notes are now both fixed in-cycle
  (see above, nothing deferred); the general cross-tab cloned-MLS-sender-ratchet property
  (every open tab independently imports the group's sender ratchet; this cycle explicitly did
  NOT resolve this, only documented it as pre-existing across every send path) is a bigger,
  separate architectural question — not scoped for a single cycle, would need its own design
  pass (e.g. leader-election among tabs, or a server-side single-sender lock) if ever prioritized;
  PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold); the `.claude/memory/project-
  context.md` file-size note (archived at cycle 340, currently ~1370 lines / 108KB — fine for
  now, re-check in a handful of cycles if it grows back toward the 256KB Read cap).

## Previous state (2026-08-23, cycle 340 — STABILIZATION: project-context.md re-archive + full security/test sweep)

- CI green (`gh run list --limit 3`), `gh issue list --state open` empty at cycle start.
- **Memory hygiene (the actual fix this cycle):** `project-context.md` had grown back to 3782
  lines / 291KB — over the Read tool's 256KB cap, so it could no longer be read whole (hit the
  cap on the very first read attempt this cycle). Flagged as overdue for 5+ cycles running
  (cycle 320's own archive-cutoff pass was itself long past the inline window). Archived cycles
  279–319's "Previous state" entries, plus a stray unarchived legacy "Cycle log (recent)" section
  (non-chronological cycles 215–262 and a stray 315 entry that cycle 320's cleanup missed) to
  `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md` (189KB). Live file is
  now 108KB / ~1370 lines, last 18 cycles kept inline. Verified the archive/live boundary is
  clean (no dropped or duplicated content) before replacing the live file.
- **Full sweep, all green, nothing to fix:**
  - `cargo audit`: 652 crates scanned, 0 advisories.
  - `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok.
  - `cargo test --workspace` (nextest not installed in this shell, used the documented fallback):
    all green across all 19 crates (0 failures).
  - `cargo clippy --workspace --all-targets -- -D warnings`: clean.
  - Frontend: `pnpm test --run` 1451/1451 tests green (104 files), `tsc -b` clean, `biome check`
    clean (170 files).
  - Target dir hygiene: 11G (well under the 20G threshold), 0-byte `.rmeta` prune ran, no further
    action needed.
- No crypto/architectural/backend-handler changes this cycle → no crypto-reviewer/threat-model-
  checker/security-auditor pass required (memory-file-only change, confirmed via `git status`).
- **Next cycle candidates:** the scheduled-messages-don't-actually-send-over-MLS gap (noted since
  cycle 339, still open, larger feature); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); pins/mentions remain session-only (no MessageRow/GroupRow fields exist for them yet).

## Archived history (cycles 20-277, 279-339, and legacy cycle-log entries)

> Cycles 20-277 were moved to `.claude/memory/archive/project-context-cycles-20-277.md` in
> cycle 320 (2026-07-19 STABILIZATION). Cycles 279-319, plus the old non-chronological
> "Cycle log (recent)" section (cycles 215-262 and a stray 315 entry that cycle 320's pass
> missed), were moved to `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
> in cycle 340 (2026-08-23 STABILIZATION). Cycles 320-339 were moved to
> `.claude/memory/archive/project-context-cycles-320-339.md` in cycle 360 (2026-08-25
> STABILIZATION) — this file had grown back to 2385 lines / 192KB, approaching the
> Read-tool 256KB cap. Only the last ~20 cycles are kept inline above. Read the archive
> files directly (with offset/limit) for older-cycle detail.

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

