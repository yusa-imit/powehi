# Powehi project-context.md archive — cycles 340-371

> Moved out of the live `.claude/memory/project-context.md` in cycle 390 (2026-08-30
> STABILIZATION) to keep the live file under the 256KB Read-tool cap, per the precedent
> set in cycles 320, 340, and 360. Read directly (with offset/limit) for this range's detail.

## Previous state (2026-08-26, cycle 371 — FEATURE: bound R2 S3 client request timeout, commit e5779db)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 368's own deferred candidate (still
  open as of cycle 370's next-cycle list): the R2 `S3Client` had no configured request
  timeout, so a hung R2 network call from the hourly media-blob GC job's `delete()`
  could hang that background task indefinitely — and since cycle 368 added a Postgres
  advisory lock (`try_gc_lock`) guarding it across replicas, a hang on one replica now
  blocks the job **cluster-wide**, not just locally.
- **What it does:** new `R2MediaAdapter::new(..., request_timeout_secs: u64)` param
  (`crates/adapters/outbound/powehi-r2/src/lib.rs`), wired into a new
  `build_s3_config()` free fn (extracted from `new()` so the timeout wiring is
  unit-testable without a `PgPool`) via `S3ConfigBuilder::timeout_config(TimeoutConfig
  ::builder().operation_timeout(request_timeout_secs).operation_attempt_timeout
  (request_timeout_secs / 3, floored at 1s).build())` — operation timeout bounds the
  whole retry loop, attempt timeout bounds one attempt; deliberately NOT set equal
  (see security-auditor finding below) so a single stalled attempt doesn't consume the
  whole retry budget and starve the SDK's standard 3-attempt retry policy. New
  `AppConfig::r2_request_timeout_secs` (default 30, `crates/infra/powehi-config/src/lib.rs`,
  same floor-validation pattern as cycle 369's `database_max_connections` —
  `MIN_R2_REQUEST_TIMEOUT_SECS`, `ConfigError::R2RequestTimeoutTooLow`), threaded
  through `main.rs`'s `R2MediaAdapter::new` call site and the testcontainers
  integration test's `setup()`. No new dependency: `TimeoutConfig` is a clean
  re-export at `aws_sdk_s3::config::timeout::TimeoutConfig` (verified against the
  vendored `aws-sdk-s3` 1.133.0 source — it's literally `pub use
  ::aws_smithy_types::timeout::{TimeoutConfig, TimeoutConfigBuilder};`), so
  `Cargo.toml`/`Cargo.lock` are untouched.
- **security-auditor: 1 round, YELLOW → fixed in-cycle, effectively GREEN.** Verified
  (not rubber-stamped) against the actual vendored `aws-smithy-runtime`/`aws-smithy-types`
  source rather than trusting the implementing agent's claims: confirmed the timeout
  genuinely takes effect on a client built via `S3Client::from_conf` (not just
  `aws_config::load_from_env()`) — `from_conf` installs the identical
  `default_plugins()` set including the sleep-impl plugin, which resolves via
  `default_async_sleep()` only under the `rt-tokio` feature (enabled workspace-wide);
  confirmed the SDK's own default `connect_timeout` (~3.1s) survives layering under
  user config rather than being clobbered (`MergeTimeoutConfig` takes missing fields
  from defaults, doesn't replace wholesale). 4 findings, all fixed same-cycle rather
  than deferred (all cheap): (1) **BLOCKING-adjacent** — original diff set
  `operation_timeout == operation_attempt_timeout`, which meant a stalled first
  attempt would consume the *entire* operation budget, so the SDK's retry policy
  never got a second chance — fixed by deriving `operation_attempt_timeout` as
  `request_timeout_secs / 3` (floored at 1s) in the new `build_s3_config()`, with 2
  new unit tests (`build_s3_config_attaches_operation_and_attempt_timeouts`,
  `build_s3_config_floors_attempt_timeout_at_one_second`) pinning both the ratio and
  the floor directly against `aws_sdk_s3::Config::timeout_config()` — zero I/O, no
  Docker needed, exactly the "is `TimeoutConfig` silently ignored" risk the auditor
  flagged as untested; (2) the floor `MIN_R2_REQUEST_TIMEOUT_SECS` was originally 1
  (just "reject zero") — auditor pointed out 1s itself passes validation but is
  **guaranteed broken** since it's below the SDK's own ~3.1s default connect timeout,
  a silent total media-GC outage that clears naive validation — raised to 5, doc
  comment on the const explains why; (3) doc/error-message overclaim — the original
  diff's rationale text (config field doc, `ConfigError` message, adapter module doc)
  claimed a hung R2 call could hang "the GC/ledger-trim background jobs" plural, but
  the daily ledger-trim job (`trim_upload_ledger_older_than`) is 100% Postgres/sqlx,
  never calls R2 — corrected all three sites to name only the hourly media-blob GC
  job, since a future reader would otherwise misjudge the advisory-lock blast radius;
  (4) test coverage gap closed via the two new unit tests above rather than a
  Docker-dependent hang-simulation test (auditor agreed the latter is a poor harness
  fit). Confirmed not crypto (no MLS/OPAQUE/KDF/AEAD touched) — `crypto-reviewer`
  correctly not required; confirmed not architectural (no new API surface, DB column,
  or server-visible metadata — pure network-timeout knob, availability not
  confidentiality/integrity) — `threat-model-checker` correctly not required.
  Documented-not-fixed residual (correctly out of this cycle's scope, matches
  precedent): `POWEHI__R2_REQUEST_TIMEOUT_SECS` isn't in the Helm ConfigMap, same gap
  as `database_max_connections` since cycle 369 — both need one combined infra-lead
  pass; aggregate GC-sweep duration is still unbounded (N slow-but-not-hung deletes at
  ~10s attempt-timeout each can still hold the advisory lock past the next hourly
  tick) — the fix bounds *per-call* hang, not total sweep wall-clock, follow-up would
  be wrapping the guarded job body in `tokio::time::timeout`.
- 4 new/updated Rust tests: 2 new unit tests in `powehi-r2` (`build_s3_config_*`,
  above), `powehi-config`'s 3 new `r2_request_timeout_*` tests
  (`_default_is_30`, `_below_floor_is_rejected` — now checks both 0 and
  `MIN_R2_REQUEST_TIMEOUT_SECS - 1`, not just 0, per the auditor's point that only
  testing zero wouldn't have caught a too-low-but-nonzero floor bug —
  `_at_or_above_floor_is_accepted`), 1 line added to the existing
  `load_uses_defaults_when_no_env_vars_set`. `cargo build/test --workspace` clean (all
  suites green, 0 failed — 726+ tests across the workspace, exact count not
  re-tallied), `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  fmt --check` clean. No `Cargo.lock` diff — `cargo audit`/`cargo deny check` (run by
  the security-auditor pass) both clean, 652 crates scanned, 0 vulnerabilities.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 375,
  STABILIZATION).
- **Next cycle candidates:** the two residuals documented-not-fixed above (Helm
  wiring for `r2_request_timeout_secs` — bundle with cycle 369's still-open
  `database_max_connections` Helm gap, needs infra-lead + real DB/R2 capacity numbers
  not yet researched; `tokio::time::timeout` around the whole guarded GC-job body to
  bound aggregate sweep duration, not just per-call latency); the hexagonal-layering
  nit (`try_gc_lock` living on the R2/S3-named adapter instead of a `LeaderLock` port
  on `powehi-postgres`, cycle 368); media-key incoming/outgoing asymmetry (confirmed
  genuinely multi-part, cycle 359); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B,
  itself gated on Phase A); project-context.md size (now ~1870 lines, comfortably
  under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 370 — STABILIZATION: align testcontainers pools with powehi_postgres::connect, commit de324a3)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start.
- Picked cycle 369's own carried-forward informational note: `pg_security_it.rs` and
  `r2_media_it.rs` (both `#[ignore]`d testcontainers integration suites) built their test
  Postgres pool via a bare `sqlx::PgPool::connect(&url)`, bypassing the crate's own
  `powehi_postgres::connect(url, max_connections)` helper that production code (`main.rs`'s
  `pg_connect`) has used since cycle 369's explicit-pool-size fix. Harmless at the time
  (sqlx's implicit default of 10 happened to sit above cycle 369's new floor of 3), but
  meant `try_gc_lock`'s own test suite (and every other adapter test in these two files)
  exercised a differently-configured pool than production, and would silently drift further
  if the production default (currently 20) ever changed without these files being touched.
- **What it does:** both `setup()` helpers now call `powehi_postgres::connect(&url, 10)`
  instead of `PgPool::connect(&url)` — kept the cap at 10 (matching the old implicit sqlx
  default, ample for these fixtures' concurrency) rather than production's 20, since test
  pools don't need to match production capacity, only go through the same construction path.
  `sqlx::PgPool` import stays used elsewhere in both files (struct fields / helper fn
  signatures) so no unused-import warning.
- **security-auditor: GREEN.** Confirmed `powehi_postgres::connect()` is a thin
  `PgPoolOptions::new().max_connections(n).connect(url)` wrapper with no extra validation,
  no `min_connections` override, no logging — so the swap is behaviorally identical besides
  the explicit cap; confirmed no plaintext/secret logging (the two `.expect(...)` messages
  are static strings, and the connection URL itself is just a local testcontainers
  `postgres://postgres:postgres@127.0.0.1:<port>/postgres`, not a real secret); confirmed
  `max_connections=10` is sane for a single ephemeral-container-per-test fixture. Not
  architectural (test-only, no production/schema/dependency change) — `threat-model-checker`
  correctly not required; not crypto — `crypto-reviewer` correctly not required.
- `cargo build --workspace` and `cargo build --workspace --tests` both clean (confirms the
  `#[ignore]`d Docker-gated tests in both files still compile). `cargo test --workspace`:
  42/42 test binaries `test result: ok`, 0 failures (no Docker in sandbox so the
  testcontainers tests themselves stay `ignored`, same as every prior cycle — will run for
  real in CI's Rust workflow). `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --check` clean. `cargo audit`: 0 vulnerabilities (652 crates scanned, exit 0).
  `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok. No `Cargo.lock` diff
  (test-only change, zero dependency impact).
- Target dir hygiene: `target/` was 25G (> the 20G threshold). Ran the 0-byte `.rmeta` prune
  (no-op, none found) and the `mtime +7` prune of `target/debug/deps`/`incremental` — also a
  no-op, every artifact in the tree is younger than 7 days (an actively-building project, not
  stale bloat). Left at 25G; not a failure, just nothing eligible to prune this cycle. Worth
  revisiting if growth continues without natural turnover.
- **Next cycle candidates (unchanged from cycle 369, still open):** derive/document a
  Postgres-side connection budget and wire `database_max_connections` through Helm
  `values.yaml` per environment instead of the baked-in default of 20 (needs infra-lead + a
  real number for the managed Postgres's own `max_connections`, not currently provisioned via
  Terraform — check where/how the DB is actually hosted before picking this); a lease/TTL or
  R2 `S3Client` request timeout so a hung GC/ledger-trim task can't block that job
  cluster-wide indefinitely (cycle 368); the hexagonal-layering nit (`try_gc_lock` living on
  the R2/S3-named adapter instead of a `LeaderLock` port on `powehi-postgres`); media-key
  incoming/outgoing asymmetry (confirmed genuinely multi-part, cycle 359); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated
  on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now ~1760 lines,
  comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 369 — FEATURE: explicit Postgres pool size + floor validation, commit 87ae758)

- CI green (`gh run list --limit 5` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start.
- Picked cycle 368's first deferred candidate: `powehi_postgres::connect()` inherited
  sqlx's undocumented `max_connections = 10` default, which cycle 368's GC advisory-lock
  fix (`try_gc_lock`) made load-bearing — two background jobs (hourly media-blob GC, daily
  ledger trim) each now pin one dedicated session-scoped connection for
  `pg_try_advisory_lock` on top of normal request-handler traffic.
- **What it does:** `connect(url, max_connections: u32)` now builds via
  `PgPoolOptions::new().max_connections(...)` instead of the bare `PgPool::connect(url)`.
  `AppConfig` gained `database_max_connections: u32` (serde default 20,
  `POWEHI__DATABASE_MAX_CONNECTIONS`), threaded through `main.rs`'s `pg_connect` call.
  `powehi_config::load()` now rejects `database_max_connections < 3` via a new
  `ConfigError::DatabaseMaxConnectionsTooLow` — below 3, a single GC/ledger-trim job's
  lock connection plus its own query connection self-deadlocks the pool, and if both
  jobs overlap every request handler starves too.
- **security-auditor: GREEN** (fully independent verification against sqlx 0.8.6 source,
  not just the diff — confirmed `acquire_timeout` fail-fast on `max_connections=0`, config-rs
  string-coercion fail-fast on non-numeric/negative values, confirmed only the two
  `GcLockGuard`s are long-lived connection holders so 20 leaves 18 free for handlers vs.
  10's 8). 4 non-blocking findings, 2 fixed same-cycle: (1) missing floor validation — now
  fixed via the `< 3` reject above, extracted into a small pure `validate()` fn so it's
  unit-testable without mutating process env; (3) `GcLockGuard`'s `Drop`-safety doc
  depending on `min_connections == 0` didn't warn the new `PgPoolOptions` builder site not
  to add `.min_connections(_)` — added that warning to `connect()`'s doc comment. 2
  deferred as genuinely bigger-scope: (2) `maxReplicas × 20` roughly doubles the
  cluster-wide connection ceiling (300 in prod-eu, 200 in prod-ap) with no documented
  Postgres-side `max_connections` or managed-DB resource anywhere in `infra/` to check it
  against — needs an infra-lead pass wiring the value through Helm `values.yaml` derived
  from actual DB capacity, not a config-crate fix; (4) `POWEHI__DATABASE_MAX_CONNECTIONS`
  isn't wired into the Helm ConfigMap yet, so every environment runs the compiled default
  of 20 regardless — same follow-up as (2). Also noted (informational, no fix needed): two
  `#[ignore]`d testcontainers files (`pg_security_it.rs`, `r2_media_it.rs`) still call bare
  `PgPool::connect` bypassing the crate's `connect()`, so `try_gc_lock`'s own test suite
  runs against a differently-sized pool than production — harmless at 10 (above the new
  floor), align next time those files are touched. Not architectural (pool sizing is
  server-internal only, no new server-visible metadata) — `threat-model-checker` correctly
  not required; not crypto — `crypto-reviewer` correctly not required.
- 2 new unit tests (`database_max_connections_below_floor_is_rejected`,
  `database_max_connections_at_or_above_floor_is_accepted`), `powehi-config` now 13/13.
  Full `cargo build/test --workspace` green (no regressions), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean. `cargo deny check`
  advisories/bans/licenses all ok (security-auditor ran it; no `Cargo.lock` diff from this
  change so not independently re-run).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle above — (2)/(4) really
  are one task: derive/document a Postgres-side connection budget and wire
  `database_max_connections` through Helm `values.yaml` per environment instead of the
  baked-in 20, needs infra-lead + a real number for the managed Postgres's own
  `max_connections` (not currently provisioned via Terraform — check where/how the DB is
  actually hosted before picking this, may be a bigger infra task than one cycle); cycle
  368's other deferred item, a lease/TTL or R2 `S3Client` request timeout so a hung GC/trim
  task can't block that job cluster-wide indefinitely; the hexagonal-layering nit
  (`try_gc_lock` living on the R2/S3-named adapter instead of a `LeaderLock` port on
  `powehi-postgres`); media-key incoming/outgoing asymmetry (confirmed genuinely
  multi-part, cycle 359); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself
  gated on Phase A); project-context.md size (now ~1660 lines, comfortably under the 256KB
  Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 368 — FEATURE: Postgres advisory lock guards GC/ledger-trim jobs, commit 20aa601)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. PATH quirk hit again this cycle (recurring across
  many past cycles per the duplicate lines already in `~/.zshrc`): the sandbox's Bash
  tool does not source `~/.zshrc` (zsh only sources `.zshrc` for interactive shells;
  this harness runs non-interactive), so `cargo` was `command not found` until each
  command explicitly ran `source "$HOME/.cargo/env"` first. Appended one more line to
  `~/.zshenv` (sourced for *all* shell types, unlike `.zshrc`) attempting a real fix,
  but confirmed via a fresh Bash call that it *still* doesn't take effect — the
  per-command `source "$HOME/.cargo/env"` workaround remains necessary; do not assume a
  future cycle can skip it just because `.zshenv` looks correct.
- Picked cycle 364/367's carried-forward candidate: the multi-replica-GC-early-exit gap
  (security-auditor cycles 364 and 367, non-blocking both times) — `MediaService::run_gc`
  (hourly) and `R2MediaAdapter::trim_upload_ledger_older_than` (daily) each ran
  independently on every server replica with no leader election/advisory lock, so a
  concurrent sweep on another replica could delete rows out from under a replica's
  in-progress keyset page, making its batch undercount and exit early (self-healing —
  leftovers just wait for the next tick — but wasteful, and explicitly flagged twice as
  worth closing).
- **What it does:** new `R2MediaAdapter::try_gc_lock(key: i64) -> Result<Option<GcLockGuard>,
  DomainError>` (`crates/adapters/outbound/powehi-r2/src/lib.rs`) acquires a non-blocking
  session-scoped Postgres advisory lock (`pg_try_advisory_lock`) via a *dedicated held*
  `PoolConnection` — advisory locks are tied to the connection/session, not the query, so
  the guard can't borrow one per-query from the shared pool the way every other method in
  this adapter does. `GcLockGuard::release()` explicitly unlocks and returns the
  connection to the pool (falling back to detach-and-drop if the unlock query itself
  errors, so a failed release still can't leave a lock-holding connection back in the
  pool). If `release()` is never called (early return/panic), `Drop for GcLockGuard`
  instead calls `PoolConnection::detach()` and drops the resulting raw `PgConnection` —
  ending the session server-side is what actually frees a session-scoped lock; an
  explicit unlock issued later from a *different* pooled connection would not find it.
  `#[must_use]` on `GcLockGuard` so a future caller can't silently drop-and-release by
  accident. Two lock-key constants (`GC_LOCK_MEDIA_BLOBS`, `GC_LOCK_MEDIA_LEDGER`) so the
  two jobs never block each other, only concurrent replicas racing the *same* job.
  `bin/powehi-server/src/main.rs`'s two background job loops now wrap their bodies with
  `try_gc_lock`/`release`; `Ok(None)` (lock held elsewhere) skips that tick at `debug`
  level, relying on the next scheduled tick. Kept a concrete `Arc<R2MediaAdapter>` clone
  (`media_r2_lock`) alongside the existing `MediaRepository` trait-object clones since the
  lock helpers are Postgres-specific, not part of the port trait — main.rs already
  concedes this kind of concrete-type escape hatch elsewhere in the same function.
- **security-auditor: GREEN**, no blocking findings; verified genuinely, not rubber-
  stamped — read sqlx 0.8.6 source directly rather than trusting the diff's doc comments:
  confirmed `PoolConnection::detach()` decrements the pool's size permit which the pool
  immediately backfills (no permanent capacity loss); confirmed sqlx-postgres 0.8.6 has no
  `Drop for PgConnection`, so dropping the detached raw connection is just an fd close →
  Postgres backend hits EOF and releases session-scoped locks; found and had me document a
  bonus reason detach-then-drop is the *correct* choice beyond what the original comment
  claimed — `PoolConnection`'s own `Drop` spawns an async task to return itself to the
  pool, which panics if invoked while Tokio is shutting down, so a plain `drop(conn)`
  inside `Drop for GcLockGuard` would have been a latent runtime-teardown panic; detach()
  sidesteps that entirely (now documented in-code, contingent on `min_connections == 0`,
  which is what `powehi-postgres::connect()` uses today — also now documented as a
  caveat). Confirmed no advisory-lock key collision: grepped the whole repo, the only
  other advisory-lock user is sqlx's own migrator (`generate_lock_id`, CRC32-based, max
  ~4.41e18), and both `GC_LOCK_*` constants exceed that range, so collision is
  arithmetically impossible, not just unlikely. Confirmed no plaintext/PII logging (new
  `debug!`s are bare strings, new `warn!`s carry only `error_kind`+opaque error text).
  Confirmed not architectural / no new server-visible metadata (three files, no proto, no
  migration, no new DB column/HTTP/gRPC/WS surface, `pg_locks` state is server-internal
  only) — `threat-model-checker` correctly not required; not crypto — `crypto-reviewer`
  correctly not required. No `Cargo.lock` diff (zero new dependencies) — `cargo audit`/
  `cargo deny check` not re-run. Non-blocking findings, all fixed same-cycle rather than
  deferred (all cheap): `#[must_use]` on `GcLockGuard`; `release()`'s unlock-query error
  was silently swallowed via `let _ = ...` — now logged at `warn` plus falls back to the
  detach path so a failed unlock still can't leave a lock-holding connection in the pool;
  added the `min_connections == 0` dependency and the "no transaction-pooling proxy
  deployed" invariant to the doc comments (a PgBouncer/RDS-Proxy in transaction mode would
  silently break session-scoped advisory locks with zero compile-time signal — none exists
  in `infra/` today, confirmed by grep); added a comment on the GC job in main.rs
  acknowledging the one real behavior change auditor flagged — average expired-blob
  deletion latency moves from ~hourly/N-replicas to ~hourly cluster-wide, still far inside
  the retention-ceiling contract (no data-minimization regression) but worth being
  explicit about since deletion latency is privacy-adjacent even when policy-compliant.
  Two findings explicitly deferred (broader scope than a single-cycle fix, both
  documented as next-cycle candidates below): `powehi-postgres::connect()` has no explicit
  `PgPoolOptions` (inherits sqlx's default `max_connections = 10`, invisible and now
  load-bearing for this new code path — a large GC backlog can pin ~20% of the shared pool
  for the sweep's duration since `R2MediaAdapter::delete` does a synchronous R2 network
  round-trip per blob); a hung GC/trim task now blocks that job cluster-wide for as long as
  the hang lasts (previously only hurt the one replica) since there's no lease/TTL/
  `statement_timeout` and k8s's liveness probe only checks the axum HTTP server, not this
  `tokio::spawn`ed background task — bounded severity (GC is best-effort against a 30-day
  ceiling) but a real new failure mode worth a follow-up (lease TTL, or an explicit
  `Client::config()` request timeout on the R2 `S3Client` to bound the likeliest hang
  source).
- 4 new `#[ignore = "requires Docker (testcontainers)"]` integration tests in
  `r2_media_it.rs` (`try_gc_lock_returns_none_when_already_held`,
  `try_gc_lock_distinct_keys_do_not_block_each_other`,
  `try_gc_lock_dropped_without_release_still_frees_the_lock` — the last one specifically
  verifies the `Drop` safety net, not just the happy `release()` path, via a bounded poll
  loop since TCP teardown after `detach()` is async). Session-scoped advisory-lock
  behavior can't be exercised by any mock (the whole point is real per-connection session
  state at the OS/Postgres level), so this is testcontainers-only coverage by necessity —
  not run locally (no Docker in sandbox), will run in CI's Rust workflow. `cargo build/test
  --workspace` clean (all non-ignored green, no regressions), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle (explicit
  `PgPoolOptions::max_connections` for `powehi-postgres::connect()` instead of inheriting
  sqlx's invisible default of 10; a lease/TTL or explicit R2 `S3Client` request timeout so
  a hung GC/trim task can't block that job cluster-wide indefinitely, now a real if
  bounded-severity new failure mode introduced by this cycle's own fix); the hexagonal-
  layering nit auditor raised but didn't block on (`try_gc_lock` is a Postgres primitive
  living on the R2/S3-named adapter, reached from main.rs via a concrete-type escape hatch
  around the `MediaRepository` port — a cleaner home would be a small `LeaderLock` outbound
  port on `powehi-postgres`, which already owns the pool; deferred as a design nit, not a
  correctness issue); the two findings deferred cycle 367 (`messaging_service.rs`'s mock's
  unreachable-in-real-Postgres members-without-groups construction, informational only;
  gRPC `sync_group_membership` missing a `member_device_ids.is_empty()` reject — re-
  evaluated this cycle and now believe this one is lower-priority than previously listed:
  `sync_group_membership` is the cross-region *sync* path (mTLS-gated peer-to-peer, not
  reachable by end users), and unlike `create_group`'s hijack bug, an empty-member group
  created here isn't permanently stuck — a later sync call with real members for the same
  group_id still succeeds via `upsert_members`'s `ON CONFLICT DO NOTHING`, and the existing
  test `sync_group_membership_zero_members_creates_group_stub` documents this as
  intentional. Only revisit if a concrete abuse scenario for the mTLS-gated path surfaces);
  `map_sqlx` raw-error-text server-side logging (pre-existing, informational, affects every
  adapter method); media-key incoming/outgoing asymmetry (needs a new crypto-reviewed WASM
  key-export/local-storage-key design, confirmed genuinely multi-part cycle 359); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size
  (now ~1610 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 367 — FEATURE: make create_group's group+member creation atomic, commit 9d1ba00)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 366's top carried-forward candidate:
  its own non-blocking LOW finding — `create_if_absent` + `add_member` in
  `create_group` were two separate, non-transactional calls, so a failure between them
  (DB error, pod kill) could leave a committed group row with zero members, which was
  then permanently stuck (every future `create_group` retry for that id hits the
  already-exists-and-not-a-member branch forever, since nothing may add a first member
  once the id is known to exist).
- **What it does:** new `GroupRepository::create_with_creator(&Group, &GroupMember) ->
  Result<bool, DomainError>` port method
  (`crates/ports/powehi-port-outbound/src/group_repo.rs`); Postgres impl
  (`crates/adapters/outbound/powehi-postgres/src/group_repo.rs`) wraps the group-row
  insert (`ON CONFLICT (id) DO NOTHING`) and the creator's membership-row insert in one
  `pool.begin()`/`commit()` transaction, same pattern as the existing `upsert_members`.
  Returns `true` if newly created, `false` if the id already existed (transaction
  dropped/rolled back untouched). `GroupService::create_group` now calls this instead of
  `create_if_absent` + `add_member`. The membership insert binds `group.id` (not
  `creator.group_id`) — closes an undocumented precondition the first security-auditor
  pass flagged as a latent footgun if the two args ever diverged; port trait doc now
  states this normatively. `create_if_absent` itself is left in the trait (still tested
  directly, still the primitive doc-comment example) but confirmed dead in production —
  its only former caller was `create_group`.
- **security-auditor: 2 rounds, RED → GREEN.** First pass found ONE BLOCKING issue: the
  new Postgres integration test's `creator_device` was a bare `DeviceId::from(Uuid::new_v4())`
  never inserted into `devices`, so the membership insert's non-deferrable FK
  (`group_members.device_id REFERENCES devices(id)`) would reject it and the test would
  panic on `.expect(...)` instead of testing anything — the sole verification of this
  cycle's atomicity claim had zero real passing coverage, and CI (which does have Docker)
  would have gone red. Fixed: seeded via the file's existing
  `insert_device(&pool, insert_user(&pool).await).await` helper, same pattern as every
  other member-inserting test in that file. Also added the actually-missing coverage for
  the rollback branch itself (`create_with_creator_rolls_back_group_row_when_member_insert_fails`
  — unregistered device triggers the FK, asserts `Err` + `find_by_id` still `None`,
  provably fails under the original two-call regression since that would have already
  committed the group row). Two non-blocking hardening items from round 1 also fixed
  same-cycle rather than deferred (both cheap, both in code this cycle wrote): the
  `group.id`-vs-`creator.group_id` binding above, mirrored into all four
  `GroupRepository` mock mocks (`group_service.rs`, `media_service.rs`,
  `messaging_service.rs`, `powehi-grpc/src/server.rs`) so no test double's behavior can
  diverge from the production adapter on this axis. Second pass (fresh instance, no
  memory of round 1) independently re-verified all three fixes by tracing SQL/FK/sqlx-tx
  semantics (no Docker in either sandbox) plus re-ran `cargo build/test/clippy/fmt` —
  **GREEN**. Round 1 also confirmed (not rubber-stamped): the new transaction is
  genuinely atomic (nothing visible to other sessions pre-commit); no new race (READ
  COMMITTED, no isolation override anywhere in the workspace — `ON CONFLICT DO NOTHING`
  against an in-flight duplicate blocks then reports 0 rows, never raises
  `unique_violation`, so the loser gets a clean `Ok(false)`); rollback-on-drop verified
  against the actually-pinned `sqlx 0.8.6` source (`Drop for Transaction` queues
  `ROLLBACK`), not assumed; no plaintext/PII/new server-visible metadata. `cargo audit`/
  `cargo deny check` clean (0 vulnerabilities, no Cargo.lock diff). Two residual LOW/
  informational findings explicitly deferred to a future cycle per the auditor's own
  recommendation (separate call sites, out of this cycle's diff scope): gRPC
  `sync_group_membership` has no minimum on `member_device_ids`, so an empty list from a
  trusted mTLS peer can still create a zero-member group via `upsert_members` (mTLS-gated
  insider path, not end-user reachable); `messaging_service.rs`'s `FakeGroupRepo` mock
  can be constructed in a members-without-groups state real Postgres's FK can't reach
  (inert today, mock never actually exercises `create_with_creator`).
- **threat-model-checker: not re-run**, consistent with cycle 364's precedent for a
  similarly-scoped internal atomicity fix — no new server-visible metadata, no
  wire-format/API change, net effect is strictly less exposure to the same failure mode
  cycle 366's `threat-model-checker` GREEN already covered (access-control/membership
  invariants of `create_group`), not a new architectural surface.
- 2 new `#[ignore = "requires Docker"]` integration tests in `pg_security_it.rs`
  (`create_with_creator_inserts_group_and_member_together`,
  `create_with_creator_rolls_back_group_row_when_member_insert_fails`) — not run locally
  (no Docker in sandbox), will run in CI's Rust workflow (21 tests total in that file now,
  confirmed compiling/counted correctly via `cargo test` locally even though ignored).
  `cargo build/test --workspace` clean (~600 tests green, 0 failed, 58 Docker-gated
  ignored across the workspace), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean (1 auto-fix applied mid-cycle, no logic change).
- Target dir hygiene: not checked this cycle (FEATURE mode; next due cycle 370,
  STABILIZATION).
- **Next cycle candidates:** the two findings deferred this cycle (gRPC
  `sync_group_membership` missing a `member_device_ids.is_empty()` reject alongside its
  existing `MAX_SYNC_MEMBERS` cap; `messaging_service.rs`'s mock's unreachable-in-
  -real-Postgres members-without-groups construction, informational only); `map_sqlx`
  raw-error-text server-side logging (pre-existing, informational, affects every adapter
  method); media-key incoming/outgoing asymmetry (needs a new crypto-reviewed WASM
  key-export/local-storage-key design, confirmed genuinely multi-part cycle 359); the
  multi-replica-GC-early-exit gap (cycle 364, `FOR UPDATE SKIP LOCKED`/advisory-lock
  guard, shared between the ledger trim job and `run_gc`); PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now ~1520 lines,
  comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-26, cycle 366 — FEATURE: fix broken access control in create_group (group hijack/rejoin), commit fe6c419)

- CI green (`gh run list --limit 3` all success), `git status` at cycle start was **NOT
  clean** — same "cycle silently fails to commit" pattern as cycles 324/326/330/332/341/
  342/355. Found a complete, passing, uncommitted diff already spanning 7 files
  (group_service.rs, group_repo.rs port+adapter, 3 mock-repo call sites, a new Docker-gated
  integration test), with doc-comment-style rationale in the diff itself framed exactly
  like a security-auditor finding-and-fix. The last commit on `main` at cycle start was
  cycle 364's memory update (b7853b9) with no cycle-365 commit anywhere in `git log` —
  strongly suggesting this is cycle 365's (STABILIZATION, security sweep step) work that
  was never committed, the same "cycle silently fails to commit" failure mode as cycles
  324/326/330/332/341/342/355, just not yet confirmed since no cycle-365 project-context.md
  entry exists to cross-reference. Per CLAUDE.md's investigate-before-discarding guidance,
  validated rather than discarded: `cargo build --workspace` clean, `cargo test --workspace`
  all green (no regressions), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean. Treated the diff's embedded claims as unverified and
  re-ran both required review agents fresh before committing.
- **What it does:** `GroupService::create_group` (`crates/application/powehi-application/src/group_service.rs`)
  previously called `group_repo.save()` — a destructive `ON CONFLICT DO UPDATE` upsert —
  then unconditionally added the caller as a member. Any authenticated device could POST
  an existing/guessed group_id and (a) reset that group's `epoch`/`home_region` to
  defaults, (b) attach itself as a member of a group it was never invited to, including a
  device previously evicted via `remove_member` — letting it rejoin and potentially
  re-evict everyone else. Fixed with a new `GroupRepository::create_if_absent(&Group) ->
  Result<bool, DomainError>` port method (`INSERT ... ON CONFLICT (id) DO NOTHING`,
  `crates/adapters/outbound/powehi-postgres/src/group_repo.rs`); `create_group` now calls
  it instead of `save()`. If the id already existed: caller already a member ->
  idempotent no-op `Ok(())` (genuine retry, doesn't reset epoch/home_region); caller not a
  member -> `DomainError::AlreadyExists` (pre-existing variant, already mapped to HTTP 409
  / gRPC ALREADY_EXISTS elsewhere). Mock `GroupRepository` impls in media_service.rs,
  messaging_service.rs, and powehi-grpc/server.rs test modules updated to implement the
  new trait method.
- **security-auditor: YELLOW (ships safely), verified not rubber-stamped:** confirmed
  `create_if_absent` is race-free (groups.id is a real UUID PK, giving `ON CONFLICT` a
  valid arbiter index; `rows_affected() == 1` correctly detects the winner under
  READ COMMITTED); confirmed no other production call site still uses `save()` for initial
  creation (the only remaining `save()`/upsert paths are `send_commit`'s epoch advance,
  member-gated, and gRPC's `upsert_members`, mTLS-region-gated and already DO NOTHING);
  confirmed the idempotent-retry path isn't TOCTOU-abusable (caller only controls
  group_id, `creator` comes from the authenticated-device extractor, membership is
  server-side DB state); confirmed no PII/plaintext logged (`DeviceId`/`GroupId` Display
  are bare UUIDs); confirmed the 409 mapping leaks no group-id-existence oracle beyond
  theoretical (128-bit random ids, route is authenticated + rate-limited, response body is
  code-only). Two non-blocking LOW findings, carried forward rather than fixed this cycle
  (see below): `create_if_absent` + `add_member` are two separate statements, not one
  transaction — if `add_member` fails after the group row lands (DB error/pod kill), the
  group is permanently unusable (zero members, every future caller hits the
  already-exists-and-not-a-member branch forever) since the fix removed the old
  self-healing unconditional `add_member`; same non-atomicity also means the loser of two
  concurrent same-creator `create_group` calls gets a spurious 409 (harmless, client can
  retry).
- **threat-model-checker: GREEN**, no prd.md/ADR update needed. Confirmed: no new
  server-visible metadata (`create_if_absent` writes strictly less than the old `save()`
  did); T7 (region jurisdiction) posture strengthened — `home_region` can no longer be
  rewritten by an arbitrary authenticated device, closing a way to move the §3.5.4
  commit-serialization point; access-control/membership invariants strengthened (closes
  evicted-device rejoin, which mattered because `group_members` drives fan-out and
  media/envelope ACLs per §3.3/§9.4.3 — a rejoined device kept receiving ciphertext/
  presigned URLs even though MLS PCS denied it plaintext); the 409-vs-204 existence-signal
  delta is within §3.3's already-documented `group_id` disclosure, no doc change required;
  confirmed no other unguarded path into group creation/upsert remains.
- 3 new tests in `group_service.rs` (non-member hijack on an existing group_id rejected
  with `AlreadyExists` + member list unchanged; a device evicted via `remove_member`
  cannot rejoin through this path; a genuine retry by an existing member is idempotent —
  no duplicate member row, epoch/home_region not reset), 1 new
  `#[ignore = "requires Docker"]` integration test in `pg_security_it.rs`
  (`create_if_absent_does_not_overwrite_an_existing_group`, proves the real Postgres
  `ON CONFLICT DO NOTHING` semantics directly: first call creates, second call with a
  different home_region/reset epoch reports already-existing and leaves every column
  including `created_at` untouched, exactly one row exists). Not run locally (no Docker in
  sandbox), will run in CI's Rust workflow. `cargo build/test --workspace` clean (all
  crates green, no regressions), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode; cycle 365 was the STABILIZATION
  cycle that should have covered it — status not visible from this session, assume covered
  unless a future cycle finds otherwise).
- **Next cycle candidates:** the security-auditor's two LOW findings this cycle
  (`create_if_absent`+`add_member` non-atomicity — a failed `add_member` after a fresh
  group row lands permanently bricks that group_id; fix by wrapping both in one Postgres
  transaction, same `pool.begin()` pattern `upsert_members` already uses, needs a new
  combined port method since the current two-call shape can't be made atomic from the
  application layer alone); `map_sqlx` raw-error-text server-side logging (pre-existing,
  informational, affects every adapter method); media-key incoming/outgoing asymmetry
  (needs a new crypto-reviewed WASM key-export/local-storage-key design, confirmed
  genuinely multi-part cycle 359); the multi-replica-GC-early-exit gap (cycle 364,
  `FOR UPDATE SKIP LOCKED`/advisory-lock guard, shared between the ledger trim job and
  `run_gc`); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`);
  OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself gated on Phase A);
  project-context.md size (now ~1420 lines, comfortably under the 256KB Read cap — no
  action needed yet).

## Previous state (2026-08-25, cycle 364 — FEATURE: batch media_upload_ledger GC trim + supporting index, commit 641556b)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 363's top carried-forward candidate: its own
  non-blocking security-auditor note that `trim_upload_ledger_older_than` was a single unbatched
  `DELETE ... WHERE uploaded_at < $1` with no supporting index (the table's only index led with
  `device_id`), so the daily sweep was a full-table scan in one unbatched statement.
- **What it does:** new migration `0016_media_upload_ledger_uploaded_idx.sql` — `CREATE INDEX
  CONCURRENTLY IF NOT EXISTS media_upload_ledger_uploaded_at_idx ON
  media_upload_ledger(uploaded_at)`, `-- no-transaction` marker (0011/0014 precedent — sqlx
  can't run CONCURRENTLY inside its migration transaction). `R2MediaAdapter::
  trim_upload_ledger_older_than` (`crates/adapters/outbound/powehi-r2/src/lib.rs`) now loops,
  deleting via `WHERE id IN (SELECT id ... WHERE uploaded_at < $1 ORDER BY uploaded_at LIMIT
  5_000)` per batch (`TRIM_LEDGER_BATCH_SIZE`), summing `rows_affected()`, exiting when a batch
  returns fewer than the cap — bounds both scan cost (index range scan per batch, not a full
  scan) and lock hold time (no single statement touches the whole stale range). Port trait
  signature (`media_repo.rs`) unchanged — pure adapter-internal change, `main.rs`'s daily
  `tokio::spawn` caller untouched.
- **security-auditor: GREEN**, no blocking findings; verified (not rubber-stamped): fully
  parameterized (no injection surface), batching loop provably terminates (cutoff is fixed for
  the whole call; only production insert path sets `uploaded_at = Utc::now()` server-side, so no
  concurrent insert can land below a 30-day-old cutoff — livelock unreachable), off-by-one exit
  condition correct (PK-keyed `IN` subquery yields distinct ids, exact-multiple case just costs
  one harmless extra zero-row statement), no PII/content logged. Two non-blocking findings, both
  applied/documented in-cycle rather than deferred (unlike cycle 363's picks, both were cheap):
  (a) switched the new index from a plain `CREATE INDEX` to `CONCURRENTLY` — auditor pointed out
  this table (unlike 0015's genuinely-empty-at-creation case) has been insert-heavy since cycle
  362, so a plain build's lock would block concurrent uploads for its duration; (b) documented
  in-code (not fixed — architectural, out of single-cycle scope) that multiple server replicas
  each running this daily sweep independently with no leader election/advisory lock (same
  pre-existing gap as `run_gc`) can make one replica's batch undercount and exit early if another
  replica deletes rows concurrently — bounded/self-healing (leftovers are still >29 days past the
  24h quota window, swept next run), not a correctness or quota-bypass risk.
- 1 new integration test in `r2_media_it.rs`
  (`trim_upload_ledger_older_than_drains_multiple_batches`): bulk-inserts 12,001 stale rows via
  raw SQL + `generate_series` (bypassing `save()`'s per-row S3+Postgres overhead — no FK on
  `device_id` in this table, confirmed safe) spanning 2 full batches + 1 partial, asserts all
  12,001 are deleted and a control fresh row survives — proves the loop fully drains a multi-batch
  range without needing thousands of slow round-trips. `#[ignore = "requires Docker"]`, not run
  locally (no Docker in sandbox), runs in CI's Rust workflow. `cargo build/test --workspace`
  clean, `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
  No `Cargo.lock` diff (no dependency changes) — `cargo audit`/`cargo deny check` not re-run.
- Target dir hygiene: not checked this cycle (FEATURE mode, next due cycle 365, STABILIZATION).
- **Next cycle candidates:** the multi-replica-GC-early-exit gap documented (not fixed) this
  cycle — would need a `FOR UPDATE SKIP LOCKED` subquery or `pg_try_advisory_lock` guard, shared
  with `run_gc`'s identical pre-existing gap, worth doing both together if ever prioritized;
  `map_sqlx` raw-error-text server-side logging (pre-existing, informational, affects every
  adapter method, cycle 363 carryover); media-key incoming/outgoing asymmetry (needs a new
  crypto-reviewed WASM key-export/local-storage-key design, confirmed genuinely multi-part cycle
  359); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid
  OPRF upgrade (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now
  ~1340 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 363 — FEATURE: daily GC trim job for media_upload_ledger, commit b578778)

- CI green (`gh run list --limit 3` all success), `gh issue list --state open` empty,
  `git status` clean at cycle start. Picked cycle 362's top carried-forward candidate: the
  accepted non-blocking gap in `media_upload_ledger` (the append-only table backing the
  per-device/per-day media upload byte quota) — no GC/TTL sweep existed, so it grew by one
  small fixed-width row per accepted upload, forever, across all devices.
- Dispatched an Explore-style scoping agent first (background) to locate the existing GC
  pattern before writing code: confirmed `bin/powehi-server/src/main.rs` already runs two
  `tokio::spawn` interval-loop background jobs (envelope GC every 300s via
  `EnvelopeRepository::delete_expired`, media blob GC every 3600s via `MediaService::run_gc`)
  — no cron/k8s CronJob/admin endpoint involved, everything in-process — and that
  `MediaService`'s existing `GC_RETENTION_DAYS = 30` (media_service.rs:32) + prd.md §11.4's
  documented 30-day default retention were the right precedent to reuse for this table's
  cutoff too (large margin over the 1-day quota-read window; no existing precedent for a
  tighter window).
- **What it does:** new `MediaRepository::trim_upload_ledger_older_than(cutoff) ->
  Result<u64, DomainError>` port method (`crates/ports/powehi-port-outbound/src/media_repo.rs`);
  `R2MediaAdapter` impl is a single parameterized `DELETE FROM media_upload_ledger WHERE
  uploaded_at < $1` returning `rows_affected()`. New daily (`interval(86400s)`)
  `tokio::spawn` loop in `main.rs`, same shape as the two existing GC loops, calling
  `trim_upload_ledger_older_than(now - GC_RETENTION_DAYS)` — reuses the constant (now `pub`)
  from `media_service.rs` rather than a duplicated literal, so the two retention windows
  can't silently drift apart. Required adding `chrono` as a direct dependency of
  `bin/powehi-server/Cargo.toml` (workspace-pinned, no new transitive dep — main.rs
  previously never called `chrono::` directly). Migration `0015`'s comment block updated
  from "known gap" to "closed cycle 363, see main.rs".
- **security-auditor: GREEN**, no blocking findings. Verified (not rubber-stamped): the
  30-day cutoff has a 29-day safety margin over the 24h rolling quota-read window with no
  code path (concurrent request, retry, clock skew) where an in-window row could be
  deleted — the two predicates (`>= now-1d` read vs `< now-30d` delete) are provably
  disjoint; the DELETE is fully parameterized with exactly one non-test call site (the
  background job itself — unreachable from any HTTP/gRPC/admin route since it lives on the
  outbound `MediaRepository` port, not the inbound `MediaUseCase` the handlers hold); no
  plaintext/PII/content logged (count-only `tracing::info!`); `rows_affected()` is a
  lossless `u64`, no cast; confirmed `threat-model-checker` genuinely not required — trims
  an internal-only table with no client-facing read path, net *decreases* server-retained
  metadata, no threat-model-negative delta. `cargo audit`/`cargo deny check` clean (1-line
  Cargo.lock diff: existing workspace-pinned `chrony` promoted to a direct dep, zero new
  transitive dependencies). Two low-severity non-blocking findings fixed same cycle: (a)
  the retention constant was a duplicated literal `30` in main.rs vs `GC_RETENTION_DAYS` in
  media_service.rs — fixed by making the constant `pub` and importing it; (b) the table's
  only index (`device_id, uploaded_at`) doesn't lead with `uploaded_at`, so each daily sweep
  is an unbatched full-table-scan DELETE — documented in place as an accepted low-severity
  gap (same unbatched shape as the pre-existing `EnvelopeRepository::delete_expired`,
  revisit if row volume ever makes scan time/lock hold matter). One informational-only,
  pre-existing, not-this-diff's-fault note left as-is: `map_sqlx` logs raw sqlx error text
  server-side only (no client exposure), same pattern as every other adapter method.
- 5 new/updated Rust tests: 2 new unit tests in `media_service.rs`'s `MockMediaRepo`
  (deletes-only-stale-rows, returns-zero-when-nothing-stale — mock's `trim_upload_ledger_older_than`
  now implemented too, required since it's a new trait method on `MediaRepository`, the only
  two implementors are `MockMediaRepo` and `R2MediaAdapter`); 3 new `#[ignore = "requires
  Docker"]` integration tests in `r2_media_it.rs` (deletes-only-rows-past-cutoff,
  does-not-touch-media_blobs — pins the no-FK invariant explicitly, returns-zero-when-
  nothing-stale) — not run locally (no Docker in sandbox), will run in CI's Rust workflow.
  `cargo build/test --workspace` clean (144 `powehi-application` unit tests green, +2 from
  cycle 362's 142 baseline count reported same-crate), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean (no reformatting needed).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** the two low-severity non-blocking notes this cycle chose to
  document rather than fix (unbatched full-scan DELETE on the ledger trim — revisit if row
  volume grows; `map_sqlx` raw-error-text server-side logging — pre-existing, informational,
  affects every adapter method, not specific to this diff); media-key incoming/outgoing
  asymmetry (still needs a new crypto-reviewed WASM key-export/local-storage-key design,
  confirmed genuinely multi-part cycle 359); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B,
  itself gated on Phase A); project-context.md size (now ~1290 lines, comfortably under the
  256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 362 — FEATURE: append-only media upload ledger closes delete-churn quota bypass, commit f30e9e0)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 361's top carried-forward candidate: the accepted residual gap in
  `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY`'s doc comment — `sum_bytes_uploaded_since` summed
  currently-live `media_blobs` rows only, so `upload -> confirm -> delete` in a loop let a
  device churn unbounded write ops/day within the 24h window while counted usage always
  read back near zero (storage stayed bounded, but write-op churn didn't).
- **What it does:** new migration `0015_media_upload_ledger.sql` — `media_upload_ledger(id
  UUID PK, device_id UUID, size_bytes BIGINT CHECK > 0, uploaded_at TIMESTAMPTZ)` +
  `(device_id, uploaded_at)` index, no FK to `media_blobs` (deliberate — must outlive the
  blob's deletion), regular (non-`CONCURRENTLY`) DDL since the table is new/empty at
  migration time. `R2MediaAdapter::save()` (`powehi-r2/src/lib.rs`) now opens a
  `PgPool::begin()` transaction and inserts into both `media_blobs` and
  `media_upload_ledger` (same `id` reused for both, both `ON CONFLICT (id) DO NOTHING`)
  before committing; `delete()` is unchanged — only touches `media_blobs`/R2, never the
  ledger. `sum_bytes_uploaded_since()` now queries the ledger instead of `media_blobs`, so
  a device's counted daily usage is monotonic within the rolling window regardless of
  deletes. Port trait signature unchanged (`media_repo.rs`), doc comments updated on both
  the port and `media_service.rs`'s `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY` (removed the now-
  closed caveat, left the still-accepted count-then-insert race-window note).
- **security-auditor: GREEN**, no blocking findings. Verified (not rubber-stamped):
  confirmed `R2MediaAdapter::save()` is the sole write path into `media_blobs` (no other
  `MediaRepository` impl, no bulk-import path) — no bypass route; the transaction means any
  partial failure aborts before `commit()` and an uncommitted `sqlx::Transaction` rolls back
  on drop, so the two tables can't diverge; all queries parameterized, no injection surface;
  `size_bytes BIGINT CHECK > 0` at the DB layer plus the existing `MAX_MEDIA_BYTES` (100MB)
  app-layer cap keeps the no-overflow reasoning valid; missing FK confirmed safe/intentional;
  non-`CONCURRENTLY` DDL confirmed correct (new table, same migration, no pre-existing-row
  contention unlike 0011/0014). One **non-blocking residual gap** flagged and documented in
  the migration file: the new ledger table has no GC/TTL sweep, so it grows unboundedly
  forever (small fixed-width rows, one per accepted upload, across all devices) — doesn't
  affect quota correctness or query performance (the rolling-24h sum only reads recent rows
  via the index), only slow permanent storage/index growth. Worth a future periodic trim job
  (delete rows older than N days, well past the 24h window). Confirmed scoping: not crypto
  (Postgres transaction + aggregate query, no MLS/OPAQUE/KDF/AEAD touched) —
  `crypto-reviewer` not required; not architectural, no new server-visible metadata (ledger
  columns mirror data already stored in `media_blobs`) — `threat-model-checker` not
  required. No plaintext/PII logged (`map_sqlx`/`map_r2` log only `error_kind`).
- 3 new/updated Rust tests: 1 new unit test (`media_service.rs`,
  `request_upload_quota_survives_delete_upload_churn` — primes 3 synthetic upload+delete
  cycles via direct `repo.save`/`repo.delete` at 40% of the daily cap each since a single
  real `request_upload` call is capped at `MAX_MEDIA_BYTES`=100MB, far below the 5GB daily
  cap; asserts a 4th real `request_upload` is still rejected despite zero live blobs), plus
  the in-memory `MockMediaRepo` test double reworked to model an immutable ledger separate
  from the mutable `saved` list (so this exact regression is now unit-test-catchable, not
  just integration-test-catchable); 1 new `#[ignore = "requires Docker"]` integration test
  in `r2_media_it.rs` (`sum_bytes_uploaded_since_survives_delete_against_real_postgres`)
  proving the same fix against real Postgres (no Docker in this sandbox, will run in CI's
  Rust workflow). `cargo build/test --workspace` clean (139 `powehi-application` unit tests
  green, was 138), `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo
  fmt --check` clean (no reformatting needed).
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** a periodic trim/TTL job for `media_upload_ledger` (this
  cycle's non-blocking residual gap — unbounded row growth, not urgent, cheap when picked
  up); the migration's `IF NOT EXISTS`-silently-no-ops-past-an-INVALID-index operational
  risk pattern (documented runbook note precedent from 0011/0014, not automated for 0014
  since nothing there drops an old index; N/A to 0015 since it doesn't use `CONCURRENTLY`);
  media-key incoming/outgoing asymmetry (still needs a new crypto-reviewed WASM key-export/
  local-storage-key design, confirmed genuinely multi-part cycle 359); PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B, itself gated on Phase A); project-context.md size (now
  ~1240 lines, comfortably under the 256KB Read cap — no action needed yet).

## Previous state (2026-08-25, cycle 361 — FEATURE: per-device/per-day media upload byte quota, commit e093ee8)

- CI green (`gh run list --limit 3` all success), `git status` clean at cycle start. Picked
  cycle 359's residual finding (carried forward through cycle 360's stabilization pass): no
  per-device/per-day byte quota existed for media uploads, only the shared per-IP
  `api_governor` rate limit (~4TB/day/IP sustained-worst-case).
- **What it does:** `MediaRepository::sum_bytes_uploaded_since(device_id, since)` (new port
  method) sums a device's live `media_blobs.size_bytes` since a given timestamp;
  `R2MediaAdapter` implements it as `SELECT COALESCE(SUM(size_bytes),0) FROM media_blobs WHERE
  uploader_device_id=$1 AND uploaded_at>=$2`. `MediaService::request_upload` now computes a
  rolling 24h window (`now - 1 day`, recomputed per call) and rejects with
  `InvalidInput("media_device_daily_quota_exceeded")` if `used + size_bytes >
  MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY` (5GB), same count-then-insert soft-cap pattern as
  `KeyPackageService::upload`. New migration `0014_media_blobs_device_uploaded_idx.sql`
  (`CREATE INDEX CONCURRENTLY IF NOT EXISTS` on `(uploader_device_id, uploaded_at)`, `--
  no-transaction`, additive-only — no old index dropped, so no `pg_index.indisvalid` guard
  needed unlike 0011-0013's precedent) makes the sum a bounded range scan instead of a full
  per-device table scan.
- **security-auditor: 1 round, needs-rework → fixed same cycle.** Required fix: the SUM query
  decoded as sqlx `i64`, but Postgres's `SUM(bigint)` returns `NUMERIC` (only `SUM(integer)`
  stays `bigint`), and this workspace's sqlx build has no `bigdecimal`/`rust_decimal` feature
  to decode `NUMERIC` — every call would have failed with a column-decode error, 500ing every
  media upload request (not a quota-bypass, but a full feature outage). The in-memory
  `MockMediaRepo` test double couldn't catch this since it never touches real SQL types, and
  Docker wasn't available locally to run the real-Postgres integration test before commit —
  fixed with an explicit `::BIGINT` cast (safe: `size_bytes` is capped at `MAX_MEDIA_BYTES`
  100MB per row, overflow past `i64::MAX` is physically impossible). 2 non-blocking
  recommendations, both applied: (a) tightened the race-window doc comment — concurrent
  same-device requests can overshoot by at most ~2x the cap in one shot, bounded by the
  per-IP governor's burst=60, not unbounded drift; (b) documented an accepted residual gap —
  `upload → confirm → delete` in a loop resets the live-bytes sum, so the quota bounds
  *storage* (correctly) but not *write-op churn* per day (an append-only usage ledger would
  close this, out of scope this cycle). Confirmed scoping: not crypto (S3 presign params +
  Postgres aggregate + application arithmetic, no MLS/OPAQUE/KDF/AEAD touched) —
  `crypto-reviewer` not required; not architectural, no new server-visible metadata
  (`uploader_device_id`/`uploaded_at`/`size_bytes` were already server-visible columns since
  the original `0003_media_blobs.sql`, this only adds a new read pattern over them) —
  `threat-model-checker` not required. No plaintext/PII logged (`#[instrument]` on the new
  adapter method only fields `device_id`, an opaque UUID).
- 8 new Rust tests: 4 unit (`media_service.rs`, in-memory mock) covering over-quota rejection,
  exact-boundary acceptance, stale (>24h) usage not counting, and per-device isolation; 2 new
  `#[ignore = "requires Docker"]` integration tests in `r2_media_it.rs` (sum scoped to device
  + window, zero-for-no-uploads via `COALESCE`) that will run in CI's Rust workflow (no Docker
  in this sandbox to run them locally, consistent with every other `r2_media_it.rs` test).
  `cargo build/test --workspace` clean (146 `powehi-application` + 7 `powehi-r2` unit tests
  green, 21 `r2_media_it.rs` tests correctly `ignored`), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean.
- Target dir hygiene: not checked this cycle (FEATURE mode, not due — next due cycle 365,
  STABILIZATION).
- **Next cycle candidates:** the 2 accepted-residual gaps from this cycle's security-auditor
  pass (both documented in `MAX_MEDIA_BYTES_PER_DEVICE_PER_DAY`'s doc comment, neither
  blocking): an append-only usage ledger to close the delete-resets-usage write-op-churn gap;
  the migration's `IF NOT EXISTS`-silently-no-ops-past-an-INVALID-index operational risk (now
  has a runbook note in the migration file itself, same as 0011's, not automated like 0012's
  since nothing here drops an old index); media-key incoming/outgoing asymmetry (still needs
  a new crypto-reviewed WASM key-export/local-storage-key design, scoped via Explore agent
  cycle 359, confirmed genuinely multi-part); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B, itself
  gated on Phase A); project-context.md size (now ~1180 lines / ~96KB after cycle 360's
  archive, comfortably under the 256KB cap — no action needed yet).

## Previous state (2026-08-25, cycle 359 — FEATURE: bind size_bytes into presigned R2 upload signature, commit 62541bb)

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

