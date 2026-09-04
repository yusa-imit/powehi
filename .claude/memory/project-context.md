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

## Current state (2026-09-04, cycle 434 — FEATURE: finished + hardened + committed cycle 433's cross-region abuse-signal propagation, commit 325ad1e)

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
