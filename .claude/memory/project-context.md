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

## Current state (2026-09-08, cycle 461 — FEATURE: fix GitHub issue #6, `pnpm build:wasm` wrote to the wrong out-dir and Vite silently substituted a no-op crypto stub, commit 86ccec7)

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

## Previous state (2026-09-07, cycle 452 — FEATURE: finish and land cycle 451's orphaned WIP implementing cycle 450's candidate #3 (pending_removals retention sweep), commit ddfa5c8)

- Mode selection: counter 451→452, 452 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on `main`. `gh issue list --state open`: empty.
  **Working tree was NOT clean at session start** — same process gap as
  cycles 448/449: cycle 451 had done substantial, coherent, well-tested
  work (a bounded daily retention sweep for `pending_removals`, closing
  cycle 450's flagged "no retention cap or sweeper" gap, modeled on the
  media-orphan-sweep pattern) but never committed it. Read the whole diff
  file-by-file to verify coherence (new `GroupRepository::sweep_stale_
  pending_removals` port+Postgres-impl, a background job in `main.rs`
  offset from the other 3 GC jobs, new config knobs, index migration
  0021, new pg_security_it.rs tests, Helm wiring, prd.md updates) before
  treating "land the abandoned WIP" as this cycle's action.
- `cargo build/test/fmt/clippy` all green on the WIP as found, `gh run
  list`/`gh issue list` clean, `helm lint`/`conftest` clean on all three
  overlays — then ran all three mandatory review gates on the whole diff
  before committing any of it.
- **crypto-reviewer: needs-rework → fixed.** Real findings: (1) the new
  `MIN_DATABASE_MAX_CONNECTIONS=5` derivation was wrong — its own doc
  comment claimed "at most one of the daily/6h jobs overlaps the hourly
  job", but the actual `tokio::time::interval` schedules (confirmed by
  reading `main.rs` directly, not trusting the comment) show media blob
  GC (hourly, unskipped) + media ledger trim (24h, unskipped) + media
  orphan sweep (6h, first tick skipped) all collide at t=24h, 48h, ... —
  a real 3-job collision needing 6 connections, not 2 jobs needing 4;
  fixed by raising the floor to 7 and correcting the doc/error-message
  math (the new pending-removals job's own 3h+24h offset to t=27h, 51h
  was already correctly designed to avoid adding a 4th job to that
  collision — only that constant's justification was wrong); (2) the
  epoch-gate doc claimed it "preserves the cost floor" of `delete_pending_
  removal` (paraphrased: "erasing a reminder costs ≥1 Commit") — false,
  since the gate is satisfied by *any* member's *any* Commit (e.g. a
  routine self-Update), not an action by the party wanting to suppress
  the reminder, so the real marginal cost to an adversary in a live group
  is 0, not 1 — reworded in the port doc, `main.rs`, and prd.md to state
  it's a *group liveness filter*, not an attacker-cost floor (only
  protects fully dormant groups, which it does correctly per a dedicated
  test); (3) required shipping `pending_removal_sweep_enabled` defaulted
  to `false` (not `true`) since no frontend consumer of `pending_removals`/
  `RemovalRequired` exists yet and there's no alternative reconciliation
  channel — enabling by default would have silently discarded the one
  durable signal cycle 448's feature exists to provide before any client
  could act on it; (4) switched the sweep's `DELETE` from a `ctid`-based
  plan to the natural key `(group_id, device_id)` — the `ctid` version's
  safety relied on a prose-only "never UPDATEd in production" invariant
  that the diff's own new test helper (`backdate_pending_removal`)
  already violates (test-only, but fragile precedent), with zero
  performance reason to prefer `ctid` since the PK is already indexed;
  added the eligibility predicate redundantly to the outer `WHERE` for
  fail-closed behavior; (5) added an `ORDER BY ..., group_id, device_id`
  tie-breaker for a true total order (ties are common: one device
  revoked across many groups shares one `now()`); (6) documented a
  pre-existing (not new) epoch-read race in `create_pending_removal`
  that this sweep is the first automatic path to act on.
- **security-auditor: needs-rework → fixed.** Independently found the
  same `MIN_DATABASE_MAX_CONNECTIONS` bug (F1, medium) — two reviewers
  converging on identical math from separate diff reads was a strong
  signal it was real. Also found: Helm `values.schema.json`'s
  `pendingRemovalSweepTimeoutSecs` had `minimum: 1` while Rust's real
  floor is 30 (schema would pass an operator value that then crash-loops
  the pod at startup) — same gap existed for the raised
  `databaseMaxConnections` floor — fixed both schema minimums to match
  Rust's `validate()` exactly, and verified via `helm template --set` that
  each now actually rejects the bad value CI would otherwise let through.
  Confirmed clean on all other axes (SQL parameterization, no plaintext
  logging, no new `unwrap()`/`expect()`, advisory lock uniqueness/release
  paths, no new attack surface).
- **threat-model-checker: YELLOW → addressed.** Required prd.md fixes,
  all applied: (1) the diff's "다만 이제 최대 30일로 상한" line was wrong
  in two ways simultaneously (30 days is a floor for active groups, not
  a ceiling — actual deletion lags grace+tick+backlog — and dormant
  groups are *never* swept, i.e. no ceiling at all for them) — rewritten
  to state both facts correctly; (2) the diff already had `GET /v1/
  groups/:group_id/pending-removals` live (from cycle 448/449) but its
  own residual-risk paragraph didn't mention this, framing "no one reads
  the reminder before it's swept" as a narrow edge case when it's
  actually the default outcome for every active group until a frontend
  policy consumes that endpoint — text now says so explicitly and ties it
  to the default-`false` decision above; (3) added a new §3.5.1 paragraph
  on a multi-region interaction the diff hadn't covered: `groups.epoch`
  advances in a group's home region regardless of which region a member
  is connected to, but the notification itself is region-local, so a
  member who structurally can never receive the alert can still be the
  one whose routine Commit satisfies the sweep's epoch gate.
- **Full gate, re-run after every fix round**: `cargo build --workspace
  --all-targets` clean, `cargo test --workspace` all green (0 failures),
  `cargo fmt --all --check` clean, `cargo clippy --workspace --all-targets
  -- -D warnings` clean. `helm lint` + `conftest test --combine` (7/7)
  clean on all three overlays; `helm template --set
  config.pendingRemovalSweepTimeoutSecs=5` and `--set
  config.databaseMaxConnections=4` both now correctly rejected by schema
  (previously would have passed CI and crashed at pod startup).
- Committed `ddfa5c8` (`feat(security): add bounded retention sweep for
  pending_removals`), 18 files changed (17 modified + new migration
  0021), pushed clean (`1d6d5eb..ddfa5c8 main -> main`).
- **Process note, same lesson as cycle 450**: this is the second time in
  three stabilization/feature cycles that a prior cycle did real,
  substantial work and burned its counter slot without committing.
  Worth a future cycle explicitly checking `git status` for uncommitted
  work as step 0, before mode-specific logic, rather than only
  discovering it via the git-status system reminder.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated):**
  1. Carried: PQ hybrid Phase A prerequisite (ml-kem 0.2.3→0.3.2 +
     libcrux/x-wing admissibility) — human/crypto-lead policy call.
  2. Carried, still explicitly BLOCKED: wiring
     `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal` into a real
     caller needs F3 (incl. the `IpHash` extension) and the
     HMAC-vs-plain-SHA256 gate resolved first — do not wire without
     re-reading both prd.md sections.
  3. **New, real, needed before the sweep can ever be turned on:** wire a
     frontend consumer of `GET /v1/groups/:id/pending-removals` /
     `RemovalRequired` with a confirmation-gated policy (prd.md §5.4's
     trust-boundary note — never auto-execute), and/or a group-scoped
     device-list endpoint clients can reconcile against. Until one of
     these exists, `pending_removal_sweep_enabled` must stay `false` in
     every environment — do not flip it to `true` as a quick config
     change without re-reading prd.md §3.3's residual-risk paragraph.
  4. Carried: no `values-prod-*.yaml`/CI overlay actually flips
     `monitoring.prometheusRule.enabled=true` yet in a real
     kube-prometheus-stack install (ops/environment-config task).
  5. Carried: CI has no job that renders the Helm chart with
     `monitoring.prometheusRule.enabled=true`/`serviceMonitor.enabled=true`
     (ci-pipeline-author follow-up, not urgent).
  6. Carried, doc-sync only: prd.md documents `key_packages.device_id` as
     having `REFERENCES devices(id)`; the actual schema never had this FK.
  7. Carried, real but scoped out (needs a GC/lifecycle decision):
     consumed `key_packages` rows are never garbage-collected.
  8. Carried, low-priority hardening (crypto-reviewer, cycle 450):
     `GroupRepository::save` is a blind `ON CONFLICT DO UPDATE` with no
     production caller today; worth a doc comment forbidding it from ever
     advancing epoch, before any future caller appears.

## Previous state (2026-09-07, cycle 450 — STABILIZATION: finish and land cycles 448/449's orphaned WIP closing the MLS-Remove-notification gap from cycle 447's candidate #8, commit 9796cba)

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

