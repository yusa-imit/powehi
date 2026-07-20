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

## Current state (2026-07-20, cycle 325 — STABILIZATION: land orphaned draft-persistence work + full sweep, commit c1ab6d5)

- `git status` at cycle start was **not clean** — cycle 324 apparently ran an
  entire FEATURE cycle (implementing per-chat unsent-composer-draft
  persistence to Dexie: schema v17 `GroupRow.draft`, `EncryptedPowehiDb.
  setGroupDraft`/`getGroupDraft`, debounced persist + rehydrate in
  `ChatLayout.tsx`, 4 new test files' worth of coverage) but never reached
  its commit step — no cycle-324 entry exists in this file and `git log`
  showed cycle 323's memory-update commit (`da4a4f1`) as HEAD. Treated as
  recoverable dropped work per CLAUDE.md's "investigate before
  deleting/overwriting uncommitted state" guidance, not as something to
  discard and redo — the diff was complete, coherent, and well-commented
  (draft is genuinely sensitive content, correctly added to
  `SENSITIVE.groups` alongside `mlsStateB64`/`name`, unlike the plain-
  preference fields slowMode/theme/mute use).
- `gh run list --limit 3` all green at cycle start, `gh issue list --state
  open` empty.
- Validated the recovered diff before touching anything further: `tsc -b`
  clean, `biome check` clean (170 files), frontend `pnpm test --run`
  **1347/1347 tests green** (104 files, was 1338 — net +9: 2 in
  `ChatLayoutDraft.test.tsx`, 4 in `encrypted-db.test.ts`, 2 in
  `schema.test.ts`, plus a pre-existing `ChatLayoutSlowMode.test.tsx` fake-
  timer-flush fix in `afterEach` bundled in the same uncommitted diff).
- **security-auditor: GREEN, no findings.** Independently verified (not
  taken on the diff's own comments): `draft` is genuinely covered by the
  encryption tier and never read/written as plaintext through any other
  `db.groups.update`/`.get` call site in `ChatLayout.tsx`; no plaintext
  draft ever reaches `console.*`/telemetry (none exist in these files); the
  per-chat-id `draftPersistTimersRef` debounce Map cannot leak a draft to
  the wrong chat under rapid switching (each timer closes over its own
  `id`/`draft`); `Dexie.waitFor()` around the encryptor call commits only
  the final ciphertext, no partial/plaintext-commit window; grep confirmed
  `draft`/`setGroupDraft`/`getGroupDraft` never touch any API client/
  WebSocket/MLS payload construction; the late-arriving-draft effect in
  `Composer` (`!editingMessage && text === ""` guard, plus a parent-side
  `prev[chatId] === undefined` guard) cannot clobber in-progress typing
  under any interleaving. One harmless note: `getGroupDraft` is unused in
  production (rehydration decrypts inline via the crypto worker instead) —
  exists for test coverage only, not a leak.
- Not architectural, no new server-visible metadata (purely local
  IndexedDB persistence of text that was already living in React state,
  never sent to server, never part of any MLS payload) —
  `threat-model-checker`/`crypto-reviewer` not required, same scoping as
  the slowMode/theme/mute/receipt persistence work in cycles 312-323.
  Reuses the existing `FieldEncryptor` mechanism — no new crypto
  primitives, so `crypto-reviewer` wasn't needed despite `draft` being
  genuinely sensitive content (contrast: it *would* be needed if this had
  introduced a new encryption scheme rather than reusing the established
  one).
- Committed as `c1ab6d5` (frontend files only — `git add` on the 7 touched
  paths, no `-A`), pushed, new CI runs queued at push time (not polled to
  completion before this memory update — the pre-existing cycle-323 CI run
  was already green, and this push only adds already-tested frontend code
  through the same pipeline).
- **Backend sweep (STABILIZATION full-sweep step, since backend wasn't
  touched by the recovered diff):** `cargo build --workspace` clean,
  `cargo test --workspace --lib` all green across all 17 crates (0
  failures), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo audit` clean (653 crates, 0 advisories), `cargo deny
  check` clean (advisories/bans/licenses/sources all ok). Note: this
  shell's `$PATH` didn't include `~/.cargo/bin` by default this cycle
  (`cargo`/`rustc` "command not found" until explicitly prepended) — worth
  a one-line callout in case a future cycle hits the same thing and
  wastes time on it; not fixed at the environment level since it's a
  per-invocation shell-init quirk, not a repo config issue.
- Target dir hygiene: 27G → pruned 0 zero-byte `.rmeta` stubs (none found)
  → still over the 20G threshold → mtime+7 prune of `.rlib`/`.rmeta`/`.o`/
  `.d` files and stale incremental dirs → 24G, 103,038 files in
  `target/debug/deps` (well under the 291k pathological-growth historical
  incident). Housekeeping only, not the cycle's mandatory commit.
- **Next cycle candidates:** PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768` — re-check crates.io periodically, not every
  cycle); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B
  95%-session threshold, not yet actionable); the still-standing opaque-ke
  live-migration login-round-trip regression test gap (cycle 318/319, no
  prod users yet, low urgency); a future cycle should double-check `gh run
  list` for this cycle's queued CI runs actually landed green (queued, not
  polled, at memory-update time); the unused `getGroupDraft` production
  dead-code note above (trivial, cosmetic, not urgent); consider whether
  the cron harness itself should be hardened against a cycle silently
  failing to commit (this is now the second time — worth noting if it
  recurs a third time) rather than relying on the next cycle to notice and
  recover the diff.

## Previous state (2026-07-20, cycle 323 — FEATURE: persist group slow-mode delay to Dexie, commit c12e540)

- `git status` clean, `gh run list --limit 3` all green at cycle start, `gh issue
  list --state open` empty. No unchecked `- [ ]` items remain in this file's phase
  checklist (all 6 phases complete) — used an Explore agent to survey for a
  genuinely new, still-open gap the same way cycles 314/321 found voice messages
  and receipt persistence: grepped dead UI affordances and React-state-only
  settings that should be in Dexie but aren't.
- Found: the admin "slow mode" per-chat message cooldown (InfoPanel dropdown,
  `SLOW_MODE_OPTIONS = [0,5,30,60,300,3600]`) was fully wired end-to-end (admin
  toggle, composer banner, send cooldown gate, countdown badge) but lived purely
  in `const [slowModeDelay, setSlowModeDelay] = useState<Record<string,
  SlowModeDelay>>({})` — zero `GroupRow` field, zero persist/rehydrate. Every
  reload silently reverted every group's slow mode to Off, including for the
  admin who set it. Same bug class as cycles 312/314/321 (a shipped feature
  missing the Dexie write path), verified myself (not taken on the Explore
  agent's word) by grepping `slowModeDelay` across `ChatLayout.tsx` and
  `app/src/db/*.ts` before touching anything.
- **Fix (self-implemented, no delegation needed — small, well-established
  pattern):** added `GroupRow.slowModeDelay?: number` (schema v16, additive, no
  index change — same non-sensitive tier as `disappearingTtlSeconds`/`chatTheme`,
  confirmed via `SENSITIVE.groups` in `encrypted-db.ts` still `["mlsStateB64",
  "name"]` only). New `handleSetSlowMode(chatId, delay)` callback mirrors
  `handleToggleMute`/`handleSetChatTheme` exactly: `setSlowModeDelay` update +
  `chatsRef.current.find(...)` + `db.groups.update(chat.mlsGroupId, {
  slowModeDelay: delay }).catch(() => {})`, replacing the old inline
  `onSetSlowMode` JSX prop. Rehydration added to the existing "load persisted
  disappearing timer" effect (7430ish): reads `row.slowModeDelay`, validates
  against `SLOW_MODE_OPTIONS.includes(...)` before restoring (fails safe to
  "off" on a corrupted/stale non-numeric value — `Array.includes` uses strict
  `===`), keyed by `activeId` (the in-memory Record's key) not `mlsGroupId`
  (added `activeId` to that effect's dependency array since it's now read
  directly in the body).
- **security-auditor: GREEN, no findings.** Independently confirmed: field
  correctly omitted from the encryption tier, allowlist-gated rehydration fails
  safe on corrupted data (no type confusion/oracle), numeric `<select>` value
  never touches HTML rendering or DB queries (no injection surface), missing-
  `mlsGroupId` case guarded identically to the mute/sound/vibrate handlers this
  pattern was cloned from.
- Not architectural, no new server-visible metadata (purely local UI preference,
  never sent to server, never part of any MLS payload) — `threat-model-checker`/
  `crypto-reviewer` not required, same scoping as the chatTheme/muted/receipt
  persistence work in cycles 312-322.
- 4 new tests: 2 in `schema.test.ts` (stores/retrieves `slowModeDelay`, leaves
  undefined when unset — v16 pattern), 2 in `ChatLayoutSlowMode.test.tsx`
  (persist-on-admin-change round-trips through `db.groups.get`, rehydrate-on-
  chat-switch restores the select value from a pre-seeded row). Had to add
  `vi.useRealTimers()` at the top of both new tests — the file's `beforeEach`
  sets `vi.useFakeTimers({ shouldAdvanceTime: false })` for the countdown-badge
  tests, which silently hung RTL's `waitFor` (fake clock never advances, so its
  internal polling never re-checks) until my own two new tests were the only
  ones timing out; real timers don't affect Dexie's microtask-based resolution.
  `tsc -b` clean, `biome check` clean (4 touched files, 1 format-only autofix
  applied). Frontend `pnpm test --run`: **1338/1338 tests green** (104 files,
  was 1334, net +4). Backend untouched this cycle (pure frontend/Dexie change,
  confirmed via `git diff --name-only`).
- **Next cycle candidates:** PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768` as of cycle 318's last check — worth a fresh crates.io
  check, not done this cycle); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B 95%-session threshold, not yet actionable); the still-standing
  opaque-ke live-migration login-round-trip regression test gap (cycle 318/319,
  no prod users yet, low urgency); `.claude/memory/project-context.md` file size
  (~210KB / 2700+ lines after this entry, was ~205KB at cycle 322 — climbing
  again since the cycle-320 archive; still under the 256KB Read cap but worth
  archiving cycles ~280-310 at the next STABILIZATION cycle, 325, if it keeps
  growing at this rate).

## Previous state (2026-07-20, cycle 322 — FEATURE: fix concurrent read-receipt readBy race, commit 331dfab)

- `git status` clean, `gh run list --limit 3` all green at cycle start, `gh issue
  list --state open` empty. Picked the top cycle-321 next-cycle candidate: the
  security-auditor YELLOW that `persistRead`'s `readBy` was a full-replace
  array computed from a possibly-stale in-memory snapshot — two `read_receipt`s
  for the same message from different devices arriving in quick succession
  could race, with the later Dexie write overwriting (not merging) the
  earlier one's entry, undercounting "Seen by N" after a reload.
- **Fix, at the persistence layer (`EncryptedPowehiDb.markMessageRead`,
  `encrypted-db.ts`):** wrapped a read-then-write in
  `this.db.transaction("rw", this.db.messages, async () => {...})` — reads
  the currently-persisted row's `readByJson` (safe try/catch parse, defaults
  to `[]` on corruption), unions it with the caller-supplied `readBy` via
  `Array.from(new Set([...existing, ...readBy]))`, writes the merged set.
  Relies on IndexedDB's guarantee that readwrite transactions on the same
  object store serialize — the second transaction's read always observes the
  first transaction's committed write, closing the race rather than just
  narrowing it. `readByJson` confirmed still not in `SENSITIVE.messages` (raw
  `db.messages.get()` used deliberately, not the decrypting `getMessage()` —
  no wasted/incorrect crypto). Updated the now-stale "deferred, not fixed"
  doc comment in `usePersistentMessages.ts`'s `persistRead` to describe the
  fix instead. No call-site changes needed — `ChatLayout.tsx`'s
  `handleIncomingReadReceipt`/`persistRead(m.id, readBy)` call is unchanged;
  the caller's snapshot is now just one input to the DB-layer merge, not the
  sole source of truth.
- **security-auditor: GREEN, no findings.** Independently confirmed (not
  taken on faith): `readByJson` non-sensitivity, the same-store IDB
  transaction-serialization argument is sound and genuinely closes (not just
  narrows) the race, no new oracle/no new plaintext logging, forged-receipt
  durability unchanged (still gated by server-authenticated
  `senderDeviceId`), `Set`-based dedup only collapses exact-duplicate IDs
  (distinct IDs preserved), and the 3 new tests would fail against the old
  blind-overwrite implementation (verified by re-running them).
- Not architectural, no new server-visible metadata (pure client-side Dexie
  write-path fix, same wire format, same receipt trust model) —
  `threat-model-checker`/`crypto-reviewer` not required, same scoping as
  cycle 321's original receipt-persistence work.
- 3 new tests in `encrypted-db.test.ts`: sequential-calls-union,
  duplicate-reader-id-dedup, and a concurrent `Promise.all` race test that
  reproduces the pre-fix race and asserts both devices' entries survive.
  `tsc -b` clean, `biome check` clean (3 touched files). Frontend
  `pnpm test --run`: **1334/1334 tests green** (104 files, was 1331, net +3).
  Backend untouched this cycle (pure frontend/IndexedDB fix, confirmed via
  `git diff --name-only`).
- **Next cycle candidates:** PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768` — re-check periodically); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold, not yet
  actionable); the still-standing opaque-ke live-migration login-round-trip
  regression test gap (cycle 318/319, no prod users yet, low urgency); the
  `.claude/memory/project-context.md` file size is climbing again (~205KB /
  2650+ lines after this entry, cycle 320 archived it down to ~197KB at
  cycle-320-time) — not yet urgent (well under the 256KB Read cap) but worth
  a glance at the next STABILIZATION cycle (325) if it keeps growing.

## Previous state (2026-07-19, cycle 321 — FEATURE: persist delivery/read receipts to Dexie, commit d02ece3)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue
  list --state open` empty. Ruled out the two survey candidates first: an
  Explore-agent survey confirmed "pins/mentions remain session-only" (the
  cycle-254 next-cycle note) is now **stale** — `pinnedMessageId` was
  persisted at schema v9 (cycle 259) and `mentionCount` at v13 (commit
  497a148), both fully wired with rehydration; dropped that note. Instead
  found a genuinely new, still-open gap by grepping `ChatMessage` fields
  against `MessageRow`/`GroupRow`: `delivered`/`read`/`readBy` (delivery and
  read receipts) had zero Dexie fields and zero persist functions — every
  reload silently reset "seen"/"delivered" checkmarks on real receipts.
- Delegated to `frontend-lead`: added `MessageRow.delivered?/read?/readByJson?`
  (schema v15, additive, not sensitive — same tier as already-unencrypted
  `senderDeviceId`/`deletedAt`, NOT added to `SENSITIVE.messages`),
  `EncryptedPowehiDb.markMessageDelivered`/`markMessageRead`, and
  `persistDelivered`/`persistRead` in `usePersistentMessages.ts` (exact
  fire-and-forget + `pendingWriteIds` mirror of `persistEdit`/`persistDelete`/
  `persistReaction`). Rehydration effect now restores `delivered`/`read`/
  `readBy` (defensive `readByJson` parse, fails safe per-row like
  `reactionsJson`) and the out-of-band reconciliation path now covers all
  three fields too.
- **Caught and fixed an agent deviation before commit:** the frontend-lead's
  first pass called `persistRead`/`persistDelivered` **inside** the `setChats`
  updater callback in `handleIncomingReadReceipt`/`handleIncomingDeliveryReceipt`
  — an impure-updater side effect this file's own established convention
  (and inline comments on `handleIncomingEdit`/`handleIncomingDelete`/
  `handleIncomingReaction`) explicitly avoids, computing persist calls from a
  `chatsRef.current` pre-update snapshot AFTER `setChats` instead. Rewrote
  both handlers to match. The agent's task also silently dropped the
  ChatLayout-level test requirement (its final message cut off mid-task) —
  added those tests myself: 2 persistence-assertion tests in
  `ChatLayoutReadReceipts.test.tsx` (delivery/read receipt → `db.messages.get`
  round-trip) + 1 `readByJson`-corruption-safety rehydration test in
  `ChatLayout.test.tsx`.
- **security-auditor: PASS.** GREEN on encryption-tier boundary (device IDs/
  booleans, not content), GREEN on receipt-forgery-durability (senderDeviceId
  is server-authenticated `env.sender`, same field regular messages use;
  `from` on rehydration is derived independently from the *original* row's
  `senderDeviceId`, never from the receipt's sender, so a forged receipt
  gains no more durability than it already had transiently), GREEN on
  no-plaintext-logging, GREEN on corrupt-JSON fail-safe parsing. One **YELLOW
  (correctness, not security, documented inline in `usePersistentMessages.ts`,
  not fixed)**: `persistRead`'s `readBy` is a full-replace array from a
  snapshot that can be stale by write time — two read_receipts for the same
  message from different devices in quick succession can race and the later
  Dexie write overwrites rather than merges the earlier one's entry,
  undercounting "Seen by N" after a reload. In-memory state is unaffected
  (functional `setChats` always sees true latest state); only the persisted
  copy can lag. Same latent limitation `persistReaction` already has —
  low severity, deferred.
- Not architectural, no new server-visible metadata (purely local persistence
  of receipts that were already being received over the wire) —
  `threat-model-checker`/`crypto-reviewer` not required, consistent with how
  cycles 252-254 scoped the identical edit/delete/reaction persistence work.
- `tsc -b` clean, `biome check` clean (170 files). Frontend `pnpm test --run`:
  **1331/1331 tests green** (104 files, was 1316 — net +15: 4 in
  `encrypted-db.test.ts`, 8 in `usePersistentMessages.test.ts`, 2 in
  `ChatLayoutReadReceipts.test.tsx`, 1 in `ChatLayout.test.tsx`). Backend
  untouched this cycle (pure frontend/IndexedDB feature).
- **Next cycle candidates:** the `persistRead` concurrent-readBy-overwrite
  YELLOW noted above (low priority, cosmetic underscount only); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768` — re-check
  periodically); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B
  95%-session threshold, not yet actionable); the still-standing opaque-ke
  live-migration login-round-trip regression test gap (cycle 318/319, no
  prod users yet, low urgency).

## Previous state (2026-07-19, cycle 320 — STABILIZATION: project-context.md archive + full sweep)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue
  list --state open` empty. `cargo audit` clean (653 crates, 0 advisories),
  `cargo deny check` clean (advisories/bans/licenses/sources all ok). Full test
  sweep before touching anything: `cargo test --workspace` all green, `cargo
  clippy --workspace --all-targets -- -D warnings` clean, frontend `pnpm test
  --run` **1316/1316 tests green** (104 files), `tsc -b` clean, `biome check`
  clean (170 files, no fixes needed). `cargo nextest` is not installed in this
  environment — used the documented `cargo test --workspace` fallback.
- Picked the item flagged as overdue across cycles 316/317/318/319: this file
  (`project-context.md`) had grown to ~630KB / 5949 lines — past the Read tool's
  256KB single-read cap, meaning a future cycle reading it whole would already be
  failing (confirmed: `Read` on the untouched file errored with "exceeds maximum
  allowed size"). Archived the verbose "Previous state" entries for cycles 20–277
  (3460 lines, ~440KB) to `.claude/memory/archive/project-context-cycles-20-277.md`
  — unmodified content, just relocated. Kept the last ~30 cycles (279 through 320)
  inline, plus the phase checklist, autonomous-dev notes, and the condensed
  "Cycle log (recent)" section untouched. Live file is now ~197KB — back under the
  Read cap. Also noted (not separately fixed, no code impact): cycles 316–319
  never appended to the older "Cycle log (recent)" condensed-format section below
  — that section predates cycle ~262 and both formats now coexist; left as-is
  since the per-cycle "Current state"/"Previous state" entries are the actual
  source of truth and are complete.
- Not a crypto/architectural/backend-handler change (pure documentation/memory
  file reorganization, zero code touched) — `crypto-reviewer`/`threat-model-checker`/
  `security-auditor` not required; confirmed via `git status`/`git diff` scope
  before commit (only `.claude/memory/**` paths changed).
- Target dir hygiene: 28G → pruned 0-byte aborted-build `.rmeta` stubs (none
  found this time) → still 27G (over the 20G threshold, mtime+7 prune found
  nothing stale enough — same "recent/warm cache" pattern noted in cycles 307/310/
  315), 120,530 files in target/debug/deps — well under the historical 291k-file
  pathological-growth incident, no further action needed.
- **Next cycle candidates:** PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768` — re-check crates.io/openmls source periodically, not every
  cycle); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold, not yet actionable); the crypto-reviewer's still-standing note from
  cycle 318 area about no regression test existing for a *live* opaque-ke version
  migration login round-trip (the cycle-319 fixture proved password-file interop
  only, not a full ServerSetup migration story — deferred, no prod users yet).

## Previous state (2026-07-19, cycle 319 — FEATURE: opaque-ke 3.0→4.0.1 password-file interop fixture, commit 02f592f)

- `git status` clean, `gh run list --limit 3` all green at cycle start. `gh issue
  list --state open` empty. Picked the top cycle-318-flagged item: crypto-reviewer's
  non-blocking YELLOW that the 3.0→4.0.1 wire-compat claim was proven only by source
  inspection, never a real stored-blob round-trip.
- Delegated to `crypto-lead`: added `#[cfg(test)] mod interop_v3` to
  `crates/adapters/outbound/powehi-opaque/src/lib.rs` with two hardcoded hex fixture
  blobs (`ServerSetup` 128B, `ServerRegistration` password-file 192B), generated by a
  throwaway standalone crate (NOT committed, deleted after use) pinned to opaque-ke
  3.0.0 with the exact pre-cycle-318 ciphersuite, driven by a seeded `ChaCha20Rng`
  for reproducibility.
- **Genuine finding surfaced (not just a green checkbox):** the per-user
  `ServerRegistration` password file IS byte-compatible 3.0.0→4.0.1 (deserializes
  cleanly — the invariant the reviewer asked to prove). But the server's long-term
  `ServerSetup` (OPRF seed + AKE keypair) is **NOT** wire-compatible across that
  boundary — both are 128 bytes but 4.0.1 rejects the 3.0 layout. Since login
  re-derives each user's OPRF key from `ServerSetup.oprf_seed`, password-file
  portability alone is necessary but not sufficient for a live-data migration; a
  cross-version *login* round-trip is structurally blocked without a portable/
  persisted `ServerSetup` or forced re-registration. Documented in both the new
  `interop_v3` module doc comment and `.claude/rules/crypto-libraries-pinned.md`
  ("opaque-ke major-version migrations" section) so any *future* opaque-ke major
  bump touching live credentials budgets for a `ServerSetup` migration story, not
  just a password-file fixture. No impact today — no prod users, `ServerSetup` is
  regenerated on startup (tracked Phase-5 limitation).
- **crypto-reviewer: GREEN.** Independently re-verified against opaque-ke 4.0.1
  source in the cargo registry cache (not the diff's own comments): confirmed the
  192B/128B byte-layout math for Ristretto255, confirmed `ServerRegistration::finish`
  and `::deserialize` never invoke the Argon2 KSF (so the fixture's stability claim
  vs. Argon2 param drift holds, scoped correctly — did flag as a documented boundary
  that this does NOT mean changing client-side Argon2 params is ever safe for
  already-stored files, since login itself re-runs the KSF), no secret-bytes logging
  risk (only `ProtocolError` variants/lengths on panic, obviously-fake password/
  identity strings), and confirmed opaque-ke 3.0.0 is not an actual workspace
  dependency (Cargo.lock/Cargo.toml show only 4.0.1; the 3.0.0 entry in the local
  registry cache is orphaned from the throwaway generator crate).
- Not architectural, no new server-visible metadata (test-only addition, no trait/
  port signature changes) — `threat-model-checker` not required.
- `cargo test -p powehi-opaque`: 10/10 green (8 pre-existing + 2 new). `cargo clippy
  -p powehi-opaque --all-targets -- -D warnings` clean. `cargo fmt --check` clean.
- **Next cycle candidates:** the **project-context.md file-size hygiene item is now
  significantly overdue** (flagged cycles 316, 317, 318 — this file is ~630KB/5900+
  lines; the next STABILIZATION cycle, currently cycle 320, MUST truncate/archive
  older "Previous state" entries — e.g. keep the last ~30 cycles inline, move the
  rest to a dated archive file — this is no longer optional deferral); PQ hybrid
  Phase A (still blocked on openmls stable PQ ciphersuite support — re-check
  periodically, not every cycle); OPAQUE PQ-hybrid OPRF upgrade itself (gated on
  ADR-0003 Phase B 95%-session threshold, not yet actionable).

## Previous state (2026-07-19, cycle 318 — FEATURE: upgrade opaque-ke 3.0→4.0.1 stable RFC 9807, commit 548289f)

- `git status` clean, `gh run list --limit 3` all green at cycle start. `gh issue
  list --state open` empty. Skipped both cycle-317-flagged candidates (PQ hybrid
  Phase A — re-verified via crates.io API: openmls `max_stable_version` is still
  0.8.1 with no `ml-kem`/`ml-dsa`/PQ ciphersuite in its source or feature list, so
  still genuinely blocked; and the project-context.md file-size hygiene item —
  that's a STABILIZATION-only task per the loop rules, not eligible this cycle).
  Instead checked crates.io for `opaque-ke` directly (the other standing waiver
  in `.claude/rules/crypto-libraries-pinned.md`, "2026-05-25: pinned at 3.0
  draft-16, only 4.1.0-pre.2 pre-release available, no production deploy until
  resolved") and found **`max_stable_version: 4.0.1`** now published — the RFC
  9807 stable release the waiver was waiting on.
- Delegated the migration to `crypto-lead`: bumped `opaque-ke` 3→4.0.1 in lockstep
  across the server adapter (`crates/adapters/outbound/powehi-opaque`) and the
  WASM client (`crates/client/powehi-crypto-wasm/src/opaque.rs`,
  `wasm_exports.rs`). Four compiler-surfaced API breaks fixed, no logic change:
  (1) `CipherSuite::KeGroup` dropped, `TripleDh` is now generic —
  `TripleDh<Ristretto255, Sha512>` reproduces 3.x's implicit SHA-512 AKE hash
  exactly (verified against `voprf-0.5.0`'s `Hash = Sha512` for Ristretto255);
  (2) `ristretto255-voprf` cargo feature renamed to `ristretto255`;
  (3) `ServerLoginStartParameters` unified into `ServerLoginParameters`, now
  passed to both `start` and `finish` (both call sites use `::default()`, so no
  start/finish param-mismatch state-confusion risk); (4) `ClientLogin::finish`
  gained a leading `rng: &mut R` — production caller (`wasm_exports.rs`) uses
  `OsRng`, confirmed cryptographically secure.
- **crypto-reviewer: GREEN.** Independently re-derived the ciphersuite-equivalence
  proof from `opaque-ke` 3.0.0/4.0.1 and `voprf-0.5.0` source in the cargo cache
  (not taken on the migrating agent's word). Confirmed server/client suites
  byte-identical, RNG is `OsRng` on the only production finish call site, error
  paths still collapse to opaque `Unauthorized`/`InvalidInput` (no oracle), no
  start/finish param divergence, `Identifiers` idU/idS-unbound limitation (Y-4)
  unaffected — still deferred, not newly exposed. One **non-blocking YELLOW
  advisory** (follow-up, not fixed this cycle): no regression test proves a
  3.0-serialized `ServerRegistration` blob round-trips under 4.0.1 — moot today
  (no prod users, prd.md blocked deploy pending exactly this upgrade) but flagged
  so crypto-lead adds a persisted-vector interop guard before any future
  mid-flight version migration, and so client/server never split across major
  opaque-ke versions in a deploy window.
- Not architectural, no new server-visible metadata (pure library-version bump,
  `OpaqueServerPort` trait signature unchanged) — `threat-model-checker` not
  required, same scoping crypto-reviewer agreed with.
- Also updated: `.claude/rules/crypto-libraries-pinned.md` (waiver retired, now
  "opaque-ke 4.x — stable, RFC 9807"); `docs/decisions/0003-pq-migration.md`
  (base RFC 9807 upgrade marked done; PQ-hybrid OPRF (X25519+ML-KEM-768) kept as
  a distinct still-future Phase B item — these are two separate upgrades within
  opaque-ke's 4.x line, not the same thing).
- `cargo build --workspace` clean, `cargo test --workspace --lib` all green (0
  failures across every crate incl. `powehi-opaque` 8/8, `powehi-crypto-wasm`
  9/9 opaque-specific), `cargo clippy --workspace --all-targets -- -D warnings`
  clean, `cargo fmt --all --check` clean (after one `cargo fmt --all` pass on the
  two migrated files — rustfmt reformatted the newly-4-argument `finish()` calls
  to multi-line).
- **Next cycle candidates:** the crypto-reviewer YELLOW (persisted-vector interop
  regression test for opaque-ke version migrations, crypto-lead), PQ hybrid Phase
  A (still blocked, re-check crates.io periodically rather than every cycle now
  that opaque-ke's equivalent gate just resolved), OPAQUE PQ-hybrid OPRF upgrade
  itself (separate from what shipped this cycle, still gated on ADR-0003 Phase B
  95%-session threshold — not yet actionable), and the **project-context.md
  file-size hygiene item is now overdue** (flagged in cycles 316 and 317 too,
  still not done — file was ~620KB before this entry, now larger; next
  STABILIZATION cycle, currently cycle 320, should truncate/archive per the
  standing note rather than deferring again).

## Previous state (2026-07-19, cycle 317 — FEATURE: zero useThumbnail local key on import-failure path, commit bd39572)

- `git status` clean, `gh run list --limit 3` all green at cycle start. `gh issue
  list --state open` empty. Picked the trivial cycle-316-flagged YELLOW from the
  "next cycle candidates" list: `useThumbnail.ts`'s local raw-key `Uint8Array` copy
  was zeroed via `key.fill(0)` placed inside the `try` block right after a
  successful `mediaImportKey` await — if `mediaImportKey` itself threw, that line
  was never reached, leaving the local copy un-zeroed (low severity: the object
  just goes out of scope for GC, and the canonical `thumbnail.key` already persists
  in long-lived `chats` state regardless — but a real hygiene gap vs. the
  `mediaTransfer.ts` `try {...} finally { mediaKey.fill(0) }` pattern this file's
  own doc comment says it mirrors).
- **Fix:** moved `key.fill(0)` into the existing `finally` block (which already
  unconditionally drops the WASM key handle), so it now runs on every exit path —
  success, decrypt failure, or an `mediaImportKey` throw. Kept an additional
  idempotent `key.fill(0)` immediately after a successful import too, so the
  success-path zeroing window stays as tight as before this change (crypto-reviewer
  defense-in-depth suggestion, adopted).
- **crypto-reviewer: GREEN** (one informational YELLOW noting the finally-only
  version would slightly widen the success-path window — addressed by keeping
  the immediate post-import zero in addition to the finally one, both idempotent).
  Confirmed: doesn't touch/reintroduce zeroing of the canonical `thumbnail.key`
  (cycle 316's revert stays intact); outer `mediaHandleLimiter(...).catch()`
  abort-before-run zeroing path unaffected, no double-issue.
- Not architectural, no new server-visible metadata — `threat-model-checker` not
  required (same scoping as cycle 316 for this file).
- New regression test: `mediaImportKey` rejects → asserts the same `Uint8Array`
  reference the mock received is all-zero after the hook settles. Frontend:
  `tsc -b` clean, `biome check` clean, full suite **1316/1316 tests green**
  (104 files, was 1315, net +1).
- **Next cycle candidates:** PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768` — unverified for several cycles now whether that's still
  true, worth a fresh check rather than continuing to assume) and the standing
  `.claude/memory/project-context.md` file-size hygiene note — file was already
  ~620KB before this entry; a STABILIZATION cycle should truncate/archive older
  "Previous state" entries (e.g. keep last ~30 cycles inline, move the rest to a
  dated archive file) rather than letting it grow unbounded.

## Previous state (2026-07-19, cycle 316 — FEATURE: fix cycle-312 thumbnail canonical-key-zeroing regression + NIST citation fix, commit f84ed5a)

- `git status` clean, `gh run list --limit 3` all green at cycle start (cycle 315's
  CI-red + flaky-test fix had already landed and gone green). `gh issue list --state
  open` empty. Picked the standing carried-since-cycle-309 "media.mediaKey-not-zeroed
  cosmetic-symmetry" next-cycle candidate — but investigated it with an Explore agent
  FIRST rather than mirroring cycle 312's thumbnail pattern onto the main media path
  blindly, since naively "fixing the asymmetry" (zeroing `media.mediaKey` canonically
  too, to match the thumbnail path) looked like the obvious move.
- That investigation found the opposite of what was assumed: cycle 312's thumbnail
  fix (zeroing the canonical `thumbnail.key` synchronously, "crypto-reviewer advisory
  A") is itself a **real, already-shipped regression**, not a model to replicate.
  `ChatLayout.tsx`'s message list is unvirtualized with content-derived (not chat-id-
  derived) React keys, so switching chats away-and-back fully unmounts/remounts every
  message's `useThumbnail`/`MediaImage`, reusing the SAME `thumbnail`/`media` object
  reference from long-lived `chats` state (not re-fetched/re-parsed). Once the
  canonical `thumbnail.key` was zeroed on first display, every later revisit
  decrypted an all-zero key — the thumbnail permanently and silently vanished (caught
  by `useThumbnail.ts`'s own non-fatal catch, "full image will still load", so no
  error surfaced anywhere). Confirmed independently that `forwardMsg.media` in the
  "forward message" flow is *also* the same object reference as the inline
  `MediaImage`'s `media` prop — so the reason `downloadAndDecryptMedia` never zeroed
  its canonical `media.mediaKey` in the first place was NOT an oversight to fix, it
  was deliberately load-bearing (a zeroed key there would silently break forwarding
  an already-displayed image too).
- **Fix (reverted, not extended):** `useThumbnail.ts` no longer zeroes the canonical
  `thumbnail.key`; only the hook's local decrypt-time `Uint8Array` copy is zeroed
  (success path: right after WASM import, before decrypt; abort-while-queued path:
  in the limiter-rejection `.catch`) — this now exactly matches
  `downloadAndDecryptMedia`'s already-accepted pattern. Updated the hook's doc
  comment and the cycle-312 test that asserted canonical-zeroing (replaced with a
  test asserting the canonical key survives + a new regression test: render →
  decrypt → unmount → remount with the same object reference → decrypts
  successfully a second time).
- **Also fixed (unrelated, doc-only):** the R-2 blob-hash-before-decrypt comments in
  `media.rs`/`wasm_exports.rs` cited "NIST SP 800-38D §5.2.1.1" for the outer
  application-layer SHA-256 ciphertext-hash check — that section actually covers
  GCM's own IV construction, not this check. Corrected the citation (dropped the
  wrong section reference, kept/clarified the substantive "application-layer check,
  runs before decrypt to avoid an oracle" reasoning) in all 3 occurrences (2 in
  media.rs, 1 in wasm_exports.rs). No logic change — comment-only, confirmed via
  `git diff` review.
- **crypto-reviewer: GREEN.** Confirmed the Rust changes are comment-only (zero
  non-comment diff lines). Confirmed the canonical-key revert doesn't introduce a
  *new* regression — it exactly restores the pre-cycle-312 baseline; the raw
  thumbnail key living in `chats` state for the session lifetime is the same
  already-accepted tradeoff the main media-key path has always had (not materially
  worse). Confirmed local-copy-zero + opaque-handle-drop-in-finally is intact on both
  the success and abort-while-queued paths. One **YELLOW (informational, pre-
  existing, not a regression from this diff, not required to fix)**: the local
  `key.fill(0)` in `useThumbnail.ts` sits inside a `try` (not a `finally`) — if
  `mediaImportKey` itself throws, the local copy is left un-zeroed (contrast
  `mediaTransfer.ts`'s `try {...} finally { mediaKey.fill(0) }` on the same call).
  Low severity (a local copy of a key whose canonical original is now intentionally
  session-resident anyway leaks nothing new) — flagged as a follow-up for crypto-lead,
  not fixed this cycle to keep the revert minimal and reviewed-as-is.
- Not architectural, no new server-visible metadata — `threat-model-checker` not
  required (client-side memory-hygiene revert + doc comment only); crypto-reviewer
  agreed with this scoping.
- Rust: `cargo build -p powehi-crypto-wasm` clean, `cargo test -p powehi-crypto-wasm
  --lib` 172/172 green, `cargo fmt --all --check` clean. Frontend: `tsc -b` clean,
  `biome check` clean, full suite **1315/1315 tests green** (104 files, was 1314 —
  net +1: replaced 1 cycle-312 test, added 2 new ones, minus 0 removed elsewhere).
- **Next cycle candidates:** the YELLOW `key.fill(0)`-not-in-`finally` hygiene gap
  noted above (trivial, crypto-lead), PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768` — unverified this cycle whether that's still true; worth
  a fresh check rather than continuing to assume), and the standing
  `.claude/memory/project-context.md` file-size hygiene note (STABILIZATION-cycle
  tooling task — file is now ~620KB+, this entry makes it larger still).

## Previous state (2026-07-19, cycle 314 — FEATURE: voice messages — record, encrypt, playback, commit e1767c1)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Investigated cycle-313's carried-forward "group-row-creation gap
  (cycle 259)" next-cycle note — it's **stale**: `db.groups.add()`/`putGroup()` was
  already wired up in `handleNewGroup`/`handleGroupCreated` back in commit `ae67d72`
  (cycle 262, "wire GroupRow creation into Dexie"). Dropped that note; it should not have
  kept resurfacing since cycle 262. Picked a genuinely new gap instead: grepped for
  `MediaRecorder` across `app/src` and found zero hits — voice messages were never
  implemented, and there was a literal dead placeholder button
  (`<IconBtn icon="mic" label="Voice" size={36} />`, no `onClick`) sitting in the
  Composer at the old `ChatLayout.tsx:4362`.
- Implemented end-to-end, reusing the existing generic encrypted-media pipeline
  **unchanged** — `useMediaSend.ts`'s `sendMedia(file: File)` and `mediaTransfer.ts`
  already handle any file type (thumbnailing safely no-ops for non-images), so voice
  messages needed zero crypto/WASM/wire-format changes.
  - New `app/src/hooks/useVoiceRecorder.ts`: `MediaRecorder` wrapper —
    `startRecording`/`stopRecording`/`cancelRecording` + `recording`/`elapsedSec`/`error`
    state. Picks the best supported mimeType (`audio/webm;codecs=opus` → `audio/webm` →
    `audio/mp4` → browser default). Mic `MediaStream` tracks are always `.stop()`-ed
    (recording stopped, cancelled, unmounted, or on any construction/permission error) —
    this is the privacy-critical invariant (mic-in-use indicator must clear).
    `cancelRecording` nulls `ondataavailable`/`onstop` *before* calling `.stop()` so a
    late event can never resurrect a File after discard. Errors are content-free
    category strings only (no-plaintext-logging.md), never raw `DOMException` detail.
  - `Composer` (`ChatLayout.tsx`) gained `onSendVoice?: (file: File) => void`; the dead
    mic button now starts recording, and while recording shows a red-dot + `m:ss` timer
    (`formatVoiceElapsed` helper) with stop/send and discard buttons. New `sendVoice`
    handler in `ChatLayout`'s body mirrors `handleFileSelect`'s optimistic-placeholder-
    then-`sendMedia(file)` pattern ("Voice message" placeholder text).
  - `MediaImage.tsx` gained a `looksLikeAudio` branch (`media.mimeType?.startsWith
    ("audio/")`, checked before the video fallback) rendering `<audio controls>` for
    playback, plus matching loading/unavailable copy.
  - New icon `square` added to `Icon.tsx` (stop button); `trash` already existed.
  - **security-auditor: YELLOW → fixed in-cycle.** Found: in `startRecording`,
    `streamRef.current` was assigned *after* `new MediaRecorder(...)`, so if the
    constructor itself threw (e.g. a real-browser `NotSupportedError` despite
    `isTypeSupported()` returning true), the catch's `stopStream()` read a still-null
    ref and the mic stream leaked (indicator stayed lit) — contradicted the hook's own
    "always stopped" invariant. Fixed by assigning `streamRef.current = stream`
    immediately after `getUserMedia` succeeds, before the construction `try`. Added the
    missing test (constructor throws → both tracks stopped, error set). Re-reviewed:
    GREEN, cleared to commit. Confirmed separately: zero changes to `useMediaSend.ts`/
    `mediaTransfer.ts`, no new crypto-worker calls, no new server-visible envelope
    fields (mimeType already existed from cycle 296) — so `crypto-reviewer`/
    `threat-model-checker` were correctly not required.
  - 17 new frontend tests (8 `useVoiceRecorder.test.ts` + 5
    `ChatLayoutVoiceMessage.test.tsx` + 4 `MediaImage.test.tsx` audio-branch), all green.
    Full suite: **1314/1314 tests, 104 files**, `tsc --noEmit` clean, `biome check`
    clean (was 1296/102 at cycle 313 start).
  - Noted but not fixed (unrelated, pre-existing, confirmed to reproduce identically on
    unmodified `main` via `git stash`): `AcceptInviteModal.test.tsx`'s
    `verification_failed` test is flaky under full-suite ordering (fails ~sometimes when
    run with the whole file/suite, passes every time in isolation) — passed on my final
    full-suite run (1314/1314) but is worth a STABILIZATION-cycle look at test isolation/
    mock-state bleed in that file if it recurs.
  - Backend: untouched this cycle (pure frontend feature, confirmed via
    `git diff --name-only` before skipping Rust build/test/audit).
  - Delegated implementation to `frontend-lead`, verified the diff and reran
    tsc/biome/vitest myself before the security-auditor pass and again after the fix.
- **Next cycle candidates:** the flaky `AcceptInviteModal.test.tsx` test noted above
  (good STABILIZATION-cycle target), the canonical `media.mediaKey`-not-zeroed
  cosmetic-symmetry note (main media path, carried since cycle 309), the NIST
  SP 800-38D §5.2.1.1 citation fix for the R-2 blob-hash-before-decrypt comments in
  `media.rs`/`wasm_exports.rs` (trivial doc-only, carried since cycle 309), PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`), and the standing
  `.claude/memory/project-context.md` file-size hygiene note (STABILIZATION-cycle
  tooling task, not a code change — file is now ~610KB+).

## Previous state (2026-07-18, cycle 313 — FEATURE: dequeue cancelled decrypts from the media handle limiter, commit ea161f8)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Picked cycle-312's Advisory B carried-forward item: a task still
  waiting in `mediaHandleLimiter`'s FIFO queue when its component unmounts (fast
  chat-switch) previously ran to completion anyway before its `cancelled` flag check
  fired — burning one of the 32 limiter slots and a real WASM `MEDIA_KEYS` handle-
  import/decrypt for a result that was just going to be discarded.
- `createLimiter` (`app/src/lib/concurrencyLimiter.ts`) now takes an optional 2nd
  arg, `signal?: AbortSignal`. A pre-aborted signal rejects immediately without
  queueing. A signal that aborts while the task is still in `queue` splices it out
  and rejects with a `DOMException("Aborted","AbortError")` — `fn` is never invoked,
  so no slot is ever consumed and no WASM call ever happens for that task. A signal
  that aborts AFTER the task has already been dequeued (running, or past the
  microtask boundary) is a no-op — `queue.indexOf(enter) === -1` guards this; the
  in-flight decrypt runs to completion as before (its own `cancelled`-flag check
  inside `fn`, unchanged, still applies for that case). Abort listeners are removed
  via `enter()` on normal dequeue too, so a task that never aborts doesn't leak a
  listener on the `AbortSignal`.
- `downloadAndDecryptMedia` (`mediaTransfer.ts`) gained an optional trailing `signal`
  param, forwarded straight into `mediaHandleLimiter(...)`. `useMediaReceive.ts` and
  `useThumbnail.ts` each create an `AbortController` per effect run, pass
  `controller.signal` through, and call `controller.abort()` in the effect cleanup
  (same place `cancelled = true` was already being set).
- Key-hygiene subtlety on the `useThumbnail.ts` path specifically: since cycle 312's
  Advisory A fix, the raw local `key` copy is created and the canonical
  `thumbnail.key` zeroed *before* queueing (not inside the queued closure) — so on
  the new abort-while-queued path, `fn` never runs and therefore never reaches its
  own post-import `key.fill(0)`. Added `.catch(() => key.fill(0))` right after the
  `mediaHandleLimiter(...)` call to close that gap; verified it only fires on the
  abort-while-queued path (never on a normal successful run, since `fn` swallows its
  own errors and always resolves the outer promise). `downloadAndDecryptMedia`'s
  `mediaKey` copy, by contrast, is created *inside* the queued closure (after
  admission), so an abort-while-queued rejection there has nothing to zero — no
  analogous gap on that path.
- **crypto-reviewer: GREEN**, no findings — confirmed no unzeroed-key path across
  immediate-admit / queued-then-run / queued-then-abort, confirmed the listener
  cleanup and no-double-entry reasoning, confirmed this is JS-side scheduling only
  (no wire format change, no new WASM-boundary data, same crypto primitives/calls
  byte-for-byte).
- Not architectural / no new server-visible metadata — `threat-model-checker` not
  required (internal JS scheduling change only).
- Frontend: `tsc --noEmit` clean, `biome check` clean on all touched files, all
  102 test files / 1296 tests green (was 1290, +6 new: 3 in `concurrencyLimiter.test.ts`
  — dequeues-aborted-while-queued-without-running, rejects-immediately-for-already-
  aborted-signal, lets-already-running-task-finish-despite-mid-flight-abort — plus 1
  each in `mediaTransfer.test.ts` (forwards already-aborted signal, no key import/no
  fetch), `useMediaReceive.test.ts`, and `useThumbnail.test.ts` (both: unmount calls
  `AbortController.prototype.abort`)). Backend untouched this cycle (pure frontend
  change, confirmed via `git diff --name-only` before skipping Rust build/test/audit).
- **Next cycle candidates:** the canonical `media.mediaKey`-not-zeroed cosmetic-
  symmetry note (main media path, carried since cycle 309 — `downloadAndDecryptMedia`
  never zeroed the canonical array, only its local copy), the NIST SP 800-38D §5.2.1.1
  citation fix for the R-2 blob-hash-before-decrypt comments in `media.rs`/
  `wasm_exports.rs` (trivial doc-only, carried since cycle 309), the group-row-
  creation gap (cycle 259 — no code path calls `db.groups.add()`, so Dexie pin/theme
  persistence is a no-op in the live app until group-row creation is wired up), PQ
  hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`), and the
  standing `.claude/memory/project-context.md` file-size hygiene note (STABILIZATION-
  cycle tooling task, not a code change — file is now ~600KB+).

## Previous state (2026-07-18, cycle 312 — FEATURE: bound concurrent receiver-path decrypt handles, commit a263b28)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Picked the standing cycle-311 crypto-reviewer advisory: thumbnail
  decrypt now shares the 256-slot `MAX_MEDIA_HANDLES` cap with the main media-key path,
  and a burst of concurrent thumbnail renders could transiently pressure it — flagged
  for crypto-lead to confirm the message list bounds concurrent thumbnail decrypts.
- Spawned an Explore-style audit first (read-only) to answer that question precisely:
  confirmed `ChatLayout.tsx`'s `MessageList` is **fully unvirtualized** (no
  react-window/react-virtual/custom windowing anywhere in `app/src`) — `buildGroups`
  renders every message unsliced inside a plain `overflowY: auto` div, so every
  `MediaImage` (and therefore every mounted `useThumbnail`/`useMediaReceive`) in a
  chat's full history fires its WASM handle-import/decrypt concurrently on chat open.
  No existing safeguard (`IntersectionObserver`, lazy-loading, debounce, or a decrypt
  queue) bounded this. This is a **real**, not theoretical, risk in media-heavy chats
  with 500+ messages.
- Chose the smaller, safer of the two options the audit surfaced — a client-side
  decrypt concurrency limiter shared by both receiver paths — over the larger option
  (virtualizing `MessageList`, a much bigger, riskier refactor better suited to its
  own dedicated cycle(s)).
- New `app/src/lib/concurrencyLimiter.ts`: generic `createLimiter(maxConcurrent)` →
  async semaphore/FIFO-queue `limit(fn)`. Exported `MEDIA_HANDLE_CONCURRENCY = 32` and
  a shared `mediaHandleLimiter` singleton from `mediaTransfer.ts` (32 is well under the
  256-slot cap, leaving headroom for concurrent sender-side handles). Wrapped the
  entire body of `downloadAndDecryptMedia` (import → download → decrypt → drop) and
  `useThumbnail`'s async body (import → decrypt → drop) in the shared limiter, so at
  most 32 receiver-path decrypts hold a `MEDIA_KEYS` handle at once regardless of how
  many `MediaImage` components are mounted.
- Caught my own bug before committing: my first pass wrote
  `mediaHandleLimiter(async () => {...})();` in `useThumbnail.ts` — the trailing `()`
  tried to call the returned *Promise* as a function (TypeError at runtime). Fixed by
  removing it; `limiter(fn)` already invokes `fn`, no extra call needed. Caught via
  re-reading the diff before running tests, not by the test suite itself (existing
  mocked tests wouldn't have surfaced this since `useCryptoWorker` is stubbed).
- **crypto-reviewer: GREEN**, 2 non-blocking findings, 1 fixed in-cycle: (A) the
  *canonical* `thumbnail.key` raw bytes (held in React chats state) were being zeroed
  only *after* acquiring a limiter slot — under the exact >32-concurrent burst this
  feature targets, that meant raw key bytes could linger in state for the full
  queue-wait instead of ~worker-import latency. **Fixed in-cycle**: hoisted the
  canonical-key copy + `thumbnail.key.fill(0)` to run synchronously at effect entry,
  *before* entering the limiter — only the already-zeroed-source local copy is queued.
  (B) cancelled-but-still-queued tasks (e.g. fast chat-switch) aren't dequeued — FIFO
  drain still guarantees no deadlock, but a stale queued decrypt burns 1 of 32 slots
  and a real WASM handle before its `if (cancelled) return` check fires post-decrypt.
  **Not fixed this cycle** (no correctness/security impact, optional QoS follow-up) —
  carried to next cycle candidates.
- Not architectural / no new server-visible metadata — `threat-model-checker` not
  required (internal WASM/JS boundary + JS-side scheduling only, same wire format).
- Frontend: `tsc --noEmit` clean, `biome check` clean on all 4 touched/new files, all
  102 test files / 1290 tests green (was 1286, +4 new: `concurrencyLimiter.test.ts`,
  covering under-cap-runs-immediately, queues-and-never-exceeds-cap, releases-slot-
  on-throw, rejects-non-positive-maxConcurrent). Backend untouched this cycle (pure
  frontend change, no Rust files touched — confirmed via `git diff --name-only` before
  skipping the Rust build/test/audit steps).
- **Next cycle candidates:** Advisory B above (queue cancellation/dequeue on unmount —
  QoS only), the canonical `media.mediaKey`-not-zeroed cosmetic-symmetry note (main
  media path, carried from cycle 309 — `downloadAndDecryptMedia` never zeroed the
  canonical array, only its local copy; distinct from the thumbnail path fixed this
  cycle), the NIST SP 800-38D §5.2.1.1 citation fix for the R-2 blob-hash-before-
  decrypt comments in `media.rs`/`wasm_exports.rs` (trivial doc-only — the cited
  section covers IV construction, not the oracle-avoidance property the comment
  actually describes; carried since cycle 309), PQ hybrid Phase A (still blocked on
  openmls stable `MLS_128_MLKEM768`), and the standing `.claude/memory/project-
  context.md` file-size hygiene note (STABILIZATION-cycle tooling task, not a code
  change).

## Previous state (2026-07-18, cycle 311 — FEATURE: receiver-side thumbnail opaque-handle pattern, commit 74c45fb)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Picked the standing "next cycle candidate" carried since cycle
  309: migrate `media_thumbnail_decrypt` (receiver path) to the same opaque-handle
  pattern used for the main media key in cycle 309 — the thumbnail key previously
  crossed the WASM-JS boundary as a raw `&[u8]` argument for the entire decrypt call.
- **Rust (`powehi-crypto-wasm`):** removed `media_thumbnail_decrypt(ct, key, iv)`
  entirely (confirmed zero remaining callers via repo-wide grep before deletion). Added
  `media_thumbnail_decrypt_with_handle(media_key_handle, ct, iv) -> {pixels}` — looks up
  the key from the **same** `MEDIA_KEYS` map used by the main media-key receiver path
  (deliberately reused rather than adding a second map/cap, since `media_import_key`/
  `media_drop_key` are already generic over any 32-byte key). Unlike
  `media_decrypt_with_handle`, this does **not** do the blob_hash/R-2 check — the
  thumbnail ciphertext travels inline inside the already-MLS-authenticated envelope
  (not an unauthenticated R2 fetch), so there's no server-swap oracle surface.
  crypto-reviewer confirmed this reasoning holds.
- **Frontend:** `useThumbnail.ts` now calls `mediaImportKey(key)` first, zeroes the raw
  key copy immediately (before decrypt even starts, not after) plus the canonical
  `thumbnail.key` array in React state, then `mediaThumbnailDecryptWithHandle(handle,
  ct, iv)`, and drops the handle in a `finally` on every path (success, decrypt-throw,
  cancelled-after-import). `crypto.worker.ts`, `__mocks__/useCryptoWorker.ts`, and
  `useThumbnail.test.ts` updated to the handle-based API (12 tests, +3 new assertions
  for import/drop call-through, drop-on-failure).
- **crypto-reviewer: GREEN**, 2 non-blocking YELLOW advisories: (1) thumbnail decrypt
  now shares the 256-slot `MAX_MEDIA_HANDLES` cap with the main media-key path (before
  this cycle it consumed none) — a burst of concurrent thumbnail renders could
  transiently pressure the shared cap; degrades gracefully (non-fatal catch in
  useThumbnail.ts) but flagged for crypto-lead to confirm the message list bounds
  concurrent thumbnail decrypts. **Not fixed this cycle** — needs a virtualization
  audit, tracked as a follow-up. (2) new Rust tests didn't cover the 12-byte IV-length
  validation branch — **fixed in-cycle**: added
  `test_thumbnail_handle_decrypt_wrong_iv_length_rejected`.
- Rust: `cargo build --workspace` / `cargo test --workspace` (172/172 in
  powehi-crypto-wasm, +3 new: round-trip, unknown-handle, wrong-iv-length) / `cargo fmt
  --all --check` / `cargo clippy --workspace --all-targets -- -D warnings` all clean
  (native + wasm32-unknown-unknown). Frontend: `tsc --noEmit` clean, `biome check`
  clean, all 1286 frontend tests green (101 files, net unchanged — replaced tests
  1:1 plus new assertions in the same file).
- Not architectural / no new server-visible metadata — `threat-model-checker` not
  required (internal WASM/JS boundary hardening, same wire format as before).
- **Next cycle candidates:** crypto-reviewer's shared-cap-contention advisory above
  (confirm/bound concurrent thumbnail decrypts), the canonical `media.mediaKey`-not-
  zeroed cosmetic-symmetry note (carried from cycle 309), the NIST SP 800-38D citation
  fix (trivial doc-only, carried from cycle 309), PQ hybrid Phase A (still blocked on
  openmls stable `MLS_128_MLKEM768`). Also noted but out of scope: `.claude/memory/
  project-context.md` itself has grown to ~590KB / 5400+ lines (append-only history) —
  a future STABILIZATION cycle should consider trimming/archiving older cycle entries
  so the file stays readable, though this is tooling hygiene, not a code change.

## Previous state (2026-07-18, cycle 310 — STABILIZATION: bound mls_credential size, commit 7268933)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Full stabilization sweep: `cargo audit` clean (652 crates, 0
  advisories), `cargo build --workspace` / `cargo test --workspace` / `cargo fmt --all
  --check` / `cargo clippy --workspace --all-targets -- -D warnings` all clean, frontend
  `pnpm test` 1286/1286 green (101 files). Also confirmed the cycle-255-memory-flagged
  "powehi-r2 lacks a testcontainers integration test" gap is stale — `r2_media_it.rs`
  (698 lines) already exists and is wired into `ci-rust.yml`'s integration-test job;
  no action needed there.
- Picked the standing security-auditor YELLOW #3 from cycle 304: `mls_credential` (on
  `RegistrationFinishRequest`, `DeviceRegistrationRequest`, and `RecoveryProof` for the
  §8.5 recovery path) had no upper bound beyond the global 512KiB HTTP body limit,
  letting an authenticated (or, via recovery, freshly re-authenticated) caller bloat the
  `devices.mls_credential` Postgres bytea column per device row (up to
  `MAX_DEVICES_PER_USER=10` per account). Mirrors the cycle-299/300 invite-KeyPackage
  size-cap precedent exactly.
- Added `const MAX_MLS_CREDENTIAL_BYTES: usize = 4 * 1024` in `auth_service.rs`,
  validated at all three call sites that build a `Device` from client-supplied bytes:
  `register_finish`/`register_device` → `DomainError::InvalidInput` (checked before any
  save, so no partial state persists on rejection); `mint_recovery_device` (the §8.5
  path) → deliberately collapses to `DomainError::Unauthorized` instead, preserving the
  function's existing anti-oracle property (every other failure mode there — unenrolled
  account, malformed pubkey/signature, bad signature, device-cap-exceeded — already
  collapses to the same `Unauthorized`, since this path runs pre-session).
- Not crypto/MLS-primitive work and no new server-visible metadata shape (same wire
  fields, just a length gate) — `crypto-reviewer`/`threat-model-checker` not required.
  Backend handler/application-layer change → `security-auditor` required.
- **security-auditor: GREEN**, no findings. Verified: size-check placement correct at
  all 3 sites (no bypass, no partial writes before rejection); the `mint_recovery_device`
  anti-oracle collapse is genuinely preserved (plain `len()` comparison after the
  `verify_strict` gate, identical `Unauthorized` response shape to sibling checks, no
  new unauthenticated-reachable oracle); 4KiB is a reasonable bound (real
  `BasicCredential` identities are well under 1KB; caps per-account bytea at
  40KiB across the 10-device limit); no other `Device::new` call site was missed (only
  test fixtures elsewhere, using server-generated bytes); zero new logging, no
  plaintext/PII/credential-content exposure. Informational-only note (not a finding):
  an oversized `register_finish` submission burns the cached registration session
  (consumed via `get_del` before the size check fires) — pre-existing behavior shared
  with the `recovery_pubkey`-length check on the same path, cache-only impact, no
  security effect.
- 4 new tests (`register_finish_rejects_oversized_mls_credential`,
  `register_device_rejects_oversized_mls_credential`,
  `register_device_at_max_mls_credential_size_succeeds`,
  `recovery_oversized_mls_credential_rejected_as_unauthorized` — the last asserts both
  the `Unauthorized` collapse AND that no device row was persisted). All backend tests
  green (120/120 in `powehi-application` alone), all frontend tests untouched/still
  1286/1286 green. `target/` hygiene pass run (23G, over the 20G threshold but mostly
  recent/warm cache per cycle 307's same finding — pruned 0-byte `.rmeta` stubs +
  mtime+7 artifacts, size essentially unchanged, not a blocker).
- This closes out the last standing security-auditor finding from cycle 304's recovery-
  phrase feature (the other two — timing-parity dummy-key and verify_strict — were
  already fixed in cycles 303/304 themselves).
- **Next cycle candidates (unchanged, carried from cycle 309):** the canonical
  `media.mediaKey`-not-zeroed cosmetic-symmetry note, the NIST SP 800-38D citation fix
  (trivial doc-only), migrating `media_thumbnail_decrypt` to the same opaque-handle
  pattern, PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`).

## Previous state (2026-07-18, cycle 309 — FEATURE: receiver-side media opaque-handle pattern, commit 493f193)

- `git status` clean, `gh run list --limit 5` all green at cycle start, `gh issue list
  --state open` empty. Picked the standing "next cycle candidate" flagged since cycle
  308: the cycle-119 YELLOW at `useMediaReceive.ts` — the receiver-path AES-256-GCM
  media key crossed the Comlink boundary as a raw `number[]`/`Uint8Array` and lived in
  JS scope for the full R2 download + decrypt round-trip, zeroed only in a `finally`
  at the very end. The sender path never had this exposure (`media_encrypt` returns an
  opaque handle, raw key never leaves WASM) — this cycle closes the asymmetry.
- **Rust (`powehi-crypto-wasm`):** new `media_import_key(raw_key) -> {mediaKeyHandle}`
  wasm export — validates 32 bytes, cap-checks the existing `MEDIA_KEYS` thread-local
  handle map (`MAX_MEDIA_HANDLES=256`, shared with the sender path), stores as
  `Zeroizing<[u8;32]>`, Y-7 pattern (build JS result before insert, no orphan handle on
  failure). New `media_decrypt_with_handle` / `media_decrypt_chunked_with_handle` —
  same R-2 blob-hash-before-AES-GCM-decrypt ordering as before, key sourced from the
  handle map instead of a raw JS argument. **Removed** `media_decrypt_with_raw_key` /
  `media_decrypt_chunked_with_raw_key` entirely (zero remaining callers after the
  migration — confirmed via full-repo grep) so JS can no longer feed a raw key
  directly into a decrypt call at all, not just "isn't encouraged to."
  `media::decrypt_with_raw_key`/`decrypt_chunked` (the pure crypto primitives in
  media.rs) are unchanged, just now only called with a handle-resolved key.
- **Frontend:** `mediaTransfer.ts`'s `downloadAndDecryptMedia` now calls
  `mediaImportKey` and zeroes the local key copy in `finally` **before the R2 fetch
  even starts** (previously the zero only fired after decrypt completed) — the
  opaque handle is used for the rest of the function and dropped via `mediaDropKey`
  in an outer `finally` on every path (success, chunked-decrypt throw, fetch throw).
  `crypto.worker.ts`, `__mocks__/useCryptoWorker.ts`, and all call-site tests
  (`mediaTransfer.test.ts`, `useMediaReceive.test.ts`, `mediaEncrypt.test.ts`,
  `ChatLayoutForwarding.test.tsx` — forwarding decrypts-then-re-encrypts, so it
  exercises both the new import-handle and the existing encrypt-handle in the same
  flow) updated to the new handle-based API.
- Thumbnail decrypt (`media_thumbnail_decrypt`) intentionally **not** migrated this
  cycle — still takes a raw key inline. Small (≤16KB) payload, lower priority;
  doc comment added flagging it as a tracked follow-up.
- **crypto-reviewer: GREEN**, no blockers. Verified handle lifecycle (no leaks/
  use-after-drop), raw-key-in-JS window now closes before the network round-trip
  (not after), R-2 ordering preserved exactly in both new handle functions, cap-check-
  before-insert + Y-7 ordering correct, no new panic surface, zero plaintext/key
  logging, zero stranded callers of the removed raw-key exports. Non-blocking notes
  (deferred, not fixed): (1) the *canonical* `media.mediaKey` array inside the
  `MediaPayload` object (as opposed to the local working copy) is still never
  zeroed — pre-existing §9.2 behavior, not worsened by this diff, but noted as a
  possible future symmetry fix; (2) the R-2 doc comment's NIST SP 800-38D §5.2.1.1
  citation is imprecise (that section is IV-uniqueness, not the swap/oracle
  argument the comment describes) — carried over from the prior comment, not
  introduced here, flagged for a future correction pass.
- Not architectural / no new server-visible metadata — `threat-model-checker` not
  required (purely an internal WASM/JS boundary hardening, same wire format).
- Rust: `cargo build --workspace` clean, `cargo test --workspace` all green (169/169
  in powehi-crypto-wasm, 6 new tests: import round-trip, wrong-length rejection,
  chunked round-trip), `cargo fmt --all --check` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean (both native and wasm32-unknown-unknown
  targets). Frontend: `tsc --noEmit` clean, `biome check` clean, all 1286 frontend
  tests green (101 files, was 1280, +6 net new).
- **Next cycle candidates:** the canonical-`media.mediaKey`-not-zeroed note above (low
  priority, cosmetic-symmetry), the NIST citation fix (trivial doc-only), migrating
  `media_thumbnail_decrypt` to the same opaque-handle pattern, PQ hybrid Phase A
  (still blocked on openmls stable `MLS_128_MLKEM768`), security-auditor's cycle-304
  YELLOW #3 (bound `mls_credential`/`proof.mls_credential` size).

## Previous state (2026-07-18, cycle 308 — FEATURE: persist unread badge + New Messages divider to Dexie, commit 36dc5b8)

- `git status` clean, `gh run list --limit 5` all green (cycle 307's CI-retry fix), `gh issue
  list --state open` empty at cycle start.
- Picked the standing "next cycle candidate" flagged by both cycle 306 and 307: `unread`/
  `firstUnreadAt` sidebar-badge state was React-state-only (same gap class mentionCount had
  before v13) — a reload silently cleared the unread badge and the "New Messages" divider for
  any background chat never re-opened since the badge last incremented.
  `GroupRow.unread?: number` (bounded count, same tier as mentionCount) and
  `GroupRow.firstUnreadMessageId?: string` (opaque MessageRow-id reference, same tier as
  pinnedMessageId) added to `app/src/db/schema.ts`, bumped to `version(14)` (additive, no
  index change).
- Chose to persist the message **id**, not the raw `firstUnreadAt` array index (which is only
  meaningful against a specific in-memory `c.messages` ordering) — mirrors the existing
  `persistedPinnedMessageId` pattern exactly: a new `persistedFirstUnreadMessageId` state +
  a second effect that resolves the id to an index via `c.messages.findIndex(...)` once
  `rows` (Dexie-loaded messages) are merged in, re-running on `rows` to win the race against
  the async group-row fetch. Guarded so it never clobbers an in-session `firstUnreadAt` and
  only applies when the rehydrated `unread` count is also positive (no stale divider on a
  zero-unread chat).
- Write-through at all 5 relevant call sites: `handleIncoming` (increments `unread` for a
  background/non-muted chat; sets `firstUnreadMessageId` only on the 0→1 transition, same
  "only set once" semantics the in-memory `firstUnreadAt` index already has — verified via a
  dedicated test that a chat starting at seed `unread: 2` does NOT get `firstUnreadMessageId`
  written on a further increment), `handleClearMessages`/`handleMarkAllRead` (reset both to
  0/undefined), `handleSelectChat` (mirrors the existing two-visit UX: first visit clears
  `unread` but keeps the persisted divider marker; a second visit, already at `unread: 0`,
  clears `firstUnreadMessageId` too), `handleNewGroup` (the `useWelcomePoller` background-join
  path persists `unread: 1` on the new GroupRow — this is the actual background-arrival case,
  distinct from `handleInviteAccepted`'s call to the same function, which immediately follows
  with `handleSelectChat` and so is momentary/already covered).
- Not crypto/MLS/architectural — `crypto-reviewer`/`threat-model-checker` not required (no
  crypto code touched, no new server-visible metadata —100% local-only Dexie state, same as
  the mentionCount precedent).
- **security-auditor: GREEN, no findings.** Confirmed: (1) the Dexie write in `handleIncoming`
  only fires when `chatsRef.current` already has a `mlsGroupId` match for the (already
  MLS-decrypted, membership-authenticated) envelope's `groupId` — no cross-group corruption
  surface; (2) `firstUnreadMessageId` read-back safely no-ops via `findIndex === -1` on an
  absent/malicious id (no crash, no loop, search confined to the owning group's own
  `messages`); (3) zero plaintext/PII in the new fields or any log statement (both fields are
  an opaque UUID + a bounded int); (4) the `chatsRef.current`-snapshot race under rapid
  incoming messages is the same accepted cosmetic-only drift class `mentionCount` already
  carries, not a new divergence; (5) unencrypted storage is appropriate — same tier as the
  existing `mentionCount`/`pinnedMessageId` fields, doesn't leak beyond what `lastActivity`
  already exposes to a local-DB-read adversary.
- 7 new tests: `ChatLayoutUnreadPersist.test.tsx` (new file, 5 tests — persists incremented
  unread+firstUnreadMessageId on background arrival, firstUnreadMessageId only set on the 0→1
  transition, rehydrates persisted unread on chat switch, clear-messages resets both,
  mark-all-read resets both for every chat) + 2 in `ChatLayout.test.tsx`'s existing "message
  history rehydration" describe block (divider renders from a persisted firstUnreadMessageId
  on mount; no stale divider when persisted unread is 0) + 1 assertion added to the existing
  Welcome-envelope GroupRow test (`row?.unread` is 1). All 101 frontend test files green (1280
  tests, was 1273); `tsc --noEmit` clean; `biome check` clean on all 4 touched/new files.
  Backend untouched this cycle (pure frontend/IndexedDB feature).
- This closes out the sidebar-badge persistence series that started with mentionCount (cycle
  306) — mute/sound/vibrate/chatTheme (v12), mentionCount (v13), and now unread/
  firstUnreadMessageId (v14) all survive a reload. No further known gaps in this class.
- **Next cycle candidate:** the receiver-side media opaque-handle pattern
  (`useMediaReceive.ts:10-11`, `mediaKey` still crosses the Comlink boundary as a raw
  `number[]` before zeroing) — heavier cycle, touches the crypto worker boundary, needs
  `crypto-reviewer`. Also standing: PQ hybrid Phase A (blocked on openmls stable
  `MLS_128_MLKEM768`), security-auditor's cycle-304 YELLOW #3 (bound `mls_credential`/
  `proof.mls_credential` size).

## Previous state (2026-07-18, cycle 307 — STABILIZATION: CI — Frontend red-on-main fix, commit ceffd59)

- Mode selection landed on FEATURE (counter 307) but `gh run list` showed `CI — Frontend` red on
  main (run 29598016853, on cycle 306's mentionCount commit) — per the mandatory CI-first check,
  switched to STABILIZATION this cycle instead of starting a new feature.
- Root-caused: 44 scattered test failures, all `TypeError: Cannot read properties of undefined
  (reading 'indexOf')`, across 10 files never touched by the mentionCount commit (auth/groups/
  invites/key_packages/media/messages/push api tests, db/encryption, useMediaSend, mediaTransfer).
  Traced through `@vitest/expect`'s `toThrow` → chai's `assertThrows` → `check-error`'s
  `compatibleMessage` (`comparisonString.indexOf(errMatcher)`) — a known vitest/chai edge case in
  the `.rejects.toThrow(string)` rejection path (vitest-dev/vitest#4559-class: the assertion's
  error-message check can dereference something falsy on this path). Not reproducible locally
  across 4 full-suite runs (1273/1273 green every time, incl. at 6x CI's fork count via
  `--poolOptions.forks.maxForks=6`) — confirmed CI-only test-infra flakiness (2 of the last 16
  `CI — Frontend` runs), not a logic regression introduced by any recent commit.
- Fix: `app/vite.config.ts` test config now sets `retry: process.env.CI ? 1 : 0` — CI-only,
  absorbs the transient upstream flake without changing local dev feedback speed. A genuine
  regression still fails deterministically on the retry, so this doesn't widen what "green" means.
- Not crypto/architectural/backend — no crypto-reviewer/threat-model-checker/security-auditor
  gate applies (pure test-config change, zero app-logic touched).
- Verified: `pnpm vitest run` 100 files/1273 tests green locally (incl. `CI=true` to exercise the
  new retry path), `tsc --noEmit` clean, `biome check` clean on the touched file. Pushed and
  confirmed all three CI workflows (`CI — Frontend`, `CI — Rust`, `CI — Live-backend E2E`) green
  on main post-fix (runs 29609288941/29609289002/29609288964).
- `cargo audit`: clean, 0 advisories (652 crates scanned) — no new RUSTSEC findings since cycle
  305's libcrux triage. `gh issue list --state open`: empty.
- `target/` housekeeping: was 23G (>20GB threshold) — pruned 0-byte `.rmeta` stubs +
  mtime+7 build artifacts per the standing hygiene step; size largely unchanged (most of the 23G
  is recent/warm cache, not stale) — not a blocker, no action needed beyond the routine prune.
- **Next cycle candidate (unchanged from cycle 306):** `unread`/`firstUnreadAt` sidebar-badge
  persistence (same Dexie-rehydration gap class as mentionCount, touches more call sites — unread
  dividers, filter tabs, notification gating). Also standing: receiver-side media opaque-handle
  pattern (`useMediaReceive.ts:10-11`), PQ hybrid Phase A (blocked on openmls stable
  `MLS_128_MLKEM768`), security-auditor's cycle-304 YELLOW #3 (bound `mls_credential`/
  `proof.mls_credential` size).

## Previous state (2026-07-18, cycle 306 — FEATURE: persist @mention badge count to Dexie, commit 497a148)

- `git status` clean, `gh run list --limit 5` all green (cycle 305's commit), `gh issue list
  --state open` empty at cycle start.
- Gap found via Explore agent sweep of prd.md vs app/src for un-implemented/session-only state:
  `GroupRow.mentionCount` was never added when the v12 wave (cycle ~272) persisted
  `muted`/`sound`/`vibrate`/`notificationSoundId`/`chatTheme` — the sidebar @mention badge
  (`ChatLayout.tsx` mention-badge + filter-tab-groups-mention-badge) reset to 0 on every reload
  even for a chat never opened since the mention arrived, same reload gap those five fields had
  before v12 / edit-delete-reactions-pin had before v7-v9.
- `GroupRow.mentionCount?: number` added to `app/src/db/schema.ts`, bumped to `version(13)`
  (additive, no index change — same style as v12). Rehydrated in the existing active-chat-load
  effect (`row.mentionCount ?? c.mentionCount`) alongside muted/sound/vibrate/chatTheme.
- Write-through at all 4 mutation sites: `handleIncoming` (increment on @all/@everyone/@<myHandle>
  in a background group chat), `handleClearMessages`, `handleMarkAllRead` (loops every chat's
  `mlsGroupId`), `handleSelectChat`. `handleIncoming`'s persist call had to duplicate the
  mention-detection predicate rather than reuse the `setChats` updater's copy, since state
  updaters must stay side-effect-free (same `chatsRef.current`-recompute pattern `persistReaction`
  established in cycle 254) — flagged by security-auditor as an accepted drift-risk cost of that
  convention, not fixed (see below).
- **security-auditor: YELLOW (non-blocking), safe to merge.** (1) the duplicated mention-detection
  logic (updater vs persist block) could drift if mention rules ever change (e.g. adding `@here`)
  — accepted, same tax the `persistReaction` precedent already pays; (2) a narrow same-React-batch
  race: two mentions to the same group arriving before the `chatsRef` sync effect flushes both read
  the same stale snapshot and can under-write the persisted count by 1 relative to in-memory state
  — bounded, self-heals the moment the chat is opened (forced to 0), accepted as cosmetic; (3)
  unencrypted plaintext storage in the `groups` table confirmed appropriate — a bounded counter,
  same tier as `disappearingTtlSeconds`/`pinnedMessageId`/`muted`/`chatTheme`, not content/PII.
- Not crypto/MLS/architectural — `crypto-reviewer`/`threat-model-checker` not required (no crypto
  code touched, no new server-visible metadata — this is 100% local-only Dexie state).
- 3 new tests in `ChatLayoutMentions.test.tsx` (persists an incremented mentionCount to Dexie,
  rehydrates a persisted mentionCount when switching to that chat, clearing messages resets the
  persisted mentionCount to 0) — all follow the `ChatLayoutMute.test.tsx` persist/rehydrate
  pattern (`db.groups.clear()` + `.add()` with a seeded `mlsGroupId`, `waitFor` the Dexie row).
  All 100 frontend test files green (1273 tests, was 1270); `tsc --noEmit` clean; `biome check`
  clean on all 3 touched files. Backend untouched this cycle (pure frontend/IndexedDB feature).
- **Next cycle candidate:** the same Explore sweep flagged `unread`/`firstUnreadAt` as the sibling
  gap (also sidebar-badge state, also session-only) — slightly riskier than mentionCount since it
  interacts with more call sites (unread dividers, filter tabs, notification gating), good
  candidate for its own FEATURE cycle. Also noted but NOT pursued: the receiver-side media
  opaque-handle pattern (`useMediaReceive.ts:10-11`, `mediaKey` still crosses the Comlink boundary
  as a raw `number[]` before zeroing) — heavier cycle, touches the crypto worker boundary, needs
  `crypto-reviewer`. Standing older candidates unchanged: PQ hybrid Phase A (blocked on openmls
  stable `MLS_128_MLKEM768`), security-auditor's cycle-304 YELLOW #3 (bound `mls_credential`/
  `proof.mls_credential` size) remains a reasonable small future STABILIZATION item.

## Previous state (2026-07-17, cycle 305 — STABILIZATION: telemetry test-race fix + libcrux RUSTSEC triage, commit 55c6b3b)

- `gh run list --limit 5` green on both `CI — Rust` and `CI — Live-backend E2E`/`CI — Frontend`
  from cycle 304's commits; `gh issue list --state open` empty; `git status` clean at start.
- Closed the cycle-296-noted `powehi-telemetry` env-var test-race flake (was on the standing
  next-candidate list since cycle 296, still open as of cycle 304's entry): the
  `otlp_config_from_env_returns_none_when_endpoint_absent` test read
  `OTEL_EXPORTER_OTLP_ENDPOINT` without holding `ENV_TEST_MUTEX`, unlike every sibling
  env-mutating test in the module — a concurrent `cargo test` thread running
  `otlp_config_from_env_returns_some_when_endpoint_set` (which holds the mutex while calling
  `EnvGuard::set` on the same var) could flip the var mid-check, causing a spurious failure.
  Fixed by acquiring `ENV_TEST_MUTEX` and using `EnvGuard::remove` instead of a bare read-check.
  Verified stable across 15 repeated `cargo test -p powehi-telemetry -- --test-threads=16` runs
  (previously reproducible only intermittently, so this isn't an exhaustive proof, but matches
  the exact race shape and now follows the same locking discipline as every other test in the file).
- `cargo audit` surfaced 5 NEW RUSTSEC advisories not present in the existing `.cargo/audit.toml`
  waiver list: RUSTSEC-2026-0207/-0208 (libcrux-sha3 0.0.8, severity 8.2 each — incorrect
  incremental-SHAKE output / AVX2 SHAKE-256 panic), RUSTSEC-2026-0212 (libcrux-secrets 0.0.5,
  severity 8.2 — non-constant-time Aarch64 swap/select), RUSTSEC-2026-0209/-0211 (libcrux-aesgcm
  0.0.7, severity 6.3 each — AAD length / non-constant-time tag check), RUSTSEC-2026-0210
  (libcrux-aesgcm unmaintained). All transitively via `openmls_rust_crypto 0.5.1 → hpke-rs 0.6.1`
  — none fixable by a dependency bump: `openmls_rust_crypto` 0.5.1 and `hpke-rs`'s pinned range
  (`^0.6.0`) are both already the latest crates.io release compatible with our tree (hpke-rs 0.7.0
  exists but is out of range; openmls_rust_crypto has no newer release).
- Did NOT rubber-stamp a waiver — traced actual compiled-graph reachability (`cargo tree -i
  <crate> --target all`, reading `hpke-rs-0.6.1`'s and `openmls_rust_crypto-0.5.1`'s real
  Cargo.toml/source from the local registry cache) and sent the reasoning to `crypto-reviewer`
  for independent verification before writing any waiver (this is a security-relevant claim —
  "this vulnerable code is unreachable" — same rigor bar as reviewing new crypto code).
  **crypto-reviewer: PASS**, with one required correction: don't reuse RUSTSEC-2026-0124's
  "panic/DoS only, no leak" impact language for RUSTSEC-2026-0211/-0212, since those two are
  timing-side-channel/confidentiality class, not availability — the waiver must describe them
  honestly (unreachable, not "harmless if reached").
  - **libcrux-aesgcm (0209/0210/0211): not compiled into any artifact at all.** Same root cause
    as the pre-existing RUSTSEC-2026-0124 waiver — reachable only through `hpke-rs`'s optional
    `"libcrux"` feature (`dep:hpke-rs-libcrux`), and `openmls_rust_crypto`'s hpke-rs dependency
    declares `default-features = false, features = ["hazmat", "serialization"]` — `"libcrux"` is
    never enabled. `cargo tree -i libcrux-aesgcm --target all` / `-i hpke-rs-libcrux --target all`
    both print nothing.
  - **libcrux-sha3/libcrux-secrets (0207/0208/0212): compiled in, but the vulnerable code is
    structurally unreachable.** `libcrux-sha3` is a *mandatory* (non-optional) dependency of
    `hpke-rs` (unlike the aesgcm chain), confirmed compiled via `cargo tree -i libcrux-sha3`
    resolving to `hpke-rs → openmls_rust_crypto → powehi-crypto-wasm`. But `hpke-rs-0.6.1/src/
    kem.rs` calls `libcrux_sha3::shake256` from exactly two call sites (lines 154, 158), both
    inside `derive_key_pair()`'s X-Wing/ML-KEM post-quantum KEM match arms — the classical-DH arm
    (`DhKemP256|K256|P384|P521|DhKem25519|DhKem448`, which Powehi's only supported ciphersuite
    `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` uses) calls `dh_kem::derive_key_pair` instead
    and never touches `libcrux_sha3`. Stronger still: `openmls_rust_crypto-0.5.1/src/
    provider.rs`'s `kem_mode()` maps `HpkeKemType::XWingKemDraft6 => unimplemented!()` and has no
    ML-KEM arm at all — this provider structurally cannot construct the `KemAlgorithm` values that
    would reach those two call sites, so it's not just "unused today," it's unreachable through
    this provider regardless of ciphersuite config. `libcrux-secrets` has no independent entry
    point (`cargo tree -i libcrux-secrets --target all` shows a single chain through
    `libcrux-sha3`), so it inherits the same argument. Bonus, non-load-bearing: hpke-rs's two call
    sites are one-shot `shake256::<32>/<64>()` calls, and the advisories' own text says 0207 needs
    multiple incremental squeeze calls and 0208 needs output length >32-and-not-divisible-by-8 —
    neither condition is met even if reached.
  - Cross-checked against `cargo deny check advisories`: it flags exactly RUSTSEC-2026-0207/-0208/
    -0212 (the compiled ones) and none of the aesgcm ones — independently confirms the
    reachability split above via cargo-deny's own feature-aware graph resolution.
  - Waived all 5 (well, 6 IDs — 0207/0208/0209/0210/0211/0212) in `.cargo/audit.toml` with the
    full trace, and the 3 cargo-deny actually flags (0207/0208/0212) in `deny.toml`, each with a
    "re-verify on any hpke-rs/openmls_rust_crypto bump" trigger and a note to crypto-lead: if
    Powehi ever ships the PQ hybrid ciphersuite through this same `openmls_rust_crypto`/`hpke-rs`
    provider+pins, these waivers move from unreachable to live and must be re-opened first.
  - `cargo audit` and `cargo deny check` both clean after the waiver; `cargo deny check` (full,
    not just advisories) also clean — licenses/bans/sources all ok.
- Full verification: `cargo build --workspace` clean, `cargo test --workspace` all 41 test
  binaries green (no regressions), `cargo clippy --workspace --all-targets -- -D warnings` clean,
  `cargo fmt --all --check` clean. Frontend untouched this cycle (pure backend
  test-race-fix + dependency-audit-triage stabilization pass, no runtime code changed).
  (`cargo nextest` still not installed in this sandbox — fell back to `cargo test --workspace`.)
- Target dir hygiene: 23G (over the 20G threshold) — ran the prune step (0-byte `.rmeta` stubs,
  >7-day-old build artifacts); size unchanged (nothing qualified this pass, likely because prior
  cycles' artifacts are all within the 7-day window). Not a commit-worthy change per the runbook.
- **Next cycle candidate:** none urgent from this pass. Standing older candidates unchanged: PQ
  hybrid Phase A (still blocked on openmls shipping a stable `MLS_128_MLKEM768` ciphersuite —
  now doubly noted, since this cycle's libcrux waiver explicitly must be re-opened if/when that
  ships); security-auditor's cycle-304 YELLOW #3 (bound `mls_credential`/`proof.mls_credential`
  size, same style as the cycle-300 KeyPackage size bound) remains a reasonable small future
  STABILIZATION item.

## Previous state (2026-07-17, cycle 304 — FEATURE: finish + secure server-verified recovery-phrase account restore, prd.md §8.5, commit cabd82a)

- Session counter file was already at 303 at start (an interrupted cycle 302/303
  had run mode-selection and started FEATURE work — the §8.5 restore feature —
  but crashed before committing or writing a memory entry; no cycle-302/303
  entry exists below, matching the cycle-299 precedent of picking up an
  orphaned prior diff rather than discarding it). Incremented to 304 (304 % 5
  != 0 → FEATURE) and finished the inherited work rather than starting fresh.
- **Real gap found and fixed before commit:** the inherited diff had already
  added a threat-model-required fix — a NEW HKDF domain
  (`RECOVERY_AUTH_KEY_DOMAIN = b"powehi-recovery-auth-v1"`,
  `derive_recovery_auth_keypair`) meant to keep the server-durably-stored
  `recovery_pubkey` cryptographically independent from the MLS identity
  signing key (`SIGNING_KEY_DOMAIN`) — but had NEVER wired that function into
  the actual WASM entry points. `mls_init_identity_from_phrase`'s
  `recoveryPubkey` output and `mls_sign_recovery_challenge`'s signing key were
  both still using `derive_signing_keypair` (the MLS key), silently defeating
  the whole point of the domain-separation fix. Fixed both call sites in
  `wasm_exports.rs`, updated the recovery.rs/wasm_exports.rs tests that had
  been asserting against the wrong key, and added an explicit
  `recovery_auth_keypair_differs_from_mls_signing_keypair` independence test.
- Feature itself (§8.5): a user with zero local devices can restore access
  with password + 24-word recovery phrase. Client re-derives the
  recovery-auth Ed25519 keypair from the phrase inside WASM, signs the
  server's login nonce (`b"powehi-recovery-challenge-v1" || 0x00 ||
  login_nonce_utf8`, domain-separated from both the MLS-key-signing domain
  and the kem_credential signing domain), server verifies with
  `verify_strict` against `users.recovery_pubkey` (new nullable BYTEA column,
  migration 0009) and — only after OPAQUE login already succeeded — mints a
  brand-new `Device` row via `AuthService::mint_recovery_device`. Every
  failure mode (not enrolled, malformed key/sig, bad signature, device cap
  hit) collapses to the same `Unauthorized`. Frontend: new "restore-account"
  `Login.tsx` mode + `Login.restore.test.tsx` (4 tests).
- **crypto-reviewer: YELLOW → fixed.** Two required findings, both addressed:
  (1) the wiring gap above, confirmed fully closed (grep swept the whole
  crate + app/ for any remaining `derive_signing_keypair` use on the recovery
  path — none); (2) added the missing KAT for
  `derive_recovery_auth_keypair` (`derive_recovery_auth_keypair_known_answer`,
  zero-seed + abandon-phrase vectors, same bar as the sibling
  `derive_signing_keypair_known_answer`) — the domain doc already warned a
  silent drift here "breaks recovery-challenge verification for every
  existing user" but nothing was pinning it. Also fixed a stale
  `crypto.worker.ts` doc comment that said `mlsSignRecoveryChallenge` signs
  with "the MLS identity signing key" — exactly the vulnerability just fixed.
- **security-auditor: GREEN** (pass), 3 non-blocking YELLOW advisories: (1)
  self-lockout — a recovery-enrolled user already at `MAX_DEVICES_PER_USER`
  (10) has no prune path via this route, availability gap not a vuln,
  accepted; (2) timing oracle — `mint_recovery_device`'s not-enrolled branch
  used to `ok_or`-short-circuit before `verify_strict`, potentially leaking
  enrollment status via timing to a caller who already passed OPAQUE. Fixed
  anyway (cheap, in-scope): added `DUMMY_RECOVERY_PUBKEY` (a fixed, valid,
  known-privkey-discarded Ed25519 point) so the not-enrolled path now runs
  the identical `verify_strict` call before rejecting, plus a
  `dummy_recovery_pubkey_is_a_valid_ed25519_point` regression test guarding
  that the constant stays decodable; (3) `proof.mls_credential` has no
  explicit size cap (bounded only by the 512KB body limit) — pre-existing
  parity with `register_finish`'s `mls_credential`, left as a candidate for a
  future cycle, not scope-creeped into this one.
- **threat-model-checker: YELLOW → docs updated.** No control was weakened
  (crypto sound, 2-factor gating strictly additive, no group-state/FS/PCS
  impact — a recovery-minted device gets no group membership until an
  existing member's MLS Commit, and an identity-key change still fires the
  §5.6 Safety Number alert), but prd.md never documented this. Added: a new
  `users.recovery_pubkey` bullet in §3.3 (server-inevitable metadata list,
  explaining the domain-separation guarantee), a new "서버 검증 복원 프로토콜"
  subsection under §8.5 documenting the challenge-response protocol and
  2-factor gating, and **ADR-003** in §16.6 for the new pre-session
  authentication surface.
- Full verification: `cargo build --workspace` clean, `cargo test --workspace`
  green across all 41 test binaries (166 in powehi-crypto-wasm incl. new KAT +
  independence tests, 116 in powehi-application incl. 8 new §8.5 tests + the
  dummy-pubkey regression test), `cargo clippy --workspace --all-targets -- -D
  warnings` clean, `cargo fmt --all --check` clean. Frontend: `pnpm test`
  green (100 files / 1270 tests, incl. the pre-existing
  `Login.restore.test.tsx`), `biome check` clean on all touched files.
  (`cargo nextest` still not installed in this sandbox — fell back to `cargo
  test --workspace` per the documented runbook fallback, same as every
  recent cycle.)
- **Next cycle candidate:** none urgent — this closes out the inherited §8.5
  work cleanly. Standing older candidates unchanged: `powehi-telemetry`
  env-var-race flake (STABILIZATION-appropriate, noted since cycle 296), PQ
  hybrid Phase A (still blocked on openmls shipping a stable
  `MLS_128_MLKEM768` ciphersuite). Minor: security-auditor's YELLOW #3 above
  (bound `mls_credential`/`proof.mls_credential` size) is a reasonable small
  future STABILIZATION item, same style as the cycle-300 KeyPackage size
  bound.

## Previous state (2026-07-17, cycle 301 — FEATURE: per-device outstanding-invite cap, prd.md §8.3, commit 67aefa3)

- `gh run list --limit 3` showed the last two CI runs (cycle 300's commits)
  green on both `CI — Rust` and `CI — Live-backend E2E`; `git status` was
  clean at session start (no orphaned work this time, unlike cycle 299).
- Picked the standing next-candidate from cycle 300's entry: no cap existed
  on the *number* of outstanding (unredeemed) invites a single authenticated
  device could hold at once — only the global per-IP rate limiter and (as of
  cycle 300) a per-invite KeyPackage size bound. security-auditor flagged
  this as an INFO note in cycle 300; this cycle closes it.
- Added `CachePort::set_remove` (default no-op, mirrors the existing
  `set_add`/`set_expire`/`set_members` pattern in
  `crates/ports/powehi-port-outbound/src/cache.rs`) and implemented it via
  Redis `SREM` in `crates/adapters/outbound/powehi-redis/src/lib.rs`.
- `InviteService` (`crates/application/powehi-application/src/invite_service.rs`)
  now tracks a per-device Redis SET (`invite:device:{uuid}`) of hashed invite
  keys (never raw codes, same no-raw-token-at-rest invariant as the invite
  cache entries themselves). `create_invite` rejects with
  `DomainError::InvalidInput("too many outstanding invites")` (400, same
  convention as the empty/oversized-KeyPackage checks in the same function)
  once the device's set reaches `MAX_OUTSTANDING_INVITES_PER_DEVICE = 20`.
  `redeem_invite` best-effort removes the freed slot via `set_remove` after
  consuming the invite (GETDEL); a cleanup failure is swallowed (logged at
  debug, no payload) and does not fail the redemption.
- **security-auditor: GREEN**, two non-blocking YELLOW notes, both
  fail-closed/bounded: (1) the device-set's TTL slides to 24h-from-now on
  every `create_invite` and SET members have no individual TTL, so a member
  for an invite that itself already expired unredeemed keeps counting
  against the cap until the device goes a full INVITE_TTL idle, not just
  until that one invite's own TTL elapses — reworded the in-code comments to
  state this precisely rather than the original (slightly incorrect)
  "TTL mirrors the invite's own" framing; (2) a TOCTOU between the
  `set_members` length check and `set_add` lets N concurrent creates for the
  same device all pass and overshoot the cap by up to N — bounded by the
  existing per-IP rate limiter, same non-atomic-check-then-write pattern
  already documented for `CachePort::get_del`'s default impl, accepted as-is
  per auditor recommendation (not worth a Lua/`SCARD` atomic upgrade for a
  generous cap of 20). No threat-model-checker run this cycle — no new
  server-visible metadata category (the SET's members are hashes already
  derivable from data the server already touches) and no architectural
  shift, matching the cycle-300 precedent of skipping that gate for a
  narrow-scope bound/cap addition.
- 5 new unit tests in `invite_service.rs` (cap enforced at/over the limit,
  succeeds exactly at the limit, cap is scoped per-device not global,
  redeeming frees a slot) — upgraded the test `FakeCache` to actually
  implement `set_add`/`set_remove`/`set_members` (previously silent no-ops
  inherited from the trait defaults, which would have made the cap
  untestable). 2 new `#[ignore]`d testcontainers tests in
  `redis_cache_it.rs` for `set_remove` (member-scoped removal,
  idempotent-on-missing-member), mirroring the existing `set_add`/
  `set_members`/`set_expire` coverage style.
- Full verification: `cargo build --workspace` clean, `cargo test
  --workspace` all green (0 failures across every crate), `cargo clippy
  --workspace --all-targets -- -D warnings` clean, `cargo fmt --all --check`
  clean. `cargo test --no-run -p powehi-redis` compiles (Docker unavailable
  in this sandbox, same as every prior cycle touching that file — the
  `#[ignore]`d tests run for real only in CI).
- **Next cycle candidate:** none urgent from this change — the two YELLOWs
  above are accepted-as-is per the auditor, not open gaps. Standing older
  candidates: the `powehi-telemetry` env-var-race test flake (STABILIZATION-
  appropriate, noted since cycle 296) or PQ hybrid Phase A (still blocked on
  openmls shipping a stable `MLS_128_MLKEM768` ciphersuite — do not pick
  until confirmed available upstream, per the ADR-0003 Y-series note below).

## Previous state (2026-07-17, cycle 300 — STABILIZATION: invite KeyPackage size guard + yanked-crate lockfile fix)

- `gh run list` returned HTTP 503 (GitHub API transient outage, not auth) both
  on first try and after a 5s retry — CI status could not be confirmed
  directly this cycle. `gh issue list --state open` returned empty (no open
  issues). Proceeded on the strength of local gates (build/test/clippy/fmt all
  green) and the fact that the last several cycles' commits already landed
  clean, per this file's own history.
- **Security sweep, item 1 — closed the cycle-299 YELLOW carryover:** cycle
  299's security-auditor flagged that `InviteService::create_invite`'s
  `key_package: Vec<u8>` had no invite-specific upper size bound (only the
  global 512KiB axum body limit + per-IP rate limiting), letting an
  authenticated caller pad a KeyPackage toward the body-limit ceiling and
  bloat Redis for up to 24h per invite (GETDEL single-use, so bounded but
  wasteful). Added `const MAX_KEY_PACKAGE_BYTES: usize = 16 * 1024;` in
  `crates/application/powehi-application/src/invite_service.rs` (real MLS
  KeyPackages are ~1-2KB, so 16KiB gives ~8-16x headroom) and a
  `key_package.len() > MAX_KEY_PACKAGE_BYTES` check right after the existing
  empty-check, reusing `DomainError::InvalidInput` (400) rather than adding a
  new error variant/HTTP status — matches the existing convention (every
  size/format rejection in this codebase maps to 400, not a dedicated 413).
  2 new tests: oversized (limit+1) fails, at-exactly-the-limit succeeds.
- **security-auditor: GREEN.** Verified the bound actually closes the gap
  (Redis value = 16-byte device UUID + key_package, so max stored value drops
  from ~512KiB to ~16KiB + 16B, a ~32x reduction), empty-check-then-size-check
  ordering is safe (neither oversized nor empty reaches `cache.set`), no
  bypass via `redeem_invite` (read-then-delete only, can't grow storage), no
  info leak (only the static `code` field crosses the wire, detail message
  never serialized). One INFO note, not fixed (out of scope): no per-device
  cap on *number* of outstanding invites, so aggregate Redis footprint is
  still bounded only by the per-IP rate limiter, not a per-principal quota —
  candidate for a future cycle if invite-spam DoS enters the threat model.
- **Security sweep, item 2 — dependency hygiene:** `cargo audit` and
  `cargo deny check` both showed only `warning: yanked crate` for `spin`
  0.9.8 and 0.10.0 (transitive via aws-sdk-s3/sqlx-mysql/tracing-subscriber's
  dep chains — not a direct dependency, no CVE). Ran
  `cargo update -p spin@0.9.8` (→0.9.9) and `cargo update -p spin@0.10.0`
  (→0.10.1), both pure patch bumps to un-yanked releases with no dependency
  edge changes. Post-update `cargo deny check` shows zero yanked warnings
  (only pre-existing benign `license-not-encountered`/`duplicate`-version
  noise, unchanged from before). security-auditor confirmed this is safe and
  in-scope to bundle with the security-focused commit (verified above).
  No RUSTSEC advisories were open this cycle (unlike cycle 250's
  crossbeam-epoch/anyhow/bitcoin_hashes fixes) — this was purely a
  yanked-version cleanup.
- Full verification: `cargo build --workspace` clean, `cargo test --workspace`
  all green (exit 0, incl. 9 invite_service tests: 7 pre-existing + 2 new),
  `cargo clippy --workspace --all-targets -- -D warnings` clean, `cargo fmt
  --all --check` clean. (`cargo nextest` binary is not installed in this
  sandbox — fell back to `cargo test --workspace` per the runbook's documented
  fallback.)
- Target dir hygiene: 21G (just over the 20G threshold). Pruned 0-byte
  aborted `.rmeta` stubs (none found) and attempted a >7-day-old prune of
  `target/debug/deps` build artifacts + incremental dirs — no effect, since
  all artifacts are from active daily-cycle development within the last 7
  days. Not a blocker; noted for a future cycle if growth continues.
- **Next cycle candidate:** per-device/per-principal cap on outstanding
  (unredeemed) invite count, if invite-spam DoS should enter the threat model
  (security-auditor INFO note above, cycle 299's separate unbounded-invite-
  keypair-accumulation note is a related but distinct client-side item).

## Previous state (2026-07-17, cycle 299 — FEATURE: pin KeyPackage hash to invite links, MITM fix, prd.md §8.3/§8.4, commit a8f4954)

- Session opened with a large uncommitted working-tree diff already present
  (touching invite.rs/invite_service.rs/invites.ts/AcceptInviteModal.tsx/
  ChatLayout.tsx/useDeepLink.ts + their tests) — evidently an interrupted
  cycle 298 that never reached a commit. No cycle-298 entry exists in this
  file or in `git log`. Investigated rather than discarded (per the "don't
  destroy unfamiliar in-progress work" guidance) and found it was a real,
  well-reasoned security feature: closing an MITM gap where the invite
  recipient fetched the inviter's KeyPackage via a server-controlled
  `GET /v1/key-packages/:deviceId` lookup, so a compromised/malicious server
  could substitute an attacker-controlled KeyPackage undetectably.
- The redeem/receiving half was fully done and well-tested (AcceptInviteModal
  hashing + comparing, useDeepLink's `code.hash` fragment parsing, the
  backend `redeem` endpoint returning the pinned KeyPackage, all with
  matching tests). **The create/inviting half was broken**: `InviteModal.tsx`
  never generated or hashed a KeyPackage at all — it called
  `createInvite(sessionToken)` with no args and destructured a
  `key_package_hash` field the Rust backend explicitly documents it will
  NEVER return (a doc comment and a regression test in `routes/invite.rs`
  assert the create response has no such field, precisely so the server
  can't author the value being verified). This cycle's actual work was
  finishing that half correctly, not just verifying the leftover diff.
- **Fix:** `InviteModal.tsx` now calls `cryptoWorker.mlsGetKeyPackage(identityId)`
  to mint a fresh KeyPackage, hashes it locally via `crypto.subtle.digest`,
  and calls the updated `createInvite(sessionToken, keyPackage: Uint8Array)`
  (POST body `{key_package}`) — the URL is built from the code plus the
  *locally computed* hash, never anything from the server response.
  `CreateInviteResponse` narrowed back to `{ code }` (no `key_package_hash`).
  Updated `invites.test.ts` and `InviteModal.test.tsx` (added a real
  `useCryptoWorker` mock + `identityId`, and switched the fragment/hash
  fixtures to the actual SHA-256 of the mocked KeyPackage rather than an
  arbitrary string, mirroring `AcceptInviteModal.test.tsx`'s existing pattern).
- **crypto-reviewer: GREEN.** Hash pinning is sound (SHA-256 over the exact
  bytes later fed to `mlsAddMember`, no TOCTOU gap), server has no path to
  author/see the hash, Rust `Vec<u8>` concat/split in `invite_service.rs` is
  panic-free, plain `!==` hash comparison is fine (both operands are public
  non-secret hashes), reusing `mlsGetKeyPackage` for a one-off pinned invite
  doesn't collide with the shared KeyPackage pool or MLS generation
  bookkeeping, no homegrown crypto / no hash confusion (server's
  `Sha256::digest` hashes the invite *code* for the cache key; client's
  `crypto.subtle.digest` hashes the *KeyPackage* — different purposes, not
  conflated). Two non-blocking LOW advisories (see below).
- **threat-model-checker: YELLOW → fixed in-cycle.** Code correctly
  strengthens the threat model (T3 malicious-server-operator) with no new
  metadata category (KeyPackage was already server-held public pool data;
  the pinned copy in Redis is shorter-lived and single-region). Required
  prd.md doc updates before commit, both applied: §3.3's metadata-honesty
  entry (line ~179) now says the Redis value is `H(code) → (DeviceId ‖
  KeyPackage bytes)`, not just `DeviceId`; §8.3 now documents the
  `code.keyPackageHash` fragment format and the pin-and-verify flow, with an
  explicit scope note that out-of-band channel tampering (malicious link
  shortener, swapped QR) remains an unchanged, separate T2 concern — the pin
  only defeats server-side substitution, not delivery-channel compromise.
- **security-auditor: GREEN**, one non-blocking YELLOW (same one
  crypto-reviewer also flagged): `key_package` has no invite-specific upper
  size bound, only the global 512KiB axum body limit + per-IP rate limiting
  (`api_governor`, burst=60). A KeyPackage is normally ~1-2KB; nothing stops
  an authenticated caller from padding it toward the body-limit ceiling,
  bloating Redis for up to 24h. Bounded (rate-limited, capped, GETDEL
  single-use) but larger than necessary. **Next cycle candidate**: add an
  explicit `key_package.len() > MAX_KEY_PACKAGE_BYTES` (~16KiB) guard in
  `InviteService::create_invite`.
- Also noted, not fixed (crypto-reviewer LOW, PQ-owner territory, out of
  scope for this MITM fix): every "Create invite link" click mints a fresh
  MLS leaf keypair + PQ decap key persisted to encrypted Dexie, with no
  GC/expiry path for ones that are never redeemed — unbounded accumulation
  over time, not a leak (encrypted at rest) but worth a cleanup story
  eventually.
- Full verification: backend `cargo build --workspace` clean, `cargo test
  --workspace` all green (159 invite/application/route tests incl. new
  `create_invite_with_empty_key_package_fails`), `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --all --check` clean
  (fixed one leftover formatting diff from the uncommitted cycle-298 work).
  Frontend: 1265/1265 tests green (was 1256, +9 new), `tsc -b` clean (fixed
  a `Uint8Array<ArrayBufferLike>` vs `Uint8Array<ArrayBuffer>` strict-TS
  mismatch introduced by passing the crypto-worker's returned KeyPackage
  straight into `crypto.subtle.digest` — copied into a fresh `Uint8Array`
  first, same pattern `AcceptInviteModal.tsx` already used), `pnpm build`
  (bundle budget) green (160KB gz JS / 643KB gz WASM, both under budget),
  `biome check` clean.
- **Lesson for future cycles inheriting an uncommitted working tree:** don't
  assume leftover diffs are either "done, just needs a commit" or "garbage,
  discard it" — read every touched file's actual logic (not just skim the
  diff) before deciding. Here the diff *looked* complete (tests existed on
  both sides, doc comments were thoughtful) but one call site
  (`InviteModal.tsx`) was silently never wired up, which only surfaced by
  tracing the actual data flow (does the server response have the field the
  frontend destructures?) rather than trusting that "tests pass" on the
  files touched so far — the create-side test file's own mocks were masking
  the gap by mocking `createInvite`'s return value with a `key_package_hash`
  the real backend would never send.

## Current state (2026-07-16, cycle 297 — STABILIZATION (mode-escalated from FEATURE by red CI): fix WasmModule TS interface drift, commit c2d51da)

- Mode selection gave FEATURE (297 % 5 = 2), but the mandatory `gh run list`
  CI check found `CI — Frontend` red on `main` (run 29493174951, cea94e5 —
  the cycle-296 mimeType commit) → escalated to STABILIZATION per the
  FEATURE-mode step-2 rule, CI-fix-first.
- **Root cause:** cycle 296 added a `mimeType?: string` trailing param to the
  Rust `#[wasm_bindgen]` exports `media_message_create` /
  `_create_chunked` / `_create_with_thumbnail` and updated every call site in
  `crypto.worker.ts`, but the hand-written `WasmModule` TS interface in that
  same file (the type `getWasm()` is cast to — this repo does NOT import the
  wasm-bindgen-generated `.d.ts` directly; `pkg/`/`app/src/wasm/` are
  gitignored build artifacts) was never updated to match. `tsc -b` caught the
  arity mismatch (`Expected 6 arguments, but got 7` etc.) at build time; every
  other CI job (Vitest, Playwright, Biome, WASM compile) passed because none
  of them run a full `tsc -b` typecheck — only the `Bundle budget check` job's
  `pnpm --filter app build` (`tsc -b && vite build`) does. **Lesson for future
  wasm-export arity changes: grep `WasmModule` in `crypto.worker.ts` alongside
  the call sites — it's a second, easy-to-miss source of truth that no test
  layer catches except the production build itself.**
- **Fix:** added the matching `mimeType?: string` param to all 3
  `WasmModule` interface signatures (3-line diff, `app/src/workers/
  crypto.worker.ts`). No Rust/WASM/crypto-boundary logic touched — pure TS
  type-surface fix, so no `crypto-reviewer` pass required (interface-only,
  zero runtime behavior change; the mock in `__mocks__/useCryptoWorker.ts`
  already had the correct 7/8-arg signatures, confirming the drift was
  interface-only).
- Verified: `pnpm build` (tsc -b + vite build) green, bundle budget script
  green (155.5KB gz initial JS / 627.4KB gz WASM, both under the 200KB/800KB
  budgets), full `pnpm test` 1256/1256 green (99 files), `biome check` clean
  on the touched file.
- Rest of STABILIZATION checklist: `gh issue list --state open` empty.
  `cargo audit` + `cargo deny check` both clean (only the same pre-existing
  allowed `spin` yanked-crate warnings via x509-parser/rsa/aws-sdk-s3
  transitive deps as prior cycles — no new CVEs). `cargo build --workspace`
  clean. `target/` at 20GB, under the 20GB prune threshold — no pruning
  needed this cycle.
- Did NOT chase the cycle-296-noted `powehi-telemetry` env-var test-race
  flake this cycle (CI-fix took the stabilization slot); still open for a
  future stabilization cycle.
- **Next cycle candidates:** (a) resume FEATURE work — cycle 296's item (c)
  "resume normal FEATURE scanning for other open prd.md gaps" is still the
  live pointer; (b) the `powehi-telemetry` env-var test-race flake
  (STABILIZATION-appropriate); (c) the standing cycle-289 security-auditor
  YELLOW (ack-on-URL-grant-not-confirmed-transfer, non-urgent). PQ hybrid
  Phase A still blocked on upstream openmls `MLS_128_MLKEM768`.

## Current state (2026-07-16, cycle 296 — FEATURE: real mimeType on media envelope, prd.md §9.2/§9.4.2, commit cea94e5)

- Closed the cycle-294 "next candidate": the media wire envelope's `type`
  field was chosen purely by size bucket (single-shot encrypt → "image",
  §9.4.2 chunked encrypt → "video"), never by the sender's real file MIME
  type — so a small video (≤16MiB) sent through the non-chunked path was
  always mislabeled "image" client-side. Cycle 294's `<img onError>`→
  `<video>` fallback in `MediaImage.tsx` was a same-cycle mitigation, not a
  fix; the mislabel was still live.
- **Fix:** added an OPTIONAL `mimeType` field to the JSON payload (itself
  inside the existing MLS-encrypted Application message — never
  server-visible beyond what `content_type` already exposes via
  `POST /v1/media/upload-url`, unchanged by this diff). Additive/non-breaking:
  `#[serde(skip_serializing_if = "Option::is_none")]` so it's omitted (not
  serialized as null) when absent, so older-client envelopes round-trip
  unchanged.
  - Rust: `crates/client/powehi-crypto-wasm/src/wasm_exports.rs` —
    `build_media_payload_json` / `_with_thumbnail` / `_chunked` each gained
    an `Option<&str> mime_type` param; the three `#[wasm_bindgen] pub fn
    media_message_create*` exports gained a matching `Option<String>` param
    (maps to `mimeType?: string | undefined` at the JS boundary — verified
    by rebuilding via `wasm-pack build --out-dir app/src/wasm` and checking
    the regenerated `.d.ts`, both `pkg/` and `app/src/wasm/` are gitignored
    build artifacts, not committed). Added `#[allow(clippy::too_many_arguments)]`
    to the 3 functions that crossed the 7-arg clippy default (8 args) —
    no existing precedent in this file, first use.
  - Frontend: `crypto.worker.ts` / `mediaTransfer.ts` thread the real
    `mimeType` (already in scope from the file being sent) through to the
    WASM export on all 3 send paths (single-shot, chunked, with-thumbnail).
    `useMessages.ts` parses `parsed.mimeType` into a new optional
    `MediaPayload.mimeType` field. `MediaImage.tsx` / `useMediaReceive.ts`
    / `ChatLayout.tsx`'s forward-path now prefer `media.mimeType` (when
    present) over the old `media.chunked === true` heuristic for image-vs-
    video display + the `sniffMimeType` videoHint + the forwarded
    `content_type` sent to `requestMediaUpload` — falling back to the old
    chunked-based heuristic when `mimeType` is absent (legacy envelope from
    an older client build).
- **crypto-reviewer: GREEN.** Confirmed: no new server-visible leak (field
  stays inside the existing MLS trust boundary); the peer-supplied
  `mimeType` string is only ever consumed via `.startsWith("video/"|"image/")`
  booleans or as a `Blob.type` — never interpolated into a URL/HTML/eval,
  no new XSS/injection surface; raw media key retrieval
  (`MEDIA_KEYS`/`media_key_handle`) is byte-identical, untouched. One
  YELLOW advisory raised (forwarding a peer's real `mimeType` as
  `content_type` to the forwarder's own server is a *fidelity* increase
  within an already-existing, already-server-visible channel) — verified
  already mitigated by the pre-existing cycle-260 `is_valid_content_type`
  RFC 6838 fail-closed check in `media_service.rs::request_upload`, which
  gates every `content_type` regardless of original-send vs. forward-relay
  origin. Not a new gap.
- **threat-model-checker: GREEN.** No new server-visible metadata category
  (unlike cycle-289's `media_acks`, which added a real server-side table —
  this field never crosses the MLS boundary), no OOS-list movement, no
  tier (T1-T6) defense reduction. Added a half-sentence to prd.md §9.2's
  envelope diagram (optional `mimeType` field) as a documentation nicety,
  not a required update.
- Tests: 4 new Rust unit tests in `wasm_exports.rs` (omit-when-None +
  carries-real-value for each of the 3 builders) — crate total 157 passed
  (was 153) + 2 ignored (pre-existing, Docker-gated), all existing arity-
  changed call sites updated in place (no test count change from those).
  Frontend: +6 new tests across `mediaTransfer.test.ts` (+2, real mimeType
  reaches both chunked and non-chunked `mediaMessageCreate*`),
  `MediaImage.test.tsx` (+3, mimeType-priority render decision + error
  text), `useMediaReceive.test.ts` (+1, mimeType wins over chunked for the
  `sniffMimeType` videoHint on generic/non-magic-byte plaintext). Updated 1
  existing test (`ChatLayoutForwarding.test.tsx`) whose
  `mediaMessageCreate` call-arity assertion needed the new trailing
  mimeType arg. 1256/1256 frontend tests green (99 files), tsc clean,
  biome clean.
- Full `cargo build/test/clippy/fmt --workspace` clean. One PRE-EXISTING,
  UNRELATED flake found and confirmed not caused by this diff:
  `powehi-telemetry::tests::otlp_config_from_env_returns_none_when_endpoint_absent`
  fails only under default parallel `cargo test` (env-var race against the
  sibling `..._returns_some_when_endpoint_set` test mutating the same
  process env var) and passes clean under `--test-threads=1`. Not touched
  by this diff (never opened `powehi-telemetry`) — left as a stabilization-
  cycle candidate, not fixed here (out of scope for a FEATURE cycle).
- **Next cycle candidates:** (a) the `powehi-telemetry` env-var test-race
  flake above (STABILIZATION-appropriate: fix via `#[serial]`/`std::sync`
  guard or per-test env isolation, not a real behavior bug); (b) the
  remaining cycle-289 security-auditor YELLOW — ack-on-URL-grant-not-
  confirmed-transfer (non-urgent, bounded by 30-day retention floor); (c)
  resume normal FEATURE scanning for other open prd.md gaps. Long-standing
  PQ hybrid Phase A block is still blocked on upstream openmls shipping a
  stable `MLS_128_MLKEM768` ciphersuite.

## Current state (2026-07-16, cycle 295 — STABILIZATION: paginate media GC scan query, commit bc6a4c2)

- CI green (`gh run list`), `gh issue list --state open` empty, `cargo audit`
  clean (only the pre-existing allowed `spin` yanked-crate warnings via
  x509-parser/rsa/aws-sdk-s3 transitive deps, already permitted), `cargo deny
  check` clean (advisories/bans/licenses/sources all ok). No dependency CVEs
  to fix this cycle, so the pass targeted the one concrete open item from
  cycle 289's memory: the security-auditor YELLOW that the hourly media-blob
  GC sweep (`MediaService::run_gc`, prd.md §9.4.3) did an unfiltered,
  unpaginated `SELECT * FROM media_blobs` into memory every run.
- **Fix:** `MediaRepository::list_undeleted()` → `list_gc_candidates(now,
  default_retention_cutoff, after_id, limit)`. The eligibility filter
  (`expires_at <= now`, or `uploaded_at <= now - 30d` when `expires_at` is
  unset) now lives in the SQL `WHERE` clause instead of a Rust-side loop over
  every row in the table, and results are keyset-paginated by `id`
  (`id > after_id ORDER BY id LIMIT n`, NOT `OFFSET` — `run_gc` deletes
  matching rows as it scans a page, so `OFFSET` pagination would skip/re-scan
  rows across pages). `run_gc` now delegates to `run_gc_batched`, looping in
  pages of `GC_BATCH_SIZE = 500` until a short page signals exhaustion,
  advancing the cursor to the last id in each page *before* any delete so an
  eligible-but-currently-undeletable blob (unacked recipients) can't stall
  the sweep — it's just deferred to the next hourly run, not lost. Retention
  semantics (30-day default, `expires_at` takes priority) are byte-identical
  to before; only the fetch mechanism changed. Delegated implementation to
  `backend-lead`.
- **security-auditor: GREEN.** Verified: parameterized SQL (no injection),
  keyset correctness (no permanent skip, no double-delete/panic — undeletable
  blobs deferred to next sweep, not dropped), no plaintext/PII/ciphertext in
  the new `#[instrument]` span, no new `unwrap()`/`expect()` in library code,
  eligibility logic provably unchanged, `list_gc_candidates` reachable only
  from the internal GC sweep (no REST route exposes it). One non-blocking nit
  applied in-cycle: the span was auto-capturing all 4 args inconsistently
  with sibling methods' explicit-field convention — changed to
  `skip(self, now, default_retention_cutoff, after_id)` +
  `fields(limit = %limit)`.
- Tests: `MockMediaRepo` test fake updated to mirror the SQL filter/keyset
  semantics in-memory; all ~7 pre-existing `run_gc_*` unit tests still green
  plus 2 new ones (`run_gc_batched_paginates_across_multiple_batches`:
  5 candidates through a batch size of 2 all get GC'd across 3 pages;
  `run_gc_batched_does_not_loop_on_undeletable_blob`: sweep terminates and
  continues past a stuck blob rather than looping forever). New `#[ignore]`d
  testcontainers test in `r2_media_it.rs` (`list_gc_candidates_filters_
  paginates_and_keysets`) compiles (`cargo test --no-run -p powehi-r2`) but
  can't execute — no Docker in this sandbox, same as every prior cycle
  touching that file; will run for real in CI.
- Verified clean: `cargo build --workspace`, `cargo test --workspace` (0
  failures across every crate), `cargo clippy --workspace --all-targets --
  -D warnings`, `cargo fmt --all --check`. Frontend untouched this cycle
  (pure backend fix) — skipped `pnpm test`/`tsc`/`biome`.
- **target/ hygiene:** at 21G (just over the 20G prune threshold) — ran the
  0-byte-`.rmeta` prune (no matches, already clean) and the mtime+7d prune
  for `.rlib`/`.rmeta`/`.o`/`.d` + stale incremental dirs; still ~20G after
  (mostly recent/active build artifacts within the 7-day window, nothing
  older to reclaim). Not a code change, doesn't count as the cycle's commit.
- **Next cycle candidates:** (a) the remaining cycle-289 security-auditor
  YELLOW — ack-on-URL-grant-not-confirmed-transfer (blob GC'd once a
  recipient *requests* a download URL, not once the download actually
  completes; bounded by the 30-day retention floor, non-urgent); (b) the
  cycle-294 mimeType-based wire-tagging fix for chunked video (bigger scope,
  needs its own crypto-reviewer/threat-model pass since it changes the wire
  schema); (c) resume normal FEATURE scanning for other open prd.md gaps.
  Long-standing PQ hybrid Phase A block is still blocked on upstream openmls
  shipping a stable `MLS_128_MLKEM768` ciphersuite.

## Current state (2026-07-16, cycle 294 — FEATURE: chunked video UI wiring, prd.md §9.4.2, commit 8f14a85)

- Closed the gap cycle 292 flagged as its own "next cycle candidate": the
  chunked AES-256-GCM video pipeline (WASM + wire format) existed but had
  zero UI reachability — the attach picker was `accept="image/*"` only (no
  video could ever be selected) and the receiver showed a static "[video]"
  placeholder with no playback.
- **What changed (frontend-only, no Rust/WASM touched):** widened the file
  input to `image/*,video/*`; `MediaImage.tsx` now renders `<video controls>`
  when `media.chunked === true`, with a non-interactive muted+play-badge
  variant (`interactive={false}`) for the InfoPanel gallery-grid thumbnails
  (avoids nesting `<video controls>` inside a `<button>` — invalid HTML,
  unreachable controls); `sniffMimeType` gained MP4 `ftyp`/WebM EBML
  magic-byte detection plus a `videoHint` fallback param, used both for the
  receive-side Blob type and when re-sniffing forwarded media; excluded
  `"[video]"` placeholder text from the Share/Copy button gates and from the
  per-message lightbox-open wrapper (same treatment `"[image]"` already had).
- **Deliberately did NOT change:** `encryptAndSendMedia`'s chunked-vs-single-
  shot routing predicate. It stays purely size-based (`bytes.length >
  MEDIA_CHUNK_THRESHOLD`), never mimeType-based — an existing cycle-292 test
  asserts a `"video/mp4"`-labeled file *at or under* the threshold still
  takes the non-chunked path, and changing that would've broken a tested,
  already-reviewed invariant for a much bigger (wire-format) change than this
  cycle's scope. Net effect: a small (≤16 MiB) video sent through the UI
  still gets wire-tagged `"image"` by the existing WASM export (pre-existing
  latent mislabel, now reachable for the first time since video selection is
  possible at all). Covered with a same-cycle mitigation instead of a
  protocol change: `MediaImage`'s `<img onError>` falls back to rendering
  `<video>` when decode-as-image fails, so small videos still play; documented
  in the component's doc comment as a known, accepted, non-regressing gap.
  Follow-up candidate for a future cycle: fix the mislabel at the source
  (tag by real content mimeType, not by size bucket) — bigger scope, needs
  its own threat-model/crypto-reviewer pass since it changes the wire schema.
- **crypto-reviewer: GREEN**, no findings. Confirmed no Rust/WASM crypto
  crate was touched; routing, key-zeroing (`mediaKey.fill(0)` in `finally`),
  and blob-hash-before-decrypt verification are all unchanged. Mime-sniffing
  only affects the `Blob` `type` passed to `URL.createObjectURL` on already-
  decrypted plaintext — cannot influence decryption, cannot be leveraged into
  XSS (only ever returns `image/*`/`video/*`, consumed via `<img>`/`<video
  src>`, never executes script). `videoHint` derives from `media.chunked`,
  an MLS-authenticated field, not attacker-controlled input crossing a trust
  boundary. threat-model-checker/security-auditor not invoked — no new
  server-visible metadata, no backend/infra touched (pure frontend diff).
- Verified: `tsc --noEmit` clean, `biome check .` clean (repo-wide, not just
  touched files), full Vitest suite 1250/1250 green (99 files, was
  94/1237 — added tests: `MediaImage.test.tsx` video-rendering branch (4),
  `mediaTransfer.test.ts` `sniffMimeType` video-detection (5), one `"[video]"`
  exclusion test each in `ChatLayoutCopy.test.tsx`/`ChatLayoutShare.test.tsx`,
  one lightbox-exclusion test in `ChatLayoutLightbox.test.tsx`). Backend
  untouched — skipped `cargo nextest run --workspace` per the same
  diff-is-provably-backend-inert exception cycle 288 established (`git
  status` confirmed only files under `app/` changed).
- **Next cycle candidates (pick one):** (a) the mimeType-based wire-tagging
  fix noted above (bigger scope, own review pass); (b) the two still-open
  cycle-289 security-auditor YELLOWs (unpaginated `run_gc` query,
  ack-on-grant-not-confirmed-transfer — both non-urgent); (c) resume normal
  FEATURE scanning for other open prd.md gaps. Long-standing PQ hybrid Phase
  A block is still blocked on upstream openmls `MLS_128_MLKEM768`.

## Current state (2026-07-16, cycle 292 — FEATURE: chunked media streaming, prd.md §9.4.2, commit 039a236)

- Found substantial uncommitted work already sitting in the working tree at
  cycle start (media.rs, wasm_exports.rs, crypto.worker.ts, mediaTransfer.ts,
  useMessages.ts + tests, ~950 lines) — an interrupted prior session had
  fully implemented prd.md §9.4.2 "chunked media encryption for large video
  streaming" but never got to review/commit. Verified it built and all
  existing tests still passed, then finished the cycle by reviewing and
  committing it rather than discarding good work to start something new.
- **What it does:** files strictly larger than `MEDIA_CHUNK_THRESHOLD` (16
  MiB) route through a new chunked AES-256-GCM path instead of the existing
  single-shot `mediaEncrypt`/`mediaDecryptWithRawKey`. Each 16 MiB chunk gets
  a distinct nonce (`base_iv` XOR big-endian chunk index — the TLS 1.3
  per-record-nonce construction) under one fresh key; the last chunk is
  zero-padded so total ciphertext length only leaks plaintext size bucketed
  to the nearest 16 MiB; blob-hash is verified before any AES-GCM decrypt
  (same oracle-avoidance rule as the non-chunked path). New WASM exports:
  `media_encrypt_chunked`, `media_decrypt_chunked_with_raw_key`,
  `media_message_create_chunked`. Receiver-side (`useMessages.ts`) parses the
  new `{type:"video", chunked:true, ...}` payload with strict type/shape
  checks, falling through to legacy text handling on any malformed field.
- **crypto-reviewer: RED → GREEN (fixed in-cycle).** First pass caught a real
  blocking ABI bug: `media_decrypt_chunked_with_raw_key` and
  `media_message_create_chunked` took `total_size: u64` directly on a
  `#[wasm_bindgen]` export. wasm-bindgen marshals a Rust `u64` param as a JS
  `bigint`, not `number` — every real call from `crypto.worker.ts` (which
  passes a plain `number`) would throw `TypeError` at runtime. Invisible to
  the entire test suite because native Rust tests and the `mediaTransfer.ts`
  mocked-worker tests both bypass the actual wasm-bindgen JS boundary. Fixed
  by generalizing the pre-existing `f64_to_generation` helper (already used
  by `mls_export_state`/`mls_import_state` for exactly this reason) into
  `f64_to_u64_checked`, switching both new exports to take `f64` +
  convert-with-validation, and adding 6 new boundary tests (2^53 exact-
  representability edge, rejects negative/non-finite/non-integer/at-or-
  beyond-`u64::MAX`-as-f64, content-free error). Re-verified GREEN. Noted but
  accepted as non-blocking: no true end-to-end JS-boundary test exists (would
  need a compiled wasm-pack + Node harness) — matches the pre-existing gap
  for `mls_export_state`'s own f64 boundary, deferred.
- Verified clean: `cargo build --workspace`, `cargo build -p
  powehi-crypto-wasm --target wasm32-unknown-unknown`, `cargo test
  --workspace` (153 powehi-crypto-wasm tests incl. new chunked round-trip +
  proptest + f64 boundary tests, zero regressions elsewhere), `cargo clippy
  --workspace --all-targets -- -D warnings` clean, `cargo fmt --all --check`
  clean (one pre-existing formatting drift in media.rs fixed via `cargo fmt`
  before commit). Frontend: 1237/1237 tests green (94 files, was 92 — new
  `mediaTransfer.test.ts` + new `useMessages.test.ts` cases), `tsc --noEmit`
  clean, `biome check` clean.
- **Housekeeping note:** the immediately preceding commit (`e36220c`, "close
  last silent-failure gap in useMessages poll loop") was never given its own
  memory entry before this session started — recorded here for the record;
  no further action needed, it was already reviewed (crypto-reviewer GREEN
  per its own commit message) and pushed.
- **Next cycle candidate:** chunked video has no UI-side send/receive
  wiring yet beyond the payload plumbing (no composer path calls
  `encryptAndSendMedia` with a >16 MiB file today, and the receiver shows
  `[video]` as static text with no playback/progressive-download UI) — a
  natural follow-up feature. Also still open: the two cycle-289
  security-auditor YELLOWs (unpaginated `run_gc` query, ack-on-grant-not-
  confirmed-transfer) and the long-standing PQ hybrid Phase A block.

## Current state (2026-07-15, cycle 289 — FEATURE: media garbage collection, prd.md §9.4.3, commit 993f05b)

- CI was confirmed green on `main` at cycle start (all three workflows passed
  on `38c6c99`), so this cycle ran as ordinary FEATURE work. Committed the
  pending cycle-288 memory chore first (`b99693e`) since it had been left
  uncommitted at the end of the prior session.
- **Feature picked:** prd.md §9.4.3 media GC ("모든 수신자가 ACK 한 blob은 N일
  후 자동 삭제") — surveyed for open gaps first (no `qrcode`/streaming-range/
  GC code anywhere in the tree; `blocked-users list` from cycles 272-273 was
  never in prd.md, still skip it) and this was the cleanest unimplemented
  prd item with a concrete, bounded scope.
- **Design:** `MediaRepository` gained `record_ack`/`list_ack_device_ids`/
  `list_undeleted`; `MediaUseCase` gained `run_gc`. `get_download_url`
  records a best-effort ack (warn-logged on failure, never blocks the
  response) whenever a non-uploader group member is granted a download URL
  — this reuses the existing download-URL-request event as the "recipient
  consumed it" signal, no new endpoint needed. `run_gc()` scans all
  undeleted blobs; eligibility = `now >= expires_at.unwrap_or(uploaded_at +
  30d)` AND (no group_id, or every group member except the uploader appears
  in that blob's ack list). Wired into `bin/powehi-server/src/main.rs` as an
  hourly `tokio::spawn` loop, mirroring the pre-existing disappearing-
  message envelope GC task in the same file (same log-only-a-count style).
  New Postgres table `media_acks(media_id, device_id)` — composite PK,
  `ON DELETE CASCADE` from both `media_blobs` and `devices`, migration
  `0008_media_acks.sql` (+ rollback).
- **Review gates (both run in-session before commit, per CLAUDE.md):**
  - `threat-model-checker`: **YELLOW** (passes the "green/yellow" gate, but
    real findings, all addressed before commit, not just accepted as-is):
    (a) `media_acks` is a new durable server-visible metadata category not
    listed in prd.md §3.3 — added a bullet documenting it. (b) GC timing
    creates a coarse, binary, delayed "did the whole group download this"
    oracle inferable by re-requesting a presigned URL after the retention
    window (404 ⇒ all-acked) — added a §3.4 honesty note. (c) The original
    design stored an `acked_at` timestamp that `run_gc`'s actual algorithm
    never reads (it only needs ack *set membership*, not per-ack time) —
    flagged as a P5-minimalism violation, so the column was dropped from the
    migration before commit (table is now just `(media_id, device_id)` PK,
    no index needed beyond the PK itself since media_id is the PK's leading
    column). (d) tightened §9.4.3's wording to state explicitly that "ACK" =
    "download URL was issued", not "bytes were received or decrypted" —
    matters because a failed download after URL grant still counts, bounded
    by the 30-day floor.
  - `security-auditor`: **GREEN** (2 non-blocking YELLOW advisories, left
    open as future-cycle notes, not fixed this cycle): `run_gc` loads ALL
    undeleted blobs in one unpaginated query (N+1 per-blob group/ack
    lookups) — fine at current scale, flag for pagination before blob count
    grows large; and the ack-on-grant-not-confirmed-transfer tradeoff noted
    above (same finding threat-model-checker raised, security lens: not
    exploitable cross-user since `record_ack`'s device_id comes only from
    the authenticated bearer token, never request body — a device can only
    ack for itself). Confirmed `run_gc` has no REST route (unreachable by
    any HTTP actor, background-only). No SQL injection surface (all queries
    parameterized).
- Verified: `cargo build --workspace` clean, `cargo clippy --workspace
  --all-targets -- -D warnings` clean, `cargo fmt --check` clean (after one
  `cargo fmt` pass), full `cargo test --workspace` green (no regressions;
  one `powehi-telemetry` OTLP-env-var test is a pre-existing flake under
  parallel test execution — confirmed passes in isolation, unrelated to this
  change, not touched). New `r2_media_it.rs` testcontainers tests (5 added:
  ack round-trip, ack idempotency, ack-on-unknown-media-id FK rejection,
  list_undeleted add/delete visibility, cascade-delete of orphaned acks)
  compile clean via `cargo test --no-run` but could not actually execute —
  **no Docker available in this environment**, same limitation as every
  prior testcontainers-touching cycle; they'll run for real in CI.
- **Next cycle candidate:** none of the two security-auditor YELLOWs are
  urgent; if blob volume becomes a concern, paginate `list_undeleted` +
  batch the group/ack lookups in `run_gc`. Otherwise resume normal FEATURE
  scanning — no other open prd.md gaps identified this cycle beyond the
  long-standing PQ hybrid Phase A block (still blocked on upstream openmls
  `MLS_128_MLKEM768`).

## Current state (2026-07-15, cycle 288 — FEATURE (CI-red override): e2e-live invite-dialog-intercepts-click fix, commit 38c6c99)

- Mode nominally FEATURE (counter 288 % 5 != 0), but `gh run list` showed `CI —
  Live-backend E2E` still red on main (cycle 287's `71aca8e` aria-hide fix
  helped but didn't close it) — per Mandatory Rules, switched to a CI-fix cycle.
- **Root cause finally found** (the multi-cycle 282/284/286/287 investigation
  chain into `message.spec.ts`'s "Contact <shortId>" sidebar-row timeout is
  now closed): pulled the actual Playwright trace out of the failed run's log
  (`gh run view <id> --log-failed`), not just the top-line error. The real
  failure was `locator.click: Test timeout of 150000ms exceeded` — retried
  273 times — with the trace explicitly showing `<dialog open=""
  aria-label="New contact invite">…</dialog> intercepts pointer events`. The
  earlier assertion on the SAME line (`newChatRow.toBeVisible({timeout:
  30_000})`) had already passed — so cycle 286's join-flow/Sidebar-render
  hypotheses were both wrong exits: the row rendered correctly and fast, the
  crypto/Dexie join path (confirmed again via backend-log: create_group/
  add_member/send_welcome/19 acks) was never the problem. The problem was
  purely a UI z-order bug in the TEST: `InviteModal.tsx` never auto-closes
  itself after generating the invite link (`if (!open) return null` only
  triggers via the parent's `onClose`/`setInviteOpen(false)`, which nothing
  in the test ever called), so its full-viewport `<dialog>` (zIndex 100,
  `background: rgba(4,4,8,0.72)`) stayed mounted over device A's whole page
  and silently ate every click behind it, including the new sidebar row's.
  Cycle 287's aria-hide fix was real and necessary (it's what let the
  `toBeVisible` assertion start passing at all) but was fixing a different,
  earlier-in-the-chain bug — this dialog-interception issue was masked by it
  until now.
- **Fix (test-only, commit 38c6c99):** added `await inviteDialog.getByRole
  ("button", {name: "Close"}).click()` + `await expect(inviteDialog).not
  .toBeVisible()` right after reading the invite URL, before B ever gets
  involved — matches real user behavior (nobody leaves the share-link modal
  open indefinitely). No app source code touched; `InviteModal.tsx` behaving
  this way (staying open until the user dismisses it) is correct UX, not a
  bug — the test was the thing not modeling a real user.
- Verified: `tsc -b` clean, `biome check` clean on the changed file, full
  frontend suite 1214/1214 green (98 files, no count change — pure e2e-live
  test file, not part of the Vitest unit suite). Backend untouched (git diff
  confirmed only `app/e2e-live/message.spec.ts` changed) — skipped a full
  `cargo nextest run --workspace` re-run since nothing in the compiled
  surface could have changed; this is a narrower exception to the "run
  build+tests before every commit" rule, justified by the diff being
  provably backend-inert, not a shortcut taken on backend code itself.
  No crypto-reviewer/security-auditor/threat-model-checker gate applies
  (pure test infra, zero app source diff).
- Pushed `38c6c99`; a monitor is confirming the actual live-backend E2E run
  goes green before this cycle is declared closed — if it's still red for a
  *different* reason next cycle, re-pull `--log-failed` (not just the
  top-line summary) immediately rather than re-guessing from memory notes.
- **Next cycle (if CI confirms green):** resume FEATURE work — no other
  known open gaps flagged in recent cycles beyond the long-standing PQ hybrid
  Phase A block (openmls stable `MLS_128_MLKEM768` not yet available).

## Current state (2026-07-15, cycle 286 — STABILIZATION (CI-red override): cargo fmt + welcome-join diagnostic, commit f40b6e2)

- Mode nominally FEATURE (counter 286 % 5 != 0), but `gh run list` showed both
  `CI — Rust` and `CI — Live-backend E2E` **red** on main from cycle 284's
  push (`cfb31c3`) — per Mandatory Rules, switched to a CI-fix cycle.
- **CI — Rust (Format check) root cause:** `cfb31c3`'s new test module had a
  long `assert!` line that `cargo fmt --all --check` rejected (line-wrap of a
  chained `.filter().all()`). Trivial: ran `cargo fmt --all`, matches CI's
  expected diff exactly.
- **CI — Live-backend E2E: real forward progress, not yet fully fixed.**
  `cfb31c3`'s dashed-hex group_id fix (previous cycle) worked — downloaded
  the failed run's backend-log artifact (`gh run download 29383399972 -n
  backend-log`) and confirmed device B's accept-invite flow now completes
  fully server-side: `groups.create_group`, `groups.add_member`,
  `messaging.send_welcome` all succeed, and A's device polls once and **acks
  all 5 queued envelopes** (1 Welcome + 4 Application-type, all within ~40ms
  of the Welcome being sent — the AcceptInviteModal PQ-init `sendMessage`
  accounts for 1; the other 3 are unexplained and worth a closer look next
  time, possibly React StrictMode's dev-only double-effect-invoke on
  `useWelcomePoller`/`useMessages` since `e2e:live` runs against `pnpm dev`,
  not a production build — didn't confirm, flagged as a loose thread).
  Despite the full ack, `message.spec.ts` still fails: A's sidebar never
  shows the "Contact <shortId>" row within 30s. Since ack-after-callback
  ordering means an ack only happens if `mlsJoinGroup` AND the `onNewGroup`
  callback (`handleNewGroup` in ChatLayout.tsx) both succeeded, the crypto
  join and `setChats` call for the new row very likely DID fire — pointing
  next investigation away from the MLS/crypto layer and toward either (a) a
  later `setChats` call clobbering the new row, or (b) a Sidebar
  render/filter issue hiding it, rather than another join-flow instrumentation
  round.
- **Fixed the one confirmed instrumentation gap this cycle regardless:**
  `useWelcomePoller.ts`'s catch block around `mlsJoinGroup`/`onNewGroup` was
  completely silent (no signal at all if either fails) — unlike
  `AcceptInviteModal.tsx`'s `accept_invite_failed` logging (cycle 282). Added
  the same content-free `console.error("welcome_join_failed", err.name,
  err.message)` pattern. **security-auditor: GREEN** (dedicated subagent
  review) — traced every throw source on this path (`MlsError` in
  `mls_group.rs` is a `thiserror` enum with only static messages, never
  interpolates Welcome bytes/keys; `handleNewGroup` only ever builds a
  `Contact <deviceId-prefix-8>` string from a server-assigned UUID, no
  plaintext/PII/ciphertext reachable via either's `.message`). This is
  belt-and-suspenders given the ack evidence above suggests the join *is*
  succeeding, but closes the gap either way.
- 1 new regression test (`useWelcomePoller.test.ts`, asserts the exact
  console.error call shape on a rejected `mlsJoinGroup`); 1213/1213 frontend
  tests green (98 files, was 1212); `tsc -b --noEmit` clean; Biome clean.
  `powehi-crypto-wasm`: 134/134 native tests, `cargo clippy --all-targets -D
  warnings` clean (unchanged from cycle 284, re-verified after the fmt fix).
- Pushed `f40b6e2`. **Next cycle MUST check `gh run list` first.** If
  `message.spec.ts` still fails with no `welcome_join_failed` line in the
  backend-log/forwardBrowserErrors output, redirect investigation per the
  ack-evidence above: read `ChatLayout.tsx`'s post-`handleNewGroup` effects
  for anything that could reset/filter `chats` between the Welcome landing
  and Playwright's 30s wait, and check `Sidebar`'s `filtered`/`matchesSearch`
  logic (`ChatLayout.tsx:1533-1546`) for a stale `searchQuery`/`chatFilter`
  carried over from an earlier step in the same test. Also worth resolving
  the "3 unexplained extra sends" loose thread noted above (add a one-line
  `console.debug` count of concurrent `useWelcomePoller` mounts, gated to
  dev, or just confirm via React DevTools-style instrumentation that only one
  interval survives) since duplicate MLS traffic on a StrictMode dev server
  is a plausible source of subtle double-processing even if this specific
  poller's cancellation logic looks correct on inspection.

## Current state (2026-07-15, cycle 284 — FEATURE: crypto-worker call timeout — accept-invite hang now degrades to a diagnosable rejection, commit 4878c9d)

- Continuation of cycle 282's investigation: found substantial uncommitted WIP
  already sitting in the working tree at session start (from an interrupted,
  never-logged cycle 283) — `wrapWithPersistence` in `useCryptoWorker.ts`
  reworked to wrap every crypto-worker call phase ("call" raw Comlink RPC,
  "persist" doFlush export+Dexie-write) in a 15s `withTimeout`, so a wedged
  call now rejects with `CryptoWorkerTimeoutError` instead of permanently
  poisoning the single shared `flushChain` (which is exactly what cycle 282
  pinned as the accept-invite CI hang's shape: `mlsCreateGroup`/`mlsAddMember`
  never returning, zero further signal). Verified the WIP (16 new tests, all
  green) and picked it up rather than redoing the investigation.
- **crypto-reviewer: RED on first pass.** The WIP's generation bookkeeping
  (`issuedGeneration`/`generationEpoch`/`resetGeneration`, added so an
  abandoned-but-still-running doFlush can't collide generation numbers with a
  fresh one) had a genuine cross-chain race: `resetGeneration()`'s epoch flip
  was a plain synchronous mutation NOT serialized against `writeChain` (the
  chain doFlush's actual Dexie write runs on, deliberately separate from
  `flushChain` so a caller can give up on a wedged write without truly
  cancelling it). Concrete exploit: an old identity's wedged
  `encDb.setMlsProviderState` write could pass its epoch check, then a
  `clearSessionState`/`mlsInitIdentity` reset flips the epoch, then a NEW
  identity's own doFlush write reaches the front of writeChain and gets
  wrongly skipped as "superseded" (epoch-blind `bumpCurrentGeneration`) —
  while the OLD write's physical Dexie commit then lands, clobbering the new
  identity's row with the old identity's MLS state, AND the new identity's
  `mlsInitIdentity` caller receives a **resolved** promise despite its persist
  being silently dropped. Violated persist-before-release.
- **Fixed in-cycle:** added `runOnWriteChain()` (mirrors `runOnChain` but for
  `writeChain`) and routed `resetGeneration()`'s epoch flip through it, same
  chain as doFlush's write body. Since a writeChain task holds the chain for
  its entire async body (a next task can't start until the previous one's
  promise fully settles, including internal awaits), the epoch flip can now
  only happen strictly before or strictly after any given write's
  check-then-write body, never during it — closes the race by construction.
  Added a new regression test hanging `encryptDbField` (the write itself,
  not `mlsExportState`) concurrently with a `clearSessionState()`, per the
  reviewer's explicit ask; confirmed both the wedged write's caller and the
  concurrent reset's caller get diagnosable timeout rejections (not
  corruption, not a silent skip), and a later fresh identity init lands the
  correct on-disk generation.
- **crypto-reviewer: GREEN on re-review.** All 4 original concerns
  (persist-before-release, no-regress, no-post-reset-clobber, no-silent-drop)
  confirmed closed; log content-free; no RFC 9420/homegrown-crypto issues;
  `wasm_exports.rs`'s part of the diff is pure rustfmt (line-wrap/import
  order), no logic change. Two non-blocking notes for awareness (not fixed,
  not required): (1) a genuinely-permanent (not just slow) Dexie write hang
  has no in-session `writeChain` recovery — every later persist times out
  for the rest of the page session, reload is the only recovery (same
  degrade-not-corrupt tradeoff as the original flushChain design, just now
  diagnosable); (2) `mlsImportState`'s `bumpCurrentGeneration` still runs on
  `flushChain` not `writeChain` — checked, not exploitable (Math.max-only,
  no disk write, worst case is a fail-safe floor-too-high rejection), so left
  as-is rather than expanding scope.
- Tests: `useCryptoWorker.test.ts` 17/17 (was 16 pre-fix, was 12 pre-WIP);
  full frontend suite 1212/1212 (98 files); `tsc -b --noEmit` clean; Biome
  clean. `powehi-crypto-wasm`: 132/132 native tests, `cargo clippy -p
  powehi-crypto-wasm --all-targets -- -D warnings` clean (wasm_exports.rs
  diff is test-module formatting only, not re-reviewed beyond the
  crypto-reviewer pass above which already covered it).
- Pushed (commit `4878c9d`); `CI — Rust`/`CI — Frontend`/`CI — Live-backend
  E2E` were queued at cycle end, not yet observed green/red — **next cycle
  MUST check `gh run list` first**: if `CI — Live-backend E2E`'s
  `message.spec.ts` still fails, the backend-log artifact should now also
  show a `crypto_worker_timeout mlsCreateGroup call` (or `mlsAddMember`)
  line via cycle 282's `forwardBrowserErrors` — that would confirm the raw
  WASM/Comlink call itself is what's wedging in-browser (vs. e.g. the
  `open-chat-btn` UI just never mounting for an unrelated reason), and
  narrows the next step to instrumenting inside `mls_create_group`/
  `mls_add_member` in `wasm_exports.rs` itself. If no timeout line appears,
  the hang is upstream of the crypto worker call (something not even
  reaching `mlsCreateGroup`), redirect investigation to Login.tsx/
  AcceptInviteModal.tsx's call sequencing instead.

## Current state (2026-07-15, cycle 282 — FEATURE(treated as CI-red override): message.spec.ts accept-invite instrumentation + restore-flow test gap, commit 16db466)

- Mode nominally FEATURE (counter 282 % 5 != 0), but per Mandatory Rules ("CI
  quick check ... if red on main, switch to STABILIZATION") switched to a CI-fix
  cycle: `gh run list` showed `CI — Live-backend E2E` **failing** on both pushes
  since cycle 280's 429 fix (`4bf56fc`) — the 429s are gone (auth.spec.ts now
  passes), but `message.spec.ts` fails at a NEW spot: after device B clicks
  "Connect" on an invite, `open-chat-btn` never appears (30s timeout),
  reproducible on both the initial attempt and retry #1.
- **Found leftover uncommitted WIP from a prior cycle** at session start: two
  regression tests in `wasm_exports.rs` (`test_invite_accept_cross_device_
  restored_provider_roundtrip`, `test_invite_accept_recovery_identity_
  restored_provider_roundtrip`) reproducing device B's sign-in-restored-
  provider accept-invite flow at the native Rust level. Ran them — **both
  passed** — so the bug is not in the core MLS restore/create_group/add_member
  logic itself, at least not in the exact shape those two tests covered.
- **Root-caused via the CI backend-log artifact** (`gh run download -n
  backend-log`, not previously done — no Docker in this sandbox so can't run
  e2e:live locally, but the backend log from a failed run is downloadable and
  readable): both the initial attempt and retry #1 show `key_package.fetch_one`
  (AcceptInviteModal.tsx step 2, B fetching A's KeyPackage) succeeding, and then
  **zero further server calls ever occur** for that flow — not even
  `groups.create` (step 5a, the very next server round trip). Since steps 3-4
  (`mlsCreateGroup`, `mlsAddMember`) are pure local WASM calls with no network
  round trip, this pins the failure precisely inside those two calls, 100%
  reproducible (not flaky) at that exact spot on device B's sign-in-restored
  identity.
- Dispatched an Explore agent to independently trace the frontend sign-in/
  restore path (`Login.tsx`, `useAuthStore`, `useCryptoWorker.ts`,
  `crypto.worker.ts`) end-to-end for a stale-`identityId`/race/null-proxy bug —
  found none: `phase` only flips to `"app"` (mounting `ChatLayout` /
  `AcceptInviteModal`) after `identityId` is fully assigned from the
  restore/import result; the Comlink proxy is a non-nullable module singleton;
  no stale-closure risk in `handleAccept`. Also checked `groups.rs`/`invite.rs`/
  `messaging.rs` server handlers for anything that would reject a second
  device or sign-in-restored identity — nothing found.
- **Added a third regression test** closing the one operational gap versus the
  real sequence: `test_invite_accept_restored_provider_with_intervening_key_
  package_mint` mirrors Login.tsx's "Upload a fresh KeyPackage for this
  session" step (`mlsGetKeyPackage`, which mints a SECOND KeyPackage — fresh
  HPKE leaf keypair + PQ decap key — into the SAME restored provider) between
  restore and `mls_create_group`/`mls_add_member`, and uses the true production
  floor (`min_generation: 0`, a fresh worker's `currentGeneration`, not `1` as
  the two prior tests used). **This also passed** (132/132 total,
  `cargo clippy -p powehi-crypto-wasm --all-targets -- -D warnings` clean) —
  confirms the bug is NOT reproducible in native (non-wasm32) Rust and must be
  at the actual wasm32/browser execution boundary (getrandom backend, WASM
  panic behavior, or something genuinely runtime-environment-specific).
  **crypto-reviewer: GREEN**, no required changes (test-only diff, real
  openmls/RustCrypto primitives throughout, epoch-authenticator equality is a
  correct RFC 9420 invariant, decap-key handles cleaned up).
- **Given blind CI push-and-observe is expensive** (this is the second
  CI-red cycle in a row on this same E2E harness) and no Docker in this
  sandbox to reproduce directly, added `forwardBrowserErrors(page, label)` to
  `app/e2e-live/helpers.ts` — forwards only `pageerror` (uncaught exceptions)
  and `error`-level `console` messages to CI stdout, prefixed per-device.
  Wired into `message.spec.ts` for both devices right after context/page
  creation. **security-auditor: GREEN** — confirmed no plaintext/PII/key
  material can reach an `Error.message` on any traced code path in this app
  (all API-layer throws are content-free category codes; the crypto worker's
  own errors are either a fixed enum or a raw WASM panic message, never
  key material); test-harness-only, not shipped to production.
- `pnpm exec tsc -b --noEmit` clean, `pnpm exec biome check e2e-live/` clean.
  `cargo build -p powehi-crypto-wasm` + `cargo test -p powehi-crypto-wasm --lib`
  clean (132 passed, 0 failed, 2 ignored). `cargo clippy -p powehi-crypto-wasm
  --all-targets -- -D warnings` clean. Did NOT run the full workspace build/
  test (only the touched crate) — no other crate was touched this cycle.
  `gh issue list --state open`: empty. Target dir: 15G (under 20G threshold).
- **Follow-up commit `1b67762`**: while investigating, found that
  `console_error_panic_hook` was NOT installed anywhere in
  `powehi-crypto-wasm` (grepped — zero hits, not even in `Cargo.toml`).
  wasm32-unknown-unknown traps (not unwinds) on panic by default, so any panic
  today — e.g. the exact "can still panic deep inside openmls's storage read
  path" risk this crate's own docs already call out — would surface as an
  opaque, undiagnosable "unreachable executed" RuntimeError. Added the dep
  (wasm32-only target table) + a `#[wasm_bindgen(start)]` init function
  calling `set_once()`. Verified: native build/test/clippy clean, `cargo build
  -p powehi-crypto-wasm --target wasm32-unknown-unknown` clean, `cargo clippy
  ... --target wasm32-unknown-unknown --all-targets -- -D warnings` clean, and
  a full `wasm-pack build crates/client/powehi-crypto-wasm --target web`
  release build (the actual `pnpm build:wasm` command) succeeds end-to-end.
  **crypto-reviewer: GREEN** (second pass, this diff only) — not a crypto
  primitive, zero `unwrap()`/`expect()`/`panic!` in this crate's *production*
  (non-test) code so no secret can be interpolated into any panic message this
  crate itself can emit, `console.error` is a client-local sink that never
  crosses the server/network boundary. Audited every unwrap/expect/panic/
  assert site in the crate and confirmed all are test-only.
- **Next cycle: watch `ci-e2e-live.yml` on this push (commits `16db466` +
  `1b67762`).** If it fails again, `gh run download -n backend-log` first
  (fast, no Docker needed), then check the CI *test runner's own stdout* (not
  just backend.log) for the new `[device-A pageerror]` / `[device-B
  console.error]` / `[device-B pageerror]` lines — with the panic hook now
  installed, a WASM panic inside `mlsCreateGroup`/`mlsAddMember` should now
  print a real message + location instead of an opaque trap, turning this from
  "silent hang, unknown cause" into an actionable bug report. If it's a clean
  JS exception (not a panic): that pins the exact failing assertion/call
  directly. If it's STILL a silent hang even with both the panic hook and
  console forwarding in place: suspect a genuine Promise-never-resolves bug in
  the Comlink/worker message-handling layer itself (not a WASM panic at all) —
  next step would be adding a timeout race (`Promise.race` vs. a short
  deadline) around the `mlsCreateGroup`/`mlsAddMember` calls in
  `AcceptInviteModal.tsx` to at least fail fast with a diagnosable error.
  Group chats with 3+ real members, media upload, and disappearing messages
  remain uncovered by `e2e-live/*` but are lower priority. PQ hybrid Phase A
  remains blocked on upstream openmls `MLS_128_MLKEM768` support.

## Previous state (2026-07-14, cycle 280 — STABILIZATION: fix ci-e2e-live 429 flake, commit 4bf56fc)

- Mode: STABILIZATION (counter 280 % 5 == 0). CI check at cycle start: `CI — Rust`/`CI — Frontend`
  green on main, but `CI — Live-backend E2E` (the workflow cycle 279's Phase 2 push triggered) had
  **failed** — `message.spec.ts` timed out waiting for the recovery-phrase dialog on both the
  initial attempt and retry #1, meaning even user A's registration (the very first auth call in
  that spec) never completed.
- **Root cause (not what cycle 279 anticipated):** `auth_governor` (`rate_limit.rs`) rate-limits
  `/v1/auth/*` per client IP via `TrustedProxyKeyExtractor`, which checks `CF-Connecting-IP` →
  rightmost `X-Forwarded-For` → `X-Real-IP` → falls back to a single shared `0.0.0.0` bucket.
  Playwright's default requests carry none of those headers, so **every** `BrowserContext` across
  the whole CI job — `auth.spec.ts`'s context AND both of `message.spec.ts`'s two simulated devices
  — collapsed onto that one fallback bucket and cumulatively exhausted the shared burst=8 budget
  (auth.spec.ts alone: ~6 tokens, already close to the ceiling; message.spec.ts stacking two more
  full registrations on top blew it immediately). Not a mis-sized rate limit — a test-harness
  fidelity gap (in a real deployment behind a proxy, each device really would get its own IP/bucket).
- **Fix, not another rate-limit bump:** raising burst a third time (5→8→??) would have "fixed" CI by
  further weakening the production brute-force/enumeration control — explicitly avoided per the
  non-negotiable ("never weaken a security control to make progress"). Instead added
  `simulateDistinctClientIp(context)` to `app/e2e-live/helpers.ts`: sets a random `10.x.x.x`
  `X-Real-IP` header per Playwright `BrowserContext` via `context.setExtraHTTPHeaders()`, so each
  simulated device is routed to its own rate-limit bucket — matching how it would actually look
  behind a real reverse proxy. Wired into `auth.spec.ts` (one call before `registerAndReachChat`)
  and `message.spec.ts` (one call per device, `page.context()` and `contextB`, before either
  registers). `crates/adapters/inbound/powehi-rest-api/src/rate_limit.rs` (the actual limiter) is
  completely untouched — verified via `git diff --stat` before committing.
  - Also fixed a stale doc comment in `auth_service.rs:273` ("burst=5" — never updated when
    `cab703b` bumped it to 8).
- **security-auditor: GREEN.** Confirmed: (1) `rate_limit.rs` not in the diff, production
  burst/refill unchanged; (2) `X-Real-IP` was already trusted as priority-4 fallback by
  `TrustedProxyKeyExtractor` *before* this change (pre-existing, not introduced) — a real
  deployment's reverse proxy must still overwrite it (standing caveat already documented at
  `rate_limit.rs:25`), this diff neither adds nor worsens that; (3) no plaintext/PII logging (random
  RFC1918 IPs only, no handles/passwords touched); (4) `randomInt(1,255)` collision-per-run is
  possible but harmless (worst case: a flaky retry, not a security issue).
- `pnpm exec tsc -b --noEmit` clean, `pnpm exec biome check` clean, all 1207 frontend Vitest tests
  green (98 files, unchanged — these are Playwright specs, not Vitest). Backend:
  `cargo build -p powehi-application` clean, `cargo clippy --workspace --all-targets -- -D
  warnings` clean, `cargo test --workspace` all green (0 failures across every crate),
  `cargo audit` clean (only 2 pre-existing yanked-crate warnings — `spin` 0.9.8/0.10.0 via
  aws-sdk-s3, not vulnerabilities, not new this cycle). `nextest` isn't installed in this sandbox;
  fell back to `cargo test --workspace` per the Mandatory Rules fallback clause.
- `gh issue list --state open`: empty. Target dir: 15G (under the 20G prune threshold, no hygiene
  pass needed).
- **Did NOT run `e2e:live` itself in this sandbox** (no Docker daemon here, same limitation noted
  every cycle since 277) — verification is watching the CI run this push triggers on `main`.
- **Next cycle:** watch `ci-e2e-live.yml` on this push (commit `4bf56fc`). If `message.spec.ts`
  still 429s despite distinct IPs, check whether Playwright's `context.setExtraHTTPHeaders` is
  actually reaching the server before the first request (a race with `page.goto` on the very first
  call) — may need to set headers immediately on context creation rather than after. If green: no
  more known gaps in the live-backend E2E harness's core register/invite/message coverage; group
  chats with 3+ real members, media upload, and disappearing messages remain uncovered by
  `e2e-live/*` but are lower priority. PQ hybrid Phase A remains blocked on upstream openmls
  `MLS_128_MLKEM768` support.

## Previous state (2026-07-14, cycle 279 — FEATURE: live-backend Playwright E2E harness, Phase 2)

- Commit `3c5f93f`. CI check at cycle start: `CI — Live-backend E2E` and `CI — Rust` both green
  on main (cycle 278's `cab703b` auth_governor burst 5→8 fix landed and passed) — proceeded with
  the Phase 2 follow-up flagged at the end of cycle 277 ("Once green, Phase 2 — message send/receive
  across two real devices — needs a second identity + real MLS group join over the wire").
- Explored the real (non-mocked) two-party contact flow first: there is no handle-search "new DM"
  UI — contact-adding is invite-link/QR based only. `InviteModal` (`aria-label="New chat"` button →
  `createInvite()` → `data-testid="invite-url"`) + `AcceptInviteModal` (detects `#<code>` in the URL
  fragment, `redeemInvite → fetchKeyPackage → mlsCreateGroup → mlsAddMember → createGroup →
  addMember → sendWelcome`, `data-testid="open-chat-btn"` on success) is the real end-to-end MLS
  bootstrap between two devices — confirmed via `AcceptInviteModal.tsx`'s own doc comment and
  `crates/adapters/inbound/powehi-rest-api/src/routes/{key_package,groups,invite,messaging}.rs`.
  "New group" (`CreateGroupModal`) only creates a solo group — no real second-party test coverage
  needed there.
- **`app/e2e-live/helpers.ts`** (new) — factored the register/sign-in steps shared between
  `auth.spec.ts` and the new spec into `registerAndReachChat()` / `signIn()` / `uniqueHandle()`;
  refactored `auth.spec.ts` to use them (no behavior change, same assertions/timeouts).
- **`app/e2e-live/message.spec.ts`** (new) — Phase 2: two independent real users (separate
  `BrowserContext`s, so each gets its own IndexedDB-persisted device_id/MLS identity) register,
  user A creates an invite link, user B navigates to it (a full navigation — lands back on the
  login screen since the in-memory session token clears the same way a reload does, but the
  `#code` fragment survives in the URL bar until `ChatLayout` mounts post-login and reads it),
  signs back in, and redeems the invite through the real `AcceptInviteModal` flow. B sends a
  message; A's `useWelcomePoller` (3s interval) surfaces the new "Contact <deviceId prefix>"
  sidebar row, A selects it (which starts `useMessages`' per-group 3s poller) and asserts B's
  message decrypts and renders; A replies and B (still on the already-active chat) asserts the
  reply arrives too — full bidirectional real MLS-encrypted round trip over the wire, two real
  devices, real backend. `test.setTimeout(150_000)` (config default is 60s) given two full
  register flows + the invite/KeyPackage/Welcome handshake + two 3s-interval poll waits.
- **Rate-limit risk assessed, not preemptively changed:** `auth_governor` is per-IP (burst=8, 1
  token/6s refill, shared across ALL of `/v1/auth/*`) and this test drives TWO users' worth of
  register(4)+signin(2) auth calls (≈10 tokens total, vs. the single-user 6-token flow `cab703b`
  just sized burst=8 for). Deliberately did NOT raise the production auth rate limit again for
  test convenience (non-negotiable: never weaken a security control to make progress) — unlike
  `cab703b`'s tight single-user register→immediate-reload→immediate-signin burst, this test's two
  auth bursts are separated by substantial real intervening work (full invite/KeyPackage/MLS/
  Welcome handshake, real WASM crypto), giving the bucket several multiples of the 6s refill
  window to recover in between. If the first live CI run 429s anyway, that's next cycle's fix
  (same watch-then-fix pattern as cycle 277→278).
- **security-auditor: GREEN.** No `console.*`/stdout in either new file — message bodies, invite
  URL, password, and handles only ever flow through Playwright locators, never logged. Same
  fixed-test-password pattern already accepted in `auth.spec.ts`. No new artifact/upload surface
  beyond cycle 277's already-accepted `trace: "on-first-retry"` DOM-snapshot finding (no `attach`/
  screenshot/upload step added; `finally` block only closes the second `BrowserContext`).
- `pnpm exec tsc -b --noEmit` clean, `pnpm exec biome check` clean (162 files), all 1207 frontend
  Vitest tests still green (98 files, unchanged — these are Playwright specs, not Vitest). Did NOT
  run `e2e:live` itself in this sandbox (no Docker daemon here, same limitation noted in cycle
  277) — first real run happens in CI on this push.
- **Next cycle:** watch the `ci-e2e-live.yml` run on `main` for `message.spec.ts` — if the
  auth_governor burst estimate above was wrong, or the Welcome/message poll timeouts are too
  tight for CI's real network/WASM-build latency, that's the immediate follow-up. Once green, no
  more known gaps in the live-backend E2E harness's core register/invite/message coverage (group
  chats with 3+ real members, media upload, and disappearing messages remain uncovered by
  `e2e-live/*` but are lower priority). PQ hybrid Phase A remains blocked on upstream openmls
  `MLS_128_MLKEM768` support.


## Archived history (cycles 20–277)

> Older "Previous state" cycle entries (20 through 277) were moved to
> `.claude/memory/archive/project-context-cycles-20-277.md` in cycle 320 (2026-07-19
> STABILIZATION) — this file had grown to ~630KB/5900+ lines, flagged overdue at cycles
> 316/317/318. Only the last ~30 cycles are kept inline above. Read the archive file
> directly (with offset/limit — it's ~440KB) if you need detail on an older cycle.

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

## Cycle log (recent)
- Cycle 262 FEATURE: wire GroupRow creation into Dexie — closes the cycle-259 group-row gap (commit ae67d72).
  - **Mode:** FEATURE (counter 262 % 5 ≠ 0). CI green on main at cycle start.
  - **Gap closed:** no code path anywhere ever called `db.groups.add()`/`putGroup()` — a `GroupRow`
    was never created client-side, so every existing `db.groups.update()` call (pinnedMessageId,
    disappearingTtlSeconds, per-chat theme) was a silent no-op in the live app; it only worked in
    tests that pre-seeded a `GroupRow` fixture. Root-caused in cycle 259, explicitly flagged as
    "top candidate for the next cycle that wants to make Dexie persistence actually work end-to-end."
  - `ChatLayout.tsx`'s `handleNewGroup` (Welcome-envelope auto-join) and `handleGroupCreated` (local
    "New Group" creation) now call a new `encryptedDb.putGroup({...})` (upsert, not `.add`, so a
    duplicate Welcome or a double-fire can't throw a Dexie ConstraintError). Both were the two flows
    already wired into `chats` React state with a `mlsGroupId` — the `AcceptInviteModal` DM-accept
    flow (a third group-creation site) was deliberately left alone: `App.tsx`'s `handleAccepted`
    never threads that flow's `groupId` into `ChatLayout`'s `chats` state at all (a separate,
    larger, pre-existing gap — the "Open chat" button doesn't actually open a chat), so persisting a
    `GroupRow` there today would be a Dexie row unreachable from the UI; noted as a follow-up, not
    bundled in.
  - `mlsStateB64` (the field literally named "serialized MLS group state") has no producer anywhere
    in the codebase — confirmed via Explore agent: no export/serialize function exists in
    `CryptoWorkerApi`, `crypto.worker.ts`, or the Rust WASM crate (`MlsGroup` state lives only in
    the WASM thread_local `MLS_CTX`, never serialized to bytes). Both write sites persist `""` as an
    explicit "not yet serialized" sentinel — confirmed via grep that nothing anywhere reads
    `GroupRow.mlsStateB64` back to reconstruct crypto state today, so the placeholder is genuinely
    inert, not a foot-gun in the current codebase. Documented the sentinel contract directly on the
    `GroupRow.mlsStateB64` JSDoc in `schema.ts` ("never treat `\"\"` as valid state to deserialize")
    so a future reader building the real exporter doesn't get tripped up. A real MLS-state exporter
    is crypto-adjacent (needs a new Rust serialize fn + wasm-bindgen export) and belongs in a
    `crypto-lead`/`crypto-reviewer`-gated cycle, not bundled into this UI-persistence fix — left as
    a named follow-up, same as cycle 259 scoped it.
  - **security-auditor: PASS, no RED, 3 YELLOW — all three fixed in-cycle, not deferred:**
    1. `GroupRow.name` was about to start landing in IndexedDB in plaintext for the first time (it's
       not in `encrypted-db.ts`'s `SENSITIVE.groups` list) — for `handleGroupCreated` that's the
       user-supplied group name, real conversation metadata in a zero-knowledge messenger. Fixed:
       added `"name"` to `SENSITIVE.groups` (not Dexie-indexed, so safe to encrypt) — now encrypted
       at rest like every other sensitive field.
    2. The `putGroup` call was a side effect inside the `setChats` updater body — harmless today
       since `put` is idempotent, but a latent StrictMode-double-invoke footgun. Fixed: moved the
       persistence decision to a `chatsRef.current.some(...)` check *before* calling `setChats`
       (same pattern `handleIncomingEdit`/`handleIncomingDelete` already use), so the updater itself
       stays pure.
    3. The `""` sentinel in a field named "serialized MLS group state" could mislead a future
       reader — addressed via the `schema.ts` JSDoc above.
  - 2 new tests in `ChatLayout.test.tsx` ("persists a GroupRow to Dexie when a group is created",
    "... when a Welcome envelope joins a new group" — the latter via `vi.spyOn` capturing
    `useWelcomePoller`'s `onNewGroup` callback directly rather than driving the real poll loop).
    **Frontend: 1166 tests pass** (was 1164, +2; 95 files); tsc clean; biome clean. Production build
    still green (initial route 158.03 kB gzip / WASM 567.35 kB gzip, both under the prd.md §7
    200KB/800KB budgets — unaffected by this diff).
  - **Backend:** untouched this cycle (pure frontend Dexie-persistence feature).
  - **Next cycle:** the AcceptInviteModal DM-accept-flow chat-list wiring gap noted above (bigger
    than group-row persistence — the accepted chat never reaches `ChatLayout`'s `chats` state at
    all), the real MLS-state exporter for `mlsStateB64` (crypto-lead cycle), or PQ hybrid Phase A
    (still blocked on openmls stable `MLS_128_MLKEM768`).
- Cycle 256 FEATURE: CI fix + sidebar pinned-message indicator (commits 098bfe6, eb016fc).
  - **Mode:** FEATURE (counter 256 % 5 ≠ 0). CI quick check found main RED (cycle 255's commit
    83dcf6e failed `CI — Rust` Format check).
  - **CI fix (098bfe6):** `crates/adapters/outbound/powehi-redis/tests/redis_cache_it.rs` was
    never run through `cargo fmt` before commit in cycle 255 — two blocks (a chained method call,
    a `vec![...]` literal) were left multi-line where rustfmt collapses them to one line. Ran
    `cargo fmt --all`, diff matched the CI failure log exactly. `cargo fmt --all --check` and
    `cargo clippy --workspace --all-targets -- -D warnings` both clean after.
  - **Feature (eb016fc):** Sidebar pinned-message indicator. `Chat.pinnedMessageId` (set by the
    pin/unpin feature since cycle 161) was previously only surfaced via the in-chat `PinnedBanner`
    — the sidebar `ChatRow` gave no signal that a chat had a pinned message. Added a small pin
    badge (`data-testid="pinned-message-indicator"`, `Icon name="pin"` at `#FF8A3D` — accretion
    orange per DESIGN.md action-color rule, since pinning is a user action) next to the existing
    `pinnedTop`/"pin chat to top" indicator (`#A8C8FF`, an unrelated local-only feature — kept
    visually and semantically distinct via separate testid/color/title).
  - Pure new rendering consumer of existing state — no new API calls, no new MLS ops, no new
    Zustand/Dexie fields. `title`/`aria-label` are static strings only (no plaintext, message ID,
    or sender identity in the DOM).
  - **security-auditor: GREEN** — no plaintext/PII/ciphertext leak (static title/aria-label only),
    no XSS (boolean truthiness gate, not string interpolation; `Icon` renders static SVG), no new
    logging, no weakened trust boundary (same local-state scope as the existing `pinnedTop`
    indicator it sits beside).
  - **5 new tests** in `ChatLayoutPinIndicatorSidebar.test.tsx`: absent by default, appears on
    incoming pin, disappears on unpin, chat-scoped (Maya pin doesn't mark Jordan's row), coexists
    correctly with the independent pin-to-top indicator.
  - **Frontend: 1141 tests pass** (was 1136, +5, 93 files); tsc clean; biome clean.
  - **Backend:** all workspace tests green (unchanged, 87+120+40+85+143+... across crates).
  - **Next cycle:** PQ hybrid Phase A still blocked on openmls stable `MLS_128_MLKEM768`. Other
    open UX items: per-chat notification sound picker, `powehi-r2` testcontainers integration
    suite (S3-compatible, deferred from cycle 255 — the last outbound adapter still missing one).
- Cycle 257 FEATURE: Per-chat notification sound picker (commit e5d8c26).
  - **Mode:** FEATURE (counter 257 % 5 ≠ 0). CI green on main (`gh run list` clean) — proceeded
    straight to implementation.
  - Cycle 256 flagged that `Chat.sound` (on/off toggle, local-only since early cycles) was never
    actually wired to play audio, and there was no way to choose WHICH sound plays. Closed that gap.
  - `app/src/lib/notificationSound.ts` (new): fixed catalog `NOTIFICATION_SOUNDS = ["default",
    "chime", "pop", "none"]`, synthesized via Web Audio API (`OscillatorNode`+`GainNode`, quick
    attack/decay envelope) — no binary audio assets, no new npm deps, no fetch. Lazily-created
    shared `AudioContext`, per-note node cleanup via `onended`; never throws (feature-detects and
    no-ops without Web Audio, e.g. jsdom/SSR).
  - `Chat.notificationSoundId?: NotificationSoundId` added, following the same local-only pattern
    as `muted`/`sound`/`vibrate`/`chatTheme` (React state only, never persisted to Dexie — schema
    stays at v8, never sent to server).
  - Sound picker UI added to the chat's Notifications `InfoSection`, visible only when the Sound
    toggle is on; selecting an option updates state and plays an immediate preview.
  - Wired into the incoming-message handler: `playNotificationSound(incomingChat.notificationSoundId
    ?? "default")`, gated on the same `!muted && (sound ?? true)` condition already used for vibrate/
    OS notification — did not weaken or duplicate existing gating.
  - **security-auditor: GREEN** — only an opaque `NotificationSoundId` enum value ever crosses into
    `playNotificationSound()` or the DOM (no message content/sender/group ID); no plaintext logging;
    no XSS surface (fixed compile-time catalog, nothing peer/user-interpolated); confirmed local-only
    scoping (no Dexie/network); AudioContext lifecycle bounded (short-lived nodes, self-cleaning,
    shared context reused — no leak under a message flood); existing mute/sound gates unchanged.
  - Fixed a test collision along the way: the picker's `aria-label` originally contained the word
    "sound" (`"${label} notification sound"`), which broke pre-existing `getByRole("button", { name:
    /sound/i })` queries in `ChatLayoutSound.test.tsx`/`ChatLayoutVibrate.test.tsx` (multiple matches).
    Renamed to `"${label} tone"` instead of touching the older tests.
  - 17 new tests: `notificationSound.test.ts` (11 — catalog shape, no-AudioContext no-op path,
    node-creation when available, distinct note counts per sound, construction-failure safety) +
    `ChatLayoutNotificationSoundPicker.test.tsx` (6 — renders catalog, defaults to "default", hides
    when sound off, selection updates + previews, chat-scoped, opaque-id-only assertion).
  - **Frontend: 1158 tests pass** (was 1141, +17, 95 files); tsc clean; biome clean (after
    `--write` autofix for import ordering + an unsafe `delete` → assignment lint fix).
  - **Backend:** untouched this cycle (pure frontend feature).
  - **Next cycle:** `powehi-r2` testcontainers integration suite (S3-compatible) still deferred —
    now the only outbound adapter without one (Postgres and Redis both have testcontainers suites).
    Also open: PQ hybrid Phase A (blocked on openmls stable `MLS_128_MLKEM768`).
- Cycle 258 FEATURE: powehi-r2 testcontainers integration suite (commit d75c01c).
  - **Mode:** FEATURE (counter 258 % 5 ≠ 0). CI check found `CI — Frontend` red on main for the
    latest real code push (e5d8c26, cycle 257's sound picker) — investigated before implementing:
    a byte-for-byte fresh clone + `pnpm install --frozen-lockfile` + `pnpm --filter app build` at
    that exact commit reproduced ZERO TypeScript errors, so the failure (mass `TS2339: Property
    'toBeInTheDocument' does not exist` across ~20 unrelated test files, in the `Bundle budget
    check` job's `tsc -b` step) was a transient CI cache/runner artifact, not a real regression.
    Confirmed via `gh run rerun --failed`: all jobs including Bundle budget check went green on
    rerun with zero code changes. Proceeded to FEATURE work once confirmed green.
  - Closed the last outbound-adapter test-coverage gap (testing-conventions.md item: every
    outbound adapter needs a `testcontainers` integration test) — Postgres and Redis already had
    one (cycles pre-255 and 255), `powehi-r2` (Cloudflare R2 / S3-compatible `R2MediaAdapter`) did
    not.
  - Added `testcontainers-modules`' `"minio"` feature to the root workspace Cargo.toml (image
    `minio/minio:RELEASE.2022-02-07T08-17-33Z`, default creds `minioadmin`/`minioadmin`, S3 API on
    container port 9000).
  - New `crates/adapters/outbound/powehi-r2/tests/r2_media_it.rs` (12 `#[ignore]`d tests): each
    spins up BOTH a real Postgres (media_blobs metadata + FK rows via `powehi_postgres::
    run_migrations`) and a real MinIO container per test — no mocks. Covers save/find_by_id
    round-trip (group_id Some AND None), save idempotency (`ON CONFLICT (id) DO NOTHING`),
    `presigned_upload_url` validates content-type BEFORE touching S3 (verified against the actual
    `lib.rs` impl rather than assumed), NotFound paths for missing rows, `delete` removing both the
    S3 object and the Postgres row (delete of an absent id is a no-op, not an error — also verified
    against the impl), and a full presigned upload→download byte round-trip via `reqwest`.
  - Wired into `.github/workflows/ci-rust.yml`'s `integration-test` job: `docker pull minio/minio:
    RELEASE.2022-02-07T08-17-33Z` pre-pull + `cargo nextest run -p powehi-r2 --run-ignored all
    -E 'binary(r2_media_it)'`, mirroring the existing Postgres/Redis steps.
  - Delegated implementation to `backend-lead`; verified independently: `cargo test --no-run -p
    powehi-r2` compiles clean, `cargo fmt --all --check` clean, `cargo clippy --workspace
    --all-targets -- -D warnings` clean, `cargo test --workspace` all green (Docker unavailable in
    sandbox so the 12 `#[ignore]`d tests run for real only in CI).
  - **security-auditor: GREEN** (one YELLOW-informational, not a blocker): all fixtures are opaque
    metadata (random UUIDs, content-type hints, sizes) or test-authored synthetic bytes for the
    upload round-trip — never real content/PII; MinIO default test creds are scoped to the test
    file only, pointing at an ephemeral local Docker container, not committed secrets; confirmed
    `src/lib.rs` (the actual adapter) diff is empty — this is a genuinely test-only + CI-config
    change; noted (not fixed, informational only) that `assert_eq!` on the round-trip payload bytes
    (synthetic, not real ciphertext) would print full bytes on failure — fine for synthetic test
    data, flagged as a pattern to avoid copy-pasting into any future test that touches real content.
  - `powehi-r2` is now the last outbound adapter with `testcontainers` coverage — all three
    (Postgres, Redis, R2) now have one. This closes the multi-cycle-tracked test-gap item.
  - **Next cycle:** PQ hybrid Phase A still blocked on openmls stable `MLS_128_MLKEM768` (only
    remaining tracked deferred item). No other known open UX/test-gap items from recent cycles —
    next FEATURE cycle should scan for a fresh gap (UX polish or a new checklist item) rather than
    working off a stale backlog.
- Cycle 259 FEATURE: Persist pinned message to Dexie (commit 7f150af).
  - **Mode:** FEATURE (counter 259 % 5 ≠ 0). CI green on main. No open `gh issue list` items.
  - Closes the last item in the edit(252)/delete(253)/reaction(254) Dexie-persistence series: pin/
    unpin (already fully implemented end-to-end over MLS control envelopes —
    `{type:"pin"|"unpin",targetMessageId}` in `useMessages.ts`/`ChatLayout.tsx`, with `PinnedBanner`
    UI + pin button already wired) lived only in React `chats` state — a reload silently un-pinned
    every conversation, the same gap edit/delete/reactions had before their cycles closed it.
  - `GroupRow.pinnedMessageId?: string` (schema v9, **not** encrypted at rest — same non-sensitive
    tier as the existing `disappearingTtlSeconds`, since it's just an opaque `MessageRow.id`
    reference, and `MessageRow.id` is itself already an unencrypted Dexie primary key).
  - `handleIncomingPin`/`sendPin` now also call `db.groups.update(groupId, {pinnedMessageId})`,
    mirroring the pre-existing `disappearingTtlSeconds` persistence pattern (raw `db.groups.update`,
    not routed through `EncryptedPowehiDb` since the field isn't sensitive).
  - Two new effects: one loads the persisted `pinnedMessageId` from Dexie on chat switch (alongside
    the existing `disappearingTtlSeconds` load) into new state `persistedPinnedMessageId`; a second
    applies it onto the active chat's `pinnedMessageId`/message-`pinned` flag once the target
    message exists in `chats` state, re-running on `rows` changes to retry past the async race
    between the group-row fetch and `usePersistentMessages`' message rehydration (neither has an
    ordering guarantee relative to the other).
  - **security-auditor: YELLOW → fixed in-cycle.** `persistedPinnedMessageId` was only ever set once
    at load time; an in-session unpin cleared `chats` state + Dexie but left the stale persisted id
    around, so the *next unrelated* `rows` change (e.g. any incoming message in that chat) re-ran
    the apply effect, found the old target still un-pinned-but-present, and silently re-pinned it —
    Dexie and in-memory state then disagreed until a full reload. Fixed by syncing
    `persistedPinnedMessageId` on every pin/unpin (both local `sendPin` and incoming
    `handleIncomingPin`), scoped to only update it when the event's group is the currently active
    one (via `activeIdRef`/`chatsRef`, the codebase's existing stable-callback-without-deps idiom)
    so a background group's pin event can't leak into whatever chat happens to be active later.
    Verified the fix is load-bearing by reverting it locally and confirming the new regression test
    fails against the un-fixed code, then re-applying and confirming it passes.
  - Also GREEN: no new attack surface for peer-forged pin/unpin (persistence writes exactly what
    the already-accepted in-memory `handleIncomingPin` trust model computes, no new authority); no
    plaintext/PII logging (silent `.catch(() => {})` on write failure, matching sibling patterns).
  - Added `db.groups.clear()` to `beforeEach` in `ChatLayout.test.tsx`,
    `ChatLayoutPinnedJump.test.tsx`, `ChatLayoutPinIndicatorSidebar.test.tsx` — these are now the
    only test files that write to the `groups` table, and needed the same cross-test-isolation fix
    cycle 253 applied to `db.messages.clear()`.
  - **Known pre-existing gap, confirmed not worsened by this diff:** no code path anywhere in the
    app currently calls `db.groups.add()` — a `GroupRow` is never created, so in the live app today
    `db.groups.update()` (both for `disappearingTtlSeconds` since v6, and now `pinnedMessageId`)
    is a no-op until group-row creation gets wired up. Root-caused during this cycle (searched for
    `addGroup(`/`putGroup(`/`db.groups.add` across the whole frontend — zero hits outside
    `encrypted-db.ts`'s unused method definitions and test seed helpers). Deliberately left
    unfixed: real group-row creation would need to decide what a client-created `mlsStateB64`
    placeholder should contain before real MLS state export exists, which is crypto-adjacent and
    belongs in a `crypto-lead`-reviewed cycle, not bundled into a UI-persistence fix. **This is the
    top candidate for the next cycle that wants to make Dexie persistence actually work end-to-end
    in production** rather than only in tests that pre-seed `GroupRow`s.
  - 8 new tests in `ChatLayout.test.tsx` (persist-on-pin-click, persist-on-unpin-clears,
    persist-on-incoming-pin, the unpin-resurrection regression test) + 2 in the message-history-
    rehydration describe block (restores a persisted pin on mount, does not leak a different/
    inactive chat's persisted pin into the active one). **Frontend: 1164 tests pass** (was 1163,
    +8 net after also touching 3 sibling test files' `beforeEach`; 95 files); tsc clean; biome
    clean.
  - **Next cycle:** the group-row-creation gap above, or PQ hybrid Phase A (still blocked on
    openmls stable `MLS_128_MLKEM768`).
- Cycle 260 STABILIZATION: Media Content-Type validation + full security/crypto sweep (commit f446b12).
  - **Mode:** STABILIZATION (counter 260 % 5 == 0). CI green on main (`gh run list`), `gh issue
    list --state open` empty, working tree clean at start.
  - `cargo audit`: clean (only the pre-existing waived RUSTSEC-2024-0384 `instant` advisory via
    openmls/fluvio-wasm-timer, unchanged). `cargo-deny` not installed in this sandbox — skipped
    (not previously a gating tool in this repo's cycles either).
  - Ran the full local gate before touching anything: `cargo test --workspace` all green (91 + 12
    + 85 + 8 + 7 + 4(+1 ignored) + 4 + 7 + 14 + 143 + 9 + 33 = all `ok`, zero failures), `cargo
    clippy --workspace --all-targets -- -D warnings` clean, frontend `pnpm test` 1164/1164 green
    (95 files) — matched cycle 259's counts exactly, no drift.
  - **security-auditor sweep (backend handlers + application services): PASS, no RED.** Two
    YELLOW findings:
    1. **Fixed this cycle:** `media_service.rs::request_upload` persisted and signed an
       unvalidated client `content_type` string into `MediaBlob` metadata and the R2 presigned PUT
       URL — no shape or length check. Added `is_valid_content_type`/`is_valid_media_type_token`
       (RFC 6838 §4.2 `type/subtype` token grammar, ASCII alnum + `!#$&-^_.+`, 128-char cap) and a
       fail-closed check in `request_upload` (mirrors the existing `size_bytes` defense-in-depth
       check, single source of truth in the application layer so gRPC/non-REST callers can't
       bypass it either). 4 new tests (2 pure-function table tests incl. a CRLF-injection-shaped
       string, 1 oversized-length test, 1 `request_upload` behavioral test) — `powehi-application`
       now 91/91 (was 87).
    2. **Documented, not fixed (architecture-level, deferred):** `push_subscription.rs`'s
       `is_private_host` SSRF guard only inspects IP literals in the endpoint URL; a registered
       hostname whose DNS resolves to an internal/link-local address at *send* time (not
       registration time) bypasses it (SSRF via DNS rebinding). Already mitigated in depth by the
       k8s egress NetworkPolicy blocking `169.254.169.254/32` + RFC-1918 (infra cycles 248/250).
       A real fix is resolve-then-validate-then-connect at send time, which is a bigger behavioral
       change to the webpush send path — left as a named candidate for a future cycle rather than
       bundled into this pass.
  - **crypto-reviewer sweep (all 7 `powehi-crypto-wasm` src files): GREEN, no regressions, no
    required changes.** Re-verified MLS state transitions stay entirely inside openmls, OPAQUE KE
    ordering intact, ML-KEM-768 sizes/KATs/implicit-rejection still correct, kem_credential domain
    separation intact, HKDF recovery-phrase derivation unchanged, AES-256-GCM media encryption
    fresh-key-per-call. Three previously-accepted findings (Y-B-1 unprefixed HKDF info, Y-3
    unverified-extract footgun-by-design, opaque-ke 3.0/draft-16 RFC-9807 waiver) reconfirmed as
    standing, not regressions — explicitly told not to re-action them.
  - **Target dir hygiene:** 13G, under the 20G prune threshold — no pruning needed this cycle.
  - **Next cycle:** the SSRF-via-DNS-rebinding hardening above (resolve-then-validate at webpush
    send time), or the group-row-creation gap (cycle 259), or PQ hybrid Phase A (still blocked on
    openmls stable `MLS_128_MLKEM768`).
- Cycle 261 FEATURE: CI fix + webpush send-time SSRF/DNS-rebinding hardening (commits 91a7045, b71d241).
  - **Mode:** FEATURE (counter 261 % 5 ≠ 0). CI check found `CI — Rust` red on main (cycle 260's
    Content-Type-validation commit `f446b12` never ran through `cargo fmt` — a boolean-chain and a
    test array literal in `media_service.rs` were left in rustfmt's pre-collapse shape).
  - **CI fix (91a7045):** `cargo fmt --all` on `media_service.rs`, no logic change. Verified
    `cargo build --workspace` and `cargo test --workspace` both green before pushing.
  - **Feature (b71d241):** closed the SSRF-via-DNS-rebinding gap cycle 260's security sweep flagged
    (documented, not fixed, at the time): the push-subscription registration-time guard
    (`is_private_host` in `powehi-rest-api::routes::push_subscription`) only validates the endpoint
    hostname once, at registration — a hostname that resolved to a public IP at registration time can
    later resolve to an internal/private address (DNS rebinding, or just a changed DNS record), and
    nothing re-checked that before the outbound `reqwest` client in `powehi-webpush` connected to it.
    1. Extracted the private-IP-range predicate (loopback/RFC-1918/link-local/ULA/unspecified/
       broadcast/IPv4-mapped-IPv6/`localhost`) out of `push_subscription.rs` into a new shared
       `powehi_domain::net_guard` module (`is_private_ip` + `is_private_host`) — single source of
       truth for both the inbound registration-time check and the new outbound send-time check, so
       they can't silently drift apart. `push_subscription.rs`'s registration-time behavior is
       unchanged (verified byte-identical logic); its now-redundant local unit tests were removed
       (the pure-logic cases moved to `net_guard`'s own tests, HTTP-level wiring tests kept in place).
    2. New `PublicOnlyResolver` in `powehi-webpush::lib` implementing reqwest's `Resolve` trait: real
       DNS resolution via `tokio::net::lookup_host`, filters out every resolved `SocketAddr` whose IP
       is private per `is_private_ip`, fails the connection if nothing public remains. Wired into
       `VapidWebPushAdapter::build_client()` via `.dns_resolver(Arc::new(PublicOnlyResolver))` — runs
       on every single send, not just at registration.
    3. **Documented scope boundary (found by security-auditor, addressed same commit):** reqwest/
       hyper-util short-circuits IP-literal hosts (e.g. `https://169.254.169.254/...`) straight to a
       socket address and never calls `Resolve::resolve` for them — so `PublicOnlyResolver` cannot see
       or block IP-literal endpoints; that class stays covered solely by the registration-time
       `is_private_host` check. The two layers are complementary (literal-IP SSRF vs.
       hostname-rebinding SSRF), not redundant — documented explicitly in `PublicOnlyResolver`'s doc
       comment so a future reader doesn't assume the resolver alone is sufficient.
    4. The auditor also flagged the original test (`notify_rejects_endpoint_that_resolves_to_private_ip`,
       using the `169.254.169.254` IP literal) as misleading: it passed only because the address is
       unreachable in CI (transport error), never because the resolver actually ran. Rewrote it as
       `notify_rejects_hostname_that_resolves_to_private_ip` using `https://localhost/...` — a real
       hostname that goes through DNS resolution (not the IP-literal short-circuit) and genuinely
       exercises the send-time resolver end-to-end via `notify()`.
  - **security-auditor: PASS** (no RED). One YELLOW (the IP-literal bypass scope gap above) — fixed
    in-cycle via the doc comment + corrected test, not deferred. Confirmed: no info leak (resolver's
    error string/resolved IP never reach a log or HTTP response — `notify()` collapses every failure
    to `error_kind="transport"` + a static `DomainError::Internal` string), no panics/unwraps added,
    no unbounded-DoS surface (DNS resolution runs inside the client's existing 10s `.timeout()`),
    `redirect(Policy::none())` (pre-existing) still closes the open-redirect-to-internal-address angle
    independently of the resolver.
  - 4 new tests in `powehi-webpush` (resolver blocks private IPv4/IPv6 literals directly, resolver
    allows a public IP literal, `notify()` end-to-end rejects a private-resolving hostname) — 13/13
    `powehi-webpush` tests pass (was 9). `cargo test --workspace`: zero failures across all crates.
    `cargo fmt --all --check` clean, `cargo clippy --workspace --all-targets -- -D warnings` clean.
  - **Frontend:** untouched this cycle (pure backend security-hardening feature).
  - **Next cycle:** the group-row-creation gap (cycle 259 — no code path calls `db.groups.add()`, so
    Dexie pin/theme persistence is a no-op in the live app until group-row creation is wired up), or
    PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`).
- Cycle 255 STABILIZATION: Redis testcontainers integration suite (commit 7f9d213).
  - CI green (no red runs), `gh issue list` empty, `cargo audit` clean (only the pre-existing
    waived RUSTSEC-2024-0384 `instant` advisory via openmls/fluvio-wasm-timer), `cargo clippy
    --workspace --all-targets -- -D warnings` clean, backend `cargo test --workspace` all green,
    frontend `pnpm test` 1136/1136 green (92 files) — no regressions found, so this cycle targeted
    the test-gap sweep instead (testing-conventions.md item 3).
  - Gap found: testing-conventions.md requires a `testcontainers` integration test per outbound
    adapter (Postgres/Redis/R2); only Postgres had one (`pg_security_it.rs`). `powehi-redis`'s
    `RedisCache` (`CachePort` impl) had only inline unit tests — never touched a real Redis.
  - Added `crates/adapters/outbound/powehi-redis/tests/redis_cache_it.rs`: 9 `#[ignore]`d
    `#[tokio::test]`s against a real ephemeral `redis:7-alpine` testcontainer (overrides the
    testcontainers-modules 0.11 default tag of 5.0, which predates GETDEL/Redis 6.2 that
    `RedisCache::get_del` issues) — covers set/get round-trip, missing-key None, TTL expiry
    (real sleep-past-deadline, not mocked), delete + idempotent delete-on-missing, exists
    presence tracking, GETDEL atomicity, SADD/SMEMBERS round-trip, and set_expire TTL-on-existing-
    key. Per-test unique key prefixes (`it:{uuid}:...`) though containers are already per-test.
  - Wired into `.github/workflows/ci-rust.yml`'s existing `integration-test` job: added a
    `docker pull redis:7-alpine` pre-pull + `cargo nextest run -p powehi-redis --run-ignored all
    -E 'binary(redis_cache_it)'` step, mirroring the existing Postgres testcontainers step.
  - Cargo.toml: added `"redis"` to workspace `testcontainers-modules` features; powehi-redis
    Cargo.toml: added `tokio`/`testcontainers`/`testcontainers-modules` to `[dev-dependencies]`.
  - Delegated implementation to `backend-lead`; verified `cargo test --no-run -p powehi-redis`
    compiles clean and `cargo clippy --workspace --all-targets -- -D warnings` stays clean (Docker
    unavailable in this sandbox, so the `#[ignore]`d tests themselves run for real only in CI).
  - **security-auditor: GREEN**, no findings. Test fixtures are synthetic/opaque (no plaintext
    content or PII), container lifecycle correct (`_c` binding keeps `ContainerAsync` alive,
    Drop tears it down), test isolation sound, CI change low-risk (mirrors existing Postgres step,
    no new secrets/permissions). Minor non-blocking nit: `redis:7-alpine` is tag- not
    digest-pinned, consistent with the existing `postgres:16-alpine` step (not a regression).
  - `powehi-r2` (S3-compatible testcontainers via minio/localstack) intentionally left as a
    separate future stabilization item — did not want to scope-creep this pass.
  - target/ at 11G (well under the 20G prune threshold) — no hygiene pass needed this cycle.
- Cycle 254 FEATURE: Persist emoji reactions to Dexie (commit 4cde17a).
  - Closed the last remaining gap in the cycle 252/253 series: reactions (already fully
    implemented end-to-end over MLS control envelopes — `{type:"reaction"|"reaction_remove",...}`
    in useMessages.ts/ChatLayout.tsx) lived only in React `chats` state; a reload reverted them,
    same gap edit/delete had before cycles 252-253 closed it for those.
  - `MessageRow.reactionsJson?: string` (JSON-serialized `Record<emoji, senderDeviceId[]>`,
    encrypted at rest like editedText) added to schema.ts, bumped to `version(8)` (additive,
    no migration needed).
  - `EncryptedPowehiDb.markMessageReactions(id, reactionsJson)` — encrypts + `db.messages.update()`,
    no-ops safely on a missing id, mirrors markMessageEdited/markMessageDeleted.
  - `usePersistentMessages` gained `persistReaction(targetMessageId, reactions)`, same
    fire-and-forget + `writeErrorCount` pattern as persistEdit/persistDelete.
  - `handleIncomingReaction`/`handleRemoveReaction` in ChatLayout.tsx now also call
    `persistReaction` with the recomputed post-mutation map (recomputed from `chatsRef.current`
    since `setChats` is async — same technique handleIncomingEdit/handleIncomingDelete already use).
  - Rehydration `useEffect` (cycle 253) now also parses `row.reactionsJson` via `JSON.parse` in a
    try/catch — a corrupt/malformed value drops reactions for just that one row rather than
    aborting the whole rehydration.
  - **security-auditor: GREEN.** Two LOW findings noted as pre-existing (not introduced this
    cycle): (1) fire-and-forget Dexie writes can race under rapid react/unreact toggles — same
    exposure persistEdit/persistDelete already have; (2) reaction attribution trusts `env.sender`
    (server-authenticated device id) which is not an MLS-cryptographic sender proof — same gap the
    live (non-persisted) reaction feature already had; persistence doesn't change severity since
    the state was already forgeable-and-displayed before this cycle.
  - 9 new tests (encrypted-db.test.ts ×2, usePersistentMessages.test.ts ×3, ChatLayout.test.tsx ×4:
    incoming-reaction persists, reaction_remove persists emoji-key-dropped map, rehydrates a
    persisted reaction chip, skips unparseable reactionsJson safely). All 1136 frontend tests green
    (92 files, was 1127); tsc clean; Biome clean.
  - This closes out the edit/delete/reaction persistence trio — no further known gaps in
    message-adjacent state persistence. Reactions/pins/mentions note from cycle 253 is now just
    "pins/mentions remain session-only", reactions no longer included.
- Cycle 253 FEATURE: Rehydrate persisted chat history from Dexie into `chats` state (commit fcab6c4).
  - Closed the follow-up noted in cycle 252: `usePersistentMessages().rows` was write-only — never
    consumed in ChatLayout.tsx — so Dexie-stored message history (incl. edited text and delete-for-
    everyone tombstones) silently vanished from the UI after a reload or a switch away-and-back.
  - New `useEffect` in ChatLayout.tsx maps decrypted `MessageRow[]` → `ChatMessage[]` (text from
    `editedText ?? plaintextB64` via `base64ToText`, `from` via `senderDeviceId === deviceId`,
    `edited`/`deleted` flags, `expiresAt`), merges by dedup-on-`id` into the active chat's `messages`,
    guarded by `row.groupId !== groupId` against the async chat-switch transition window where
    `usePersistentMessages`'s `rows` briefly still holds the previous group's data.
  - **security-auditor YELLOW → fixed in-cycle:** rows from `getMessagesByGroup` aren't TTL-filtered
    and the `purgeExpired()` sweep only runs every 30s, so an already-expired disappearing message
    could flash back on screen for up to 30s after every mount — added
    `if (row.expiresAt && row.expiresAt <= Date.now()) continue;` in the rehydration loop.
  - **security-auditor YELLOW → documented/deferred (not fixed):** (1) `from: "me"` attribution
    trusts `senderDeviceId` (server-authenticated via `AuthenticatedDevice` extractor at send time,
    but not an MLS-cryptographic sender proof) — a compromised server could in principle mislabel a
    peer's message as self-authored on rehydration specifically (live/non-rehydrated incoming always
    hardcodes "them" regardless of sender, so this divergence is scoped to the rehydration path only,
    under a compromised-server assumption outside current threat model). (2) dedup is add-only —
    an id already in `chats` is left untouched even if Dexie's copy was since edited/deleted
    out-of-band (e.g. another tab), so an inactive tab that switches away-and-back (not a full reload)
    won't retroactively redact an in-memory bubble; a full reload still heals it since `chats` starts
    empty. Both documented inline in ChatLayout.tsx with "security-auditor finding, cycle 253" comments.
  - Reactions/pins/mentions remain session-only (no MessageRow/GroupRow fields exist for them) —
    explicitly out of scope; a real fix needs a schema bump, left as a future item.
  - 4 new tests in ChatLayout.test.tsx (mount rehydrates incl. edited/deleted, chat-switch doesn't
    leak, missing-plaintext row skipped safely, no duplicate for already-in-state id); also added
    `db.messages.clear()` to `beforeEach` in ChatLayout.test.tsx + 4 sibling ChatLayout*.test.tsx files
    (previously only `verifiedContacts` was cleared — cross-test Dexie pollution was latent until this
    cycle made `rows` actually get read). All 1127 frontend tests green (92 files, was 1123); tsc clean;
    Biome clean.
- Cycle 252 FEATURE: Persist edit/delete-for-everyone state to Dexie (commit 97b1f14).
  - Gap: "edit message" / "delete for everyone" were already fully implemented end-to-end over MLS
    control envelopes ({type:"edit"|"delete",...} in useMessages.ts/ChatLayout.tsx), but the edited
    text and deleted tombstone lived only in React `chats` state — a page reload reverted edits and
    un-deleted tombstoned messages, since `usePersistentMessages`'s Dexie-loaded `rows` were never
    hydrated back into `chats` (that hydration gap is separate/larger — noted as a follow-up below).
  - `MessageRow.editedText?: string` (encrypted at rest, added to SENSITIVE.messages) + `.deletedAt?: number`
    (plain, same tier as receivedAt/expiresAt); schema.ts bumped to `version(7)`, no index change.
  - `EncryptedPowehiDb.markMessageEdited(id, newTextB64)` / `.markMessageDeleted(id)` — Dexie `update()`
    no-ops safely on a missing id (attacker-influenced targetMessageId from peer envelopes, confirmed safe).
  - `usePersistentMessages` gained `persistEdit`/`persistDelete`, mirroring the existing
    `persistIncoming`/`persistOutgoing` fire-and-forget + `writeErrorCount` pattern.
  - **security-auditor YELLOW → fixed in-cycle:** `handleIncomingEdit`/`handleIncomingDelete` called
    `persistEdit`/`persistDelete` unconditionally, bypassing the `m.from === "them"` guard that already
    protected the `setChats` mutation — a forged peer envelope targeting the victim's own "me" message
    could still poison the local Dexie mirror even though in-memory state stayed correct. Fixed by
    gating persistence on the same `chatsRef`-derived from==="them" check used by the state guard.
    Added regression tests (ChatLayout.test.tsx) asserting `markMessageEdited`/`markMessageDeleted` are
    NOT called for forged edits/deletes targeting own messages, and ARE called for legitimate peer ones.
  - 9 new tests (encrypted-db.test.ts ×3, usePersistentMessages.test.ts ×6); all 1123 frontend tests green
    (92 files); tsc clean; Biome clean.
  - **Follow-up (not done this cycle):** `usePersistentMessages`'s loaded `rows` are still never read back
    into `ChatLayout`'s `chats` state on mount/group-change — full chat history (and now edited/deleted
    state) does not actually rehydrate into the UI after a reload. This is a larger, separate feature
    (mapping decrypted `MessageRow[]` → `ChatMessage[]` incl. reactions/pins/mentions/sender resolution)
    that deserves its own cycle rather than a half-finished addition here.
- Cycle 250 STABILIZATION: Security dependency fixes + domain proptest suite (commit c0c8179).
  - Fixed RUSTSEC-2026-0204 (crossbeam-epoch 0.9.18→0.9.20, invalid ptr deref via metrics-exporter-prometheus + openmls).
  - Fixed RUSTSEC-2026-0190 (anyhow 1.0.102→1.0.103, unsound downcast_mut).
  - Replaced yanked bitcoin_hashes 0.14.100→0.14.101 (via bip39 in powehi-crypto-wasm).
  - Upgraded vitest ^3.2.0→^3.2.7 (critical UI-server file-read advisory, dev-only).
  - Added 12 proptest property-based tests in crates/domain/powehi-domain/tests/prop_serde.rs:
    JSON serde roundtrips + UUID identity + Display/FromStr for GroupId/DeviceId/UserId/EnvelopeId/Epoch/MessageType.
  - security-auditor: GREEN (no RED findings; Y-LOW rate_limit XFF deploy-time precondition documented, already waived).
  - cargo audit: clean (1 existing waiver: RUSTSEC-2024-0384 instant via openmls).
  - All tests: 1114 frontend (92 files) + 52 backend domain tests (40 unit + 12 proptest) + all workspace tests passing.
- Cycle 231 FEATURE: Linked Devices panel + GET /v1/auth/devices endpoint (commit 85a4a54).
  - Fixed CI-Frontend failure: proptest moved to [target.cfg(not(wasm32)).dev-dependencies] in powehi-crypto-wasm (wait-timeout doesn't compile on wasm32).
  - Backend: DeviceInfo type (device_id, created_at, last_seen_at; no mls_credential), list_devices in AuthUseCase + AuthService, GET /v1/auth/devices handler (rate-limited, auth-gated), 2 new backend tests.
  - Frontend: LinkedDevicesPanel component (current device badge, 2-step revoke confirm, error/empty/loading states), listDevices + revokeDevice API functions in auth.ts, 11 component tests + 6 API tests.
  - security-auditor: GREEN (6 questions all clean; authorization scoped to authenticated user, no credential leakage, rate-limited, no plaintext logging, encodeURIComponent on DELETE URL).
  - All tests: 987 frontend (81 files) + all backend tests passing.
- Cycle 215 STABILIZATION: Added 4 security-invariant tests (KeyPackage single-use, cross-device isolation, expired-envelope suppression, TTL complement). security-auditor GREEN. 83/83 application tests. commit 6cbde19.
- Cycle 315 STABILIZATION: Fixed CI-red on main + a flaky invite test (commit 7ce596a).
  - `gh run list` showed cycle 314's "feat(media): voice messages" commit had a red
    CI — Frontend run: `tsc -b && vite build` failed with 3 TS errors in
    `useVoiceRecorder.test.ts`.
  - Root cause 1: `MockMediaRecorder.isTypeSupported = vi.fn((type: string) =>
    type === "audio/webm;codecs=opus")` — TS 5.5+'s control-flow-based type
    predicate inference turned this into `(type: string) => type is
    "audio/webm;codecs=opus"`, so a later `vi.fn(() => false)` reassignment in the
    "falls back to browser-default..." test no longer type-checked. Fixed with an
    explicit `: boolean` return annotation on the mock.
  - Root cause 2 (separate, genuine TypeScript compiler limitation, confirmed via
    minimal repro outside the file): a `let file: File | null = null` reassigned
    only inside a nested `async () => {...}` closure passed to `act()`, then read
    after the `await act(...)` — TS narrows `file` to `never` post-closure ONLY
    when the *containing* function is itself `async` (sync IIFE closures don't
    trigger it; a direct same-scope assignment doesn't either). Worked around in
    all 3 affected tests by replacing the `let` with an object-wrapper
    `const fileRef: { current: File | null } = { current: null }` — object-property
    mutation isn't subject to the same buggy CFA path.
  - Separately found (not in CI's failing job, but locally reproducible 100% of the
    time when running the full file, 0% in isolation): `AcceptInviteModal.test.tsx`'s
    "shows loading state while accepting" mocks `redeemInvite` behind a REAL 50ms
    `setTimeout` (not fake timers), asserts the loading text, then returns — leaving
    its own accept-flow promise chain (redeemInvite → real crypto.subtle.digest
    KeyPackage-hash check → mlsCreateGroup → createGroup → ...) running in the
    background past the test's end. `vi.restoreAllMocks()` in `afterEach` doesn't
    cancel real pending timers, so ~50ms of real wall-clock later the timer fires
    mid-way through whatever test is running THEN (2 tests later:
    "verification_failed"), and the resumed chain calls `createGroup` against
    that test's freshly-created spy — flakily failing its
    `expect(createGroupSpy).not.toHaveBeenCalled()` assertion. Fixed by adding a
    trailing `await waitFor(...)` on the success text so the flow fully drains
    before the test ends (no assertion removed/loosened — this was pure test
    isolation leakage, not a real race: `handleAccept` is single linear async,
    the KeyPackage-hash gate unconditionally precedes `mlsCreateGroup`/`createGroup`
    with no concurrent-invocation path in real usage).
  - **security-auditor: GREEN.** Confirmed the AcceptInviteModal fix doesn't mask a
    production race and doesn't weaken any assertion; confirmed the useVoiceRecorder
    changes are behaviorally equivalent workarounds.
  - Verified: `tsc -b` clean, `pnpm --filter app build` succeeds, `pnpm test --run`
    104/104 files · 1314/1314 tests green (was flaky on AcceptInviteModal before this
    fix), Biome clean, `AcceptInviteModal.test.tsx` re-run 5× standalone all green
    (was 100% reproducing the flake pre-fix). Backend: `cargo test --workspace`
    all green (untouched this cycle — pure frontend test fix).
  - Target dir hygiene: 23G (over the 20G threshold) → pruned artifacts older than
    7 days per the housekeeping step; still 23G after (nothing stale enough to
    prune this cycle), 108,949 files in target/debug/deps — well under the past
    291k-file pathological-growth incident, no further action needed.
  - `gh issue list --state open` — empty, nothing else to triage this cycle.
  - **Next cycle:** no known gaps flagged from this pass; check `gh run list` first
    to confirm this fix went green on main before starting new FEATURE work.
