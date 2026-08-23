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

## Current state (2026-08-23, cycle 343 — FEATURE: persist sender's own copy of forwarded text messages, commit 3fab286)

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

## Previous state (2026-08-22, cycle 339 — FEATURE: persist scheduled ("send later") messages to Dexie, commit 8cc5998)

- CI green, `gh issue list` empty at cycle start. Per cycle 338's "Next cycle candidates", closed
  the scheduled-message persistence gap flagged as a runner-up for 2 cycles running: scheduling,
  cancelling, and firing a "send later" message was entirely React-state-only — a reload silently
  dropped any pending scheduled message. Followed the poll-persistence pattern exactly (a
  not-yet-fired scheduled message has no MLS envelope either, same as a poll).
- `MessageRow.scheduledFor?: number` added (schema v26), not encrypted (a timestamp, same tier as
  expiresAt/lastSeenAt). `EncryptedPowehiDb` gained `clearMessageScheduled(id)` (fires it — clears
  scheduledFor, no-ops on missing row) and `deleteMessage(id)` (cancels it — hard delete, the only
  non-tombstoning delete in this class since a cancelled scheduled message never went out over MLS
  so there's nothing to tombstone). `usePersistentMessages` gained
  `persistScheduledCreate`/`persistScheduledFire`/`persistCancelScheduled`. Wired into ChatLayout's
  existing `sendScheduled`/`fireScheduled` sweep/`cancelScheduled`, plus the rehydration effect
  (both the initial push and the cross-tab reconciliation block).
- **security-auditor: YELLOW, all 4 findings fixed in-cycle (2 more documented/deferred, not fixed):**
  1. **MEDIUM, fixed:** `persistScheduledCreate` never threaded `expiresAt` — a scheduled message
     composed in a disappearing-message chat would never be purged (same retention-policy gap
     already fixed for `persistOutgoing`/`persistPollCreate`). Fixed: `sendScheduled` now computes
     `expiresAt` from `disappearingTtl` at schedule/compose time (same clock poll creation uses) and
     threads it through both the in-memory push and `persistScheduledCreate`.
  2. **LOW, fixed:** `deleteMessage` was an unguarded hard delete keyed by a bare id — the only
     thing stopping misuse against a real MLS message (or a `markMessageDeleted` tombstone) was the
     UI-side gate on `scheduledFor` being set. Fixed: `deleteMessage` now reads the row first and
     only deletes when `scheduledFor` is still defined — no-ops otherwise (2 new regression tests).
  3. **LOW, fixed (correctness, not exploitability):** the fire sweep's `firedIds` snapshot (from
     `chatsRef`) and the `setChats` mapper independently re-evaluated `scheduledFor <= now` — could
     theoretically diverge by one message across the snapshot boundary. Fixed: the mapper now flips
     exactly the ids captured in `firedIds`, nothing else.
  4. **LOW, documented/deferred:** hard-deleting a cancelled scheduled message has no cross-tab
     reconciliation path (the rehydration reconcile loop is add/update-only, matching every OTHER
     mutation here which tombstones instead of hard-deleting) — a narrow cross-tab race (cancel in
     tab A, tab B independently fires the same message locally first) can leave a phantom "sent"
     bubble in tab B until a full reload. Documented inline; not fixed — a generic "remove missing
     ids" pass would need to distinguish "hard-deleted" from "not yet written" (`persistScheduled-
     Create` doesn't reserve a `pendingWriteIds` slot the way `persistEdit`/`persistDelete` do), and
     getting that wrong risks deleting a just-scheduled message from the UI before its own Dexie
     write lands.
  5. **INFO, documented, no action:** firing a scheduled message still does not actually
     encrypt+send it over MLS (pre-existing, separate, larger gap, unchanged by this cycle) —
     persistence now makes that gap's *symptom* durable (a local-only "sent" record with no peer
     delivery) instead of erasing it on reload. Tracked with the existing gap, not this one.
  6. **INFO, accepted (same class already accepted for polls):** `persistScheduledCreate`'s Dexie
     write is async and unawaited; firing/cancelling before it lands is a silent no-op, self-heals
     since create's own write lands after. Requires racing a sub-second crypto write against either
     real elapsed wall-clock time (firing) or a separate user click (cancelling) — impractical.
- 15 new tests across `usePersistentMessages.test.ts` (creation incl. `expiresAt` threading ×2,
  fire, cancel, durable-Dexie variants of both, no-op/error-count coverage), `encrypted-db.test.ts`
  (`clearMessageScheduled`/`deleteMessage` incl. the new guard's 2 regression tests, encrypted-at-
  rest), and `ChatLayoutScheduleSend.test.tsx` (create/cancel/fire persistence, rehydration with
  badge). Also added `db.messages.clear()` and a `cleanup()` call to that file's beforeEach/
  afterEach (was missing `cleanup()` entirely — caused 17 unhandled post-test exceptions and a
  nonzero exit code once tests started setting a real deviceId/sessionToken; same test-isolation
  bug class fixed across ChatLayout*.test.tsx since cycle 335, this file had just never hit it
  before since none of its original tests left the auth store in the "app" phase).
- **Frontend: 1451/1451 tests green** (was 1446, 104 files). `tsc -b` clean, `biome check` clean
  (149 files). Production build: initial route 164.37 kB gzip / WASM 642.87 kB gzip (both under
  prd.md §7 budgets).
- **Backend:** untouched (pure frontend fix, confirmed via `git status`).
- Target dir hygiene: not checked (FEATURE mode, backend untouched).
- `gh issue list --state open` — empty.
- **Next cycle candidates:** the `.claude/memory/project-context.md` file-size note (now ~3800+
  lines, worth archiving cycles below ~320 at the next STABILIZATION cycle — flagged 5 cycles
  running now, cycle 320's own archive-cutoff cycle is itself long past inline-window); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold); the pre-existing "scheduled messages never
  actually send over MLS when they fire" gap noted above (separate, larger, not attempted this
  cycle).

## Previous state (2026-08-22, cycle 338 — FEATURE: thread expiresAt into persistOutgoing, commit 32a4538)

- CI green, `gh issue list` empty at cycle start. Closed one of cycle 337's flagged follow-ups:
  `persistOutgoing` (the sender's own Dexie copy of a sent message) never set `expiresAt`, even
  though `ChatLayout.sendMessage` already computes it (`disappearingTtl ? Date.now() +
  disappearingTtl*1000 : undefined`) and uses it correctly for the in-memory optimistic UI
  message. Result: a disappearing message's sender-side local copy was durably retained forever
  — bypassing both the `purgeExpired`/`purgeExpiredMessages` sweep and the rehydration TTL-skip
  check — while the recipient's copy (`persistIncoming`, already threaded `msg.expiresAt`
  correctly) and the in-memory UI copy expired as designed. Confirmed via grep there is exactly
  one `persistOutgoing` call site in the whole tree (`ChatLayout.tsx:9367`).
- Fix: added `expiresAt?: number` as `persistOutgoing`'s 6th param (after the existing `replyTo`),
  threaded into the constructed `MessageRow`, single call-site update passes the already-computed
  `expiresAt` through. Minimal, additive — no schema bump needed (`expiresAt` already existed on
  `MessageRow`, this cycle just stopped `persistOutgoing` from always leaving it `undefined`).
- **security-auditor: GREEN.** Confirmed no new logging, no new server-visible metadata (the
  reviewer flagged and I should record precisely: the premise "server never sees the raw TTL" is
  actually false and pre-existing — `disappearingTtl` already travels as `ttl_seconds` in the
  plaintext POST body / `Envelope.expires_at` for server-side envelope expiry, unrelated to and
  unchanged by this diff; the MLS-encrypted `{type:"text",...,ttl}` payload is for the receiver's
  *client-side* expiry only, not for hiding the duration from the server — don't cite "server
  never sees TTL" as an invariant in future cycles). Two non-blocking informational notes: (1)
  `expiresAt` is a Dexie plaintext index field (must be, to stay queryable for the sweep) so raw-
  IndexedDB access without the DB key can now see that self-sent messages carry a TTL — accepted,
  same exposure incoming/poll rows already had, and deleting content beats hiding one timestamp;
  (2) the first draft of the `purgeExpired` regression test only asserted in-memory `rows`, not
  the actual Dexie row — strengthened in-cycle to `await waitFor(... db.messages.get(id) ...)`
  before AND after purge, so the test now actually fails if the durable-deletion half regresses.
- 3 new tests in `usePersistentMessages.test.ts` (expiresAt threads through when given; stays
  undefined when omitted; `purgeExpired` durably deletes the Dexie row once past `expiresAt`, not
  just the in-memory copy). **Frontend: 1429/1429 tests green** (was 1426, 104 files). `tsc -b`
  clean, `biome check` clean (149 files via `src/`, ran `--write` once for `ChatLayout.tsx`
  formatting after the edit — no logic change). Production build: initial route 164.22 kB gzip /
  WASM 642.87 kB gzip (both under prd.md §7 budgets).
- **Backend:** untouched (pure frontend fix, confirmed via `git status` — no crypto-reviewer/
  threat-model-checker needed).
- Target dir hygiene: not checked (FEATURE mode, backend untouched).
- `gh issue list --state open` — empty.
- **Next cycle candidates:** scheduled-message persistence (cycle-336 runner-up, still not done);
  the `.claude/memory/project-context.md` file-size note (now ~3700+ lines, worth archiving
  cycles below ~300 at the next STABILIZATION cycle — flagged 4 cycles running now); PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-22, cycle 337 — FEATURE: persist quote-reply context (replyTo) to Dexie, commit 2fc6ae5)

- CI green, `gh issue list` empty at cycle start. Per cycle 336's "Next cycle candidates", closed
  one of the two runner-up gaps flagged there: quote-reply `replyTo` metadata (`ReplyContext =
  { messageId, excerpt }`) was React-state-only — `persistOutgoing` never received it and
  `persistIncoming` silently dropped `msg.replyTo` even though `IncomingMessage` already carried
  it (decoded from the same JSON-structured plaintext as `text`/media) — so a reload dropped which
  message a reply was quoting. Scheduled messages remain the other flagged-but-not-done candidate.
- Followed the established pattern exactly: `MessageRow.replyToJson?: string` (schema v25,
  encrypted at rest — added to `SENSITIVE.messages`). Unlike reactionsJson/pollJson, replyTo is
  set once at message-creation time and never mutated afterward, so no `markMessageReplyTo`
  setter was added — `persistIncoming`/`persistOutgoing` just thread it into the row at creation
  (`persistOutgoing` gained a new optional 5th param `replyTo?: ReplyContext`). One call-site
  change in ChatLayout.tsx: `persistOutgoing(..., replyContext)`. Rehydration effect parses
  `row.replyToJson` with a JSON.parse try/catch AND a shape guard (`messageId`/`excerpt` both
  strings), modeled on the pollJson handling added cycle 336 (this app has no ErrorBoundary
  anywhere, so a bad shape reaching PollView/reply-quote render could blank the whole UI).
  `replyTo` is deliberately excluded from the effect's "reconcile already-in-state ids against
  fresh Dexie rows" comparison block — it never changes post-creation, same treatment as
  `ts`/`expiresAt`/`from`.
- **security-auditor: GREEN**, no RED/blocking findings. One YELLOW documented inline (not code-
  fixed): a reply excerpt (≤100 chars) is now durably persisted independent of the *quoted*
  message's own `expiresAt` — a reply to a disappearing message can outlive the original by up
  to 100 chars, same class as cycle 336's accepted poll/expiresAt finding. Documented on
  `MessageRow.replyToJson`'s doc comment in schema.ts (bounded, encrypted, standard Signal/
  WhatsApp-style quote-preview behavior, not fixed). Confirmed: encryption-at-rest complete (only
  writers are `EncryptedPowehiDb.addMessage/putMessage`, both go through `encRow`), rehydration
  fails closed on malformed/wrong-shape JSON, peer-controlled `messageId`/`excerpt` are already
  wire-validated (≤36 chars / `.slice(0,100)`) in `useMessages.ts` before ever reaching Dexie, no
  new server-visible metadata (replyTo already traveled inside the same MLS-encrypted structured
  payload, unchanged), migration is additive (old rows get `replyToJson: undefined`). Noted
  (not this cycle's scope, flagged as pre-existing): `persistOutgoing` never sets `expiresAt` at
  all (sender's own copy of a disappearing message is never locally purged) — a real, separate
  gap worth its own cycle.
- 15 new tests: 1 in `encrypted-db.test.ts` (`putMessage` round-trips `replyToJson` encrypted at
  rest), 4 in `usePersistentMessages.test.ts` (persistOutgoing threads/omits replyTo,
  persistIncoming threads/omits msg.replyTo), 10 in `ChatLayout.test.tsx` (3 rehydration: renders
  reply-quote from a persisted row, skips bad-JSON replyToJson safely, skips wrong-shape
  replyToJson safely; 1 end-to-end send-path integration test: replying to a real incoming
  message and sending persists the exact `{messageId, excerpt}` to Dexie). **Frontend: 1426/1426
  tests green** (was 1417; 104 files, unchanged file count). `tsc -b` clean, `biome check` clean
  (170 files, ran `--write` once for 4 files' formatting after the edits — no logic changes).
  Production build: initial route 164.17 kB gzip / WASM 642.87 kB gzip (both still under the
  prd.md §7 200KB/800KB budgets).
- **Backend:** untouched this cycle (pure frontend Dexie-persistence feature, confirmed via
  `git status` — no crates touched, so no crypto-reviewer/threat-model-checker needed).
- Target dir hygiene: not checked this cycle (FEATURE mode, backend untouched).
- `gh issue list --state open` — empty, nothing else to triage.
- **Next cycle candidates:** scheduled-message persistence (the other cycle-336 runner-up,
  still not done); `persistOutgoing` never threading `expiresAt` (flagged this cycle by
  security-auditor — sender's own copy of a disappearing message is never locally purged, a
  real gap independent of the replyTo work); the `.claude/memory/project-context.md` file-size
  note (now ~3670+ lines, worth archiving cycles below ~300 at the next STABILIZATION cycle);
  PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold).

## Previous state (2026-08-22, cycle 336 — FEATURE: persist group polls (question + votes) to Dexie, commit a1e16b8)

- CI green, `gh issue list` empty at cycle start. Per cycle 335's "Next cycle" note, re-ran an
  Explore-agent survey for the next unwired-Dexie-persistence UI feature. Found: group polls
  (`ChatMessage.poll`) were created/voted entirely in React state —
  `handleCreatePoll`/`handleVotePoll` never called `persistOutgoing` (there is no MLS envelope
  type for polls at all — confirmed via grep, they're genuinely local-only, never sent to
  server/peers), so a reload silently wiped every poll and its votes. Worse than a partial-field
  gap: the entire message row was never written, not just a poll-specific field.
- Followed the established `reactionsJson` (v8) pattern: `MessageRow.pollJson?: string` (schema
  v24, encrypted at rest — added to `SENSITIVE.messages`), `EncryptedPowehiDb.markMessagePoll`,
  and two new `usePersistentMessages` helpers — `persistPollCreate` (creates the row; unlike
  every other persist* helper this one CREATES rather than updates, since polls never go through
  `persistOutgoing`'s MLS-send path) and `persistPollVote` (updates it, mirrors `persistReaction`).
  Poll rows use `ciphertextB64: ""` as an explicit "not applicable, local-only" sentinel — same
  convention as `GroupRow.mlsStateB64`. Wired into `handleCreatePoll`/`handleVotePoll` and into
  the existing Dexie-rehydration `useEffect` (parses `pollJson` back into `ChatMessage.poll`; the
  `if (!textB64) continue` skip guard was relaxed to `if (!textB64 && !row.pollJson) continue`
  since a poll row legitimately has no plaintext).
- **security-auditor: PASS, no RED, 4 YELLOW — 2 fixed, 1 fixed-differently, 1 documented/deferred:**
  1. *(fixed)* `persistPollCreate` didn't thread `expiresAt` — a poll created in a disappearing-
     message chat would persist forever instead of being purged like every other message
     (retention-policy bypass). Fixed: `expiresAt` param added, `handleCreatePoll` computes it
     from `disappearingTtl` same as `sendMessage` does; the existing generic `purgeExpired`
     sweep and rehydration TTL-skip both already work automatically once the field is set.
  2. *(fixed)* Rehydration's `JSON.parse(row.pollJson)` only caught syntax errors, not wrong
     shape — a syntactically-valid-but-missing-`options` value would parse fine then throw
     inside `PollView`'s `.reduce`/`.map` during render, and this app has **no ErrorBoundary
     anywhere** (confirmed via grep), so one bad row would blank the entire UI. Fixed: added a
     shape guard (`question` is a string, `options` is an array of `{text: string, voters:
     array}`) before accepting the parsed value.
  3. *(fixed, different approach than suggested)* `handleVotePoll`'s toggle computed the new
     poll from `chatsRef.current` (only synced via a post-commit effect) rather than from fresh
     state — two votes on different options in the same tick could read a stale poll and drop
     one. Fixed by moving the toggle computation inside `setChats`'s functional updater (always
     latest state) and capturing the result in an outer variable for persistence, instead of
     reading a pre-update snapshot.
  4. *(documented, not fixed)* A narrow async-ordering race: `persistPollCreate` awaits 2
     sequential `encryptDbField` round-trips (ciphertextB64 + pollJson) before its `putMessage`
     lands, vs `persistPollVote`'s 1 round-trip before `markMessagePoll` (update-only, no-ops on
     a missing row) — a vote fired within roughly one round-trip of the poll's own creation could
     have its Dexie write silently dropped (in-memory state is unaffected; self-heals on the next
     vote). Not fixed to avoid changing markMessage*'s shared no-op-on-missing-row contract into
     an upsert. Documented inline on `persistPollVote`.
- Also fixed an unrelated **pre-existing test-isolation bug** in `ChatLayoutPoll.test.tsx`,
  discovered while adding the new persistence tests: the file's `afterEach` never called RTL's
  `cleanup()` (only `vi.restoreAllMocks()`), so previous tests' `ChatLayout` instances stayed
  mounted across tests. Once new tests started issuing real async Dexie writes (`persistPollCreate`/
  `persistPollVote`, gated on `deviceId` which only the new tests set), a write settling after
  `restoreAllMocks()` had already un-mocked `useMessages` — but before the (missing) unmount —
  hit the real hook mid-lifecycle on a still-mounted stale tree, corrupting React's hook order
  (`TypeError: Cannot read properties of undefined (reading 'length')` in
  `react-dom`'s `areHookInputsEqual`, surfaced as an "Unhandled Error" after the test already
  showed passing). Root-caused via careful bisection (isolated minimal repro files, `-t` filters,
  git-stash diffing against the pre-change baseline) since the trace pointed at `useMessages.ts`/
  zustand `useSyncExternalStore` internals with no direct connection to polls. Fixed by adding
  `cleanup()` to the file's `afterEach`, alongside the same `db.messages.clear()` fix cycle 335
  applied to 11 other `ChatLayout*.test.tsx` files (this file wasn't in that list since, at the
  time, nothing in it wrote to `db.messages` — this cycle's feature changed that).
- 13 new tests: 2 in `encrypted-db.test.ts` (`markMessagePoll` persists/no-ops), 6 in
  `usePersistentMessages.test.ts` (`persistPollCreate`/`persistPollVote` incl. the `expiresAt`
  threading fix), 5 in `ChatLayoutPoll.test.tsx` (create/vote persist to Dexie, rehydrates incl.
  votes, bad-syntax and bad-shape `pollJson` don't crash the app). **Frontend: 1417/1417 tests
  green** (was 1404; 104 files, unchanged file count). `tsc -b` clean, `biome check` clean (170
  files). Production build: initial route 164.07 kB gzip / WASM 642.87 kB gzip (both under the
  prd.md §7 200KB/800KB budgets, unaffected by this diff).
- **Backend:** untouched this cycle (pure frontend Dexie-persistence feature, confirmed via
  `git status` — no crates touched, so no crypto-reviewer/threat-model-checker needed; polls have
  no server-visible metadata, never leave the client).
- Target dir hygiene: not checked this cycle (FEATURE mode, backend untouched — no build
  artifacts changed).
- `gh issue list --state open` — empty, nothing else to triage.
- **Next cycle candidates:** the `.claude/memory/project-context.md` file-size note (now ~3600+
  lines — was flagged worth archiving cycles below ~300 at a STABILIZATION cycle since cycle
  330/334/335, genuinely worth doing soon); the accepted narrow persistPollCreate/persistPollVote
  ordering race above if it ever proves not self-healing in practice; PQ hybrid Phase A (still
  blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003
  Phase B 95%-session threshold); re-run the cycle-326/336-style Explore-agent survey again for
  any remaining unwired-Dexie-persistence UI features (scheduled messages and quote-reply
  `replyTo` metadata were both flagged as runner-up candidates this cycle, not yet fixed).

## Previous state (2026-08-22, cycle 335 — STABILIZATION: fix db.messages test-isolation gap + fake-timer hang, commit 294463e)

- `git status` clean, CI green (`gh run list --limit 5`), `gh issue list --state open` empty at
  cycle start. Picked up the standing cycle-329/334 sweep candidate: a grep sweep for the
  `db.messages.clear()`-missing-in-`beforeEach` bug class across all `ChatLayout*.test.tsx` files
  (the same bug fixed once already in `ChatLayoutStarred.test.tsx`, cycle 329).
- Dispatched an Explore agent (read-only) to triage: of 43 files importing `db` but never calling
  `db.messages.clear()`, most are no-ops (never drive a real `capturedOnMessage`/composer-send that
  writes into `db.messages`, or their assertions don't depend on message count/position). The agent
  found **11 genuinely at-risk files** — same fixed `mlsGroupId` reused across multiple tests, real
  `persistIncoming`/`persistOutgoing` writes via `capturedOnMessage`, and count/position-based
  assertions (`bubbles[bubbles.length - 1]`, `toHaveLength(N)`, singular `getByTestId`) that a
  leftover row from an earlier test in the same file could silently break:
  `ChatLayoutDateSeparator`, `ChatLayoutJumpToReply`, `ChatLayoutKeyboardShortcuts`,
  `ChatLayoutMarkAllRead`, `ChatLayoutMediaGallery`, `ChatLayoutMentionHighlight`,
  `ChatLayoutMentions`, `ChatLayoutMute`, `ChatLayoutThread`, `ChatLayoutTimeGrouping`,
  `ChatLayoutGroupReadReceipts`. Added `await db.messages.clear();` to each file's `beforeEach`
  (mirroring the existing `db.verifiedContacts.clear()` line already there).
- **Second latent bug surfaced by the fix (not pre-existing risk, a real hang):** adding the clear
  to `ChatLayoutTimeGrouping.test.tsx` made the full suite hang — every test after the first timed
  out after 10s in `beforeEach`. Root cause: this file's `afterEach` called `vi.useRealTimers()`
  without first draining pending fake-timer-scheduled continuations
  (`vi.runOnlyPendingTimersAsync()`), so a fake-indexeddb transaction still in flight when timers
  were force-switched left the shared `db` singleton's `messages` object store locked — the next
  test's real-timer `db.messages.clear()` then hung forever waiting on that dead transaction. Fixed
  by draining before switching timers, exactly matching the pre-existing pattern in
  `ChatLayoutSlowMode.test.tsx`'s `afterEach` (same directory) — confirms and closes the
  "documented pattern/rule if it recurs a second time" note flagged at the end of cycle 334
  (unconditional-Dexie-read-vs-fake-timers is now a two-occurrence class; the fix pattern is
  `if (vi.isFakeTimers()) await vi.runOnlyPendingTimersAsync(); vi.useRealTimers(); cleanup();
  vi.restoreAllMocks();` — drain-then-real-timers-then-unmount, in that order).
- **security-auditor: GREEN.** Reviewed as test-only, zero-assertion-change diff (verified: no
  `expect`/`it`/`describe`/`.skip`/mock-return-value touched anywhere in the 11-file diff, only
  `beforeEach`/`afterEach` scaffolding). Confirmed the `db.messages.clear()` additions can't mask a
  test's own subject-under-test (none of the 11 files read `db.messages` back — they assert on
  rendered DOM via the mocked `useMessages` hook; seed messages come from the in-memory
  `SEED_CHATS` constant, not DB rows). Confirmed `vi.runOnlyPendingTimersAsync()` (not
  `runAllTimers`) can't cascade or bleed a test's scheduled logic into the next test. One
  LOW/informational finding — the auditor's first-pass ordering (drain → cleanup → restoreAllMocks
  → useRealTimers) left `cleanup()`'s unmount effects (presence-offline send, disappearing/
  scheduled-message sweeps) running under fake timers with no drain after — fixed in-cycle by
  reordering to drain → useRealTimers → cleanup → restoreAllMocks, the exact `ChatLayoutSlowMode`
  order.
- `cargo build/test/clippy/fmt --workspace` all green (backend untouched, confirmed via
  `git diff --name-only` — pure frontend test-scaffolding change). `cargo audit`/`cargo deny check`
  both clean, no new advisories. Frontend: `tsc -b` clean, `biome check` clean (170 files),
  `npx vitest run`: **1404/1404 tests green** (104 files, unchanged count — this cycle fixed
  isolation, not test coverage). Re-ran `ChatLayoutTimeGrouping.test.tsx` standalone (391-403ms,
  was hanging ~90s/timing out before the fix) to confirm the hang is gone, not just hidden by run
  ordering.
- Target dir hygiene: 11G, well under the 20G threshold — no pruning needed this cycle.
- `gh issue list --state open` — empty, nothing else to triage.
- **Next cycle candidates:** the `.claude/memory/project-context.md` file-size note (now ~3490+
  lines, was flagged at cycles 330/334 as worth archiving cycles below ~300 at a STABILIZATION
  cycle — deferred again this cycle in favor of the higher-value test-isolation fix; genuinely
  worth doing at cycle 340 if it keeps growing) is still the top low-priority housekeeping item; PQ
  hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold); opaque-ke live-migration
  login-round-trip regression test gap (cycle 318/319, no prod users yet, low urgency); the lru
  RUSTSEC-2026-0253 waiver re-verification trigger from cycle 333 (only if aws-sdk-s3 bumped past
  1.143.0). No new feature gap surfaced this cycle — next FEATURE cycle should re-run the
  cycle-326-style Explore-agent survey for any remaining unwired-Dexie-persistence UI features, or
  pick from the standing PQ/OPAQUE backlog above.

## Previous state (2026-08-22, cycle 334 — FEATURE: persist custom user status to Dexie LocalIdentity, commit d03fb24)

- `git status` clean, `gh run list --limit 5` green at cycle start. Picked the top next-cycle
  candidate carried from cycles 326-333: `customStatus` (user-global emoji+text status, the last
  remaining gap from cycle 326's original Explore-agent survey — every other field fixed across
  323-332 was `GroupRow`/`MessageRow`-shaped; this one needed a fresh Explore-agent pass since it
  lives on the singleton identity row instead).
- Explore-agent survey confirmed: `LocalIdentity` (schema.ts, singleton `id:1` row, currently v22)
  is the correct target — not `GroupRow`. Found a pre-existing full `StatusEditor` UI + test
  scaffold (`ChatLayoutCustomStatus.test.tsx`, 12 tests, all passing against the React-state-only
  implementation) — confirmed the job was exactly "persist `customStatus` from
  `ChatLayout.tsx:6935` into `LocalIdentity`." No server API call, no MLS control-envelope type
  carries it (purely local, unlike `presence`).
- **What it does:** `LocalIdentity.customStatusEmoji?`/`customStatusText?` added (schema v23,
  encrypted at rest — real user-authored content, same tier as `GroupRow.nickname`/`description`,
  not a plain boolean preference). `EncryptedPowehiDb.setCustomStatus`/`getCustomStatus` follow the
  exact `setGroupNickname`/`getGroupNickname` pattern (partial `db.identity.update(1, {...})` inside
  an explicit `db.transaction("rw", ...)` with `Dexie.waitFor()` around the external encryptor
  call; no-op if the identity row doesn't exist yet). `ChatLayout.tsx`'s `handleSaveStatus` wraps
  the existing `setCustomStatus` React-state setter with a fire-and-forget
  `encryptedDb.setCustomStatus(status).catch(() => {})`; a new mount-time `useEffect` rehydrates
  via `getCustomStatus()`.
- **Regression caught and fixed before commit (self-caught, not present in the original diff's own
  tests as authored):** the rehydration effect's first version was gated only on `[encryptedDb]`
  (fires on every ChatLayout mount) — this broke 2/10 tests in the *unrelated*
  `ChatLayoutTimeGrouping.test.tsx` (off-by-one `msg-avatar` counts) purely from timing: it's the
  first unconditional read against the `identity` Dexie table at mount, and its underlying
  fake-indexeddb transaction interacts badly with that file's `vi.useFakeTimers()` +
  `vi.advanceTimersByTime()` calls (confirmed by bisection: commenting out just the new effect
  restored all 10 passes; confirmed the effect, not cross-file pollution, via running the file
  standalone both before and after). Fixed by gating on `[encryptedDb, deviceId]` (deviceId only
  set post-login via `useAuthStore`) — mirrors how the existing message-rehydration effect is
  scoped to a real chat's `mlsGroupId` rather than firing unconditionally on mount, and matches
  real app behavior (no point rehydrating identity-scoped state before a session exists). This in
  turn required seeding `useAuthStore.setState({ deviceId: ... })` in the new persistence tests'
  setup (moved a stray `useAuthStore.setState({ deviceId: null })` from `afterEach` to `beforeEach`
  along the way — the afterEach placement combined with `vi.restoreAllMocks()` running first was
  triggering a real-`useMessages`-on-a-still-mounted-component React hook-order crash, a second,
  independently-caught bug in the test scaffolding itself).
- **security-auditor: GREEN.** SENSITIVE classification confirmed correct (mechanically `encRow`
  only touches string fields anyway); Dexie's `update(id, {field: undefined})` genuinely deletes
  the property (verified against vendored Dexie source), no stale ciphertext left behind; no
  cross-user confusion risk (dbKey is per-user-derived from the OPAQUE export key, nulled on
  logout; a different user signing in on the same browser can't decrypt the prior user's blob —
  AEAD auth fails and the catch handler now fails closed); no plaintext logging; fire-and-forget
  write ordering is sound (IndexedDB serializes same-store `rw` transactions). Applied one
  non-blocking LOW finding: the rehydration effect's catch handler now explicitly
  `setCustomStatus(null)` on decrypt failure (fail closed) instead of leaving stale React state.
  Three informational notes left as-is (full-`put` in `setIdentity` could silently wipe status if
  a future caller reconstructs `LocalIdentity` from scratch — documented, not fixed; test mock's
  passthrough `encryptDbField` can't itself catch an encryption regression, already covered by
  `encrypted-db.test.ts`'s dedicated raw-row assertion; `presence.status` vs `customStatus` naming
  collision is a maintenance note only).
- Not architectural, no new server-visible metadata (purely local, same scoping as every
  GroupRow-field persistence cycle 323-332) — `threat-model-checker`/`crypto-reviewer` not
  required, consistent with precedent (this touches the encryption *wrapper*, not a crypto
  primitive).
- `tsc -b` clean, `biome check` clean (6 touched files, 1 auto-format applied to `encrypted-db.ts`).
  Frontend `pnpm test`/`npx vitest run`: **1404/1404 tests green** (104 files, was 1391 at cycle
  332 — net +13: 6 in `encrypted-db.test.ts`, 2 in `schema.test.ts` v23, and net +5 in
  `ChatLayoutCustomStatus.test.tsx`, was 12). Backend untouched (pure frontend/Dexie change,
  confirmed via `git diff --name-only`).
- `gh issue list --state open` — empty, nothing else to triage this cycle. Target dir hygiene not
  needed (STABILIZATION-only step, this was a FEATURE cycle).
- **Next cycle candidates:** the cycle-330 `db.messages.clear()`-missing-in-`beforeEach` sweep note
  (still outstanding, low priority); PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session
  threshold); opaque-ke live-migration login-round-trip regression test gap (cycle 318/319, no prod
  users yet, low urgency); the lru RUSTSEC-2026-0253 waiver re-verification trigger from cycle 333
  (only if `aws-sdk-s3` is ever bumped past 1.143.0 or S3 Express One Zone support is ever added to
  `powehi-r2`); `.claude/memory/project-context.md` file size — still climbing (now ~3450 lines),
  consider archiving cycles below ~300 at the next STABILIZATION cycle (335 or 340) if growth
  continues; **new this cycle** — the `ChatLayoutTimeGrouping.test.tsx` fragility this cycle
  surfaced (any future unconditional-on-mount Dexie read can silently break fake-timer-based tests
  elsewhere in the suite) is worth a documented pattern/rule if it recurs a second time, but not
  worth a dedicated cycle on its own yet — one occurrence, already fixed at the root (the
  `deviceId` gate) rather than papered over.

## Previous state (2026-08-22, cycle 333 — STABILIZATION (mode override): fix red CI on main, dependency advisories, commits de1976b + a013723)

- Counter said FEATURE (333 % 5 = 3), but `gh run list --limit 3` showed **CI — Rust red on
  main** (cycle 332's push) — per CLAUDE.md's mode-selection override, switched to
  STABILIZATION for this cycle instead of starting new feature work.
- Root cause: `cargo-deny`'s `advisories` check failed on **RUSTSEC-2026-0258** (h2 0.4.14,
  unbounded empty DATA frames without limit → unbounded memory/panic; low severity, transitive
  via `aws-smithy-http-client`/`hyper` 1.9.0). Fixed with `cargo update -p h2 --precise 0.4.16`
  (patched upstream). Verified `cargo build --workspace`, `cargo test --workspace` (all green),
  `cargo deny check advisories` → `advisories ok`. Committed + pushed alone first (de1976b) so
  CI would go green as fast as possible; confirmed green via `gh run list` before continuing.
- While in the neighborhood, ran `cargo audit` locally (not part of the failing job, but part of
  the STABILIZATION security sweep) and found **two advisories not yet in `.cargo/audit.toml`'s
  documented ignore list** (both `informational = "unsound"`, not `vulnerability` — this is why
  `cargo-deny` never flagged them; it only errors on the `vulnerability` category by default,
  confirmed via `cargo deny check advisories --format json` returning zero entries even with
  both crates compiled in):
  1. **RUSTSEC-2026-0221** (event-listener 5.4.1, `!Send` tag crosses thread boundary via
     `StackSlot`, transitive via `sqlx-core`) — cleanly fixed, no waiver needed:
     `cargo update -p event-listener --precise 5.4.2`.
  2. **RUSTSEC-2026-0253** (lru 0.16.4, potential UAF in `LruCache::pop()` if a stored key's
     `Drop` impl panics mid-pop) — **no upgrade path**: `aws-sdk-s3` 1.133.0 through the latest
     1.143.0 all pin `lru = "^0.16.3"` non-optionally (verified via
     `cargo update -p aws-sdk-s3 --precise 1.143.0`, which still resolved lru to 0.16.4; that
     speculative aws-sdk-s3 bump was reverted via `git checkout -- Cargo.lock` + a clean re-apply
     of just the event-listener update, to avoid unrelated dependency churn). Added a documented
     waiver to `.cargo/audit.toml` with the reachability trace: `cargo tree -i lru` confirms it
     IS compiled in (`lru -> aws-sdk-s3 -> powehi-r2 -> powehi-server`), but aws-sdk-s3 1.133.0's
     only `LruCache` use is the S3 Express One Zone session-credentials cache
     (`s3_express.rs`, keyed by a plain `CacheKey(String)` newtype, no custom `Drop`), and the SDK
     never calls `pop()` on it — only `get_or_insert_mut` — so the advisory's panic-during-pop
     precondition is structurally unreachable through that call path regardless of key type.
     Doubly unreachable because Powehi's R2 client uses `force_path_style` against Cloudflare R2
     and never touches S3 Express One Zone buckets. Also added a note to `deny.toml` explaining
     why this waiver doesn't need a mirror entry there (cargo-deny's vulnerability-only default
     policy). **security-auditor: reviewed the waiver draft, verdict "acceptable with two text
     fixes"** — flagged that the first draft's rationale ("Powehi's own key types are plain
     Strings/UUIDs") was a non-sequitur since Powehi types never enter that cache at all; the
     real argument is that `pop()` is simply never called on it. Rewrote the waiver using the
     agent's verified trace before committing (a013723).
- Verified: `.cargo/audit.toml`/`deny.toml` diff, `cargo build`/`cargo test --workspace` all green,
  `cargo audit` output empty (zero findings — both crates resolved) after this commit.
- `gh issue list --state open` — empty, nothing to triage.
- Target dir hygiene: was 27G (over 20G threshold) → pruned 0-byte `.rmeta` stubs + artifacts
  older than 7 days → down to 7.4G. Did not count as the cycle's mandatory commit (housekeeping
  only, per CLAUDE.md); the two dependency-fix commits above satisfy that requirement.
- Confirmed both pushes went green on `gh run list` (CI — Rust) before ending the cycle; did not
  wait for the slower CI — Live-backend E2E job (untouched dependency surface, no reason to
  expect it's affected, and it was already green pre-cycle).
- **Next cycle candidates (carried from cycle 332, none touched this cycle):** `customStatus`
  (user-global emoji+text status — needs fresh `LocalIdentity.customStatus` field + Explore-agent
  pass, not `GroupRow`/`MessageRow`-shaped like the run of fields fixed across cycles 323-332);
  cycle-330's `db.messages.clear()`-missing-in-`beforeEach` sweep note (still outstanding, low
  priority); PQ hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE
  PQ-hybrid OPRF upgrade (gated on ADR-0003 Phase B 95%-session threshold); opaque-ke
  live-migration login-round-trip regression test gap (cycle 318/319, no prod users yet, low
  urgency); `.claude/memory/project-context.md` file size — still climbing, consider archiving
  cycles below ~300 at the next STABILIZATION cycle (335 or 340) if growth continues; **re-verify
  the lru waiver** if `aws-sdk-s3` is ever bumped past 1.143.0 or if S3 Express One Zone bucket
  support is ever added to `powehi-r2` (re-run `grep -n "LruCache::pop\|get_or_insert_mut"` on the
  new `s3_express.rs`).

## Previous state (2026-07-21, cycle 332 — FEATURE: persist presence "last seen" timestamp to Dexie, commit 5d81862)

- `git status` at cycle start was **not clean** — a complete but uncommitted diff sat in the
  working tree (schema v22 `GroupRow.lastSeenAt`, `ChatLayout.tsx` presence-persist/rehydrate
  wiring, 5 new tests across `schema.test.ts`/`ChatLayout.test.tsx`), the same "cycle silently
  fails to commit" pattern flagged after cycles 324/325/326. Per CLAUDE.md's "investigate before
  deleting/overwriting uncommitted state" guidance, treated it as recoverable dropped work rather
  than discarding: the diff was coherent and well-commented, so validated and landed it instead of
  redoing it from scratch. `gh run list --limit 3` green, `gh issue list --state open` empty.
- **What it does:** `handleIncomingPresence` (`ChatLayout.tsx`) now also writes
  `db.groups.update(gId, { lastSeenAt: now.getTime() })` (fire-and-forget) on every online→offline
  transition (both the immediate path and the 90s auto-offline timer path). The chat-switch
  rehydration effect formats a persisted `row.lastSeenAt` as `HH:MM` and restores it as the
  `lastSeen` label — deliberately never restoring `online: true` from a stale DB row. Same bug
  class/shape as `archived`/`pinnedTop` (v18): a fully-wired UI feature whose Dexie write path was
  missing, `GroupRow`-shaped, plain non-sensitive field (same tier as `unread`/`pinnedMessageId`).
- **Two real bugs found and fixed before commit (self-caught during validation, not present in the
  original diff's own tests as authored):**
  1. Both new "persist" tests called `db.groups.update(...)` against a groupId that was never
     seeded into `db.groups` (the seed chats are in-memory-only `SEED_CHATS`, not Dexie rows) —
     `db.groups.update` silently no-ops on a missing row, same gotcha called out in nearly every
     prior persistence cycle's notes (326/327/328/329). First test failed outright
     (`lastSeenAt` stayed `undefined`). Fixed by seeding `db.groups.add({id, name, mlsStateB64,
     lastActivity})` before render, matching the established `ChatLayoutArchive.test.tsx`/
     `ChatLayoutPinTop.test.tsx` pattern exactly.
  2. The fake-timer test used `await vi.advanceTimersByTimeAsync(90_000)` then read Dexie
     immediately — this hung (5s test timeout), and because the timeout fired before the test's own
     trailing `vi.useRealTimers()` line ever ran, fake timers stayed active for the rest of the
     file, cascading into 34 more failures (a `beforeEach` `db.*.clear()` hook timeout, then every
     subsequent test in the file). Fixed by switching to non-async `vi.advanceTimersByTime` +
     `vi.useRealTimers()` immediately after (before the Dexie read, wrapped in `waitFor`) —
     mirrors the file's own pre-existing "online status automatically reverts to offline" test at
     line ~1879, which already uses this exact non-async pattern successfully. Full suite went from
     36 failed / 1355 passed to 0 failed / 1391 passed after both fixes.
- **security-auditor: GREEN, 2 low-severity non-blocking notes (fixed one, left one).** Independently
  verified: `lastSeenAt` correctly excluded from `SENSITIVE.groups` (reveals strictly less than the
  already-plaintext `lastActivity`; also noted `encRow`/`decRow` only encrypt `string`-typed fields,
  so listing a `number` field there would silently no-op regardless — the exclusion is the only
  option for this type, not just a policy choice); zero plaintext/PII logging (no `console.*`/
  telemetry in this file at all); grep-confirmed `lastSeenAt` never reaches any API client/
  WebSocket/MLS payload — purely local; `gId` in `handleIncomingPresence` comes from `useMessages`'
  own local `groupId` param (server-authenticated per-connection), not envelope-controlled, and
  presence arrives inside an MLS-decrypted, `env.group_id`-checked envelope — no cross-group-leak or
  spoofing lever, a peer can influence *when* a transition is recorded but not the persisted value
  (`Date.now()`, never peer-supplied). Two findings: (a) **fixed** — the `HH:MM` formatter only
  guarded `!== undefined`, so a corrupted non-numeric IndexedDB value would render "last seen
  NaN:NaN"; added `Number.isFinite(row.lastSeenAt)` to the guard, matching the sibling
  `TTL_OPTIONS.includes`/`SLOW_MODE_OPTIONS.includes` allowlist-validation pattern used by adjacent
  rehydration fields. (b) **not fixed, informational only** — a live offline event landing while the
  chat-switch `db.groups.get` is still in flight can have the resolved (older) `persistedLastSeen`
  clobber a fresher in-memory label; same class of same-session-only race already documented and
  accepted for `description`/`nickname` in cycles 327/328 (stale-older only, never shows false
  "online", not a security defect) — no action, parity with prior precedent.
- Not architectural, no new server-visible metadata, reuses the existing raw-field (non-crypto)
  persistence mechanism — `threat-model-checker`/`crypto-reviewer` not required, same scoping as the
  `archived`/`pinnedTop`/`slowModeDelay`/`starred` non-sensitive-field work in cycles 323-329.
- `tsc -b` clean, `biome check` clean (4 touched files). Frontend `pnpm test`/`npx vitest run`:
  **1391/1391 tests green** (104 files, was 1386 at cycle 329 — net +5: 2 in `schema.test.ts` v22
  raw round-trip + leaves-undefined, 3 in `ChatLayout.test.tsx`'s "user presence" describe block).
  Backend untouched (pure frontend/Dexie change, confirmed via `git diff --name-only`).
- **Next cycle candidates:** `customStatus` (user-global emoji+text status, the last remaining gap
  from cycle 326's original Explore-agent survey — needs a new `LocalIdentity.customStatus` field,
  not `GroupRow`/`MessageRow`-shaped like every field fixed across cycles 323-332, so likely needs a
  fresh Explore-agent pass); the cycle-330 `db.messages.clear()`-missing-in-beforeEach sweep note
  (still outstanding, low priority, was deferred at cycle 330 in favor of the media-ack fix); PQ
  hybrid Phase A (still blocked on openmls stable `MLS_128_MLKEM768`); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold); the still-standing opaque-ke live-migration
  login-round-trip regression test gap (cycle 318/319, no prod users yet, low urgency); consider
  whether the cron harness should be hardened against a cycle silently failing to commit — this is
  now the fourth occurrence (324, 326, and now presumably a cycle between 330-332) — a future
  STABILIZATION cycle could add a `git status --porcelain` check as literally the first action, before
  even reading memory, so recovery happens immediately rather than whenever the next cycle happens
  to notice; `.claude/memory/project-context.md` file size — climbing again, worth archiving older
  cycles (below ~cycle 300) at the next STABILIZATION cycle (335) if growth continues.

## Previous state (2026-07-21, cycle 330 — STABILIZATION: media download-ack timing fix, prd.md §9.4.3, commit 88d4a07)

- `git status` clean, CI green (`gh run list --limit 5`), `gh issue list --state open` empty at
  cycle start. `cargo audit`/`cargo deny check` both fully clean (no advisories beyond the already-
  documented, still-valid `.cargo/audit.toml`/`deny.toml` waivers — no new dependency work needed).
  Full backend (`cargo build/test/clippy/fmt --workspace`) and frontend (`pnpm test`/`tsc`/`biome`,
  1379/1379) were already green before touching anything. The memory-noted `powehi-telemetry`
  env-var-race flake candidate turned out to already be fixed (proper `ENV_TEST_MUTEX` + `EnvGuard`
  RAII pattern already in place, verified via 3 repeated `cargo test -p powehi-telemetry` runs) —
  do not re-pick that as a candidate, it's closed.
- **Picked the standing cycle-289 security-auditor advisory** ("ack-on-URL-grant not confirmed-
  transfer") instead — dispatched an Explore-style research agent first to verify the gap was still
  real (not fixed by an intervening cycle) and confirm it fit in one stabilization cycle before
  touching code; it was still open and exactly as described.
- **Root cause:** `MediaService::get_download_url` (crates/application/powehi-application/src/
  media_service.rs) recorded a recipient's GC ack (`media_repo.record_ack`) the instant a presigned
  download URL was granted — not once the recipient actually verified receipt. A failed/aborted
  transfer (network drop, client crash) could still count as acked; once every recipient appeared
  acked and the 30-day retention floor elapsed, `run_gc` could delete a blob a device never actually
  received. Bounded/non-exploitable (data-loss only, not confidentiality; the URL-fetch is re-
  callable before the floor expires) but a real gap.
- **Fix:** added `confirm_download` to the `MediaUseCase` port trait + `MediaService` (same
  uploader-or-group-member authorization predicate as `get_download_url`, verified via
  `GroupRepository::list_members` — uploader's own confirm is a no-op since `run_gc` never requires
  it). New `POST /v1/media/:id/confirm-download` handler/route (same `AuthenticatedDevice` extractor
  as every sibling media endpoint — no way to spoof another device's ack). `get_download_url` no
  longer writes the ack at all. Frontend: `mediaTransfer.ts`'s `downloadAndDecryptMedia` now fires
  `confirmMediaDownload` (new `app/src/api/media.ts` client fn) fire-and-forget (`.catch(() => {})`,
  not awaited) ONLY after `mediaDecryptWithHandle`/`mediaDecryptChunkedWithHandle` both succeed —
  i.e. blobHash verified + AES-GCM decrypt succeeded, the actual "transfer genuinely completed"
  signal. Single call site (only `downloadAndDecryptMedia` calls `getMediaDownloadUrl`; thumbnails
  are inline/no separate R2 fetch), so this stayed a single-cycle-sized fix as scoped up front.
- **security-auditor: GREEN.** No auth bypass (device_id always comes from the server-side
  `AuthenticatedDevice` session lookup, never client-supplied); confirmed a malicious-but-authorized
  group member acking without downloading can only forfeit their own future access (GC requires
  *all* non-uploader members acked, so one member's fake ack can't force deletion while any other
  honest member is still unacked) — and this capability already existed pre-fix via plain
  `get_download_url`, so no new griefing lever. `record_ack` is `ON CONFLICT DO NOTHING` (idempotent/
  replay-safe). No new unwrap()/expect(). Grepped for other callers of `get_download_url`'s old ack
  side-effect — none found (only call site was the REST handler; both frontend receive paths
  — `useMediaReceive.ts` and `ChatLayout.tsx`'s forward flow — go through the same shared
  `downloadAndDecryptMedia`).
- **threat-model-checker: YELLOW → resolved in-cycle.** No new metadata category or DB column
  (`media_acks(media_id, device_id)` unchanged) — only the *timing/meaning* of each row shifts from
  "URL was granted" to "recipient cryptographically verified genuine, complete plaintext". This is a
  genuine (not cosmetic) tightening of the §3.4 GC-timing read-receipt oracle: the known 404-after-
  retention-floor inference upgrades from "all members requested a URL" to "all members actually
  received working plaintext". Doc-corrected directly (agent has Read/Grep per its type, but the
  edit landed in the working tree regardless — verified via `git diff` before trusting the claim,
  per this project's memory-verification discipline): prd.md §3.3 (media_acks bullet, was line 182),
  §3.4 (GC-timing oracle paragraph, was line 203), §9.4.3 (GC ACK definition, was line 1280) all
  corrected from "ACK = URL 발급" to "ACK = confirm-download 호출 (blobHash+AES-GCM 검증 후)", plus a
  §16.7 changelog entry. Also fixed a stale doc comment in `crates/ports/powehi-port-outbound/src/
  media_repo.rs`'s `record_ack` doc and the `0008_media_acks.sql` migration header comment (both
  said "obtained a download URL" — now say "confirmed a verified download").
- 9 new backend tests (`media_service.rs`: `confirm_download_by_group_member_records_ack`,
  `_by_uploader_is_a_noop`, `_by_non_member_returns_unauthorized`, `_not_found_when_blob_missing`,
  plus the renamed `get_download_url_by_group_member_does_not_record_ack` asserting the OLD ack
  side-effect is gone; `lib.rs`: `confirm_download_returns_204` + added to the 401-without-token
  sweep) + 7 new frontend tests (`api/media.test.ts`: 3 for `confirmMediaDownload`;
  `mediaTransfer.test.ts`: 4 — confirms-after-chunked/non-chunked-decrypt, does-NOT-confirm-on-
  decrypt-failure, best-effort-doesn't-fail-receive-when-confirm-itself-rejects). Full backend
  (build/test/clippy/fmt, 124 application-crate tests + 140 rest-api-crate tests, was 120/139) and
  frontend (1386/1386, was 1379) green. Target dir hygiene: pruned 0-byte `.rmeta` stubs (24G→23G,
  still over the 20GB housekeeping threshold — not urgent, no action beyond the standard prune this
  cycle). **Next candidate:** none urgent from this change — the doc/timing gap is now fully closed.
  Standing candidates: the Y-4 PQ hybrid epoch-key-mixing gap (still blocked on openmls upstream,
  see ADR-0003 Phase B section below) or a fresh sweep for any newly-accumulated unwrap()/expect()
  in library code (last full sweep this cycle found only 4 pre-existing, already-justified
  instances — grpc client.rs:291, rest-api rate_limit.rs:72, opaque lib.rs:160, auth_service.rs:92 —
  none needing action).

## Current state (2026-07-21, cycle 329 — FEATURE: persist starred/bookmarked messages to Dexie, commit 265e9bb)

- `git status` clean, `gh run list --limit 3` all green at cycle start (cycle
  328's push), `gh issue list --state open` empty. Picked the top cycle-328
  next-cycle candidate: `starred` (message star/bookmark toggle) — verified
  the gap was still real myself (`grep -i starred` across `schema.ts`/
  `encrypted-db.ts`, zero hits) before touching anything.
- **Different shape from the last several cycles' `GroupRow` fields:**
  `starred` is `MessageRow`-shaped (per-message, not per-chat), confirmed via
  `ChatLayout.tsx`'s `handleStarMessage` (line 8323) which only ever did
  `setChats` — zero Dexie write — and the message-loading rehydration effect
  (line ~7322, the one that builds `ChatMessage`s from Dexie `MessageRow`s on
  chat mount/switch, already restoring `delivered`/`read`/`readBy`) which
  never read a `starred` field either. Same bug class as every previous
  cycle in this series: a shipped, fully-wired UI feature (star button,
  `StarredPanel`, aria-label toggle) missing only the Dexie write/read path.
- **Fix (self-implemented, mirrors the existing `delivered`/`read` v15
  pattern):** `MessageRow.starred?: boolean` (schema v21, additive, NOT
  sensitive — same tier as `delivered`/`read`, confirmed `SENSITIVE.messages`
  in `encrypted-db.ts` still `["ciphertextB64", "plaintextB64", "editedText",
  "reactionsJson"]` only). New `EncryptedPowehiDb.markMessageStarred(id,
  starred)` mirrors `markMessageDelivered` (raw `db.messages.update`, no
  read-then-merge needed — unlike `markMessageRead`'s `readByJson` union,
  `starred` has exactly one writer, no multi-device-race to close). New
  `usePersistentMessages.persistStarred` mirrors `persistDelivered` exactly
  (optimistic `setRows` + `pendingWriteIdsRef` + fire-and-forget). Wired
  `handleStarMessage` to also call `persistStarred(target.id, !target.starred)`
  computed from a pre-update `chatsRef.current` snapshot — same "recompute
  from pre-update snapshot" pattern as `handleIncomingReaction`, since
  `setChats` is async and its updater result isn't otherwise available here;
  only persisted when the message has a stable id (msgId can be undefined
  for an optimistic message not yet backfilled, same guard other message
  actions use). Rehydration effect now also copies `starred: row.starred`
  alongside the existing `delivered`/`read`/`readBy` fields.
- **security-auditor: GREEN, no findings.** Independently verified (not
  taken on the diff's own comments): `starred` correctly excluded from
  `SENSITIVE.messages` (reveals strictly less than the already-unencrypted
  `read` flag); zero plaintext/PII logging; grep confirmed `starred` never
  reaches `mlsEncrypt`/`sendMessageApi`/any API client or WebSocket payload
  (contrasted directly against `handlePinMessage`, which deliberately does
  send a wire signal, to confirm `handleStarMessage` correctly does not);
  the `chatsRef.current`-snapshot persist call can't produce a stale value
  under realistic interleavings (real click events force a React flush
  between them, refreshing `chatsRef` before the next click); raw
  `db.messages.update` (no merge) is correct since `starred` has a single
  writer, unlike `readByJson`'s multi-device merge case.
- Not architectural, no new server-visible metadata, reuses the existing
  raw-field (non-crypto) persistence mechanism — `threat-model-checker`/
  `crypto-reviewer` not required, same scoping as the `delivered`/`read`/
  `archived`/`pinnedTop` non-sensitive-boolean work in prior cycles.
- **One test-authoring bug caught and fixed before commit (self-caught, not
  agent-caused):** the first draft of the two new persistence tests in
  `ChatLayoutStarred.test.tsx` (persist-true, then persist-false) failed
  when run as part of the full file — but passed in isolation. Root cause:
  unlike ~10 sibling `ChatLayoutXxx.test.tsx` files (`ChatLayoutReactions`,
  `ChatLayoutCopy`, `ChatLayoutForwarding`, etc.), `ChatLayoutStarred.test.tsx`
  had never had a `db.messages.clear()` in its `beforeEach` — only
  `db.verifiedContacts.clear()`. Since Dexie/fake-indexeddb's `db` singleton
  persists across tests within a file, earlier tests' incoming messages
  accumulated in Maya's chat, and my new tests' `bubbles[bubbles.length - 1]`
  lookup no longer reliably pointed at the just-added message once enough
  prior-test messages had piled up. Added the standard `await
  db.messages.clear()` line to this file's `beforeEach` (bringing it in line
  with its ~10 sibling files) — fixed, full suite green afterward.
- 8 new tests: 2 in `schema.test.ts` (v21 raw round-trip + leaves-undefined),
  4 in `encrypted-db.test.ts` (sets starred:true, toggles back to false
  — unlike the one-way `delivered`/`read` flags, no-op-on-missing-row), 1 in
  `ChatLayout.test.tsx` (rehydrates a persisted starred flag on mount — the
  message-loading-path rehydration effect, not the group-rehydration effect
  used by the last several cycles' `GroupRow` fixes), 2 in
  `ChatLayoutStarred.test.tsx` (persist-on-star / persist-on-unstar round-trip
  through `db.messages.get`). `tsc -b` clean, `biome check` clean (8 touched
  files). Frontend `pnpm test --run` (via `npx vitest run`): **1379/1379
  tests green** (104 files, was 1371, net +8). Backend untouched this cycle
  (pure frontend/Dexie change, confirmed via `git diff --name-only`).
- **Next cycle candidates:** `customStatus` (user-global emoji+text status,
  the last remaining gap from cycle 326's Explore-agent survey — would need
  a new `LocalIdentity.customStatus` field, not `GroupRow`/`MessageRow`-
  shaped like the six fields fixed across cycles 326-329, so likely needs a
  fresh Explore-agent pass to confirm exact React-state shape and call
  sites rather than reusing the same survey); the informational
  rehydration-race note from cycles 327/328 (very low priority, cosmetic
  same-session-only race affecting `description`/`nickname`); the
  `db.messages.clear()`-missing-in-beforeEach class of bug this cycle just
  hit in `ChatLayoutStarred.test.tsx` — worth a quick grep sweep at the next
  STABILIZATION cycle (330) across all `ChatLayoutXxx.test.tsx` files for
  any other file missing this clear that happens to not yet have a test
  order-dependent enough to expose it; PQ hybrid Phase A (still blocked on
  openmls stable `MLS_128_MLKEM768` — this environment has no network access
  to re-check crates.io this cycle either); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold, not yet actionable); the
  still-standing opaque-ke live-migration login-round-trip regression test
  gap (cycle 318/319, no prod users yet, low urgency); `.claude/memory/
  project-context.md` file size (~245KB after this entry, was ~237KB at
  cycle 328) — still under the 256KB Read cap but climbing; the next
  STABILIZATION cycle (330) should archive older cycles if the growth rate
  continues, same standing note as cycles 326-328.

## Previous state (2026-07-21, cycle 328 — FEATURE: persist per-DM nickname to Dexie, encrypted at rest, commit eeddf54)

- `git status` clean, `gh run list --limit 3` all green at cycle start (cycle
  327's push), `gh issue list --state open` empty. Picked the top cycle-327
  next-cycle candidate: `nickname` (per-DM custom display name editor) —
  verified the gap was still real myself (`grep -i nickname` across
  `schema.ts`/`encrypted-db.ts`, zero hits) before delegating an Explore
  agent to nail down exact state shape and line numbers.
- **Key finding that changed the plan slightly:** cycle 327's note guessed
  `nickname` "likely also SENSITIVE-tier like description" — confirmed true,
  but also found it's **DM-only** (InfoPanel gate `!chat.isGroup &&
  onUpdateNickname`, line 5246), unlike `description` which is group-only.
  Despite that semantic difference, the persistence *mechanism* is
  identical: DMs get a `GroupRow` in `db.groups` keyed by `mlsGroupId` just
  like multi-member groups (MLS treats a 1:1 conversation as a 2-member
  group), so no new table/keying scheme was needed — confirmed via
  `SEED_CHATS`'s Maya entry (`mlsGroupId: "1111...1111"`) and the existing
  `archived`/`pinnedTop`/`muted` fields already working identically for both
  DMs and groups.
- Also found `ChatLayoutNickname.test.tsx` already existed (14 UI-only
  tests: edit/save/cancel/Escape/Enter, ConversationHeader/QuickSwitcher
  display) but zero Dexie persistence assertions — same "feature shipped,
  Dexie write path missing" bug class as cycles 312/314/321/323/326/327.
- **Fix (self-implemented, byte-for-byte mirror of cycle 327's `description`
  v19 pattern):** `GroupRow.nickname?: string` (schema v20, additive, added
  to `SENSITIVE.groups` alongside `mlsStateB64`/`name`/`draft`/
  `description`). New `EncryptedPowehiDb.setGroupNickname`/`getGroupNickname`
  are an exact mirror of `setGroupDescription`/`getGroupDescription` (same
  `Dexie.waitFor` + explicit-transaction pattern, same partial
  `db.groups.update` so sibling fields are untouched). `handleUpdateNickname`
  now also calls `encryptedDb.setGroupNickname(...)` fire-and-forget
  (`.catch(() => {})`) alongside its existing `setChats` update. Rehydration
  added to the same effect used by `draft`/`description`, decrypting
  `row.nickname` from the already-fetched `row` and merging via `setChats`
  keyed by `mlsGroupId`.
- **security-auditor: GREEN.** Independently verified: `nickname` correctly
  reaches `SENSITIVE.groups` so both the dedicated methods AND the generic
  `encRow`/`decRow` helpers encrypt it; zero plaintext logging; the
  `Dexie.waitFor` + explicit-transaction pattern is safe against
  sibling-field corruption (partial merge); grep confirmed `nickname` never
  reaches any API client/WebSocket/MLS payload; rehydration decrypt failure
  is fail-safe. One informational note (pre-existing pattern, not introduced
  this cycle, inherited verbatim from `description`): the rehydration
  unconditionally overwrites `{ ...c, nickname }` rather than using `draft`'s
  "only fill if not already present" guard — a transient same-session race
  (in-flight decrypt clobbering a same-chat edit that landed after the fetch
  started), not a security defect, since the DB write itself is always
  correct. No action taken — parity with the shipped `description` behavior.
- Not architectural, no new server-visible metadata, reuses the existing
  `FieldEncryptor` mechanism — `threat-model-checker`/`crypto-reviewer` not
  required, same scoping cycle 327 used for `description`.
- 9 new tests: 2 in `schema.test.ts` (v20 raw round-trip + leaves-undefined),
  5 in `encrypted-db.test.ts` (unknown-group-undefined, persist-and-read-back,
  clear-via-undefined, sibling-fields-undisturbed, raw-DB-stores-ciphertext),
  2 new persistence tests appended to the pre-existing
  `ChatLayoutNickname.test.tsx` (persist-on-save round-trips through
  `db.groups.get` for Maya's seed `mlsGroupId`, rehydrate-on-chat-switch
  restores the nickname text from a pre-seeded row — same
  `db.groups.clear()` + `.add()` pre-seed gotcha every prior persistence
  cycle's tests hit, since `db.groups.update` silently no-ops on a missing
  row). `tsc -b` clean, `biome check` clean across all 149 `app/src` files
  (2 files needed `--write` auto-format on tab/wrap-style, applied). Frontend
  `pnpm test --run`: **1371/1371 tests green** (104 files, was 1362, net +9).
  Backend untouched this cycle (pure frontend/Dexie change, confirmed via
  `git diff --name-only`).
- **Next cycle candidates:** the remaining two gaps from cycle 326's
  Explore-agent survey — `starred` (`MessageRow`-shaped, star/bookmark on
  messages — needs a `MessageRow.starred` field + rehydration in the
  message-loading path, not the group-rehydration effect used by this and
  the last several cycles' fixes) and `customStatus` (user-global emoji+text
  status, would need a new `LocalIdentity.customStatus` field, not
  `GroupRow`-shaped like the other five fixed so far) — both still real
  gaps, ranked in that order; the informational rehydration-race note above
  (very low priority, cosmetic same-session-only race, affects both
  `description` and now `nickname` — not worth a dedicated cycle unless it
  recurs in user reports); PQ hybrid Phase A (still blocked on openmls
  stable `MLS_128_MLKEM768` — this environment has no network access to
  re-check crates.io this cycle either); OPAQUE PQ-hybrid OPRF upgrade
  (gated on ADR-0003 Phase B 95%-session threshold, not yet actionable); the
  still-standing opaque-ke live-migration login-round-trip regression test
  gap (cycle 318/319, no prod users yet, low urgency); `.claude/memory/
  project-context.md` file size (~237KB after this entry, was ~230KB at
  cycle 327) — still under the 256KB Read cap but climbing; the next
  STABILIZATION cycle (330) should archive older cycles if the growth rate
  continues, same standing note as cycles 326/327.

## Previous state (2026-07-20, cycle 327 — FEATURE: persist group description to Dexie, encrypted at rest, commit 3a56944)

- `git status` clean, `gh run list --limit 3` all green at cycle start (cycle
  326's push), `gh issue list --state open` empty. Picked the top cycle-326
  next-cycle candidate: `description` (`Chat.description`/group topic editor)
  — verified the gap was still real myself (grep `description` across
  `schema.ts`/`encrypted-db.ts`, zero hits) before delegating an Explore agent
  to nail down exact line numbers (`handleUpdateGroupDescription` at line
  8378 only touched React state, no Dexie write; rehydration effect at
  7444-7532 never read/applied it either) — agent's findings matched my own
  spot-check exactly.
- **Key difference from the last several cycles' persistence work (archived/
  pinnedTop/slowModeDelay, all plain non-sensitive booleans via raw
  `db.groups.update`):** `description` is real user-authored content
  describing the group — same sensitivity tier as `name`/`draft`, not a UI
  preference. Checked `SENSITIVE.groups` in `encrypted-db.ts` first to
  confirm this distinction before writing any code, rather than defaulting
  to the raw-write pattern out of habit.
- **Fix (self-implemented, mirrors the existing `draft` v17 pattern
  exactly):** `GroupRow.description?: string` (schema v19, additive, added to
  `SENSITIVE.groups` alongside `mlsStateB64`/`name`/`draft`). New
  `EncryptedPowehiDb.setGroupDescription`/`getGroupDescription` methods are a
  byte-for-byte mirror of `setGroupDraft`/`getGroupDraft` (same
  `Dexie.waitFor` + `this.db.transaction("rw", this.db.groups, ...)` pattern
  for the encrypt-then-write, same partial `db.groups.update` so
  `mlsStateB64`/`name`/`draft` are never touched). `handleUpdateGroupDescription`
  now also calls `encryptedDb.setGroupDescription(...)` fire-and-forget
  (`.catch(() => {})`) alongside its existing `setChats` update — no
  debounce needed (explicit Save-button action, not per-keystroke, unlike
  `handleDraftChange`). Rehydration added to the existing "load persisted
  disappearing timer/mute/archived/pinnedTop/draft" effect: decrypts
  `row.description` via `cryptoWorker.decryptDbField` from the
  already-fetched `row` (same race-avoidance rationale as the adjacent
  `draft` rehydration — no second concurrent `db.groups.get`), applies via
  `setChats` keyed by `mlsGroupId`.
- **security-auditor: GREEN, no findings.** Independently verified (not
  taken on the diff's own comments): `description` correctly reaches
  `SENSITIVE.groups` so both the dedicated methods AND the generic
  `encRow`/`decRow` helpers (used by `addGroup`/`getGroup`) encrypt it — not
  just the new methods; zero `console.*`/logger/telemetry references;
  the `Dexie.waitFor` + explicit-transaction pattern (identical to the
  already-shipped `draft` one) is safe against sibling-field corruption
  under concurrent writes (partial merge, not a full-row overwrite); grep
  confirmed `description` never reaches any API client/WebSocket/MLS
  payload — purely local like `draft`; rehydration decrypt failure is
  fail-safe (`.catch(() => {})`, ciphertext never assigned to chat state,
  no oracle/crash).
- Not architectural, no new server-visible metadata, reuses the existing
  `FieldEncryptor` mechanism (no new crypto primitive) — `threat-model-checker`/
  `crypto-reviewer` not required, same scoping rationale cycle 325 used for
  the `draft` field (would be required only if this introduced a new
  encryption scheme, which it doesn't).
- 9 new tests: 2 in `schema.test.ts` (raw store round-trip + leaves-undefined,
  v19 pattern), 5 in `encrypted-db.test.ts` (unknown-group-undefined,
  persist-and-read-back, clear-via-undefined, sibling-fields-undisturbed,
  raw-DB-stores-ciphertext-not-plaintext — mirrors the 5 existing `draft`
  tests exactly), 2 in `ChatLayoutGroupDescription.test.tsx` (persist-on-save
  round-trips through `db.groups.get` — had to pre-seed a `db.groups` row for
  the Design Team seed chat first since `db.groups.update` silently no-ops
  on a missing row, same gotcha every prior persistence cycle's tests hit;
  rehydrate-on-chat-switch restores the description text from a pre-seeded
  row). `tsc -b` clean, `biome check` clean (6 touched files). Frontend
  `pnpm test --run`: **1362/1362 tests green** (104 files, was 1353, net +9).
  Backend untouched this cycle (pure frontend/Dexie change, confirmed via
  `git diff --name-only`).
- **Next cycle candidates:** the remaining three gaps from cycle 326's
  Explore-agent survey — `nickname` (per-DM nickname editor, likely also
  SENSITIVE-tier like description since it's user-authored text, not a
  boolean/enum preference), `starred` (`MessageRow`-shaped, star/bookmark on
  messages — needs a `MessageRow.starred` field + rehydration in the
  message-loading path, not the group-rehydration effect used by this
  cycle's fix), and `customStatus` (user-global emoji+text status, would
  need a new `LocalIdentity.customStatus` field, not `GroupRow`-shaped like
  the other four) — all still real gaps, ranked in that order; PQ hybrid
  Phase A (still blocked on openmls stable `MLS_128_MLKEM768` — this
  environment has no network access to re-check crates.io this cycle either,
  confirmed via failed `curl`, same as cycle 326); OPAQUE PQ-hybrid OPRF
  upgrade (gated on ADR-0003 Phase B 95%-session threshold, not yet
  actionable); the still-standing opaque-ke live-migration login-round-trip
  regression test gap (cycle 318/319, no prod users yet, low urgency);
  `.claude/memory/project-context.md` file size (~230KB after this entry,
  was ~222KB at cycle 326) — still under the 256KB Read cap but climbing;
  the next STABILIZATION cycle (330) should archive older cycles if the
  growth rate continues, same standing note as cycle 326.

## Previous state (2026-07-20, cycle 326 — FEATURE: persist chat archived/pinnedTop flags to Dexie, commit a42849b)

- `git status` at cycle start was **not clean**: cycle 325's own memory-update
  chore commit had never landed (its `project-context.md` edit sat uncommitted
  while the feature commit `c1ab6d5` it documented did land) — this is the
  same "cycle silently fails to commit" pattern flagged as a watch-item at the
  end of cycle 325's entry. Committed it first as `782f8eb` before starting
  this cycle's own work, so it doesn't compound a third time.
- `gh run list --limit 3` all green at cycle start (the cycle-325 draft-
  persistence push), `gh issue list --state open` empty. No unchecked `- [ ]`
  items remain in the phase checklist (all 6 phases complete, confirmed via
  grep) — same opportunistic-gap-finding mode as cycles 312-325.
- Delegated the survey to an Explore agent (grep `useState` near the top of
  `ChatLayout.tsx`, cross-reference against `GroupRow`/rehydration/persist
  call sites, rule out already-fixed fields): it surfaced **six** genuine
  candidates — `archived`, `pinnedTop`, `description`, `nickname` (all
  `Chat`/`GroupRow`-shaped), `starred` (`MessageRow`-shaped), and
  `customStatus` (user-global, not per-chat). Verified the top two myself
  before touching anything (`grep archived`/`pinnedTop` across
  `schema.ts`/`encrypted-db.ts` — zero hits, confirming no persistence
  existed) rather than taking the agent's word.
- **Picked `archived` + `pinnedTop` as one batch** (not all six) — same
  scope-discipline as every prior cycle in this series, but batched these two
  specifically because they're byte-identical-shape one-line boolean toggles
  sitting directly adjacent to each other in the handler block (mirrors the
  v12 precedent, which batched 5 fields — muted/sound/vibrate/
  notificationSoundId/chatTheme — into one version bump for the same reason).
  `description`/`nickname`/`starred`/`customStatus` are a different shape
  (string content, message-level, and user-global respectively) — left for
  future cycles, noted below.
- **Fix (self-implemented, small well-established pattern, no delegation
  needed):** added `GroupRow.archived?: boolean` and `GroupRow.pinnedTop?:
  boolean` (schema v18, additive, not sensitive — same tier as
  `muted`/`vibrate`, confirmed `SENSITIVE.groups` in `encrypted-db.ts` still
  `["mlsStateB64", "name", "draft"]` only). `handleToggleArchive`/
  `handleTogglePinTop` now call `db.groups.update(chat.mlsGroupId, {
  archived/pinnedTop: ... }).catch(() => {})` mirroring `handleToggleMute`/
  `handleToggleVibrate` exactly. Rehydration added to the existing "load
  persisted disappearing timer/mute/sound/vibrate/..." effect's `setChats`
  block, keyed by `mlsGroupId` like the sibling fields (only fires on
  chat-switch, not a full-list rehydrate on mount — same known limitation
  the muted/chatTheme fields already have, not a new gap introduced here).
  Also mirrored the pre-existing in-memory "incoming message auto-unarchives"
  rule (`archived: c.archived ? false : c.archived` at line ~7655) into the
  persisted `groupUpdate` object at the incoming-message handler's
  `db.groups.update(msg.groupId, groupUpdate)` call (same call that already
  persists `mentionCount`/`unread`/`firstUnreadMessageId`) — without this the
  persisted flag would go stale relative to the sidebar after an auto-
  unarchive, surviving a reload as "still archived" when the UI had already
  shown it unarchived.
- **security-auditor: GREEN, no findings.** Independently verified (not
  taken on the diff's own comments): both fields correctly excluded from
  `SENSITIVE.groups`, no plaintext logging/oracle/injection surface (plain
  booleans, only ever rendered as `?/:` conditionals), `db.groups.update`
  partial-merge + `.catch(() => {})` cannot corrupt sibling encrypted fields
  on write failure, the auto-unarchive-persisted-write is *safer* than the
  mentionCount/unread precedent it rides alongside (writes only the constant
  `false`, idempotent, monotonic toward unarchived — cannot produce an
  inconsistent intermediate the way a counter increment could), and grep
  confirmed `archived`/`pinnedTop` never reach any API client/WebSocket/MLS
  payload. Agreed threat-model-checker/crypto-reviewer scoping (not required)
  is correct — same class as the v12/v16 non-sensitive-boolean additions.
- Not architectural, no new server-visible metadata — `threat-model-checker`/
  `crypto-reviewer` not required, same scoping as chatTheme/muted/slowMode/
  draft persistence work in cycles 312-325.
- 6 new tests: 2 in `schema.test.ts` (store/retrieve both v18 fields, leave
  undefined when unset), 2 in `ChatLayoutArchive.test.tsx` (persist-on-toggle
  round-trips through `db.groups.get`, rehydrate-on-chat-switch restores
  "Unarchive Chat" label from a pre-seeded row), 2 in
  `ChatLayoutPinTop.test.tsx` (same pair for pinnedTop). Had to seed
  `db.groups` explicitly via `db.groups.clear()` + `.add()` before each
  persistence test — confirmed (same as the existing mute/slowMode
  persistence tests) that `db.groups` starts empty in tests; the initial
  sidebar list comes from the in-memory `SEED_CHATS` constant, not a Dexie
  read, so a toggle handler's `db.groups.update()` on an unseeded row would
  silently no-op rather than error. `tsc -b` clean, `biome check` clean (5
  touched files). Frontend `pnpm test --run`: **1353/1353 tests green** (104
  files, was 1347, net +6). Backend untouched this cycle (pure
  frontend/Dexie change, confirmed via `git diff --name-only`).
- **Next cycle candidates:** the remaining four gaps from this cycle's
  Explore-agent survey — `description` (`Chat.description`, group topic
  editor), `nickname` (per-DM nickname editor), `starred` (`MessageRow`-
  shaped, star/bookmark on messages — would need a `MessageRow.starred`
  field + rehydration in the message-loading path, not the group-rehydration
  effect), and `customStatus` (user-global emoji+text status, would need a
  new `LocalIdentity.customStatus` field, not `GroupRow`-shaped like the
  other five) — all confirmed real gaps, not yet fixed, ranked in that order
  by the survey; PQ hybrid Phase A (still blocked on openmls stable
  `MLS_128_MLKEM768` — this environment has no network access to re-check
  crates.io this cycle, confirmed via failed `curl`; a future cycle with
  network access should re-check); OPAQUE PQ-hybrid OPRF upgrade (gated on
  ADR-0003 Phase B 95%-session threshold, not yet actionable); the
  still-standing opaque-ke live-migration login-round-trip regression test
  gap (cycle 318/319, no prod users yet, low urgency); `.claude/memory/
  project-context.md` file size (~222KB / 2900+ lines after this entry, was
  216KB at cycle 325) — still under the 256KB Read cap but climbing again,
  worth archiving older cycles at the next STABILIZATION cycle (330) if the
  growth rate continues.

## Previous state (2026-07-20, cycle 325 — STABILIZATION: land orphaned draft-persistence work + full sweep, commit c1ab6d5)

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


## Archived history (cycles 20-277, 279-319, and legacy cycle-log entries)

> Cycles 20-277 were moved to `.claude/memory/archive/project-context-cycles-20-277.md` in
> cycle 320 (2026-07-19 STABILIZATION). Cycles 279-319, plus the old non-chronological
> "Cycle log (recent)" section (cycles 215-262 and a stray 315 entry that cycle 320's pass
> missed), were moved to `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
> in cycle 340 (2026-08-23 STABILIZATION) — this file had grown back to ~3800 lines / 291KB,
> over the Read-tool 256KB cap, despite the cycle-320 pass. Only the last ~18 cycles are kept
> inline above. Read the archive files directly (with offset/limit) for older-cycle detail.

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

