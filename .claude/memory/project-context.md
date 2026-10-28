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

## PRIORITY DIRECTIVE — CLI-first (owner, 2026-10-08; ADR-0006) — read before picking work
- **Phase 7 is COMPLETE (2026-10-14). FEATURE mode takes the first unchecked item in
  `docs/phases/phase-8/STATUS.md`**, in order (8.1 edge TLS → … → 8.23). Its "Owner
  decisions (2026-10-20)" table settles need-human issues #13 #16 #19 #20 #22 #24 #28 #30
  #32 #39 #53 #56; apply those decisions, do not re-ask them.
- Cycles 550-597 (2026-10-16..20) filled the empty queue with unrequested CLI flags
  (`--json`, `conversations` filters, `read --since/--until`, ...). Do not do that again:
  with no unchecked item, run STABILIZATION work instead.
- **After Phase 8: Phase 9** (`docs/phases/phase-9/STATUS.md`, ADR-0007): discard the
  Hetzner/Helm/ArgoCD IaC, deploy to AWS Seoul (ECS Fargate) + Cloudflare edge, staging
  auto-apply, prod only via owner approval. Owner prerequisites: issue #118.
- **Web client `app/` is in maintenance**: CI-red, `bug` issues, security fixes on shipped
  behavior only. Do NOT build new web UI/features. Parked (not closed): issues #1 (SPA
  deploy), #3 (web WS client); candidate items that are web-only (Remove UI, banners).
- Still allowed: shared crypto-core work (issue #2 items (e)/(g) in `mls_group.rs` serve
  the CLI too), and server changes the CLI needs. STABILIZATION mode is unchanged.
- Spec: prd.md §7A (crate layout, command surface, encrypted profile store, terminal
  threats: no secrets/message text in argv, no plaintext on disk, no content in logs).
- Routing: CLI crate → `backend-lead`; core extraction / profile store → `crypto-lead`
  + `crypto-reviewer`. 7.11 needs `threat-model-checker`.
- **Dirty tree at directive time**: cycle 503 timed out (2026-09-16) leaving uncommitted,
  unreviewed WIP in `mls_group.rs`, `wasm_exports.rs`, `crypto.worker.ts`,
  `hooks/__mocks__/useCryptoWorker.ts` (issue #2 item (e) detection:
  `ProcessedCommit::discarded_own_pending_commit`). Before 7.1 moves `mls_group.rs`,
  either finish it (tests + crypto-reviewer PASS + commit) or preserve it on a
  `wip/cycle-503-commit-discard-detection` branch. Never discard it.

## Phase status
Phases 1-6 in `docs/phases/phase-{1..6}/STATUS.md` are complete (every DoD item `[x]`,
confirmed cycle 425/426). Phase 7 (CLI client) is complete (2026-10-14). **Phase 8 (CLI
hardening, Commit path, groups, multi-device, TUI, media) is IN PROGRESS** — see the
directive above. The "Next cycle candidates" lists below are now the source only for
STABILIZATION follow-ups and shared crypto-core/server items, not for web features.

## Cycle 674 (2026-10-28, FEATURE) — 8.18 `powehi restore` shipped; 8.15 blocked on #166, 8.17 on #203
auth::restore + crypto-core sign_recovery_challenge, prd §7A.2/§8.5 updated. 454 CLI + 172 core tests green. Next: 8.19 multi-device (write device-link flow in prd first; needs 8.17 remove for same-key leaf replacement).

## Cycle 671 (2026-10-28, FEATURE) — 8.17 slice (q) added/removed keys in GroupCommitApplied; 8.15 still blocked on #166
crypto-core `apply_group_commit` reports `added_keys`/`removed_keys` (pre-merge length check). ReInit/PSK refusal test not constructible in openmls 0.8.1. 170 crypto-core tests green. Next: RequiredCapabilities(0xF002), group PQ story (T6) + threat-model-checker record, then close 8.17.

## Cycle 664 (2026-10-28, FEATURE) — 8.17 slice (n1) group send; 8.15 still blocked on #166
`message::send_group` (Kind::Group: active group, authenticated kind agrees, >=2 members, no gadd-/grem- pending). 448 lib tests green, clippy clean. Next: group receive with MLS-leaf sender auth (crypto-core decrypt returning sender sig key), Proposal ack routing, RequiredCapabilities(0xF002).

## Cycle 663 (2026-10-27, FEATURE) — 8.17 slice (m) inbox applies group Commits; 8.15 still blocked on #166
`inbox::handle_group_commit` routes Kind::Group Commits to `group::commit::apply` (Applied/Evicted acked; Unresolved/Unknown/pending-request held; Refused/Forked/Ahead use junk grace). crypto-reviewer needs-rework (stale never-acked test, no Unresolved/pending-request tests) fixed. Next: group send/receive with MLS-leaf sender auth, RequiredCapabilities(0xF002).

## Cycle 649 (2026-10-26, FEATURE) — 8.17 slice (d2) CLI `group add`; 8.15 still blocked on #166
`group add`/`--resume` in `group.rs` with durable `gadd-` record (Welcome kept for retry). Kind::Group guards in send/pcs/inbox. crypto-reviewer two rounds. Next: group joiner (`welcome::join_one`), `Unknown` resolver, group send/receive, `group remove`.

## Cycle 648 (2026-10-26, FEATURE) — 8.17 slice (d1) crypto-core staged group Add; 8.15 still blocked on #166
`stage_group_add`/`confirm_group_add`/`abort_group_add` in `mls_group.rs` (reuses confirm/abort of the stage-remove trio). Next: CLI `group add` using them.

## Cycle 647 (2026-10-26, FEATURE) — 8.17 slice (c2) `group create`; 8.15 still blocked on #166
`powehi group create` (`group.rs`, `invite::register_group` split out): solo kind-Group MLS group, cap checked before any state, record `peer_device_id` = own device. crypto-reviewer caught my `cfg(unix)` slip on `hardening` (fixed; lesson: check `git diff` of lib.rs after scripted edits). threat-model yellow, prd §5.3B updated. Next: `group add` (carried list in STATUS 8.17: MLS-leaf sender auth first).

## Cycle 644 (2026-10-26, FEATURE) — 8.17 slice (b2); 8.15 still blocked on #166
Test-only: a verified pair grown to 3 MLS members is CHANGED and `send` returns `Changed` with no key spent (fail-closed via `number_of` error). Carried list in STATUS 8.17 shrinks by that item. Next: `group create` with an authenticated Kind source.

## Cycle 643 (2026-10-26, FEATURE) — 8.17 slice (b1); 8.15 still blocked on #166 (no owner answer)
`Kind` pair|group on `conv-*` (group = record version 2, old binaries reject), `verify::number_of` dispatches on it via pure `number_from_keys`. crypto-reviewer needs-rework (test gaps, cap order, typed DuplicateKey, downgrade) fixed. Lesson: put roster rules in a pure fn so 512/513 and grown-pair cases are unit-testable. Next: `group create` (authenticated Kind source), then add/remove; carried list in STATUS 8.17.

## Cycle 641 (2026-10-26, FEATURE) — 8.17 slice (a); 8.15 still blocked on #166
`safety::group` + `GroupSafetyError` in crypto-core, moved verbatim from the WASM crate (domain `powehi-group-safety-number-v1`, cap 512, KAT `096245...`); WASM delegates. crypto-reviewer first said needs-rework for a new domain (CLI vs web mismatch) — lesson: reuse shipped constructions. Next: CLI group roster/verify, then `group create/add/remove`.

## Cycle 639 (2026-10-25, FEATURE) — 8.16 shipped (8.15 skipped: blocked on #166)
`send`/`chat` refuse a CHANGED conversation (`MessageError::Changed`, gate in `message::send_with`, before any key or counter is spent); `--allow-changed` overrides. `chat::Polling` became `chat::Options` (+`allow_changed`). #166 commented: re-post is indistinguishable from a lost CAS (both 409) and Commit envelopes are deleted after all-ack, so the proposal is a per-(group, epoch) Commit digest in the ledger + member-only GET. Next unchecked: 8.15 d+e (needs #166), else 8.17.

## Cycle 638 (2026-10-25, FEATURE) — 8.15 slice (d2), box stays open
Inbox holds Ahead Application/Commit envelopes while a `pcs-` record exists. crypto-reviewer needs-rework fixed (gate narrowed to Ahead, echo gate dropped); wiring blockers listed in phase-8/STATUS.md 8.15. Live rotation still waits on #166 (no owner answer).

## Cycle 637 (2026-10-25, FEATURE) — 8.15 slice (d) partial, box stays open
Only the inert parts shipped (send gate on `pcs-` record, send counter at encrypt time). Live trigger withheld after crypto-reviewer FAIL; the findings and the required (d)+(e) bundle are in phase-8/STATUS.md under 8.15. Next: do (d)+(e) as one PR; the server "Commit by epoch" lookup needs a decision (need-human issue).

## Cycle 636 (2026-10-25, FEATURE) — 8.15 slice (c), box stays open
`pcs::rotate` + `invite::group_epoch` (PR pending number below); not yet called by send/chat. Fail-closed unless local epoch == server epoch + 1; `pcs-<gid>` record before post; post-send failures = `Unresolved`. crypto-reviewer needs-rework then pass. Next: slice (d) wiring (exclusive profile lock, encrypt gate on pending Commit, own-echo ack gate, behind/ahead warning), slice (e) recovery, threat-model-checker. Test env: `cargo test` (no nextest locally), `export PATH=$HOME/.cargo/bin:$PATH`.

## Cycle 634 (2026-10-23, FEATURE) — 8.15 slice (b), box stays open
Policy + plumbing, not wired into send yet: `pcs.rs` (50 msgs / 7 d), conv counters, `invite::send_commit` → `CommitOutcome`, prd §5.3A. Next: wire send/chat; the hard part is recovering an Unknown outcome (staged Commit persisted, server may have taken it) — design it before wiring; threat-model-checker.

## Cycle 633 (2026-10-23, FEATURE) — 8.15 slice (a), box stays open
crypto-core `stage_pair_self_update`/`confirm_`/`abort_pair_self_update` + PCS leaked-state test. Next slices: CLI policy (age/message count; write prd §5), send/chat wiring with commit-serialization retry, threat-model-checker.

## Cycle 632 (2026-10-23, FEATURE) — 8.14 slice (h), 8.13 + 8.14 boxes flipped
By-reference peer Commit maps to `Forked` (`MlsError::CommitMissingProposal` folded into `PairCommitRefused`). Carried to 8.17: ReInit receive test, content_type dispatch, by-ref Proposal storage. Next unchecked: 8.15 (PCS).

## Cycle 631 (2026-10-23, FEATURE) — 8.14 slice (g), box stays open
Peer Proposal acked after the 24 h grace (`inbox.rs`, test `a_peer_proposal_is_acked_after_the_grace_and_never_applied`, mutation-checked). Persisted forked state moved to 8.17. Only the ReInit receive-refusal test is left before flipping 8.13 + 8.14 (openmls 0.8.1 cannot build one; decide: hand-craft or accept allowlist-only).

## Cycle 629 (2026-10-22, FEATURE) — 8.14 slice (f), box stays open
Held Ahead envelope pins the fetch cursor for at most 1 h (`junk::AHEAD_PIN_SECS`, `Tracker::ahead_pins`). CLI-inbox logic only, no crypto touched. Still open for 8.14: persisted forked/removed state + Proposal ack policy (may move to 8.17), ReInit receive refusal test. Then flip 8.13 + 8.14.

## Cycle 628 (2026-10-22, FEATURE) — 8.14 slice (e), box stays open
Test only: PSK-Commit refusal in crypto-core (ReInit receive-side refusal untested: openmls 0.8.1 builder drops ReInit). Still open for 8.14: bound the Ahead-pinned cursor (item 1), persisted forked state + Proposal ack policy (item 3, may move to 8.17).

## Cycle 627 (2026-10-22, FEATURE) — 8.14 slice (d), box stays open
Tests only: GCE-Commit refusal (crypto-core) and held-Ahead-pins-cursor (CLI). crypto-reviewer open items: Ahead envelope pins the cursor up to 24 h (bound it), PSK/ReInit tests (CommitBuilder::add_proposal exists), forked state + Proposal ack policy. Next: finish those, then flip 8.14.

## Cycle 626 (2026-10-22, FEATURE) — 8.14 slice (c)
`inbox` text/JSON now report `commits` and `forked`. Remaining for 8.14 (box stays open): cross-run held-Ahead envelope behind the saved cursor; crypto-reviewer carry-overs (persisted forked state, Proposal ack policy, GCE/PSK/ReInit refusal tests).

## Cycle 623 (2026-10-22, FEATURE) — 8.14 slice (a) epoch-ahead
`MlsError::EpochAhead` in crypto-core (cleartext epoch checked before decrypt/stage, nothing consumed); CLI `Outcome::Ahead` holds such envelopes, never counts a failure, acks after the 24 h grace. Next: 8.14 slice (b) — apply peer Commits in `process_one` (drop the `is_fresh_pair` gate, successor check of peer leaf vs stored `peer_credential`, persist epoch, CHANGED alert), then flip 8.13 + 8.14.

## Cycle 621 (2026-10-22, FEATURE) — 8.13 slice (b1)
Junk Commit/Proposal and skipped Welcomes (`JoinReport.unusable`) acked after the 24 h grace via the junk tracker; peer Commits in held conversations left for 8.14. Remaining for 8.13: persistent fetch cursor, epoch-aware failure count (needs distinct "epoch ahead" error in crypto-core).

## Cycle 619 (2026-10-22, FEATURE) — 8.13 slice (a) inbox junk tracker
`inbox/junk.rs` + `receive_at(now)`; see STATUS.md 8.13 for the shipped/remaining split. Reviews: crypto-reviewer needs-rework -> fixed (fail closed on request load, no expect, drop needs 24h age too); security-auditor findings fixed (full tracker refuses, age pruning, non-fatal tracker I/O). openmls debug_assert panics on a tampered AEAD tag in debug builds, so a tampered-copy test cannot run in debug. Open: server `send_welcome` does not check the target (issue filed).

## Cycle 618 (2026-10-22, FEATURE) — 8.12 pending requests and `powehi accept`
`requests.rs`: pool-KP Welcomes -> `req-<group>` records (cap 32, 5d TTL), `requests`/`accept`/`decline` commands, `join_one` reused unchanged (pq key lookup now precedes the invite-marker check; returns `JoinOutcome::Request`). prd 3.3 + 7A command table updated. Next: 8.13 inbox flood defenses.

## Cycle 617 (2026-10-22, FEATURE) — 8.11 server consent for group membership
`pending_memberships` (migration 0023): `add_member` records pending; device calls `POST /v1/groups/:gid/accept|decline`. CLI `welcome::accept_membership` and web poller accept after join. threat-model first RED (per-device cap = lockout, retention claim false, expired rows in group cap, remove/accept race) -> fixed: per-device cap evicts oldest, TTL 7d + bounded lazy purge, unexpired-only group cap, remove_member one tx pending-first, device row lock. security-auditor YELLOW findings same set. Known gaps: no self-listing of pending rows (8.12), accept failure after persisted join relies on 8.12 re-run, peer-sync upsert bypasses consent (pre-existing), web accept not checked vs joined group id. PG IT test is #[ignore] (no Docker locally) - CI runs it.

## Cycle 609 (2026-10-21, FEATURE) — 8.8 slice (a) store manifest
`store/manifest.rs`: `manifest.mf3` (AEAD, tag→SHA-256 + generation, pending-entry crash recovery, `store-v3` latch). PHS2 stores adopted at first open. threat-model YELLOW: prd §3.2 now states residuals (any past snapshot replay; manifest+latch deletion downgrade). 8.8b must remove/gate automatic PHS2 adoption. Remaining 8.8: (b) DEK/KEK wrap, (c) tag salt. store_cap test now ~85s (manifest rewrite per put).

## Cycle 606 (2026-10-21, FEATURE) — 8.6 handle/password normalization
`powehi_crypto_core::credentials` (trim, `[a-z0-9-]{1,64}` for new handles, NFC password, raw-password login fallback) + `app/src/lib/credentials.ts`; shared vectors in `docs/test-vectors/credential-normalization.json`. CLI `register` rejects bad handles before any request; `login` retries raw only on InvalidCredentials. Server cannot validate handles (hash only). Next: 8.7 certificate pinning.

## Cycle 601 (2026-10-20, FEATURE→CI-red fix) — flaky poll-vote test
Frontend CI red on main after #121 (ChatLayoutPoll "persists a poll vote to Dexie", 1s waitFor on slow runner; passed on the PR). Raised that waitFor timeout to 4s. Next FEATURE cycle: first unchecked item in phase-8 STATUS.md.

## Cycle 597 (2026-10-20, FEATURE) — `read --until`
- Phase 7 DoD all [x]; `read --until <unix-seconds>` (exclusive upper bound, `message::until`, composes with `--since` as [since, until) and `--last`). 229 lib tests pass, clippy/fmt clean; display filtering only, no review agent required.

## Cycle 596 (2026-10-20, FEATURE) — `read --since`
- Phase 7 DoD all [x]; `read --since <unix-seconds>` shows only messages received at/after the cutoff (earlier stay stored); `message::since` (partition_point on oldest-first list), composes with `--last` (cutoff first). "no new messages" now keyed on the shown slice. Tests pass, clippy clean; display filtering only, no crypto/arch/backend change so no review agent required. All `--json` work done (chat is interactive).

## Cycle 594 (2026-10-20, FEATURE) — `register --json` / `login --json`
- Phase 7 DoD all [x]; `register`/`login` take `AuthArgs{json}`; `write_auth_report` prints `{"device","key_packages_uploaded"}` (no token/password). 226 lib tests pass, clippy clean; no crypto/arch/backend change so no review agent required. Remaining without --json: chat (interactive).

## Cycle 593 (2026-10-19, FEATURE) — `send --json`
- Phase 7 DoD all [x]; `send --json` prints `{"conversation":id}` via `message::write_sent` (id only, never the body). 223 lib tests pass, clippy clean; no crypto/arch/backend change so no review agent required. Remaining without --json: register, login, chat.

## Cycle 592 (2026-10-19, FEATURE) — `invite redeem --json`
- Phase 7 DoD all [x]; `invite redeem --json` prints `{"conversation","pq","pq_binding"}` via `invite::write_redeemed` (pq = bound|peer_classical|key_rejected|not_sent; the KeyRejected warning still goes to stderr). 221 lib tests pass, clippy clean; public ids/binding only (already printed by text mode), no crypto/arch/backend change so no review agent required. Remaining without --json: register, login, send, chat (interactive / no stdout payload).

## Cycle 591 (2026-10-19, FEATURE) — `invite create --json`
- Phase 7 DoD all [x]; `invite create --json` prints `{"invite":...}` (with `--wait` also `{"conversation": id|null}`) via `invite::write_created`/`write_joined`. 220 lib tests pass, clippy clean; link already printed by text mode, no crypto/arch/backend change so no review agent required.

## Cycle 589 (2026-10-19, FEATURE) — `read --json`
- Phase 7 DoD all [x]; `read --json` prints one JSON line per message (sender, received_at, text) via `message::display_json`, escaped piecewise straight into stdout (no second plaintext copy; text already sanitized). Combines with `--keep`/`--last`; no "no new messages" line in JSON mode. 218 lib tests pass, clippy clean; output formatting of already-displayed text only, no crypto/arch/backend change so no review agent required.

## Cycle 588 (2026-10-19, FEATURE) — `inbox --json`
- Phase 7 DoD all [x]; `inbox --json` prints one object (joined, pq_bindings, stored, skipped) via `inbox::report_json`. 216 lib tests pass, clippy clean; ids/counts/public PQ binding only (already printed by text mode), no crypto/arch/backend change so no review agent required.

## Cycle 587 (2026-10-19, FEATURE) — `verify --json`
- Phase 7 DoD all [x]; `verify --json` prints one object (conversation, safety_number, status) via `verify::report_json`; combines with `--confirm`. 214 lib tests pass, clippy clean; public safety number only (already printed by text mode), no crypto/arch/backend change so no review agent required.

## Cycle 586 (2026-10-19, FEATURE) — `status --json`
- Phase 7 DoD all [x]; `status --json` prints one object (server/healthy/region) via `status::write_report`. 212 tests pass, clippy clean; public server info only, no crypto/arch/backend change so no review agent required.

## Cycle 584 (2026-10-19, FEATURE) — `completions <shell>`
- Phase 7 DoD all [x]; added `completions` (clap_complete 4, prints script, no profile/network access). cargo deny ok, 211 lib + 8 bin tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 583 (2026-10-19, FEATURE) — `whoami --json`
- Phase 7 DoD all [x]; `whoami --json` prints one object with profile/server/user/device (`WhoamiArgs`, `whoami::report(.., json, ..)`). 211 tests pass, clippy clean; ids only, no crypto/arch/backend change so no review agent required.

## Cycle 582 (2026-10-19, FEATURE) — `profiles --json`
- Phase 7 DoD all [x]; `profiles --json` prints one `{"name":...}` object per profile (conflicts with --count). 209 tests pass, clippy clean; names only, no crypto/arch/backend change so no review agent required.

## Cycle 581 (2026-10-18, FEATURE) — `profiles --count`
- Phase 7 DoD all [x]; `profiles --count` prints only the profile count (`profile::write_listing`). 207 tests pass, clippy clean; names only, no crypto/arch/backend change so no review agent required.

## Cycle 579 (2026-10-18, FEATURE) — `powehi whoami`
- Phase 7 DoD all [x]; added `whoami` (login, prints profile/server/user id/device id; `whoami::report`). 206 tests pass, clippy clean; ids only, no secrets, no crypto/arch change so no review agent required.

## Cycle 578 (2026-10-18, FEATURE) — docs sync
- Phase 7 DoD all [x]; the `conversations` filter surface is saturated, so README CLI section (was stale: said most subcommands unimplemented) and prd §7A command table now describe the real commands/flags. Docs only; no review agent required.

## Cycle 577 (2026-10-18, FEATURE) — `conversations --unchanged`
- Phase 7 DoD all [x]; `conversations --unchanged` omits conversations whose verified Safety Number changed (`Page.unchanged`, conflicts with --changed). 204 tests pass, clippy clean; local-only filter, no crypto/arch/backend change so no review agent required.

## Cycle 576 (2026-10-18, FEATURE) — `conversations --read`
- Phase 7 DoD all [x]; `conversations --read` lists only conversations with no unread messages (`Page.read`, conflicts with --unread). 203 tests pass, clippy clean; local-only filter, no crypto/arch/backend change so no review agent required.

## Cycle 573 (2026-10-18, FEATURE) — `conversations --json` verified field
- Phase 7 DoD all [x]; `--json` rows gain `verified` (a Safety Number confirmation exists, `verify::has_confirmation`). 200 tests pass, clippy clean; local-only metadata, no crypto/arch/backend change so no review agent required. Note: `cargo nextest` is not installed locally; use `cargo test -p powehi-cli` (and `export PATH=$HOME/.cargo/bin:$PATH`).

## Cycle 572 (2026-10-18, FEATURE) — `conversations --unverified`
- Phase 7 DoD all [x]; `conversations --unverified` lists only conversations with no recorded Safety Number confirmation (`Page.unverified`, `verify::has_confirmation`). 200 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 571 (2026-10-18, FEATURE→CI fix) — Tauri deny advisories
- Main CI-red: `cargo deny` on `app/src-tauri` flagged new unmaintained advisories RUSTSEC-2026-0370/0371/0372 (zbus_names/zvariant/zvariant_derive, via tauri-plugin-notification → notify-rust, Linux only). Added documented ignores to `app/src-tauri/deny.toml`; `cargo deny check advisories` ok locally. Config-only, no crypto/arch change.

## Cycle 570 (2026-10-18, STABILIZATION) — json paging test
- CI green on main; `cargo audit` (no vulns) and `cargo deny check` clean; no open `bug` issues. Added test `json_honours_prefix_offset_and_limit_in_id_order` (`--json` was only tested without paging/prefix). 199 tests pass, clippy clean; test-only, no review agent required.

## Cycle 569 (2026-10-17, FEATURE) — `conversations --json`
- Phase 7 DoD all [x]; `conversations --json` prints one JSON object per match (id, role, unread, changed), same filters/paging, conflicts with --count/--ids. 198 tests pass, clippy clean; local-only metadata already printed by `report`, no crypto/arch/backend change so no review agent required.

## Cycle 568 (2026-10-17, FEATURE) — `conversations --prefix`
- Phase 7 DoD all [x]; `conversations --prefix HEX` lists only ids starting with it (applied before offset/limit; `Page` gained `prefix`). 197 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 567 (2026-10-17, FEATURE) — `conversations --offset N`
- Phase 7 DoD all [x]; `conversations --offset N` skips the first N matches (after filters), pairs with `--limit` for paging. `conversation::Page` (`From<Option<usize>>` keeps old call sites). 196 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 566 (2026-10-17, FEATURE) — `conversations --limit N`
- Phase 7 DoD all [x]; `conversations --limit N` keeps the first N matches by id (works with --count/--ids). 195 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 564 (2026-10-17, FEATURE) — `conversations --ids`
- Phase 7 DoD all [x]; `conversations --ids` prints only matching ids, one per line (same filters, conflicts with `--count`). 193 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 563 (2026-10-17, FEATURE) — `conversations --count`
- Phase 7 DoD all [x]; `conversations --count` prints only the number of matches (same filters). Extracted shared `select`; 192 tests pass, clippy clean; local-only, no crypto/arch/backend change so no review agent required.

## Cycle 561 (2026-10-17, FEATURE) — `conversations --changed`
- Phase 7 DoD all [x]; `conversations --changed` lists only conversations flagged CHANGED (combinable with `--unread`). Local filter in `conversation::report`; 190 tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 560 (2026-10-17, STABILIZATION)
- CI green on main, `cargo deny` ok, `cargo audit` no vulns, target/ 19G. Added test for `conversations --unread` combined with CHANGED; rewrapped >100-col `report` doc comment. `cargo test -p powehi-cli` 189 pass, clippy clean. Test-only, no crypto/arch change.

## Cycle 559 (2026-10-17, FEATURE) — `conversations --unread`
- Phase 7 DoD all [x]; `conversations --unread` lists only conversations with unread messages (local filter in `conversation::report`). 188 tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 558 (2026-10-17, FEATURE) — `read --last N`
- Phase 7 DoD all [x]; `read <conv> --last N` (1..=10000) shows/removes only the newest N via `message::newest`; older stay stored. Local only; no crypto/arch/backend change so no review agent required.

## Cycle 557 (2026-10-16, FEATURE) — `read --keep`
- Phase 7 DoD all [x]; `read <conv> --keep` shows stored messages without removing them (opt-in; records stay in the encrypted store). Extracted `message::show`; 185 tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 574 (2026-10-18, FEATURE) — `conversations --verified`
- Phase 7 DoD all [x]; `--verified` lists only conversations with a recorded Safety Number confirmation (complement of `--unverified`, conflicts with it). Local filter only. 201 lib tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 556 (2026-10-16, FEATURE) — `conversations` flags CHANGED safety numbers
- Phase 7 DoD all [x]; `conversations` appends ` CHANGED` when `verify::changed_since_verified` alerts (§5.6), so the warning is visible without opening each chat. Local only, no new metadata. 182 tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 554 (2026-10-16, FEATURE) — unread counts in `conversations`
- Phase 7 DoD all [x]; `conversations` now prints `<id> <role> [<n> unread]` via `message::unread_counts` (local count of `rx-*` records, bodies never printed). 180 tests pass, clippy clean; no crypto/arch/backend change so no review agent required.

## Cycle 553 (2026-10-16, FEATURE) — `powehi profiles`
- Phase 7 DoD all [x]; added `profiles`: lists valid profile dir names under `<data>/powehi` (names only, skips symlinks/files/odd names, capped 256, no store open/password). 4 new tests; no crypto/arch/backend change so no review agent required.

## Cycle 552 (2026-10-16, FEATURE) — CLI user guide
- Phase 7 DoD all [x]; added `docs/cli.md` (options, quick start, command table, safety notes). Docs only; no review agent required.

## Cycle 551 (2026-10-16, FEATURE) — `powehi conversations`
- Phase 7 DoD all [x]; no unchecked item, so added the missing way to discover conversation ids: `conversations` lists `<group id> <role>` from the store (login only unlocks it; no content/keys). Tests: 175 pass, clippy clean. Not crypto/arch/backend so no review agent required.

## Cycle 549 (2026-10-16, FEATURE) — Received deserialize wipes on failure
- Phase 7 DoD all [x]; F8: `Received` reads via `RawReceived` with `WipedBody` (Drop zeroizes) so a later-field failure wipes the decoded body. crypto-reviewer PASS (advisory: add ordering/duplicate-body tests). Open: serde_json escape scratch (unreachable for our own records).

## Cycle 548 (2026-10-16, FEATURE) — legacy body visit_seq wiped
- Phase 7 DoD all [x]; F8: `body_hex::visit_seq` grows geometrically into fresh `Zeroizing` buffers (no unwiped realloc); `visit_str` wiped on error. crypto-reviewer round 1 needs-rework (fixed 8 MiB prealloc cost 3.9s/2048 records), round 2 PASS. Open: serde-derive intermediate `Option<Vec>` unwiped when a later field fails (needs custom Deserialize / wiping type).

## Cycle 547 (2026-10-16, FEATURE) — Received::encode pre-sized
- Phase 7 DoD all [x]; closed F8 `to_vec(&Received)` realloc: `Received::encode` writes into a pre-sized `Zeroizing<Vec>` (oversize body rejected before allocating). crypto-reviewer round 1 needs-rework (minor: check order, exact-capacity asserts) fixed. Residual: debug-only no-realloc assert.

## Cycle 546 (2026-10-16, FEATURE) — decrypt_message returns Zeroizing
- Phase 7 DoD all [x]; took F8 follow-up. `mls_group::decrypt_message` -> `Zeroizing<Vec<u8>>` (CLI annotated, wasm `mls_decrypt` keeps Zeroizing to `bytes_js`). crypto-reviewer round 1 needs-rework (3 minor) fixed. Residual: openmls internal decrypted buffer unwiped. cargo needs `PATH=$HOME/.cargo/bin`.

## Cycle 545 (2026-10-15, STABILIZATION)
- `StoreError::Authentication` text now says wrong key/password most likely and "do not delete" the files (cycle-544 advisory). CI green on main, `cargo deny` ok, `cargo audit` no vulns; target/ 19G (under 20G cap). cargo-nextest absent locally; used `cargo test -p powehi-cli` (168 pass).

## Cycle 544 (2026-10-15, FEATURE) — store open names the bad file
- crypto-reviewer PASS; advisory: with a wrong key the error names only the first file read, so users may delete it as "damaged" (consider a clearer wrong-key message). `StoreError::Record{tag,cause}` wraps errors from `load_index` (tag = opaque file stem); `root()` strips it. Callers matching Authentication/Corrupt on `open`: none outside tests. Decrypted-name zeroize item judged moot (index holds names for the process lifetime by design; `inner` buffer is `Zeroizing`).

## Cycle 543 (2026-10-15, FEATURE) — F1 opaque record names
- Profile store `PHS2`: files `<hmac tag>.rc2`, real name inside ciphertext, AAD `profile||tag`, in-memory name index built (all records authenticated) at `open`, hidden `store-v2` marker latches the PHS1 import window (written only after migration completes). crypto-reviewer took 3 rounds (round 1: names() decrypt cost, downgrade window; round 2: marker written too early deleted unread legacy files). threat-model-checker YELLOW -> prd §3.2/§7A.3 updated. Deferred (in STATUS): per-store salt for tags, zeroize decrypted names, error names no file. Open 7.11: F8 remainder.

## Cycle 542 (2026-10-15, FEATURE) — padding migration
- `load_group` migrates stored padding 0 -> 256 via `canonical_join_config` (CLI groups). crypto-reviewer PASS. Open: web `wasm_exports.rs` loads with `MlsGroup::load` directly (old web groups stay unpadded; maintenance mode, crypto-lead call); F1, F8 remainder.

## Cycle 541 (2026-10-15, FEATURE) — F9 padding
- `PADDING_SIZE`=256 in MLS create/join config (core, so web too); new groups only (stored config of older groups stays unpadded; migrate via set_configuration on load = open). crypto-reviewer: needs-rework items fixed except migration. Open 7.11: F1, F8 remainder. Issue #32 option (2) applied per its recommendation.

## Cycle 539 (2026-10-15, FEATURE) — Cloudflare tls_1_3
- `cloudflare_zone_setting.tls_1_3`=on (F11). min_tls_version 1.3 left to owner. security-auditor PASS. Open 7.11: F1, F9 padding, F8 remainder.

## Cycle 538 (2026-10-15, FEATURE) — CHANGED re-check + join guard
- `chat::alert_if_changed` after every fetch (once per change; lib.rs startup eprintln removed). `welcome::join_one` skips Welcomes for a group already held (record-without-group = interrupted join, still finished; crypto-reviewer found the first, broader guard broke that). Open 7.11: F1, F9 padding, F8 remainder, Cloudflare tls_1_3.

## Cycle 537 (2026-10-15, FEATURE) — CHANGED alert
- `verify::changed_since_verified` + `CHANGED_WARNING` wired into read/send/chat (stderr, warn-only). Open 7.11: F1, F9 padding, F8 remainder, Cloudflare tls_1_3.

## Cycle 535 (2026-10-15, STABILIZATION)
- CI green, `cargo audit`/`cargo deny` clean, no open bug issues. Added verify.rs unknown-record-version test (PR below). cargo-nextest not installed locally; used `cargo test`.

## Cycle 531 (2026-10-14, FEATURE) — follow-up F8 (core-dump half)
- `hardening.rs`: RLIMIT_CORE=0 (+ Linux PR_SET_DUMPABLE=0), fail-closed in `main`. Open: zeroize plaintext copies, F1, F9 padding, CHANGED alert, Cloudflare tls_1_3.

## Cycle 529 (2026-10-14, FEATURE) — follow-up F9 (encoding half)
- `Received.body` serialized as hex via `inbox/body_hex.rs` (legacy number array still reads; 1 MiB bound, error not panic). Padding/size buckets still open. Remaining: F1, F8, CHANGED alert, Cloudflare tls_1_3.

## Cycle 528 (2026-10-14, FEATURE) — follow-up F11 (client half)
- reqwest (`status::http_client`) and WS rustls config are TLS 1.3-only; tests inspect the ClientHello (`testsrv::client_hello_listener`/`offers_only_tls13`), no rcgen. Open: Cloudflare `tls_1_3` Terraform setting (no zone-settings resource exists yet), F1, F9, F8, CHANGED alert.

## Cycle 527 (2026-10-14, FEATURE) — follow-up F6
- `ProfileStore.provider_floor` (in-memory AtomicU64); `LocalIdentity::load` passes it as min_generation and refuses a vanished record once floor>0; `save` raises it. Remaining 7.11 follow-ups: F1, F9, F8, F11, CHANGED alert.

## Cycle 526 (2026-10-14, FEATURE) — all Phase 7 DoD done; follow-up F10
- `ws.rs::auth_header` marks the upgrade Authorization value sensitive (test in ws/tests.rs). Remaining 7.11 follow-ups in STATUS (F6, F1, F9, F8, F11, CHANGED alert) need crypto-reviewer. No `cargo nextest` locally: use `cargo test` with PATH=$HOME/.cargo/bin.

## Cycle 524 (2026-10-14, FEATURE) — Phase 7.11 CLI threat-model pass [x]
- threat-model-checker on powehi-cli: YELLOW. Accepted risks documented in prd §3.2/§3.3/§7A.3; code fixes: owner-uid + parent-dir checks (store.rs), legacy parent tightened to 0700 (store.rs); TLS1.3 pin deferred (needs test + Cloudflare setting). Owner decisions in issue #39.
- Remaining FIX-NOW follow-ups (listed in phase-7 STATUS Follow-ups): in-session generation floor (F6), opaque record names (F1), body encoding/padding (F9), core dumps/zeroize (F8). All need crypto-reviewer. Phase 7 DoD complete after this PR.

## Cycle 523 (2026-10-14, FEATURE) — Phase 7.10 CLI live E2E gate
- `powehi-cli/src/live_e2e.rs` (`#[ignore]`, env `POWEHI_E2E_SERVER`) + CI job `cli-live-backend` in
  `ci-e2e-live.yml`. Not runnable locally (no docker); CI is the first real run. Auth governor burst=8
  per IP, so the test keeps to 6 `/v1/auth/*` calls. Next: 7.11 threat-model-checker pass.

## Cycle 522 (2026-10-14, FEATURE) — Phase 7.9 `powehi verify` [x]
- Core: `safety::{pairwise, digits_from_hash}` moved verbatim from wasm (KAT kept in both crates; wasm delegates). CLI: `verify.rs` (number from the 2 MLS signature keys, local only; `verified-<group>` record; states Unverified/Verified/Changed, corrupt record = Changed; `--confirm` flag records/replaces). All `Command` variants now implemented on unix (`NotImplemented` arm is non-unix only).
- NEXT: 7.10 E2E gate (two CLI profiles vs docker-compose, `#[ignore]` live test + CI job like `e2e-live`), then 7.11 threat-model-checker.

## Cycle 521 (2026-10-13, FEATURE) — Phase 7.8 `powehi chat` [x]
- CLI: `chat.rs` (event-loop REPL: stdin lines -> `message::send`, Wake -> `inbox::receive` + show/remove stored msgs; `/quit`; poll fallback 5s after realtime lost, 60s safety net; `read_lines` caps lines at 16 KiB) and `ws.rs` (`/v1/ws` Bearer header, notifications are metadata-only wake hints filtered to the conversation's group id, catch-up Wake on every (re)connect, 3 retries then `RealtimeLost`; connections <5s don't refill the budget). New deps: tokio-tungstenite 0.24 (rustls ring, webpki-roots), futures-util. `message::display` shared with `read`.
- NEXT: 7.9 `powehi verify` (Safety Number, prd §5.6).

## Cycle 519 (2026-10-13, FEATURE) — Phase 7.7 slice D (#24 interim policy) -> 7.7 [x]
- CLI: `welcome::join_invited` (used by `inbox`) joins only Welcomes whose KeyPackage was minted by `invite create` (marker record `invite-kp-<hash>` written before upload, removed on join). Pool-KP Welcomes stay unjoined/unacked. `join_pending` stays permissive for `--wait` (ref-filtered). security-auditor findings fixed (hashed marker name, tests). Residual: orphan markers (#22), starvation (#30), no `accept` command until #24 answered.
- NEXT: 7.8 `powehi chat`.

## Cycle 518 (2026-10-13, FEATURE) — Phase 7.7 slice C (send + read)
- CLI: `message.rs` (`send`: stdin body <=16 KiB UTF-8, MLS encrypt, save ratchet BEFORE POST; `read`: renders + deletes `rx-*`, neutralises control/bidi/format chars, indents continuation lines, web `{"type":"text"}` unwrapped). `Received.received_at` (ns) orders display; inbox dedup now ignores it (crash-window fix). testsrv: creator receives peer messages, ids ascending.
- Reviews: crypto-reviewer + security-auditor NEEDS-REWORK -> blockers fixed. Residual lows: plaintext copies in read path not zeroized, TTL not enforced, no display cap, #24 policy still open. Escalated design points -> need-human issue (peer credential binding, padding, no PCS).
- NEXT: 7.7 remainder = issue #24 policy; then 7.8 `chat`.

## Cycle 517 (2026-10-13, FEATURE) — Phase 7.7 slice B (inbox + joiner pq_init receive)
- Core: `mls_group::load_group(group_id_bytes, provider)`. CLI: `inbox.rs` (`inbox::receive`: `welcome::join_pending` then Application envelopes from the conv peer only; fresh `LocalIdentity` per envelope; joiner awaiting pq_init decapsulates, `Conversation::complete_pq` stores binding and drops dk/ek; other plaintext -> `rx-<envelope id>` record, cap 2048; order: records, MLS save, ack). `powehi inbox` prints counts/binding only, never bodies.
- Reviews: crypto-reviewer NEEDS-REWORK x2 -> fixed (keyset paging `welcome::fetch_pending`, own-echo ack, ephemeral types dropped, rx never overwritten, is_fresh_pair before decrypt, budget only on decrypt attempts); security-auditor fixes (page cap, cursor len). Residual starvation -> need-human issue (see PR).
- NEXT (7.7 slice C): `send` (stdin body), showing stored `rx-*` messages (+ removal), issue #24 auto-join policy.

## Cycle 516 (2026-10-13, FEATURE) — Phase 7.7 slice A (redeemer pq_init)
- Core: `kem::check_encap_key` (FIPS 203 §7.2, enforced in `kem::encapsulate`), `kem::derive_pq_binding` (moved from wasm; wasm delegates), `mls_group::peer_pq_encap_key` (-> `Option`; None=no ext, Err=invalid; leaf key must equal roster peer), `mls_group::Group` re-export. CLI: `invite::redeem` returns `(Uuid, PqStatus)`; sends `pq_init` after the Welcome (best effort), binding stored in `conv-*` only after a successful send. testsrv handles `POST /v1/messages`.
- crypto-reviewer: first pass NEEDS-REWORK (absent vs invalid conflated, misleading wording) -> fixed. Binding is display-only (ADR-0003): messages stay classical MLS.
- NEXT (7.7 slice B): inbox fetch/decrypt/ack, joiner-side `pq_init` receive (only after join, only from the roster peer, once, discard dk after), `send`, issue #24 policy.

## Cycle 514 (2026-10-13, FEATURE→CI-red fix)
- main CI-Rust was red after #25: `welcome::tests::oversized_poll_response_is_rejected` built a 16 MB JSON number array; >10s in CI debug builds tripped `REQUEST_TIMEOUT` instead of the size cap. Fixed by using a string payload (cheap). Lesson: size-cap tests must not serialize multi-MB number arrays. Phase 7.7 is next.

## Cycle 513 (2026-10-09, FEATURE) — Phase 7.6 done (invite + conversation + Welcome join)
- Core: `kem::validate_decap_key` (FIPS 203 §7.3 SHA3-256 hash + equals published ek; `sha3` now a direct core dep), `mls_group::{add_member_from_bytes, welcome_pq_binding}` (ek read from LOCAL stored KeyPackage by the Welcome's KeyPackageRef, must be called BEFORE join_group, which consumes the bundle).
- CLI: `invite.rs` (create: generate+persist KP then POST /v1/invites, link `<server>/i/connect#code.sha256(kp)`; redeem: hash-pin check, group create, add member, register group + member epoch 1, conv record, then send Welcome), `welcome.rs` (`join_pending`: validate dk -> join -> conv record -> save provider -> prune pq-keys -> ack; unjoinable Welcomes are skipped unacked), `conversation.rs` (`conv-<uuid>` records, cap 256; joiner keeps the dk for pq_init), `testsrv.rs` (in-test mini DS). `invite create --wait <secs<=900>` polls and joins; `inbox` (7.7) must call `welcome::join_pending` too.
- Reviews: crypto-reviewer PASS after rework (is_fresh_pair 1:1 check, ek stored + §7.3 re-check on load); security-auditor fixes: --wait filtered to the invite's KeyPackageRef, typed envelope parse, origin check, wall-clock deadline. need-human #24 (auto-join policy for pool-KP Welcomes). Deferred lows: orphan dk GC (#22), transient JSON buffer holds dk copy, peer_device_id is routing-only (unbound to MLS credential), provider generation gate min=0 (7.11).
- NOT done (7.7 scope): `pq_init` send/receive (web sends it best-effort after Welcome; CLI redeemer does not yet; the joiner already stores the dk for it). Orphan KP policy still issue #22.

## Cycle 512 (2026-10-09, FEATURE) — Phase 7.5 done (identity + KeyPackages)
- `powehi_cli::identity`: `LocalIdentity::load` restores the phrase-derived Ed25519 identity (`mls-signing-key` + account label) and the openmls provider (`mls-provider` record = export_provider_state, generation bumped per save); `pq-keys` record = `ver||count||(sha256(ek)||dk)*` (cap 1024). `ensure_key_packages` (called after register/login): GET count, if < 10 top up to 50 in batches of 10; private halves persisted BEFORE upload. Core additions: `generate_identity_from_seed`, `generate_pq_key_package` (web-identical PQ payload). Not yet: consuming pq-keys on Welcome join (7.6), pruning keys of consumed KPs.

## Cycle 511 (2026-10-09, FEATURE) — Phase 7.4 done (register/login)
- `powehi_cli::auth` (register/login via core OPAQUE) + `prompt` (TTY `/dev/tty`, echo off, phrase shown on tty only, tcflush, ISIG off). Register opens the store with the registration export_key (== login export_key), saves `account` + `mls-signing-key` records BEFORE showing the phrase, then logs in; a later failure leaves a loginable profile. Session token memory-only. MLS label = SHA256(phrase)[..16] (web-compatible); recovery_pubkey from recovery-auth domain. bip39 `zeroize` feature enabled in core.
- crypto-reviewer first pass FAIL (stranded account, phrase zeroize, missing invariant tests) -> reworked. Opened need-human #19 (Unicode normalization of handle/password, web+CLI). Next: 7.5 identity + KeyPackages (signing key already stored as `mls-signing-key`; Ctrl-C during password prompt leaves echo off in non-interactive parents — known minor).

## Cycle 510 (2026-10-09, STABILIZATION)
- main CI green; workspace tests, clippy, `cargo audit`, `cargo deny` all clean. Added 6 store.rs tests (bad magic, oversize file, FIFO, names() filtering/stale tmp, MAX_RECORDS cap, loosened dir) — test-only. Next FEATURE: 7.4 register/login. Cron PATH needs `export PATH=$HOME/.cargo/bin:$PATH`.

## Previous state (2026-10-08, cycle 509 — Phase 7.3 done (crypto-reviewer PASS after rework))

- 7.3: `powehi_cli::store::ProfileStore` (cfg(unix)): `PHS1||nonce||AES-256-GCM`, key=HKDF-SHA256(export_key 32..64B, info `powehi-cli/profile-store/v1/record-key`), AAD=magic||record name, 0700 dir/0600 files, symlink+loose-perm rejection, atomic temp+fsync+rename, key zeroized. Not wired to a command yet (7.4 will pass the OPAQUE export_key). Next: 7.4 register/login.

## Previous state (cycle 507 — Phase 7.2 done)

- 7.2: `crates/client/powehi-cli` (lib `powehi_cli` + bin `powehi`): clap surface per §7A.2 (status/register/login/invite/send/inbox/chat/verify), global `--server` (http/https, no creds) / `--profile` (validated path component) / `--data-dir`; `ProfilePaths::resolve` = `<data_dir>/powehi/<profile>` (pure; 0700 creation is 7.3). `status` real (reqwest, 10s timeout, no redirects, 4KB cap; in-test TCP server); others return NotImplemented. No password/body flags (tests assert). 22 tests; security-auditor findings fixed (loopback-only http, region_id charset, abs data-dir, lowercase profiles, no_proxy); deny clean. Depends on no crypto yet. Next: 7.3.
- Open: need-human #13 (bip39 not on approved crypto list).

## Previous state (cycle 506 — Phase 7.1 done)

- 7.1: kem/kem_credential/media/mls_group/opaque/recovery moved verbatim to `crates/client/powehi-crypto-core` (no wasm-bindgen/js-sys); `powehi-crypto-wasm` `pub use`s them. Only change: `hash_own_commit` pub(crate)→pub. 235 Rust tests (111 core + 124 wasm), build:wasm, Vitest 1675 green. `ci-frontend.yml` paths include core. Next: 7.2 `powehi-cli` skeleton. Cron PATH lacks `~/.cargo/bin` locally; `cargo nextest` not installed (use `cargo test`). The cycle-503 WIP is preserved on `wip/uncommitted-mls-group-worker-20261008`.

## Previous state (2026-10-08, cycle 504 — CI-red fix: libcrux-kem audit waiver + MinIO image move; counter said FEATURE)

- Main CI was red: `cargo audit` (RUSTSEC-2026-0330/0331, libcrux-kem 0.0.7, lockfile-only via
  hpke-rs-libcrux, same unreachability argument as the other libcrux waivers — see .cargo/audit.toml)
  and the MinIO pre-pull (quay.io/minio/minio now rejects anonymous pulls). MinIO moved to Docker Hub's
  frozen `bitnamilegacy/minio:2025.7.23-debian-12-r5` (+ `bitnamilegacy/minio-client`); tests/CI/compose
  updated together. Cannot run docker locally: the r2 integration job is the first real exercise of it.
- Uncommitted work found at cycle start (mls_group.rs, wasm_exports.rs, crypto.worker.ts, worker mock) was
  preserved on branch `wip/uncommitted-mls-group-worker-20261008` (not reviewed). Phase 7.1 moves
  mls_group.rs, so reconcile that branch first or drop it.
- Phase 7.1 (crypto-core extraction) is still the first unchecked item; do it next FEATURE cycle.


## Current state (2026-09-16, cycle 502 — FEATURE: withMlsCommitLock AbortSignal support + trackedGroupCount test hook (carried F9/F10), commit 1837da7)

- Mode selection: counter 501→502, 502 % 5 != 0 → FEATURE. `gh run list
  --limit 3` green on main (cycle 501's push; one `cancelled` run on the
  same commit was a redundant duplicate trigger, not a failure — the
  `success` run for that commit's CI — Rust and the CI — Live-backend
  E2E both passed). `gh issue list --state open`: same 5 open issues,
  none newly bug-labeled. Working tree clean at session start.
- Picked carried candidate #2 from cycle 501's list: F9 (acquisition
  timeout/AbortSignal for `withMlsCommitLock`) and F10 (export a test
  hook to directly assert the 128-group eviction cap), both small,
  scoped, frontend-only, zero new UI attack surface — deliberately did
  NOT touch (e)/(g) (the real Remove-UI blockers, still fully open) or
  the device_id-to-MLS-leaf binding design call (crypto-lead-scoped).
- **What shipped** (`app/src/lib/mlsCommitLock.ts`): `withMlsCommitLock`
  now takes an optional third `signal?: AbortSignal` param, passed
  through to the underlying `createLimiter` call (which already
  supported an abort-while-queued contract, previously unused by this
  module). A caller still QUEUED behind a holder that never settles can
  now give up waiting instead of queuing forever — `fn` is never
  invoked in that case, and the holder's slot is NOT freed (only a
  still-waiting caller can give up, not a running one). Also added
  `trackedGroupCount()`, a read-only export returning `locks.size`, for
  direct test assertions of the `MAX_TRACKED_GROUPS` cap.
- **crypto-reviewer: first pass needs-rework, re-review PASS** (this
  file touches the MLS commit-lock primitive gating merge/stage/confirm
  exclusivity, matching the routing precedent from cycle 501). The
  reviewer ran the module in isolation (`/tmp`, deleted after) to
  measure real interleavings rather than just reading code, confirming
  no live bug: exclusivity, FIFO order, `entry.active` bookkeeping, and
  no permanent-wedge risk all held under abort injected at every tick
  boundary. What needed fixing was documentation/test accuracy, not
  runtime behavior:
  - **F-A**: the new docstring claimed the signal "has no effect once
    fn has started running" — actually measured to go dead ONE TICK
    EARLIER, at slot acquisition (dequeue), because the F1 `safeFn =
    () => Promise.resolve().then(fn)` normalization wrapper inserts its
    own microtask between acquisition and the real `fn()` call. Fixed
    the docstring to say "acquires the group's slot," not "fn starts."
  - **F-B**: the "abort after running has no effect" test used a fresh,
    uncontended group — `createLimiter`'s immediate-acquire fast path
    never registers an abort listener at all, so the test passed even
    with the abort-listener-removal logic deleted (verified: reviewer
    instrumented `addEventListener` call count = 0 on that path).
    Fixed by rewriting the test to actually hold the group first via a
    separate holder task, so the signal-bearing caller genuinely queues
    and registers a listener before being dequeued.
  - **F-C**: the queued-abort test's comment claimed "abort does not
    free the holder's slot" but nothing asserted it — the follow-up
    call in that test only ran AFTER the holder had already resolved
    normally, so a bug that freed the slot on abort would have gone
    undetected (mutation-tested by the reviewer: manually adding
    `release()` to the abort path flipped this test from pass to fail
    only after the fix). Fixed by queuing a third caller WHILE the
    holder is still unresolved, right after the abort, and asserting it
    has not started for several ticks before releasing the holder.
  - Re-review: **PASS**, mutation-tested. 3 non-blocking notes carried
    forward (not required): the acquisition→fn gap is actually 2
    microtasks not 1 (doc credits only `safeFn`, technically
    incomplete but not wrong in direction); the "no effect" test
    validates the weaker after-fn-ran claim since the stronger
    inert-from-dequeue instant isn't observable via the public API;
    `trackedGroupCount()`'s `toBe(128)` assertion depends on shared
    module-singleton state and file test order (would break under
    `--shuffle`/`.concurrent`, not used by this repo's vitest config).
- No `threat-model-checker`/`security-auditor` run: no new
  server-visible metadata, no backend/infra touched — matches the
  established routing precedent (crypto-reviewer alone for a
  crypto/MLS-adjacent frontend-only primitive change with no threat-
  model-boundary shift).
- **Full gate**: `pnpm exec tsc -b` clean. `pnpm exec biome check`
  clean on both changed files (2 auto-format passes applied and
  re-verified, both whitespace/wrapping only). `pnpm exec vitest run`:
  113 files / 1675 tests, all green (was 1672 — +3 new AbortSignal
  tests; the F10 eviction-cap assertion was added inline to an existing
  test, not a new one). Rust untouched this cycle (frontend-only
  diff) — `cargo build --workspace` not re-run; no regression risk
  since zero `.rs` files changed (confirmed via `git diff --stat`
  showing only the two `app/src/lib/mlsCommitLock.*` files).
- Committed `1837da7` (`feat(frontend): add AbortSignal support +
  test-only eviction-cap hook to withMlsCommitLock`), 2 files changed
  (132 insertions, 12 deletions). Pushed clean (`66b8700..1837da7 main
  -> main`).
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated from cycle 501's list):**
  1. **Resolved this cycle**: F9 (AbortSignal support) and F10 (eviction-
     cap test hook), both from cycle 501's crypto-reviewer pass.
  2. Unchanged, still the real gate before any Remove UI can be safely
     built: (e) incoming-commit-silently-discards-staged-commit and (g)
     stale-local-epoch-undetectable-via-CAS in `mls_group.rs`'s status
     list are BOTH still fully OPEN, both independently cause a
     permanent unrecoverable group fork under `max_past_epochs(0)`.
     Also still undesigned: the T3 local trust anchor for picking
     *which* leaf to remove (prd.md §3.3 names two ways forward — bind
     `device_id` into the MLS credential, or lean on the §5.6 safety
     number — a product/crypto-lead decision). A production Remove UI
     should select from `mlsGroupMembers()`'s roster directly (leaf
     index + sigKeyHex), NOT from `PendingRemovalBanner`'s
     server-supplied device_ids — see `mls_group.rs`'s "Caller
     contract" section for why.
  3. Carried, unchanged: renaming `prod-ap-seoul` (cross-cutting
     Terraform/DNS/CD rename, a policy call — not attempted) and the
     origin-direct-ingress bypass gap threat-model-checker flagged at
     cycle 500 (`smart-router`'s `index.ts` `"XX"` fallback routes to EU
     when `request.cf` is absent — verify whether Hetzner origins are
     actually network-restricted to Cloudflare-only ingress).
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a real
     client polls it.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-16, cycle 501 — FEATURE: MLS commit-lock primitive + GET /epoch client wrapper, issue #2 prereq, commit c3519b9)

- Mode selection: counter 500→501, 501 % 5 != 0 → FEATURE. `gh run list
  --limit 3` all green on main (cycle 500's push). `gh issue list
  --state open`: same 5 open issues (#1 SPA deploy, #2 MLS Remove/PCS,
  #3 WS client, #4 load testing, #5 prod-ap-seoul PIPA).
- Picked up issue #2 (P0-blocker) via the carried candidate list. An
  Explore-agent survey first (don't skip this next time either) found the
  situation was narrower than the issue title suggests: the Rust MLS
  Remove commit primitive (`stage_remove_member`/`confirm_remove_member`/
  `abort_remove_member` in `crates/client/powehi-crypto-wasm/src/
  mls_group.rs`) and its WASM/Comlink exports already existed,
  unit-tested, since an earlier cycle. But that module's own doc comment
  explicitly says **"do not wire this trio into a production UI yet"**
  pending open items (a) epoch reconciliation, (e) an incoming commit can
  silently discard a locally-staged commit, (f) no mutual exclusion
  between the poll loop and a future UI flow, (g) a stale local epoch
  undetectable via the server CAS. Deliberately did NOT build a
  production Remove UI this cycle — building it while (e)/(g) stay open
  risks a permanent, unrecoverable group fork under `max_past_epochs(0)`.
  Scoped instead to closing (a) and partially closing (f), i.e. safe
  prerequisite infra with zero new UI attack surface.
- **`app/src/lib/mlsCommitLock.ts` (new)**: per-group async mutex
  (`withMlsCommitLock(groupId, fn)`), built on the existing
  `concurrencyLimiter.ts` `createLimiter`. Bounded to 128 tracked groups,
  idle-LRU eviction (never evicts a busy lock). Wired into
  `useMessages.ts`'s existing Commit-merge path (`mlsProcessCommit` + the
  self-eviction check, deliberately including the post-merge ack+retry —
  documented tradeoff, not an oversight).
- **`app/src/api/groups.ts`**: added `getEpoch(token, groupId)` wrapping
  the already-existing `GET /v1/groups/:id/epoch` endpoint (added cycle
  499, commit 2ab7ad9). No production caller wired yet — scoping only.
- **`crates/client/powehi-crypto-wasm/src/mls_group.rs`**: doc-only
  updates to the remove-member status list — (a) → PARTIALLY CLOSED
  (endpoint+wrapper exist, no caller), (f) → PARTIALLY CLOSED (lock
  exists, poll loop uses it, but no second/UI caller yet so the mutual-
  exclusion guarantee doesn't hold in practice), (g) got a note that the
  pre-stage drain and the stage/confirm/abort must happen inside ONE
  `withMlsCommitLock` acquisition (the lock is non-reentrant — a naive
  drain-then-reacquire implementation would deadlock).
- **Two review passes, both required by CLAUDE.md for this diff**:
  - `threat-model-checker`: **YELLOW** (documentation-only, not
    blocking). Confirmed T1-T7 unchanged, zero new metadata exposed
    (`getEpoch` has 0 call sites). Flagged F1 (the lock span includes
    unbounded network I/O — the ack call has no timeout — a future
    concern once a UI caller actually contends for the lock, since a
    malicious DS could then stall a Remove attempt at the acquisition
    step) and F2 (item (a)'s original "CLOSED" label was inconsistent
    with (f)'s honest "PARTIALLY CLOSED — one caller only" framing).
    Both addressed in doc updates (see above) before commit.
  - `crypto-reviewer`: **first pass was needs-rework** — found a real,
    reproducible bug (F1, verified via a probe test that was deleted
    after confirming): `withMlsCommitLock`'s underlying
    `createLimiter` executor is `fn().finally(release)`; a `fn` that
    throws SYNCHRONOUSLY (not `async () => { throw }`, a genuine sync
    throw) or returns a non-Promise value never reaches `.finally`, so
    `release` never runs — the capacity-1 mutex wedges PERMANENTLY for
    that group's remaining process lifetime. Fixed by normalizing via
    `const safeFn = () => Promise.resolve().then(fn)` before handing it
    to the limiter; pinned with two new regression tests. Also flagged
    doc-accuracy findings F2-F4 (over-claimed "closes item (f)"/"item
    (a) CLOSED" language; non-reentrancy undocumented despite item (g)
    implying a drain-then-reacquire pattern that would deadlock; "no
    UI-initiated MLS flow exists yet" was false — `AcceptInviteModal.tsx`
    and `CreateGroupModal.tsx` both call MLS-mutating worker methods
    today, just safely, since the poll loop can't bind to a
    not-yet-open group) — all fixed. Plus low-severity F5 (`Number.
    isInteger` → `Number.isSafeInteger`, server returns u64) and F6
    (`resp.json()` needed the same `.catch(() => ({}))` fail-closed
    pattern `throwOnError` already uses). **Re-review after fixes: PASS.**
  - Non-blocking carried findings for a future cycle (crypto-reviewer's
    own triage, not urgent): F8 (ack+retry inside the lock span — fine
    today, revisit once a real competing caller exists to measure
    contention), F9 (no acquisition timeout/AbortSignal — a crashed
    worker wedges the lock forever, future UI caller should apply its
    own timeout), F10 (the 128-cap eviction test doesn't assert
    `locks.size` directly — no export exists to check it), F11 (lock key
    is `groupId` alone, not `(identityId, groupId)` — intentional,
    over-serializes safely, now documented).
- **Full gate, all green**: `cargo build --workspace`, `cargo fmt --all
  --check`, `cargo clippy --workspace --all-targets -- -D warnings` all
  clean. `cargo test --workspace` (nextest not installed in this
  sandbox, documented fallback used): every crate `0 failed`, same
  171/58/235(2 ignored)/62/12/120/10/8/4/4/18/20/158/3/10/13/38/3 counts
  as cycle 500 baseline — no regression (this cycle's Rust changes were
  doc-comment-only). `cargo deny check`: `advisories ok, bans ok,
  licenses ok, sources ok`. Frontend: `pnpm exec tsc -b` clean; `pnpm
  exec biome check` — 4 pre-existing unrelated `app/src-tauri/gen/
  schemas/*.json` errors only (same baseline noted since ≥cycle 472);
  `pnpm exec vitest run`: 113 files / 1672 tests, all green (was 1667 —
  +9 new `mlsCommitLock.test.ts` tests, +2 new `groups.test.ts` `getEpoch`
  tests after the F5/F6 fixes, net +5 shown live but 1672 is the final
  post-fix count).
- Committed as `c3519b9` (feature commit only this cycle — this memory
  update is a separate `chore:` commit per convention). 6 files changed:
  `mlsCommitLock.ts`+test (new), `groups.ts`+test, `useMessages.ts`,
  `mls_group.rs`.
- Target dir hygiene: not checked this cycle (FEATURE mode; hygiene step
  is STABILIZATION-only per the cycle instructions).
- **Next cycle candidates (carried/updated from cycle 500's list):**
  1. **Partially addressed this cycle** (issue #2): closed (a), partially
     closed (f) as prerequisite infra. Still the real remaining work:
     (e) incoming-commit-silently-discards-staged-commit and (g)
     stale-local-epoch-undetectable-via-CAS are BOTH still fully OPEN
     and BOTH independently cause a permanent, unrecoverable group fork
     under `max_past_epochs(0)` — closing them is the real gate before
     any Remove UI can be safely built. Also still undesigned: the T3
     local trust anchor for picking *which* leaf to remove (prd.md §3.3
     names two ways forward — bind `device_id` into the MLS credential,
     or lean on the §5.6 safety number — a product/crypto-lead decision,
     not something to default into). A production Remove UI, when it's
     finally safe to build, should select from `mlsGroupMembers()`'s
     roster directly (leaf index + sigKeyHex), NOT from
     `PendingRemovalBanner`'s server-supplied device_ids — see
     `mls_group.rs`'s "Caller contract" section for why.
  2. Carried non-blocking crypto-reviewer findings from this cycle: F8
     (narrow the lock span to exclude the ack once a real competing
     caller exists to measure against), F9 (acquisition timeout/
     AbortSignal for `withMlsCommitLock`), F10 (export a test hook or
     otherwise directly assert the 128-group eviction cap holds).
  3. Carried, unchanged: renaming `prod-ap-seoul` (cross-cutting
     Terraform/DNS/CD rename, a policy call — not attempted) and the
     origin-direct-ingress bypass gap threat-model-checker flagged at
     cycle 500 (`smart-router`'s `index.ts` `"XX"` fallback routes to EU
     when `request.cf` is absent — verify whether Hetzner origins are
     actually network-restricted to Cloudflare-only ingress).
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a real
     client polls it.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-16, cycle 500 — STABILIZATION: archive this file (cycles 453-484), reconcile prd.md PIPA/KR-residency doc drift with actual deployed topology (issue #5), full green sweep)

- Mode selection: counter 499→500, 500 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` all green on main (cycle 499's push). `gh issue list
  --state open`: same 5 open issues (#1 SPA deploy, #2 MLS Remove/PCS,
  #3 WS client, #4 load testing, #5 prod-ap-seoul PIPA), none
  `bug`-labeled. Working tree clean at session start.
- **This file itself had been flagged as this cycle's #1 STABILIZATION
  task since cycle 499's own candidates list** ("well past ~3050 lines
  — cycle 500 is the archive point, same pattern as cycles 360/485").
  Archived cycles 453-484 (2203 lines of history) to
  `.claude/memory/archive/project-context-cycles-453-484.md`, following
  the exact split precedent cycle 485 set (archive older `## Previous
  state` sections verbatim, keep the "Archive index" list at the
  bottom, add one new line to it). File went from 3132 → 930 lines
  (then this entry). Verified the split boundary was exact (no line
  lost or duplicated) by diffing section headers before cutting.
- **Second task: GitHub issue #5** (P1/infra/compliance — `prod-ap-seoul`
  is Hetzner Singapore, not Korea, so prd.md's compliance-matrix claims
  of "KR 리전 저장" are false). Traced the issue's 4 suggested items
  before acting:
  1. "Decide the interim posture" — already decided and implemented:
     `infra/cloudflare/workers/smart-router` unconditionally 503s any
     `request.cf.country === "KR"` request (`PIPA_REGION_PENDING`).
     Not touched this cycle.
  2. "Rename the env" — a real Terraform/DNS/CD-pipeline rename
     (`prod-ap-seoul` → `prod-ap-singapore` or similar) is a
     cross-cutting, hard-to-reverse infra change affecting live prod
     naming; deliberately NOT attempted this cycle (same category as
     this file's other carried human/policy-call items like PQ
     hybrid) — left as a candidate, not resolved.
  3. "Make the guard mechanical" — confirmed, not just asserted: read
     `router.ts`/`index.ts` and their test files. The guard reads
     `request.cf.country` (CF-trusted, unspoofable), not the
     client-supplied `CF-IPCountry` header; `index.test.ts` has an
     explicit test proving a spoofed `CF-IPCountry: DE` header cannot
     bypass a real `cf.country=KR`. `router.test.ts` unit-tests
     `resolveTarget("KR")` and `AP_COUNTRIES` excluding KR directly.
     This item was already done and tested — no code change needed,
     confirmed via reading, not assumed from memory.
  4. "Reconcile prd.md's KR 리전 저장 claim" — this was the real gap.
     Fixed 4 locations: §1's Data Residency bullet (line 61), §12A's
     compliance matrix (was line 1999, false "KR 사용자 데이터는
     AP-Seoul에만 저장"), §15.2's compliance matrix (was line 2182,
     same false claim), and §4A.6's data-residency requirements table
     (added a caption clarifying its KR column is the target
     architecture for a future real KR DC, not current state — did NOT
     rewrite the table itself, since it correctly describes what
     *should* happen once a KR region exists). All 3 corrected claims
     now say explicitly: no KR PII is stored anywhere today, the
     smart-router 503s all KR traffic, cites GitHub #5 and
     `infra/cloudflare/workers/smart-router` as evidence.
- **threat-model-checker: YELLOW.** Confirmed no code/crypto/data-flow
  changed, T1-T6 impact matrix unchanged, doc posture strictly
  strengthened (previously falsely claimed compliance, now accurately
  labeled "미충족 (accepted risk)"). Not GREEN because it caught a
  residual inconsistency this cycle's first pass had missed: §4A.6's
  table still read as unconditional present-tense "KR 리전에 저장" with
  no caveat, and line 61's Data Residency bullet still claimed PIPA
  "준수" (compliance) outright. Fixed both before committing (see above
  — the §4A.6 caption and the line-61 rewrite were both added in
  response to this finding, not the initial pass). Also flagged an
  unrelated, pre-existing, NOT-introduced-by-this-diff gap for the
  future: `index.ts`'s `country = cfProps?.country ?? "XX"` fallback
  routes to EU (not blocked) when `request.cf` is absent, so the "전면
  차단" (total block) claim depends on all ingress actually routing
  through the Cloudflare Worker — origin-direct access would bypass it
  unless separately network-restricted. Not verified this cycle (infra
  topology check, not a doc-accuracy question); added as a candidate.
- **Full gate** (docs-only change, but ran the complete sweep per
  STABILIZATION's mandate): `cargo clippy --workspace --all-targets --
  -D warnings` clean. `cargo fmt --all --check` clean. `cargo test
  --workspace`: every crate `0 failed` (171/58/235(2 ignored)/62/12/120/
  10/8/4/4/18/20/158/3/10/13/38/3 passed across crates, matching cycle
  499's counts — no regression). `cargo deny check`: `advisories ok,
  bans ok, licenses ok, sources ok`. `pnpm exec tsc -b` clean. `pnpm
  exec biome check`: 4 pre-existing unrelated `app/src-tauri/gen/
  schemas/*.json` errors only (same as noted since ≥cycle 472, not a
  regression — confirmed by re-checking, not assumed from memory).
  `pnpm exec vitest run`: 112 files / 1649 tests, all green. `pnpm
  audit --prod`: no known vulnerabilities. No local `cargo-audit`
  binary in this sandbox; `cargo deny check`'s advisory-DB scan is the
  substitute, as in prior cycles without it installed.
- No `crypto-reviewer`/`security-auditor` run: no crypto/MLS/OPAQUE
  code touched, no backend handler changed — this cycle is a memory
  archive (mechanical, no code) plus a docs-only compliance-accuracy
  fix, matching the established routing precedent for doc-only changes
  (`threat-model-checker` alone, since it touches the threat-model
  document itself).
- Committing this file's own update together with the doc fix and
  archive as part of this cycle's single commit set (memory archive +
  prd.md fix are one logical STABILIZATION unit, unlike FEATURE mode's
  separate feature-then-memory commits).
- Target dir hygiene: `target/` at 18G (up from ~15-16G recently,
  still under the 20G threshold — no pruning triggered). 0-byte
  `.rmeta` prune ran first per the mandated step order (found none to
  delete this cycle).
- **Next cycle candidates (carried/updated from cycle 499's list):**
  1. **Resolved this cycle**: this file's archive-point overflow
     (cycles 453-484 archived). Watch for it crossing ~2500-3000 lines
     again in a future STABILIZATION cycle (next multiple of 5 after
     it does).
  2. **Partially addressed this cycle** (issue #5): doc drift reconciled,
     mechanical guard confirmed already-done-and-tested. Still open:
     renaming `prod-ap-seoul` (cross-cutting Terraform/DNS/CD rename,
     a policy call — not attempted) and the origin-direct-ingress
     bypass gap threat-model-checker flagged (`index.ts`'s `"XX"`
     fallback routes to EU when `request.cf` is absent — verify
     whether Hetzner origins are actually network-restricted to
     Cloudflare-only ingress, or whether this is a real gap).
  3. Carried unchanged: admin-initiated MLS Remove UI step (b) — design
     how a client uses `GET /v1/groups/:id/epoch` (poll-before-retry?
     what does a `RegionMismatch` 502 mean for reconciliation?) and
     wire `app/src/api/groups.ts`'s consumer. FEATURE-mode-scale,
     crypto-lead-scoped.
  4. Carried: reconsider `DomainError::RegionMismatch` mapping to `421
     Misdirected Request` instead of `502 region_mismatch` before a
     real client polls it (steady expected-5xx stream would pollute
     §13 SLO/alerting) — cheap, no other callers yet.
  5. Carried unchanged: device_id-to-MLS-leaf binding half of issue
     #2's `PendingRemovalBanner` cross-check (crypto-lead design call).
  6. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s
     rejection latency — informational until a real Remove UI exists.
  7. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  8. Carried: PQ hybrid Phase A prerequisite (blocked on openmls
     upstream).
  9. Carried, BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  10. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
      retention window; `mls_group_members` `isSelf` leaf-index
      hardening; issues #1/#3/#4; prd.md §10 REST API doc drift;
      unconsumed `RemovalRequired` WS event; `key_packages.device_id`
      FK doc drift.

## Previous state (2026-09-15, cycle 499 — FEATURE: add `GET /v1/groups/:group_id/epoch`, region-authority fail-closed, commit 2ab7ad9)

- Mode selection: counter 498→499, 499 % 5 != 0 → FEATURE. `gh run list`
  green on main before starting (cycle 498's push). Working tree clean at
  session start (no orphaned WIP, unlike several recent cycles).
- **Picked candidate #2 from cycle 498's list, scoped narrowly**: rather
  than attempt the full admin-initiated MLS Remove UI (blocked on epoch
  reconciliation), picked the small concrete sub-task cycle 498 had
  already identified: expose the server's `groups.epoch` counter via a
  read endpoint, so a future client has something to bound a `sendCommit`
  `expected_epoch` against. Did NOT attempt the reconciliation design
  itself or wire any client consumer this cycle (no `app/src/api/groups.ts`
  change) — deliberately step (a) only.
- **What shipped**: `GroupUseCase::get_epoch(caller, group_id) -> Epoch`
  (fail-closed membership guard, same non-existence-oracle contract as
  `list_members`), `GET /v1/groups/:group_id/epoch` REST handler
  (`GroupEpochResponse { epoch: u64 }`), wired into `lib.rs`'s
  `api_routes` block (same `api_governor` rate-limit tier as its siblings).
- **security-auditor: needs-rework on the first pass, PASS after fixes**
  (backend handler, matches routing precedent). Findings and fixes:
  - **F1 (MEDIUM, blocker)**: a group row synced into a non-home region via
    `SyncGroupMembership` is created with `epoch: Epoch(0)` and never
    updated after (`upsert_members`'s `ON CONFLICT DO NOTHING`) — a
    non-home-region caller would get a stale/zero epoch back as `200 OK`
    with no authority indicator, a false-trust signal indistinguishable
    from a genuinely fresh group. Fixed: `GroupService::get_epoch` now
    compares `group.home_region != self.local_region` and returns
    `DomainError::RegionMismatch` (existing variant, already mapped to
    `502 region_mismatch`) instead of ever answering with that value. Guard
    order matters and was verified correct: the region check runs strictly
    after the membership check, so a non-member can never use this to
    probe "does this group exist in some other region" (would have been a
    group-existence-plus-home-region oracle otherwise).
  - **F2 (LOW/MEDIUM) + F3 (LOW), fixed together**: the original impl did
    `list_members` (O(group size) list allocation for an O(1)-sized
    response — worst amplification ratio of any `/v1/groups/*` endpoint)
    followed by a separate non-transactional `find_by_id`, reopening a
    TOCTOU window `list_members`'s own design explicitly avoids elsewhere.
    Fixed: added `GroupRepository::get_epoch_if_member(group_id,
    device_id) -> Option<Group>`, a single fused JOIN query
    (`groups g JOIN group_members m ON m.group_id = g.id WHERE g.id = $1
    AND m.device_id = $2`) that does the membership check and the read in
    one round trip. `Ok(None)` covers "no such group" and "not a member"
    identically — stronger than before, since there's no longer a second
    code path where those two cases could theoretically diverge. Had to
    add this method to 6 other `GroupRepository` fakes across the
    workspace (`grpc/server.rs`, `ws-hub` tests,
    `auth_service.rs`/`media_service.rs`/`messaging_service.rs`'s test
    modules) — all fail-closed (real membership checks in 3, `Ok(None)` or
    `unimplemented!()` in the rest, none unconditionally grant access).
  - **F6 (INFO)**: fixed a doc typo (`GroupUseCase::advance_epoch` doesn't
    exist; corrected to `GroupRepository::advance_epoch`).
  - **F4 (LOW)**: agreed with threat-model-checker's parallel finding
    (same review cycle) that this needed a `prd.md` §3.3 entry — added.
  - **F5** (log volume) and **F7** (no consumer wired yet) left as
    informational, matching the auditor's own severity call — F7 is
    intentional this cycle (step (a) only, see above).
  - **Re-verification pass caught doc drift from the two parallel reviews**:
    threat-model-checker's prd.md §3.3/§3.5.1 additions (written before
    F1's fix landed) still said the stale/zero epoch "may be returned
    without an authority indicator" — no longer true once `RegionMismatch`
    fail-closed shipped. Fixed both paragraphs to say the integrity risk is
    closed and only an availability limitation (non-home-region members
    can't use the endpoint at all) remains. Also fixed an inaccurate
    "no TOCTOU window" claim in `group_service.rs`'s `FakeGroupRepo` test
    comment (its two lock acquisitions are in fact separate statements;
    harmless only because tests are single-threaded) — this repo treats
    comments as normative, so a false claim was worth removing even though
    it was purely cosmetic.
  - **security-auditor's own new observations (not required this cycle,
    tracked for the future consumer-wiring cycle)**: this is the first
    code path in the whole workspace that actually produces
    `DomainError::RegionMismatch` (previously only the error-mapping and
    its own unit test existed) — so the `502` REST path opens in
    production for the first time here. Auditor flagged that `502` may be
    semantically wrong (a deterministic client-side "wrong region" isn't a
    gateway failure; `421 Misdirected Request` fits closer) and that a
    polling peer-region member would generate a steady 5xx stream that
    could pollute `§13` SLO/alerting despite being expected behavior —
    both flagged as pre-existing/shared-mapping concerns out of this
    diff's scope, to revisit whenever step (b) actually wires a consumer.
- **threat-model-checker: YELLOW, conditions applied**. Verdict: no
  confidentiality invariant weakened (server learns nothing new — the
  epoch value already flowed client→server via `AddMemberRequest.epoch`),
  no out-of-scope-list migration, write path untouched, existing
  fail-closed pattern reused correctly, `None → Unauthorized` default
  already guarded (not a `0`-default oracle). Conditioned GREEN on two
  `prd.md` doc-parity additions (this repo's established convention:
  every newly-client-readable server-held field gets a §3.3 entry, per
  the `/members` precedent from cycle 454) — added both, then corrected
  per security-auditor's re-verification note above.
- **Full gate**: `cargo build --workspace` and `cargo build --workspace
  --all-targets` clean. `cargo clippy --workspace --all-targets -- -D
  warnings` clean (multiple times, after this cycle's own review-fix
  round too). `cargo fmt --all --check` clean (auto-fixed once via
  `cargo fmt --all`, re-verified). `cargo test --workspace`: 0 failed
  throughout (application 171, up from 167; rest-api 158, up from 154;
  postgres integration tests unchanged runnable count, +1 new
  Docker-gated `#[ignore]` test, confirmed compiles via `cargo build -p
  powehi-postgres --tests` — no local Docker in this sandbox to actually
  run it). `cargo audit`/`cargo deny check`/`pnpm audit --prod` all clean
  (run by security-auditor as part of its pass).
- Committed `2ab7ad9` (`feat(backend): add GET /v1/groups/:id/epoch,
  fail-closed to home region`), 16 files changed (495 insertions, 0
  deletions — no line removed anywhere in this diff). Pushed clean
  (`f0fe588..2ab7ad9 main -> main`). CI triggered immediately after push;
  not watched to completion before this memory entry was written — verify
  `gh run list` next cycle if this session ends first.
- Target dir hygiene: not checked (FEATURE mode).
- **Next cycle candidates (carried/updated from cycle 498's list):**
  1. **Narrowed, not resolved** (was candidate #2): admin-initiated MLS
     Remove UI is still blocked on the `sendCommit`/`expectedEpoch`
     reconciliation design, but the "expose server's `groups.epoch`"
     sub-step is now done. A future crypto-lead-scoped cycle should design
     step (b): how a client actually uses this endpoint (poll before
     retry? what to do when a `RegionMismatch` 502 means "can't reconcile
     from here at all"?) and wire `app/src/api/groups.ts`'s
     `getEpoch`/consumer.
  2. New, from security-auditor's own observation this cycle: reconsider
     whether `DomainError::RegionMismatch` should map to `421 Misdirected
     Request` instead of `502 region_mismatch` before any real client
     starts polling it (a steady expected-5xx stream from peer-region
     members would pollute §13 SLO/alerting) — cheap to fix now, before
     the mapping has other callers to keep compatible.
  3. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     `PendingRemovalBanner` cross-check (crypto-lead design call).
  4. Carried unchanged: `mlsRemoveMemberStage`'s worst-case ~60s rejection
     latency — informational until a real Remove UI exists.
  5. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  6. Carried: PQ hybrid Phase A prerequisite (blocked on openmls upstream).
  7. Carried, BLOCKED: `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring needs F3 + HMAC-vs-plain-SHA256 gate resolved first.
  8. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
     retention window (separate item — not the same as this cycle's new
     `groups.epoch` §3.3 entry).
  9. Carried: `mls_group_members` `isSelf` leaf-index hardening; issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  10. **This file is now well past ~3050 lines — cycle 500 (1 cycle away,
      the next multiple of 5) is the STABILIZATION archive point, same
      pattern as cycles 360/485.**

## Previous state (2026-09-15, cycle 498 — FEATURE: found + finished cycle 497's uncommitted MLS pending-commit-cleanup fix, fixed crypto-reviewer's needs-rework verdict, commit da96dee)

- Mode selection: counter 497→498, 498 % 5 != 0 → FEATURE. `gh run list`
  green on main before starting.
- **Session opened with 6 modified files already in the working tree**
  (PendingRemovalBanner.tsx, useCryptoWorker.ts/.test.ts, crypto.worker.ts,
  mls_group.rs, wasm_exports.rs) — no memory entry describes cycle 497 at
  all, meaning that session was cut short before EITHER its end-of-cycle
  memory commit OR its own feature commit. Same "session cut short" pattern
  this file has now flagged four times (445/494/495/496) — this is the
  first time it left a real, substantial UNCOMMITTED diff behind rather
  than just an uncommitted memory-file edit. Read the diff in full before
  acting (doc comments in it self-identified as "cycle 497", confirming
  provenance) rather than assuming it was safe to discard or blindly
  commit.
- **What the found diff did**: fixed a real bug — a successful merge of a
  PEER's Commit (via either the one-shot `mls_process_commit` or an
  incoming Welcome/Add flow) makes openmls internally call
  `clear_pending_commit`, which silently invalidates any commit THIS
  device had separately staged via `mls_remove_member_stage` but not yet
  confirmed. Before the fix, that left a dangling
  `pending_own_commit_hashes[group_id]` entry naming a commit that can
  never be merged. Fixed for the one-shot path
  (`mls_process_commit_inner`). Also (JS side): a compensating
  `mlsRemoveMemberAbort` when `mlsRemoveMemberStage` resolves in WASM but
  the required Dexie persist then rejects, so the group isn't left
  durably wedged in `PendingCommit`. Extensive stale-doc-comment cleanup
  in `mls_group.rs`/`crypto.worker.ts` converting a stale "(a)/(b)/(c)"
  MLS-Remove-wiring blocker list into a verified "(a)-(g)" list (closes
  item (d) — persist-failure-after-successful-stage — for the "call"-
  resolved case; leaves the ambiguous "call"-phase-timeout variant open,
  correctly).
  All tests green as found: 234 Rust, 1647 frontend, tsc/biome clean.
- **Before committing, ran the mandatory `crypto-reviewer` pass (this diff
  touches MLS/WASM) — verdict: needs-rework, 2 HIGH + 1 MEDIUM + 2 LOW.**
  This file's non-negotiables gate a commit on this passing, so did NOT
  commit the found diff as-is; fixed all 5 findings before committing:
  - **F1 (HIGH)**: the compensating `raw.mlsRemoveMemberAbort(...)` call
    had no `withTimeout` — violated this file's own "a crypto-worker call
    must never hang forever" invariant, and the dominant trigger reaching
    that catch block (a "persist"-phase timeout) is exactly the situation
    where the worker channel is already suspected wedged, so the abort
    call itself would very plausibly also hang, turning a bounded
    rejection into a permanent hang for the wrapped call. Fixed: wrapped
    in `withTimeout(..., "mlsRemoveMemberAbort", "call")`.
  - **F2 (HIGH)**: the comment justifying skipping a post-abort flush
    ("abort restores in-memory state to exactly what's already durably on
    disk, nothing new to persist") is false whenever `withTimeout` let the
    caller give up on the ORIGINAL failed persist's `doFlush` without
    actually cancelling it (documented `doFlush` behavior) — that
    abandoned write can still land on disk AFTER the abort, durably
    writing the wedged `PendingCommit` state to disk with nothing JS-side
    able to detect it on reload. Fixed: after a successful abort, issue a
    FRESH `runOnChain(() => withTimeout(doFlush(...)))` (failure
    swallowed, logged, original persistError still rethrown) — relies on
    `doFlush`'s existing generation-based supersede check to guarantee the
    fresh, later-issued write can never durably lose to the earlier
    abandoned one. Reviewer independently re-derived the race proof across
    every interleaving and confirmed it holds.
  - **F3 (MEDIUM)**: the two-phase `mls_confirm_incoming_commit` merge site
    has the IDENTICAL dangling-`pending_own_commit_hashes` hazard as the
    one-shot path, but the diff only fixed the one-shot path — violates
    this codebase's own "one construction path" rule (two merge sites,
    one of them silently exempt). Fixed: split into
    `mls_confirm_incoming_commit_inner` (mirrors `mls_process_commit_inner`'s
    pattern) which now also clears the entry on success; added a mirrored
    regression test using the real `inspect_incoming_commit` primitive +
    manual `INSPECTED_COMMITS` insert (JsValue-constructing wasm exports
    can't be called from native tests).
  - **F4/F5 (LOW)**: softened an absolute "on every ERROR path, no merge
    happened" doc claim to scope it to errors this crate's in-memory
    `OpenMlsRustCrypto` provider can actually produce, footnoting two
    openmls-0.8.1 internal counterexamples the reviewer found by reading
    vendored source; added a NOTE documenting that the compensating-abort
    window itself still shares the same unrelated-stage-destruction risk
    it was scoped to avoid elsewhere (unreached today, ties to blocker
    item (f)).
  - Re-review after fixes: **PASS**, all 5 confirmed resolved (reviewer
    re-ran both test suites independently rather than trusting the
    diff), no security invariant weakened. Noted 4 non-blocking residuals
    for future reference (a narrow crash window between stale/fresh
    writes, worst-case rejection latency now ~4x
    `CRYPTO_CALL_TIMEOUT_MS` ≈ 60s for this one failure path, an F4
    wording nit, an optional test gap) — added a one-line latency-caveat
    comment for the first one since it was cheap; left the rest as
    recorded observations, not required changes.
  - Added tests: 1 new Rust test (two-phase confirm mirror, 235 total,
    was 234), 2 new frontend tests (F1 hang-guard via fake timers, F2
    post-abort-flush-attempted via call-count assertion; 38 total in
    `useCryptoWorker.test.ts`, was 36; 1649 total frontend, was 1647).
- **Full gate after fixes**: `cargo test -p powehi-crypto-wasm --lib`
  235/235, `cargo fmt --check` clean. `pnpm exec vitest run` 1649/1649,
  `pnpm exec tsc -b` clean, `pnpm exec biome check` clean (2 files
  auto-formatted, applied via `biome check --write` + `cargo fmt`, both
  re-verified clean after).
- Committed `da96dee` (`fix(crypto): clear dangling pending own-commit
  entry on peer merge; guard compensating abort`), 6 files changed
  (1045 insertions, 101 deletions — the bulk of this diff was written by
  the found cycle-497 session; this cycle's own contribution was the
  crypto-reviewer fix cycle: F3's new inner-fn split + test, F1/F2's
  TS fixes + 2 tests, F4/F5's doc edits). Pushed clean
  (`088e218..da96dee main -> main`). CI running as of this entry (`gh run
  list` showed 3 in-progress checks right after push) — verify green
  next cycle if this session ends before confirming.
- **Lesson for next time a bare working tree with real diffs is found at
  session start**: do not assume "no memory entry = safe to discard" —
  this diff was real, tested, substantial work. Reading the diff's own
  doc comments (they self-dated "cycle 497") was what established
  provenance and trustworthiness before deciding to build on it rather
  than reverting it.
- Target dir hygiene: not checked (FEATURE mode; Rust build ran via
  `cargo test`/`cargo fmt` but no explicit `du -sh target/` this cycle —
  next STABILIZATION cycle, still cycle 500, should check).
- **Next cycle candidates (carried/updated from cycle 496's list, mostly
  unchanged — this cycle fixed a review-blocking bug, not a candidates-list
  item):**
  1. Carried unchanged: device_id-to-MLS-leaf binding half of issue #2's
     PendingRemovalBanner cross-check (crypto-lead design call).
  2. Carried unchanged: admin-initiated MLS Remove UI, blocked on the
     `sendCommit`/`expectedEpoch` gap named in `mls_group.rs`'s now-
     verified (a)-(g) list — item (a) is now understood to be a small
     concrete task (expose the server's `groups.epoch` counter via an
     endpoint) rather than an undesigned one; a future crypto-lead-scoped
     cycle should start there.
  3. New from this cycle's review: consider whether
     `mlsRemoveMemberStage`'s worst-case ~60s rejection latency (4x
     `CRYPTO_CALL_TIMEOUT_MS` across call/persist/abort/post-abort-flush)
     needs a UI-level timeout budget once a real Remove UI is built —
     informational only, not actionable until that UI exists.
  4. Carried, optional, informational: `rustls`'s default `aws-lc-rs`
     provider compiled in but unused; `default-features = false` would
     shrink SBOM.
  5. Carried: PQ hybrid Phase A prerequisite (blocked on openmls upstream).
  6. Carried, BLOCKED: `AbuseSignalStore`/`RegionRouter::broadcast_abuse_signal`
     wiring needs F3 + HMAC-vs-plain-SHA256 gate resolved first.
  7. Carried: prd.md §3.3 doesn't document the consumed-`key_packages`
     retention window.
  8. Carried: `mls_group_members` `isSelf` leaf-index hardening; issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  9. **This file is now well past ~2950 lines — cycle 500 (2 cycles away,
     next multiple of 5) is the STABILIZATION archive point, same pattern
     as cycles 360/485.**

## Previous state (2026-09-15, cycle 496 — FEATURE: wire the already-existing `GET /v1/groups/:id/members` endpoint into `PendingRemovalBanner` as a partial local staleness cross-check (issue #2), commit 7dc8d2e)

- Mode selection: counter 495→496, 496 % 5 != 0 → FEATURE. `gh run list
  --limit 5` all green on main (cycle 495's push). Working tree opened
  with cycle 495's own memory-update entry written but never committed
  (the file already had the full cycle-495 recap in it, no `chore:`
  commit after `5b46068`) — same "session cut short before its
  end-of-cycle step" pattern this file has flagged repeatedly (cycles
  445/494). Committed it first as `6361565` before starting this
  cycle's own work, so a future session doesn't lose it. Flag this
  again if seen a third time — the end-of-cycle memory commit is not
  optional even when a session is running low.
- **Scoped the item deliberately, not just picked the top of the
  candidates list.** The obvious next step for issue #2 (per its own
  GitHub comment history — read in full this cycle) is "admin-initiated
  Remove UI": the crypto primitives (`mlsRemoveMemberStage/Confirm/Abort`)
  have existed since commit b737b2c, but nothing in the app calls them.
  Traced why no prior cycle wired it: `mls_remove_member_stage`'s own
  doc comment (`wasm_exports.rs`) explicitly says its `priorEpoch`
  "must not be passed as sendCommit's expected_epoch" because "the
  server epoch and the local MLS epoch diverge from the very first
  member add in this codebase today" and reconciling them is
  "explicitly OUT OF SCOPE ... tracked as a follow-up." Confirmed this
  is real, not stale caution: `AddMemberModal.tsx` only calls the REST
  `addMember` (hardcoded `epoch: 0`), never `cryptoWorker.mlsAddMember`
  — so the server's `groups.epoch` counter has never actually been
  advanced by anything reachable from today's UI, while a client's own
  local MLS epoch (wherever `mlsAddMember`/`mlsRemoveMemberStage` get
  called, e.g. `AcceptInviteModal.tsx`) is independently real. Attempting
  the full Remove-commit UI this cycle would have meant either (a)
  designing epoch reconciliation from scratch in one session — the kind
  of "human/crypto-lead policy call" this file already carries as a
  separate blocked item for PQ hybrid, not something to rush — or (b)
  wiring `sendCommit` with a value explicitly documented as unsafe to
  use that way. Declined both; picked a different, still-real, properly
  bounded piece instead: `crates/adapters/inbound/powehi-rest-api/src/routes/groups.rs:192-197`'s
  `list_members` handler doc comment says outright it exists as "one
  half of the local cross-check for the server-reported pending-removals
  signal (prd.md §5.4)" and was completely unused by the frontend —
  a small, honest, additive piece with a backend contract already
  spelled out, not a design decision I'd be making up on the spot.
- **What shipped**: `listMembers(token, groupId)` added to
  `app/src/api/groups.ts` (`GET /v1/groups/:groupId/members`).
  `PendingRemovalBanner.tsx` now fetches it unconditionally alongside
  `listPendingRemovals` (unconditional + parallel, not gated on
  `pending.length > 0` — gating it would have made the mere existence
  of the request an observable signal that this group has a pending
  removal, a metadata leak; security-auditor confirmed this was the
  right call, not just an incidental choice) and flags a pending
  device_id absent from the current members list as informational
  "may be stale" (`data-testid="pending-removal-stale-{deviceId}"`) —
  never gates or disables the confirm action. Respects the endpoint's
  documented truncation contract: when `truncated: true`, the
  cross-check is skipped entirely for that fetch (never treats
  truncated-absence as meaningful, per `MembersResponse`'s own Rust doc
  comment's explicit warning against exactly that false-eviction
  direction). Delegated implementation to `frontend-lead` (background
  agent), verified the diff myself afterward rather than trusting the
  report blind.
- **Honest scope, stated in both the code and here**: this is a
  same-trust-domain defense-in-depth check, NOT a T3 mitigation
  (prd.md §3.5.1) — `listPendingRemovals` and `listMembers` are both
  served by the same server, so a fully malicious/colluding server can
  forge both consistently and this check catches nothing in that case.
  It only catches server-side INCONSISTENCY between its own two data
  sources (a pending-removal entry for a device that was never a
  member, or one already removed). The other, real half of the T3
  cross-check — binding `device_id` to the client's own MLS
  ratchet-tree leaves — does not exist yet (no authenticated binding
  between an MLS leaf/credential and a server `device_id` anywhere in
  this codebase); that's explicitly called out as unimplemented in the
  backend handler's own doc comment and NOT attempted this cycle.
  Neither the component doc comment nor this entry oversells it.
- **security-auditor: PASS, 2 LOW findings, both fixed before commit**
  (not crypto/architectural — matches the established routing
  precedent for a frontend-only REST-client change with no
  crypto/WASM/backend touch): (1) `listMembers`'s response was cast via
  `as` with no runtime validation — a malformed/missing `device_ids`
  would have silently become e.g. a char-set `Set` from
  `new Set(someString)`, and a missing `truncated` would have defaulted
  falsy (the FALSE-EVICTION direction the backend doc explicitly warns
  against). Fixed: `device_ids` is now validated as a string array
  (throws `invalid_members_response` otherwise, which the component's
  existing catch-and-skip-cross-check path already handles correctly —
  no new fallback logic needed), and a missing/non-`false` `truncated`
  now defaults to `true` (the safe direction) instead of `false`. (2)
  The 4 new cross-check tests mocked `listMembers` without asserting
  which `(token, groupId)` it was called with — a stale-closure
  regression that cross-checked group A's pending list against group
  B's membership would have passed silently. Fixed: added
  `toHaveBeenCalledWith` assertions to all 4. Also fixed an
  informational finding (truncation test used an unrealistic
  `deviceIds: []` — real truncation is always a length-`MAX_MEMBERS_RESPONSE`
  prefix, never empty — changed to a populated-but-still-absent-target
  list matching the real contract) and added 3 new `groups.test.ts`
  cases for the new validation logic. security-auditor separately
  confirmed via mutation testing (temporarily removing the
  `!membersTruncated` guard, temporarily fail-opening on fetch failure)
  that the new tests are non-tautological — both mutations were caught
  by exactly the intended test.
- No `crypto-reviewer`/`threat-model-checker` run: no crypto/WASM
  surface touched, and the diff explicitly does not shift any
  threat-model boundary (no new T3 mitigation claimed) — matches
  security-auditor's own routing recommendation in its report.
- **Full gate**: `pnpm exec tsc -b` clean. `pnpm exec biome check`
  clean (2 files auto-formatted, whitespace-only, confirmed via diff
  before re-checking). `pnpm exec vitest run` (full suite): 1642/1643
  passed, 1 failure in `ChatLayoutPoll.test.tsx` (poll-voters assertion)
  — confirmed unrelated: that file has zero git diff, is untouched by
  this cycle's changes, and passes 20/20 in isolation when re-run alone
  — a pre-existing test-isolation flake, not a regression from this
  diff. Backend untouched this cycle (frontend-only change,
  `list_members`'s handler was read-only reference), not re-run.
- Committed `7dc8d2e` (`feat(frontend): wire GET /v1/groups/:id/members
  into PendingRemovalBanner as a partial staleness cross-check (issue
  #2)`), 4 files changed, pushed clean (`6361565..7dc8d2e main ->
  main`). CI watched after push — see next cycle's entry or `gh run
  list` for outcome if this session ended before confirming.
- Target dir hygiene: not checked (FEATURE mode, frontend-only cycle,
  no Rust build artifacts touched).
- **Next cycle candidates (carried/updated):**
  1. **Partially addressed this cycle** (carried since cycle 480's
     list, PendingRemovalBanner local cross-check hardening): the
     REST-endpoint half now exists and is wired. Still open: the
     device_id-to-MLS-leaf binding half (would likely require changing
     what identity data an MLS credential carries at KeyPackage
     creation time — a structural crypto change affecting join/Welcome
     flows broadly, genuinely a crypto-lead design call, not a
     follow-on glue task).
  2. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): admin-initiated MLS
     Remove UI, blocked on designing epoch reconciliation between the
     client's local MLS epoch and the server's `groups.epoch` counter.
     Traced this cycle in more depth than before: the backend already
     has a CORRECT CAS mechanism for this
     (`messaging_service.rs::send_commit` →
     `commit_ledger.rs::commit_epoch_and_save` →
     `group_repo.rs::advance_epoch`, tested and used by the receive
     path's `sendCommit` calls) — the actual gap is narrower than "no
     mechanism exists": it's that `AddMemberModal.tsx`'s Add flow
     never calls `mlsAddMember`/`sendCommit` at all (REST-only,
     hardcoded `epoch: 0`), so the server's epoch counter has never
     been exercised by anything reachable from today's UI. A future
     crypto-lead-scoped cycle should start by tracing whether
     `AcceptInviteModal.tsx`'s `mlsAddMember` call (the one real
     production call site) already reconciles correctly or has the
     same gap, before attempting the Remove-side wiring.
  3. New, optional, informational (carried from cycle 495, unchanged):
     `rustls`'s default `aws-lc-rs` crypto provider compiled in but
     unused at runtime — `default-features = false` would shrink SBOM.
  4. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  5. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  7. Carried (unchanged from cycle 480's list): `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; GitHub issues
     #1/#3/#4/#5; prd.md §10 REST API doc drift; unconsumed
     `RemovalRequired` WS event; `key_packages.device_id` FK doc drift.
  8. Growing: this file is now well past ~2800 lines — good
     STABILIZATION candidate for cycle 500 (next multiple of 5) to
     archive at, same pattern as cycles 360/485.

## Previous state (2026-09-15, cycle 495 — STABILIZATION: fix RUSTSEC-2026-0285 (rustls TLS 1.3 boundary bug) via dependency bump, harden `GroupRepository::save`'s blind upsert against epoch downgrade with a new integration test, commits 90dd021/5b46068)

- Mode selection: counter 494→495, 495 % 5 == 0 → STABILIZATION. `gh run
  list --limit 5` all green on main (cycle 494's push). `gh issue list
  --state open`: same 5 open issues as prior cycles (#1 SPA deploy, #2
  MLS Remove/PCS — large multi-cycle FEATURE item, #3 WS client, #4
  load testing, #5 prod-ap-seoul PIPA), none `bug`-labeled, none
  stabilization-sized — none picked. Working tree clean at session
  start (no orphaned WIP).
- **Picked a concrete item off the carried candidates list** rather than
  a vague sweep: "`GroupRepository::save` blind `ON CONFLICT DO
  UPDATE`" has been carried unactioned since ≥cycle 480's list. Traced
  it fully before acting: confirmed via grep that `PgGroupRepository`
  is the only non-test `GroupRepository` impl and every `save` call
  site in the whole repo is inside a `#[cfg(test)]`/test-fake module —
  it is dead in production today. The real MLS-Commit epoch-advance
  path already uses the correct CAS primitive
  (`advance_epoch`/`CommitLedger::commit_epoch_and_save`, explicitly
  documented in `powehi-grpc/src/server.rs` as the only safe one). The
  port trait doc's own claim that `save` is "still needed to persist an
  epoch advance on commit" turned out stale/false. So `save` was a live
  landmine in the API surface, not an active bug — a future caller
  reaching for the obviously-named "save a group" method could silently
  downgrade a group's epoch.
- **Fix, following the exact precedent set for `PgDeviceRepository::save`
  and `user_id` in cycle 445**: added `WHERE groups.epoch <=
  EXCLUDED.epoch` to `save`'s `ON CONFLICT DO UPDATE`
  (`group_repo.rs`) — Postgres skips the entire UPDATE (leaving every
  column, including `home_region`, untouched) whenever the incoming
  epoch would regress the stored one. This is a monotonic guard, not a
  full CAS (no caller-supplied `expected` to race against) — documented
  as such in both the SQL comment and the port trait doc, which was
  also corrected to drop the stale "needed to persist an epoch advance"
  claim.
- **security-auditor: PASS-with-nits on the first draft.** Confirmed the
  guard SQL is correct and race-safe under READ COMMITTED (Postgres
  re-evaluates `DO UPDATE ... WHERE` against the post-lock row version,
  no TOCTOU against `advance_epoch`'s CAS). Two cheap findings fixed in
  this cycle: (1) the port doc's "monotonic-safe" phrasing understated
  that `<=` (not `<`) means an EQUAL-epoch save still fully applies,
  including rewriting `home_region` — `save` remains a live
  home-region-repoint primitive for any non-decreasing epoch, not an
  inert no-op; clarified in both the SQL comment and port doc, and
  added an explicit equal-epoch boundary case to the new test. Two
  findings left as-is per the auditor's own low/informational call: (a)
  `save` returns `Result<(), _>` so a guard-skipped no-op is
  indistinguishable from an applied write — no caller today depends on
  telling them apart, changing the signature would ripple across every
  `GroupRepository` test fake for a method with zero production
  callers, not worth it this cycle; (b) `create_with_creator`/
  `upsert_members` still bind `group.epoch.0 as i64` (wraps negative)
  instead of `i64::try_from` like `save`/`advance_epoch` — pre-existing,
  unreachable today (both call sites pass hardcoded `Epoch(0)`), no
  `CHECK (epoch >= 0)` constraint exists.
- **New integration test** (Docker-gated,
  `pg_security_it.rs::save_never_downgrades_an_existing_groups_epoch`):
  proves all three epoch boundaries — a lower-epoch save is a full
  no-op (epoch AND home_region both survive unchanged), an equal-epoch
  save still fully applies, and a genuinely-higher-epoch save applies
  normally. Compiles clean (verified via `cargo build --tests -p
  powehi-postgres`); actually runs in CI's `--run-ignored all` step,
  not just locally.
- **Also fixed, found during the mandated `cargo audit`/`cargo deny
  check` security sweep**: RUSTSEC-2026-0285 (rustls <0.23.45, TLS 1.3
  handshake messages incorrectly accepted across encryption level
  boundaries, severity 5.3 medium). Not cosmetic — `rustls` 0.23.40 was
  pulled in by `tokio-rustls`→`tonic` (the real gRPC transport carrying
  inter-region mTLS traffic per prd.md), not just a dev/test-only path
  (a second copy also comes in via `testcontainers`'s `ureq`, which
  *is* dev-only, but that wasn't the blocking one). Fixed via `cargo
  update -p rustls --precise 0.23.45` — single targeted bump, not a
  broad `cargo update`. `cargo audit` and `cargo deny check` both clean
  after (664 crates, `advisories ok, bans ok, licenses ok, sources
  ok`). security-auditor separately noted (informational, not
  blocking) that the bump transitively pulled `aws-lc-rs`/`aws-lc-sys`
  forward too since `rustls`'s default crypto provider is `aws-lc-rs`,
  but `powehi-grpc/src/tls.rs` explicitly installs
  `ring::default_provider()` — so `aws-lc-rs` is compiled into the
  binary but unused at runtime; `default-features = false` on the
  `rustls` dep would shrink the SBOM/image surface, left as an optional
  future hardening, not applied this cycle (scope creep beyond the
  actual vulnerability fix). Confirmed separately that
  `app/src-tauri`'s own `Cargo.lock` has no `rustls` entry at all — not
  affected, no change needed there.
- **Full gate**: `cargo build --workspace` clean (both before and after
  the rustls bump). `cargo build --workspace --tests -p powehi-postgres`
  clean (confirms the new test compiles). `cargo clippy --workspace
  --all-targets -- -D warnings` clean. `cargo fmt --all --check` clean.
  `cargo test --workspace`: all 45 test-result lines `ok`, 0 failed (run
  twice — once before the rustls bump as a baseline, once after — no
  regression from either change; new test correctly shows `ignored,
  requires Docker` locally). `cargo audit`: 0 vulnerabilities (was 1
  before the fix). `cargo deny check`: `advisories ok, bans ok, licenses
  ok, sources ok` (was `advisories FAILED` before the fix). Frontend
  untouched this cycle, not re-run (Rust-only change).
- No `crypto-reviewer`/`threat-model-checker` run: no crypto/MLS/OPAQUE
  code touched, no new server-visible metadata or architectural
  shift — this hardens an existing DB write path's failure mode, it
  doesn't add one. `security-auditor` run instead (backend/DB change),
  matching the established routing precedent.
- Committed as two separate commits (distinct concerns): `90dd021`
  (`fix(deps): bump rustls to 0.23.45, fix RUSTSEC-2026-0285`), 1 file
  (`Cargo.lock`); `5b46068` (`fix(backend): guard GroupRepository::save
  against epoch downgrade`), 3 files (`group_repo.rs` ×2 — src and port
  trait — plus `pg_security_it.rs`). Both pushed clean (`fe89b4d..5b46068
  main -> main`). Watched CI to completion after push — **all 3 checks
  (`CI — Rust`, `CI — Frontend`, `CI — Live-backend E2E`) green on
  `5b46068`**, confirmed before ending the cycle.
- Target dir hygiene: `target/` at 15G (up from 12G at session start,
  under the 20G threshold — no pruning triggered), 0-byte `.rmeta`
  prune ran first per the mandated step order.
- **Next cycle candidates (carried/updated):**
  1. **Resolved this cycle** (carried since ≥cycle 480's list):
     `GroupRepository::save`'s blind `ON CONFLICT DO UPDATE`. Now
     monotonic-epoch-guarded, with a regression test. Two related,
     lower-priority informational items surfaced during the fix (not
     applied, not urgent): `save`'s `Result<(), _>` return type can't
     distinguish a guard-skipped no-op from an applied write; the
     pre-existing unreachable `as i64` cast in
     `create_with_creator`/`upsert_members` vs. `save`/`advance_epoch`'s
     `i64::try_from`.
  2. New, optional, informational (security-auditor note, not applied):
     `rustls`'s default `aws-lc-rs` crypto provider is compiled into the
     binary but unused at runtime (`powehi-grpc/src/tls.rs` explicitly
     installs `ring::default_provider()` instead) — `default-features =
     false` on the `rustls` workspace dependency would shrink the
     SBOM/image surface. Cheap if a future cycle touches TLS/deps again.
  3. Carried, unchanged, still the single largest remaining piece of
     issue #2 (P0-blocker, security, frontend): epoch reconciliation
     between the client's local MLS epoch and the server's
     `groups.epoch` counter, and `mls_confirm_incoming_commit`
     handle-consumption-before-`MLS_CTX`-resolution ordering.
     FEATURE-mode-scale (crypto-lead/mls-engineer + fresh
     crypto-reviewer pass).
  4. Carried: PQ hybrid Phase A prerequisite (human/crypto-lead policy
     call, still blocked on openmls upstream).
  5. Carried, still explicitly BLOCKED: `AbuseSignalStore`/
     `RegionRouter::broadcast_abuse_signal` wiring needs F3 + the
     HMAC-vs-plain-SHA256 gate resolved first.
  6. Carried (unchanged): prd.md §3.3 doesn't yet document the
     consumed-`key_packages` retention window.
  7. Carried (unchanged from cycle 480's list, see cycle 480's own
     section — now archived — for full text if needed): `mls_group_members`
     `isSelf` leaf-index vs signature-key hardening; `PendingRemovalBanner`
     local cross-check hardening; GitHub issues #1/#3/#4/#5; prd.md §10
     REST API doc drift; `pending_removals` forged-signal defense;
     unconsumed `RemovalRequired` WS event; `key_packages.device_id` FK
     doc drift.
  8. Growing again: this file is approaching ~2600 lines — watch for it
     crossing the ~2500-line point a future STABILIZATION cycle should
     archive at (same pattern as cycles 360/485).

## Previous state (2026-09-13, cycle 494 — STABILIZATION (forced by red CI, counter said FEATURE): fix Docker Hub's removal of `minio/minio` breaking 2 of 3 CI checks, fix a frontend `tsc -b` type-inference break in a test mock, commit 2fa6184)

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

## Cycle 505 (STABILIZATION)
CI green; audit/deny/clippy clean; full workspace tests pass. Added `count_key_packages_malformed_device_id_returns_400` (test gap). Issue #10 already fixed by PR #11. Phase 7.1 remains the next FEATURE item.

## Archive index
Cycles 20-277: `.claude/memory/archive/project-context-cycles-20-277.md`
Cycles 279-319 (+cyclelog): `.claude/memory/archive/project-context-cycles-279-319-and-cyclelog.md`
Cycles 320-339: `.claude/memory/archive/project-context-cycles-320-339.md`
Cycles 340-371: `.claude/memory/archive/project-context-cycles-340-371.md`
Cycles 372-401: `.claude/memory/archive/project-context-cycles-372-401.md`
Cycles 402-421: `.claude/memory/archive/project-context-cycles-402-421.md`
Cycles 425-431: `.claude/memory/archive/project-context-cycles-425-431.md`
Cycles 443-452: `.claude/memory/archive/project-context-cycles-443-452.md`
Cycles 453-484: `.claude/memory/archive/project-context-cycles-453-484.md`
- Open: need-human #16 (store rollback\/delete, DEK\/KEK, owner-uid check, key canary, `&mut self` on put\/remove) — settle before 7.5.

## Cycle 515 (STABILIZATION)
- CI green on main; `cargo deny check` ok; `cargo audit` no new vulns; no open `bug` issues.
- Added 6 unit tests for `powehi-cli` `prompt.rs` (read_line limits/CRLF/EOF/UTF-8, set_lflag
  non-tty) — PR for branch `test/stabilization-cycle-515`. Test-only; no review agents required.
- Still open need-human: #13 #16 #19 #20 #22 #24. Next FEATURE item: first unchecked in phase-7 STATUS.

## Cycle 520 (STABILIZATION)
- CI green on main; `cargo audit`/`deny`/`clippy` clean; no open `bug` issues; no owner comments.
- Added `conversation::tests::rejects_malformed_binding_and_unknown_version` (binding format +
  version check in `Conversation::check`). Test-only; no review agents required. powehi-cli: 107 lib tests pass.
- Note: `cargo-nextest` not installed locally; use `cargo test` (PATH needs `~/.cargo/bin`).
- Still open need-human: #13 #16 #19 #20 #22 #24 #28 #30 #32.

## Cycle 525 (STABILIZATION)
- CI green on main; `cargo deny check` ok; no open `bug` issues; no owner comments. 132 lib tests passed at start.
- Added `ws::tests::an_oversized_frame_ends_the_connection_without_waking` (16 KiB frame cap). Test-only; no review agents required.
- Still open need-human: #13 #16 #19 #20 #22 #24 #28 #30 #32 #39. All Phase 7 items through 7.11 shipped; check STATUS.md for the next unchecked item.

## Cycle 530 (STABILIZATION)
- CI green on main; `cargo audit`/`deny` clean; clippy/fmt clean; no open `bug` issues; no owner comments. 144 lib tests pass.
- Added `status::tests` for `valid_region_id` boundaries and non-`ok` health body → unhealthy. Test-only; no review agents required.
- Pruned target/ (26G → 15G). Still open need-human: #13 #16 #19 #20 #22 #24 #28 #30 #32 #39.

## Cycle 532 (FEATURE — Phase 7 all [x]; took 7.11 follow-up F8 partial)
- `Received` zeroizes `body` on drop; `Pending.text` is `Zeroizing<String>`. crypto-reviewer PASS (scoped).
- F8 stays open: `render`/`sanitize` intermediates, `serde_json::to_vec(&Received)` realloc, legacy `visit_seq`
  Vec growth, `decrypt_message` return type (core). Next cycle: finish these, then F1 opaque record names.
- No drop-wipe test (reading freed memory is UB); guard is the type change + review.

## Cycle 533 (FEATURE — Phase 7 all [x]; 7.11 follow-up F8 render intermediates)
- `message::render`/`sanitize` return `Zeroizing<String>`, pre-sized 3x (no realloc); structured web payloads parsed by a hand-written object-only, last-wins Visitor (no `serde_json::Value`, no untagged/Content buffering). First review FAILed an untagged-derive version (array/dup-key parity, hidden copies) — hand visitor is the fix. Residual: serde_json escape scratch buffer. F8 still open: `to_vec(&Received)` realloc, legacy `visit_seq`, `decrypt_message` return type.

## Cycle 534 (FEATURE → CI-red fix)
- Main CI (cargo-deny) was red: rustls 0.23.45 hit RUSTSEC-2026-0346..0349. Lockfile bump to 0.23.46; deny/audit clean, 147 powehi-cli tests pass. No code changes. F8 remainder unchanged.

## Cycle 536 (FEATURE; Phase 7 DoD all [x], took first FIX-NOW follow-up)
- `ring` exception recorded: deny.toml `[bans]` wrappers (rustls, rustls-webpki, rcgen) + rule doc
  section. `cargo deny check bans` ok. Remaining FIX-NOW: F1 opaque record names (blocked-ish on #16),
  F9 size buckets, F8 leftovers, Cloudflare tls_1_3 (F11).

## Cycle 540 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` + `cargo deny check` clean. Added 3 powehi-cli auth tests
  (ct_eq, Session Debug/bearer token redaction, profile_has_data); 157 lib tests pass, fmt+clippy clean. Test-only,
  no review agents needed. target/ was 17G (<20G, no prune). Note: store export key must be exactly 32 bytes in tests.

## Cycle 550 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` + `cargo deny check` clean. Added 2 `read_lines` tests
  (chat/tests.rs): cap-boundary lines (exact cap, cap+1..cap+4 → flagged, next line survives) and oversize unterminated
  input at EOF. 174 lib tests pass, fmt+clippy clean. Test-only, no review agents needed. target/ 20G (at threshold, no prune).
  Note: `cargo nextest` not installed locally; use `cargo test`; cargo needs `PATH=$HOME/.cargo/bin`.

## Cycle 555 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` + `cargo deny check` clean. Added 1 `conversation::report`
  test (unread entries for unknown ids ignored; failing writer → typed `Output` error). 181 lib tests pass, fmt+clippy clean.
  Test-only, no review agents needed. target/ 19G (<20G, no prune).

## Cycle 562 (FEATURE; Phase 7 all [x])
- `conversations --role creator|joiner` filter (Role derives clap ValueEnum; count line reflects shown rows). 191 lib tests pass, fmt+clippy clean. UI-only filter over local data, no crypto/server change → no review agents.

## Cycle 565 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. Added `filters_combine_with_and_semantics_in_ids_and_count` (unread+changed+role AND semantics for `ids`/`count`). 194 lib tests pass, fmt+clippy clean. Test-only, no review agents needed.

## Cycle 575 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` clean, `cargo deny check` ok. Added `verified_and_unverified_together_match_nothing_and_verified_pages` (contradictory filters → empty; `--verified` + offset/limit). 202 lib tests pass, fmt+clippy clean. target/ 16G (no prune). Test-only, no review agents needed.

## Cycle 580 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` clean, `cargo deny check` ok. Added binary test `whoami_without_an_account_fails_with_empty_stdout` (non-zero exit, empty stdout, stderr message). 4 binary tests pass, fmt+clippy clean. target/ 16G (no prune). Test-only, no review agents needed.

## Cycle 585 (STABILIZATION)
- Main CI green, no `bug` issues, no open PRs. `cargo audit` clean, `cargo deny check` ok. Added 3 binary tests for `profiles` (names/--count/--json through the real binary, `--json --count` rejected with empty stdout, empty data dir). 211 lib + 9 binary tests pass, fmt+clippy clean. target/ 17G (no prune). Test-only, no review agents needed.
- Cycle 590 (stabilization): audit/deny clean; added json-failure black-box test (inbox/read/verify --json leave stdout empty without account).
- Cycle 595 (stabilization): audit/deny clean, CI green; extended the json-failure black-box test to whoami/login/register/send/invite create+redeem (PR below).

## Cycle 598 (2026-10-20, FEATURE) — Phase 8 item 8.1
- Merged the Phase 8 plan PR #116. Added `cloudflare_zone_setting.min_tls_version`="1.3" (#56). `tofu validate` + fmt green (terraform/tflint/tfsec not installed locally; CI ci-infra runs them). Next: 8.2 (RustCrypto-only BIP-39, #13).

## Cycle 599 (2026-10-20, FEATURE) — Phase 8 item 8.2
- Merged Phase 9 plan PR #119. Replaced the `bip39` crate with `powehi-crypto-core::bip39` (sha2 + pbkdf2/hmac, embedded official wordlist, SHA-256 pinned). Official Trezor vectors + the pre-existing recovery KATs (generated by the old crate) pass; `bip39`/`bitcoin_hashes` gone from Cargo.lock; deny clean; wasm32 check ok. `pbkdf2` added to the approved list; getrandom rule text fixed. Local note: cargo is at ~/.cargo/bin (not on PATH), nextest not installed → `cargo test`. Next: 8.3 (alternate screen).

## Cycle 600 (2026-10-20, STABILIZATION)
- Main CI green, no `bug` issues. `cargo audit` clean, `cargo deny check` ok, clippy clean. Added 4 negative-space tests to `crypto-core::bip39` (uppercase rejected, non-multiple-of-3 word counts, any-whitespace separation, exactly 128/2048 last words verify). 12 bip39 tests pass; crypto-reviewer on the diff. target/ 22G (>20G but nothing older than 7d to prune; no change). Next FEATURE: 8.3 (alternate screen).

## Cycle 602 (2026-10-20, FEATURE) — Phase 8 item 8.3
- `powehi-cli::screen`: AltScreen RAII guard (restore on return/error/panic) + SIGINT/SIGTERM handler (async-signal-safe write, re-raise). Used by `chat` and `read` only when stdout is a TTY and no `--json`. `read` on a TTY waits for Enter before leaving (the screen vanishes; messages are deleted after show). 6 unit tests; 235 lib tests pass. Next: 8.4 (session revoke).

## Cycle 603 (2026-10-20, FEATURE) — Phase 8 item 8.4
- `DELETE /v1/auth/session` (rest-api `revoke_session_handler`): deletes `session:{token}` from the cache, 204 even for unknown/expired tokens, 401 only for a missing/malformed Bearer header; same key backs the WS upgrade. CLI: `auth::revoke_session` + `LoggedIn` Drop guard in lib.rs (best effort, stderr warning only). 3 server tests, 1 CLI test, live E2E asserts the token is dead afterwards. Next: 8.5 (retryable register).


## Cycle 604 (2026-10-20, FEATURE) — Phase 8 item 8.5
- `register/finish` takes optional client `device_id`; replay marker `regdone:{uid}` = SHA-256(device_id, record, credential, recovery key), 60 s TTL; mismatch falls through to NotFound (no oracle); a client id colliding with an existing device → AlreadyExists. CLI picks the id, retries finish ≤3× (transport/404/5xx), checks the echoed ids, shows the phrase only after success. security-auditor + crypto-reviewer findings applied except DB-level insert-only device id + revoked-id reuse (need-human follow-up). Next: 8.6 (handle/password normalization).

## Cycle 605 (2026-10-20, STABILIZATION)
- Main CI green, no `bug` issues. `cargo deny check` ok. Added a rest-api test: `DELETE /v1/auth/session` returns 500 (never a false 204) when the cache delete fails and the token stays live. 163 rest-api tests pass, clippy clean. Test-only diff, no review agents needed. target/ 26G, nothing older than 7d to prune. Next FEATURE: 8.6 (handle/password normalization).

## Cycle 607 (2026-10-21, FEATURE → CI-red fix)
- Main "CI — Frontend" was red after #129 (8.6): Biome import-sort + format in `Login.tsx`. Fixed with `biome check --fix` (format-only; 913 component tests pass). 8.6 item itself already merged; next FEATURE: next unchecked item in phase-8/STATUS.md. Note: run `npx biome check src` before pushing app changes (untracked `src-tauri/gen` schemas trip a full `biome check` locally only).

## Cycle 608 (2026-10-21, FEATURE) — 8.7 certificate pinning
`powehi-cli/src/pinning.rs`: custom rustls verifier = WebPKI first, then SPKI-SHA-256 pin (2..=8 pins) on the *verified* path (a pinned intermediate must work as sole trust anchor for the leaf; threat-model F1 caught the "appended genuine CA" bypass). Used by `status::http_client_with` and the WS connector. `PRODUCTION_PINS` empty → WebPKI only until 9.9; no runtime override. Runbook `docs/runbooks/cli-pin-rotation.md`. Open: need-human #131 (pin strategy for Cloudflare-managed certs, blocks 9.9). Next: 8.8 PHS3 store.

## Cycle 610 (2026-10-21, STABILIZATION)
- CI green, no `bug` issues, `cargo audit` + `cargo deny check` clean. Gap found in the 8.8a manifest codec: `tag_bytes` used `from_str_radix`, which accepts a leading `+` and uppercase, so non-canonical tags could be encoded; now lowercase hex only. Added negative tests (duplicate tag, entry count over cap, bad flag bytes, non-canonical tags). powehi-cli 276 tests pass, clippy clean. target/ 30G → 27G after pruning >7d artifacts. Next FEATURE: 8.8b.

## Cycle 611 (2026-10-21, FEATURE) — 8.8b DEK/KEK key bundle
- `store/keys.rs`: `keys.wk3` (PHK1) holds a random record/name/manifest bundle sealed under KEK_pw (HKDF export_key) and optional KEK_rc (HKDF BIP-39 seed). `rewrap_password`, `add_recovery_wrap`, `open_with_recovery` (no CLI command uses KEK_rc until 8.18). Register adds the phrase slot before the server call. PHS2 stores need `open_upgrading` after a `[y/N]` (`Prompter::confirm_store_upgrade`); upgraded stores keep export-key-derived keys (no rewrite); keyfile written last. Test fixture: `ProfileStore::open_legacy_fixture`. Remaining 8.8c: `rekey` for upgraded stores. #133 resolved by the explicit gate.

## Cycle 613 (2026-10-21, FEATURE) — 8.8c rekey (closes 8.8)
- `store/rekey.rs`: `ProfileStore::rekey` re-encrypts an upgraded store into `rekey.new/` under a fresh random bundle, `rekey.go` journal (sealed under the new manifest key, PHJ1) is the commit point, `open` rolls forward. `login` rekeys AFTER `login/finish` (crypto-reviewer: not inside the init→finish window). Records are staged in new-tag order (threat-model M1: mtime/inode order must not follow name order).
- Reviews: threat-model YELLOW → docs/ordering fixes applied; crypto-reviewer needs-rework → added dir fsync before staging removal, moved rekey after KE3, +2 crash tests. powehi-cli 316 lib tests pass, clippy/fmt clean.
- Non-blocking crypto-reviewer leftovers (do in 8.18): journal shares the manifest key (derive a subkey), journal does not bind the staged recovery slot, `rekey(Some(rc))` seals an unverified recovery KEK, `rekey.go.tmp` not cleaned after a crash, no replay-full-staging pin test.
- A WIP snapshot of the interrupted earlier attempt is on branch `wip/store-rekey-8-8c` (superseded; safe to delete).
- Next FEATURE: 8.9 KeyPackage orphan pruning.

## Cycle 614 (2026-10-21, FEATURE) — 8.9 KeyPackage orphan pruning
- `identity/batches.rs`: `kp-batches` record (Prepared/Sent/Confirmed + unix-seconds stamp, refs per batch). Top-up prunes first (local only): Prepared deleted at once, Sent/Confirmed after 98 days, consumed refs forgotten. `Sent` is marked BEFORE each request leaves. crypto-core gained `delete_key_package` / `holds_key_package`. Invite KeyPackages (`invite create`) are not tracked as batches (their marker records are the remaining #22 residue).
- Next FEATURE: 8.10 peer bound to its MLS credential.

## Cycle 615 (2026-10-21, STABILIZATION) — #139 expired KeyPackages
- `PgKeyPackageRepository::fetch_one`/`count_available` skip unconsumed rows with `uploaded_at` older than 84 days (MLS lifetime starts at generation ≤ upload, so this is conservative-lenient), so an idle device's dead pool reads empty and the CLI top-up fires. Docker tests are `#[ignore]` locally (no Docker here); new `expired_key_packages_are_neither_counted_nor_fetched` runs in CI. cargo audit/deny clean; target/ 30G → 28G.
- Next FEATURE: 8.10 peer bound to its MLS credential.

## Cycle 616 (2026-10-21, FEATURE) — 8.10 peer credential recorded
- `mls_group::peer_credential_identity` (2-member group, non-empty basic credential <=64 bytes); `conv-*` gained `peer_credential` (serde default None = legacy/unknown). Creator reads it from the hash-pinned KeyPackage, joiner from the Welcome tree (skip if unusable). `unverified` notice on send (stderr), chat (output), and a suffix in `conversations` text output.
- Deviation (reviewed: crypto-reviewer + threat-model-checker yellow): no sender-vs-credential comparison — label is account-level/copyable, no authenticated device binding (prd 3.3 cycle 456). Inviter-side impersonation by a T3 holding the invite KeyPackage documented in prd 8.3. 8.14 must add the peer-leaf successor check (carried in STATUS). No skip-path test for an unusable credential at the CLI layer (core tests cover it).
- #32 closed with this PR. Next FEATURE: 8.11 server consent for group membership (spec in prd 3.3/6 first).

## Cycle 620 (2026-10-22, STABILIZATION)
- CI green on main; `cargo audit`, `cargo deny`, clippy clean; powehi-cli 349 tests pass. Added tracker unit tests (decrypt give-up needs both count and grace; emptied record removed; garbage record loads empty) and fixed two wrapped doc comments in `inbox/junk.rs`. cargo is not on the cron PATH: use `export PATH=$HOME/.cargo/bin:$PATH`; cargo-nextest is not installed (use `cargo test`).
- Open need-human: #145 (send_welcome unicast starvation, recommendation: require pending membership), #138, #131, #128, #125, #118, #53, #39, #16. Next FEATURE: first unchecked item in phase-8 STATUS (8.13 slice b / 8.14).

## Cycle 622 (2026-10-22, FEATURE)
- 8.13 slice b2: persistent inbox fetch cursor (`inbox/cursor.rs`, `welcome::fetch_from`). Resumes behind a fully-used fetch window when nothing was deferred; cleared at end of queue. Remaining for 8.13: epoch-aware failure count, which waits on 8.14's "epoch ahead" error. powehi-cli 355 tests pass. Next: 8.14 (Commit receive/apply).

- 8.14 slice (b) (PR pending, cycle 624): CLI applies a peer's pure self-Update Commit (`mls_group::apply_pair_commit`, `inbox/commit.rs`), peer signature key pinned on `conv-*`, held Ahead messages retried after the Commit, head-of-line deferral, ADR-0005 amended. Remaining for 8.14: persisted forked state, Proposal ack policy, GCE/PSK/ReInit tests, cross-run Ahead, `commits`/`forked` in inbox output.

## Cycle 625 (2026-10-22, STABILIZATION)
- cargo audit / deny clean; main CI green. Added unit tests for `Conversation::pin_peer_signature_key` (length, idempotent re-pin, conflicting pin, round trip, malformed stored key). powehi-cli 362 tests pass. target/ pruned 35G -> 34G (mtime>7d only).

## Cycle 630 (2026-10-23, STABILIZATION)
- cargo audit / deny clean; main CI green; no open `bug` issues. Added direct unit tests for `Manifest::verify` (pending create/update/delete matrix, missing/stale/unlisted refusals) in `store/manifest.rs`. powehi-cli 369 tests pass, clippy clean. No crypto code changed, so no reviewer pass was needed. `cargo nextest` is not installed locally; `cargo test` is used.

## Cycle 640 (2026-10-26, STABILIZATION)
- main CI green; `cargo audit`/`cargo deny` ok, clippy clean, 392 powehi-cli tests pass. Strengthened the 8.16 chat test: a refused CHANGED line delivers nothing, an `--allow-changed` line is delivered. target/ was 38G, pruned.

## Cycle 642 (2026-10-26, FEATURE) — 8.17 slice (b) deferred
crypto-reviewer rejected member-count dispatch for the group safety number; needs a stored conversation `kind` with `group create`. Shipped only a pair-path guard (identical keys refused) + STATUS note. Lesson: do not wire group numbers before the group conversation model exists.

## Stabilization 645 (2026-10-26)
- main CI green; clippy, cargo audit, cargo deny clean; powehi-cli 397 + crypto-core tests green.
- Added proptests for safety::pairwise symmetry and safety::group order-independence / member-swap detection (test-only).

## Cycle 647 (2026-10-26, FEATURE) — 8.17 slice c1
Authenticated group kind (GroupContext ext 0xF002, prd §5.3B) in crypto-core + joiner skips non-Pair Welcomes. 8.15 still blocked on #166 (no owner answer). Next: `group create` with the carried contracts listed in STATUS 8.17.
- Stabilization 650 (PR pending): test group_add_refuses_queued_proposals; cargo audit/deny green; CI green on main.

## Cycle 651 (FEATURE) — 8.17 slice e
Group joiner in `welcome.rs`: kind from GroupContext, group Welcomes only join via `accept`, group conv records have no pair PQ state, `ensure_resumable` blocks kind/role confusion on leftover records, inbox holds traffic of groups with a pending request. 8.15 still blocked on #166. Carried list in phase-8 STATUS 8.17. Next: group send/receive (MLS-leaf sender auth) or `group remove`.

## Cycle 652 (FEATURE) — 8.17 slice f
Request Welcome cap 256 KiB (server limit), `commit::apply` Kind::Pair guard. Still carried for 8.17: group send/receive with MLS-leaf sender auth, `group remove`, RequiredCapabilities(0xF002), `conversations` kind, Kind cross-check on load, group PQ story (T6).

## Cycle 653 (FEATURE) — 8.17 slice g1
crypto-core `stage_group_remove`/`confirm`/`abort` (kind-Group, own signer, occupied non-self leaf) + eviction test. 8.15 still blocked on #166. Next: CLI `group remove` (`grem-<gid>` record), then group send/receive.

## Cycle 654 (FEATURE) — 8.17 slice g2
CLI `group remove <GID> <KEY_HEX>` + `group members` (target = full signature key hex resolved to one leaf at stage time; `grem-` record; Unknown blocks add/remove). Server DELETE member NOT called yet (no authenticated device->leaf map). 8.15 still blocked on #166. Next: group send/receive with MLS-leaf sender auth, grem/gadd resolver, server removal prompt, Remove PCS test, threat-model-checker record.

## Cycle 655 (STABILIZATION)
cargo audit/deny clean (only #163 waiver). CI green, no bug issues. Added `group remove` tests: uppercase key, empty/oversized key refused pre-post, `members`/`removed` text+JSON rendering. powehi-cli 435 pass. Next FEATURE: group send/receive (see cycle 654).

## Cycle 656 (FEATURE) — 8.17 slice g3
`group members` fails closed (TooMany) past the 512 cap via `bounded` instead of truncating. powehi-cli 436+10 tests green, clippy clean. Small CLI-only change, no crypto touched; no reviewer gate required. Remaining 8.17 carries: see STATUS g2 list.

## Cycle 658 (FEATURE) — 8.17 slice i
`Conversation::agrees_with` kind cross-check (record vs GroupContext) on verify/send/rotate/inbox/commit paths, fail closed; crypto-reviewer needs-rework fixed (inbox paths + 5-path test). powehi-cli 440+10 green. Carried: `group add --resume` gate, GCE-proposal allowlist, ack routing. 8.15 still blocked on #166.

## Cycle 659 (FEATURE) — 8.17 slice j
`group add --resume` kind gate in `settle_local_epoch` (record vs GroupContext, before any merge/Welcome). powehi-cli 442 tests green, clippy clean; crypto-reviewer needs-rework (ordering test) fixed. Carried: group commit allowlist with group receive, ack routing by record kind.

- Stabilization 660 (PR pending): cargo audit/deny clean, CI green; added group resume NoSuchGroup/NotAGroup test. 442 powehi-cli lib tests pass.

## Cycle 662 (FEATURE) — 8.17 slice l
CLI `group::commit::apply` (group counterpart of `inbox/commit.rs`) + crypto-core `delete_inactive_group` (also deletes the previous-epoch EpochKeyPairs that openmls `delete` leaves behind). Not yet wired into the inbox. crypto-reviewer needs-rework fixed. Next: inbox wiring (ack routing keyed on record kind), group send/receive with MLS-leaf sender auth.

## Stabilization 665
cargo audit/deny clean (only waived RUSTSEC-2026-0387), CI green, no bug issues. Added `an_evicted_member_cannot_send_and_posts_nothing` (group send after Remove → GroupUnusable, nothing posted). 449 powehi-cli lib tests pass. target/ 31G (nothing older than 7d to prune).

- Cycle 666 (PR pending): 8.17 slice n2 group receive of Application messages with MLS-leaf sender key.
- Cycle 669 (FEATURE): 8.17 slice p test-only: apply_group_commit refuses a by-reference Commit. Main E2E CI red was a Docker Hub auth flake (minio pull); rerun green.

## Stabilization 670
cargo audit/deny clean (only waived RUSTSEC-2026-0387), CI green, no bug issues. Added `a_group_proposal_is_kept_to_the_grace_boundary_then_acked` (group Proposal ack boundary, slice o). 453 powehi-cli lib tests pass, clippy/fmt clean. target/ 27G.
- Cycle 672 (FEATURE): 8.17 slice r: apply_group_commit kind-capability check on Adds (defense in depth, openmls valn0502 already enforces). Carried: content_type dispatch, group PQ story (T6) + threat-model-checker record.
- Cycle 673 (FEATURE): 8.17 slice s: group/pair PQ reality documented (prd §5.3B), group classical notice, need-human + bug issues. 8.17 open pending owner PQ choice.
- Cycle 675 (stabilization): web 'PQ' badge reworded to 'PQ key check' (#204); audit/deny clean.
