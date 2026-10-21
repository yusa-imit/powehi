# Phase 8: CLI Hardening, Commit Path, Groups, Multi-Device

## Status: IN PROGRESS (owner decisions 2026-10-20)

**Priority rule**: this phase is the FEATURE-mode work queue. Take the first
unchecked item, in order. An item too large for one cycle ships in slices
(note each slice next to the item, as Phase 7 did); the box flips when the
last slice lands. The web client (`app/`) stays in maintenance (ADR-0006):
it changes only where a shared server or protocol change below requires it
(8.6, 8.11), never for new web UI. When every box below is checked, the queue
moves to `docs/phases/phase-9/STATUS.md` (real deployment, ADR-0007).

The order matters: 8.8 changes the profile store format, and later items add
new records to it, so it lands before them. The Commit path (8.14) comes
before PCS, the CHANGED block, groups and multi-device, which all build on it.

## Owner decisions (2026-10-20)

Given by the owner in an interactive session; each issue carries a comment
pointing here. Close the issue in the PR that finishes its item.

| Issue | Decision | Item |
|---|---|---|
| #56 | Edge `min_tls_version = 1.3` now (the web SPA is not deployed, #1) | 8.1 |
| #13 | Replace `bip39` with a RustCrypto-only BIP-39 now | 8.2 |
| #39-5 | Alternate screen buffer for `chat`/`read` | 8.3 |
| #39-4 | Add server session revoke; the CLI calls it on exit | 8.4 |
| #20 | Client-chosen `device_id` makes `register/finish` retryable | 8.5 |
| #19 | Handles ASCII `[a-z0-9-]`; passwords NFC, with a legacy login fallback | 8.6 |
| #39-3 | Certificate pinning: SPKI pin set plus a backup pin | 8.7 |
| #16, #39-1, #39-6, #53-2 | PHS3 store: MAC'd manifest + generation; DEK wrapped by an export_key KEK and a recovery-phrase KEK | 8.8 |
| #22 | Client-only orphan pruning (never-sent batches now; lost-response batches after 84 days + slack) | 8.9 |
| #32-1 | Bind the peer to its MLS credential; warn "unverified" on send until verified | 8.10 |
| #30 | Server consent before a device receives a group's traffic, plus client defenses | 8.11, 8.13 |
| #24 | Explicit `powehi accept` for Welcomes that are not from the user's own invite | 8.12 |
| #39-2, #32-3 | PCS in this phase: periodic self-Update Commits | 8.15 |
| #53-1 | Block send on CHANGED (`--allow-changed` override) once Commits apply | 8.16 |
| #28 | Keep warn-and-continue on an invalid inviter PQ key (current behaviour) | none |
| Scope | Add groups + Remove, multi-device + restore, full-screen TUI, media | 8.17–8.21 |

## Definition of Done (in order)

### Quick hardening
- [x] 8.1 Edge TLS 1.3 minimum (#56) — set Cloudflare `min_tls_version = "1.3"` in
  `infra/terraform/envs/cloudflare/main.tf` and drop the "owner call" comment there.
  Gate: `terraform validate`, `tflint`, `tfsec`, the `infra-test` skill.
- [x] 8.2 RustCrypto-only BIP-39 (#13) — replace the `bip39` crate in
  `powehi-crypto-core::recovery` with `sha2` + `pbkdf2` + `hmac` and the embedded
  BIP-39 English wordlist. Tests: the official BIP-39 test vectors (entropy →
  mnemonic → seed), checksum failure → typed error, and a phrase generated before
  the change still yields the same seed and the same MLS identity. `bip39` and
  `bitcoin_hashes` leave `Cargo.lock`; `cargo deny check` green. Also fix the
  `getrandom` feature name in `.claude/rules/crypto-libraries-pinned.md` (rule says
  0.3 `wasm_js`, code uses 0.2 `js`). WASM build + Vitest still green. crypto-reviewer.
- [x] 8.3 Alternate screen for `chat` and `read` (#39-5) — enter the alternate screen
  only when stdout is a TTY and `--json` is off; always restore it on normal exit,
  error, panic and SIGINT/SIGTERM. Tests: piped/`--json` output never contains the
  escape sequences; the restore path runs on error.

### Server and auth
- [x] 8.4 Session revoke (#39-4) — `DELETE /v1/auth/session` revokes the caller's
  bearer token (idempotent, 204; a revoked token is rejected on REST and on the `/v1/ws`
  upgrade). The CLI calls it when a command that logged in exits (best effort: a
  failure is a stderr warning and never changes the exit code). Tests on both sides.
  security-auditor.
- [x] 8.5 Retryable register (#20) — `register/finish` accepts an optional client-chosen
  `device_id` (UUIDv4). A retry with the same user, `device_id` and OPAQUE record
  returns the original response; a different record → conflict error. The CLI picks
  the id before `finish`, retries on a lost response, and shows the recovery phrase
  only after success. Requests without the field behave as today (web unchanged).
  security-auditor + crypto-reviewer.
  Shipped: the replay fingerprint binds device_id, record, credential and recovery key; a
  mismatch is indistinguishable from "no session" (no conflict oracle; deviates from the
  "conflict error" wording by audit finding); replay window 60 s. Follow-up: insert-only
  device id + revoked-id reuse (need-human issue).
- [x] 8.6 Handle and password normalization (#19) — registration accepts only handles
  matching `[a-z0-9-]` (server validation, CLI and web); login still accepts any
  existing handle unchanged so older accounts keep working. Passwords are NFC-
  normalized before OPAQUE in the CLI and the web; when the NFC form differs from
  the raw input and login fails, retry once with the raw input (legacy accounts).
  Shared test vectors (NFD input, U+FEFF / U+0085 trim cases) run in both Rust and
  Vitest and must give the same OPAQUE input. crypto-reviewer.
  Shipped: the server stores only `SHA-256(handle)`, so it cannot validate the charset;
  the CLI and web enforce it (deviates from "server validation"). Trim = White_Space + U+FEFF.
- [x] 8.7 Certificate pinning (#39-3, prd §3.1 T2) — SPKI SHA-256 pin set with at least
  one backup pin whose key is not deployed, enforced for reqwest and the WS client
  after normal WebPKI verification (a custom rustls verifier). Pins are compiled in;
  loopback/test servers use an explicit test-only override. First find out whether
  the edge certificate key is under our control (Cloudflare custom certificate) or
  Cloudflare-managed and rotating; if pinning the leaf is not workable, pin the
  issuing CA intermediates and record that in prd §3.1. If neither fits, open a
  `need-human` issue and move on. Tests: pinned key accepted, a valid but unpinned
  cert rejected, backup pin accepted. Add a rotation runbook to `docs/`. No domain or
  production certificate exists until Phase 9 (ADR-0007, issue #118), so ship the
  mechanism with test pins here; the production pin set is chosen in 9.9. The edge
  uses Cloudflare-managed certificates whose keys rotate.
  crypto-reviewer + threat-model-checker.
  Shipped: `pinning.rs` pins intermediates (Cloudflare leaf keys rotate); production set empty
  (WebPKI only) until 9.9; runbook `docs/runbooks/cli-pin-rotation.md`.

### Profile store v3 (PHS3)
- [x] 8.8 PHS3 store format (#16, #39 items 1 and 6, #53 item 2) — may ship in slices:
  (a) a MAC'd manifest that lists every record tag with its ciphertext hash and a
  monotonic generation, rewritten atomically on each mutation; `open` rejects a
  missing, extra, stale or swapped record with a typed error, so deleting
  `verified-<group>` is detected; (b) a random per-store DEK encrypts the records,
  wrapped by KEK_pw (from the OPAQUE export_key) and KEK_rc (from the recovery
  phrase). A password change rewraps only the DEK, and KEK_rc reopens the store if
  the server's OPRF key is regenerated. Profiles migrated from PHS2 have no KEK_rc
  until the user enters the phrase; (c) a per-store random salt for the record-name
  HMAC tags (the F1 follow-up deferred from Phase 7). PHS2 stores migrate when
  opened, as PHS1 did. Whole-store snapshot replay stays the accepted risk in prd §3.2.
  Tests: roll back one record, delete one, mix two snapshots, swap two records,
  migration, password-change rewrap, phrase unlock. Update prd §3.2/§7A.3.
  crypto-reviewer + threat-model-checker.
  Slice (a) shipped: `store/manifest.rs` (`manifest.mf3`, AEAD-MAC'd tag→SHA-256 list +
  generation, pending-entry crash recovery, `store-v3` latch against manifest deletion); PHS2
  stores are adopted at first open. Remaining: (b) DEK/KEK wrap, (c) per-store tag salt.
  Owner call on the interim downgrade window: issue #133.
  Slice (b) shipped: `store/keys.rs` (`keys.wk3`: random record/name/manifest bundle sealed under
  KEK_pw and an optional KEK_rc; `rewrap_password`, `add_recovery_wrap`, `open_with_recovery`);
  register adds the phrase slot; PHS2 adoption now needs `open_upgrading` after a `[y/N]`
  confirmation (closes the #133 window). Upgraded stores keep their export-key-derived keys (no
  record rewrite). New stores get a random name-tag key, which covers (c) for them. No CLI
  command uses KEK_rc yet (8.18 `restore`). Remaining slice (c): a `rekey` that moves an
  upgraded store onto a fresh random bundle (new tag key included), so a password change also
  retires the old export-key-derived keys.
  Slice (c) shipped: `store/rekey.rs` — `ProfileStore::rekey` re-encrypts an upgraded store into
  `rekey.new/` under a fresh random bundle (new tag key, so new file names), commits with the
  `rekey.go` tag journal, and `open` rolls the switch forward (idempotent; a crash before the
  journal discards the staging dir). `login` rekeys any store with derived keys and no recovery slot, so a password
  change then retires them. Stores with a recovery slot need the phrase KEK (left for 8.18): a recovery-opened handle cannot
  tell derived from random keys, so `rewrap_password` refuses it (`RekeyRequired`); 8.18's `restore`
  must persist or re-derive that fact before it rewraps, and needs a rekey that works without the
  old export key.
  Done condition for (b): remove the automatic PHS2 adoption (or gate it behind an explicit
  user action) so deleting the manifest + latch no longer downgrades the store (prd §3.2 ②).
- [ ] 8.9 KeyPackage orphan pruning (#22) — store a per-batch upload state
  (`prepared` → `sent` → `confirmed`). A batch never sent is deleted at once. A batch
  whose response was lost may already be live on the server, so it, like confirmed
  but unconsumed packages, is deleted only after 84 days + 14 days slack. Top-up
  prunes before checking the 400 cap. No new server-visible metadata. crypto-reviewer.

### Conversation trust
- [ ] 8.10 Peer bound to its MLS credential (#32 item 1) — at Welcome join and at
  redeem, take the peer identity from the peer leaf's credential and reject a
  Welcome whose server-reported sender does not match it; the `conv-*` record keeps
  the credential identity. `send`/`chat` print an "unverified" warning on stderr
  until `verify --confirm` is recorded, and `conversations` shows the state. Close
  #32 (items 2 and 4 were done in Phase 7; item 3 is 8.15). crypto-reviewer.
- [ ] 8.11 Server consent for group membership (#30 option 2, pairs with #24) — adding
  a device to a group creates a *pending* membership. A pending device receives only
  that group's Welcome, and the server neither stores nor fans out other traffic of
  the group for it until it accepts (or declines) through a new endpoint. A redeemed
  invite counts as consent for its own group. The web client calls accept right
  after it auto-joins (no UI change). Spec it in prd §3.3/§6 first.
  threat-model-checker (new server-visible state) + security-auditor.
- [ ] 8.12 Pending requests and `powehi accept` (#24) — `inbox` keeps Welcomes that are
  not for the user's own invite KeyPackages as pending requests (sender, group,
  received time; capped) in the store. `powehi requests` lists them, `powehi accept
  <id>` joins and calls the 8.11 accept, `powehi decline <id>` drops and declines.
  Invite Welcomes still auto-join. Close #24. crypto-reviewer.
- [ ] 8.13 Inbox flood defenses (#30 client part) — a persistent per-device fetch
  cursor in the store; envelopes for groups we neither hold nor have a pending
  request for are acked after a 24 h grace; envelopes from a known peer that fail to
  decrypt N times are acked and dropped; a per-conversation decrypt budget so one
  peer cannot starve the others. Test with a junk-flood fixture. Close #30.
  crypto-reviewer + security-auditor.

### Commit path, PCS, groups
- [ ] 8.14 CLI Commit receive/apply — incoming Commits apply through the ADR-0005
  one-shot merge; the epoch is persisted; the safety number is recomputed and the
  §5.6 CHANGED alert fires on a change. Tests across several epochs, including a
  Commit that arrives before the Application messages that follow it.
  crypto-reviewer.
- [ ] 8.15 Post-compromise security (#39 item 2, #32 item 3) — periodic self-Update
  Commits from `send`/`chat` (crypto-lead sets the policy, e.g. age or message
  count, and writes it in prd §5); concurrent-Commit handling per the §4A commit
  serialization. PCS regression test: a leaked epoch secret cannot read messages
  after the update. crypto-reviewer + threat-model-checker.
- [ ] 8.16 CHANGED blocks send (#53 item 1) — `send`/`chat` refuse a conversation
  whose verified safety number is CHANGED unless `--allow-changed` is given; the
  refusal says how to re-verify. Close #53. crypto-reviewer.
- [ ] 8.17 Groups of three or more and MLS Remove (#2, CLI side) — `group create`,
  `group add`, `group remove` with a real Remove Commit that advances the epoch;
  the group variant of the §5.6 safety number. A server `RemovalRequired` /
  pending-removal signal is shown as a prompt and never removes on its own (it is a
  request, not a proof: prd §3.5.1 T3). PCS regression test for Remove. The web
  side of #2 stays parked. crypto-reviewer + threat-model-checker.

### Multi-device and recovery
- [ ] 8.18 Recovery-phrase restore — `powehi restore` sets up a new machine from the
  recovery phrase: the MLS identity is phrase-derived, so the same signing key comes
  back, and a new device is registered. Old messages are not recoverable (forward
  secrecy); say so in the command output. If the server lacks a recovery route,
  spec it in prd first. crypto-reviewer + threat-model-checker.
- [ ] 8.19 Multi-device — link a second device to an account (the existing device
  approves; the new device is added to every conversation by Commit). Write the
  device-link flow in prd before the code, and open `need-human` issues for open
  policy calls (approval UX, device cap). Depends on 8.14 and 8.17.
  crypto-reviewer + threat-model-checker.

### TUI and media
- [ ] 8.20 Full-screen TUI — `powehi tui` (`ratatui`) on top of the same lib:
  conversation list, message pane, input line, unread / CHANGED / unverified
  markers, alternate screen, no message text in logs. Behaviour tests on the lib
  layer; a smoke test with a test backend.
- [ ] 8.21 Media send/receive (prd §9) — `send --file` and saving received media to
  `0600` files, encrypted per prd §9.2 and ADR-0004, with size caps.
  crypto-reviewer + security-auditor.

### Gates
- [ ] 8.22 E2E gate — extend `src/live_e2e.rs` and the `cli-live-backend` CI job:
  accept flow, a self-Update Commit, a three-member group with a Remove, a second
  device, and a media round trip.
- [ ] 8.23 threat-model-checker pass on Phase 8 as a whole; prd §3 and §7A updated.

## Not in Phase 8
- Web feature work and web↔CLI interop (web stays in maintenance).
- Issues #1, #3, #4, #5 (web deploy, web WS client, load test, Seoul region
  provider) stay parked under ADR-0006.
