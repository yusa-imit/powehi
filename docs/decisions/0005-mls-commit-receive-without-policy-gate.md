# ADR-0005: MLS Commit Receive Path Uses the One-Shot Merge, With No Application-Level Policy Gate

## Status: Active

## Context

GitHub issue #2 (P0-blocker, security: "Client cannot evict a compromised
device: no MLS Remove commit path, PCS unattainable") required wiring peer
Commit processing into the live frontend for the first time. Before cycle
493, `useMessages.ts` and `useWelcomePoller.ts` ack-and-dropped every Commit
envelope — the crypto primitives existed (`mls_process_commit`, and the
two-phase `mls_inspect_commit` / `mls_confirm_incoming_commit` /
`mls_discard_incoming_commit` trio) but nothing in the running application
ever merged one, so Post-Compromise Security (PCS) was unreachable in
practice even though the crate-level unit tests proved it.

Two APIs already existed in `crates/client/powehi-crypto-wasm/src/wasm_exports.rs`
for merging an incoming Commit:

- **One-shot** (`mls_process_commit`): decrypts, validates, and merges
  unconditionally in a single call. No point in the call chain exposes the
  Commit's add/remove proposals or the committer's identity before merging.
- **Two-phase** (`mls_inspect_commit` → `mls_confirm_incoming_commit` /
  `mls_discard_incoming_commit`): stages the Commit and returns
  `StagedCommitInfo` (committer leaf index, add/remove proposals,
  `self_removed`) *before* merging, so a caller can run an application-level
  policy check and decide to confirm or discard.

The two-phase API was built specifically to enable a future policy gate
(e.g. "only an admin may remove members"). No such policy exists in this
codebase today — there is no admin/role concept anywhere in the group model.

## Decision

`useMessages.ts` (the per-active-group poll hook) calls the **one-shot**
`mls_process_commit` (exposed as `mlsProcessCommit`) unconditionally for
every Commit envelope belonging to its own `groupId`, in the same poll
cursor as its Application-message decrypt. Self-eviction is detected
afterward via a new export, `mls_group_is_active`/`mlsGroupIsActive`, which
reads openmls's own `group.is_active()` state rather than comparing leaf
indices (see "Why not `isSelf`" below). The two-phase trio remains built and
tested but is not called from any consumer loop.

## Rationale

### Why the one-shot API, not the two-phase trio

With no policy to evaluate between inspect and confirm, wiring the two-phase
API today would only be "inspect, then unconditionally confirm" — the same
outcome as the one-shot call, plus a real cost: a window between inspect and
confirm/discard where a staged commit handle exists and must be cleaned up,
which is an orphaned-resource risk if the caller crashes or the tab closes
in that window (`inspect_incoming_commit`'s doc comment: "discard is
quarantine, not undo" — a discarded/orphaned staged commit is not free to
retry). The one-shot call has no such window. The two-phase trio is kept
available, fully tested, for the day a real policy is designed — see
"Revisit" below.

### Why not gate on `isSelf` for eviction detection

`mls_group_members`'s `isSelf` field is a leaf-index comparison
(`leaf_index == own_leaf_index()`). RFC 9420 §12.3 requires Remove
proposals to apply before Add proposals within one Commit, and §12.1.1 has
Add fill the tree's leftmost blank leaf (`free_leaf_index()`, verified
against vendored openmls 0.8.1's `treesync/diff.rs`). A single "kick and
replace" Commit — Remove this device, Add a new member, both in one Commit
— therefore commonly reuses this device's just-vacated leaf index for the
new member. `own_leaf_index()` on the evicted handle still reports that
same (now reused) index, so `isSelf` reads `true` for the new member's row
and silently misses the eviction. `mls_group_is_active` reads openmls's own
group-active flag directly and has no such false negative. Regression
tests: `test_kick_and_replace_commit_reuses_vacated_leaf_defeats_leaf_index_self_check`
(`mls_group.rs`), `test_mls_group_is_active_inner_kick_and_replace_evicted_caller_returns_false`
(`wasm_exports.rs`).

## Accepted Risk (signed off, not an oversight)

This design has **no application-level veto point**: any current,
authenticated group member's Commit merges unconditionally. Three specific
consequences, verified rather than hand-waved:

1. **Remove is signaled to the victim only; Add is not signaled at all.**
   `mlsGroupIsActive` tells the evicted device itself (surfaced via
   `GroupRemovedBanner` in `ChatLayout.tsx`) but produces no diagnostic and
   no UI change for any bystander when a member silently adds an
   attacker-controlled device. Bystanders get only an indirect signal: the
   chat's Safety Number recompute (`chat.groupCommitVersion`, bumped by
   `useMessages.ts`'s `onGroupChanged` callback on every merged Commit,
   group or DM), which requires the user to actively re-verify.
2. **The Delivery Service's envelope ordering became a content-loss lever,
   not just a delay lever.** This group's `max_past_epochs(0)` discards the
   previous epoch's keys the instant a Commit merges. The client's only
   ordering evidence is the DS's own delivery order (prd.md §5.4 item 2,
   §4A.5). A DS that delivers a Commit ahead of a same-epoch Application
   message permanently and undetectably destroys that message.
   `useMessages.ts`'s single poll cursor plus head-of-line deferral (shared
   between Commit and Application, with a bounded, per-sender-capped
   reserved pool for Commit entries) prevents *accidental* client-side
   reordering but cannot prevent the DS from choosing this order
   deliberately. Tracked in prd.md §3.1 (T3 addendum) and §3.4.
3. **This is a T4-derived capability, not a T3 (server) capability.** The
   DS cannot construct a valid Commit — Commit acceptance requires a
   current member's signature, and the server never holds MLS LeafNode
   signing material (prd.md §3.3, "서버가 알지 못하는 것"). The unconditional-merge
   risk belongs to a compromised/malicious *member device* (T4), bounded by
   MLS's own membership authentication — not to the server operator.
   Tracked in prd.md §3.1 (T4 addendum).

None of the three change the confidentiality invariant (server never sees
plaintext). They are availability/integrity-adjacent gaps in what a
bystander's client can observe or trust — and are the necessary cost of
making PCS reachable at all, which was previously impossible (issue #2).

## Also decided in this pass: Proposal envelopes are acked, not withheld

An interim version of this wiring left standalone Proposal envelopes
permanently unacked, reasoning that a later `ProposalOrRef::Reference`
Commit would need the original Proposal envelope to still exist
server-side. This was verified incorrect and reverted: RFC 9420 §12.4
resolves a by-reference proposal against the **receiver's own local**
`MlsGroup::store_pending_proposal` state, never by re-fetching the original
envelope from the DS — and this codebase never calls
`store_pending_proposal` at all (`process_incoming_commit`'s doc comment,
item (e), `mls_group.rs`), so a by-reference Commit already fails
identically whether or not the Proposal envelope survives server-side.
Withholding the ack bought no safety and only grew an unbounded,
attacker-inflatable backlog (re-scanned from the head of the 30-day
retention window on every poll tick, chat switch, and reload). Both
`useMessages.ts` and `useWelcomePoller.ts` ack Proposal envelopes silently
again. Standalone Proposal *processing* remains unimplemented — a separate,
still-open follow-up.

## Revisit trigger

Re-evaluate this ADR — and switch the wiring from the one-shot
`mls_process_commit` to the two-phase trio — the day an application-level
policy for gating incoming Commits (e.g. admin-only Remove) is designed.
Until then, any new caller processing incoming Commits should match the
one production caller that exists (`useMessages.ts`), not introduce a
second, inconsistent policy.

## Consequences

- PCS (issue #2's stated goal) is now reachable by the running application,
  not just proven in crate-level tests.
- prd.md §3.1 gained a T3 addendum (delivery-order-based permanent message
  destruction) and a T4 addendum (membership integrity), §3.3's
  `envelope_acks` bullet gained a note on Commit ACK semantics changing
  from "polled" to "successfully merged locally", and §3.4 gained a
  paragraph on the same delivery-order risk.
- `docs/prd.md` and this ADR are now the canonical reference the
  `mls_process_commit`/`mls_inspect_commit` doc comments in
  `wasm_exports.rs` point to — keep them in sync if this decision changes.
