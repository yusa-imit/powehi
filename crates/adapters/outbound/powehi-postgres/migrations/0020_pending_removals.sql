-- pending_removals: a durable "IOU" that outlives the device row it was
-- written for.
--
-- WHAT IT IS: two UUIDs and a timestamp. No key material, no ciphertext, no
-- PII — it records the fact "the remaining members of `group_id` still owe
-- an MLS Remove for `device_id`", nothing more. It is pure routing/
-- notification metadata: it grants no capability and cannot be replayed as
-- a credential by anyone. Only a client that already holds `group_id`'s MLS
-- group state can act on it, by constructing and sending the actual Remove
-- Commit — the server cannot do this itself (no group state, no keys), which
-- is precisely why this table exists instead of the server just performing
-- the removal.
--
-- WHY group_id CASCADES: if the group itself is gone, there is nobody left
-- to perform the Remove and the reminder is meaningless — it must be
-- garbage-collected along with the group it refers to.
--
-- WHY device_id DELIBERATELY HAS NO FOREIGN KEY (the entire point of this
-- table): a `pending_removals` row is written BECAUSE `device_id`'s device
-- row is being deleted as part of revocation. `group_members.device_id` DOES
-- cascade on `devices(id)` deletion — that is exactly why the server loses
-- its own membership record for the revoked device and needs a separate,
-- independent reminder that outlives it. An FK from `pending_removals.
-- device_id` to `devices(id)`, whether ON DELETE CASCADE or the default
-- RESTRICT, would destroy or block this row at the exact moment it becomes
-- necessary — CASCADE would delete the very reminder the device deletion is
-- supposed to create, and RESTRICT would prevent the device deletion (and
-- thus the revocation) from completing at all.
--
-- CONTRAST WITH the analogous case of `key_packages.device_id` (see
-- 0019_key_packages_device_id_idx.sql): there, a MISSING enforcement path
-- was the bug — stale KeyPackages survived device revocation and could
-- still be handed out to a peer trying to add the revoked device to a
-- group, so `KeyPackageRepository::delete_by_device` had to be added to
-- explicitly purge them. Here the absence of an FK is intentional and the
-- inverse situation: the surviving row is a notification, never a
-- credential. Losing it (via a CASCADE we didn't want) would silently drop
-- the one signal that tells remaining group members "go issue a Remove",
-- leaving a revoked device's leaf live in the MLS tree indefinitely.
--
-- LIFECYCLE: a row is written by `create_pending_removal` as part of device
-- revocation, and a caller REQUESTS it be cleared by calling
-- `delete_pending_removal` (wired to run after `remove_member`) — but the
-- request only takes effect once the epoch gate below is satisfied.
--
-- EPOCH GATE (`created_at_epoch`), A HEURISTIC, NOT A PROOF: `group_members`
-- is pure server routing metadata — calling `remove_member` only proves a
-- current member asked the server to stop routing to `device_id`, never that
-- anyone landed an MLS Remove Commit for it. So `delete_pending_removal`
-- cannot simply trust its caller: a row records the group's epoch at the
-- moment the reminder was written (`created_at_epoch`), and the delete only
-- takes effect once `groups.epoch` has advanced strictly past that value.
-- `groups.epoch` only ever moves via `advance_epoch`'s CAS (used directly, or
-- through `CommitLedger::commit_epoch_and_save`), i.e. only when SOME Commit
-- was accepted. That is as far as the server can see: it cannot read Commit
-- contents (RFC 9420 §6, §12.4), so it cannot tell the Remove this row asks
-- for apart from any unrelated Add/Update/Remove Commit landing afterward —
-- an ordinary self-Update (which RFC 9420 §12.1.2/§12.4.3 recommends clients
-- send routinely for PCS) already satisfies this gate. Without this gate, any
-- current member could erase the reminder for FREE merely by calling
-- `remove_member`, with zero Commits sent; with it, erasing the reminder
-- without the requested Remove ever landing still costs at least one Commit.
-- That is a noise-reduction heuristic, not a security control — the only
-- party that can actually verify a leaf was removed is a client reconciling
-- its own ratchet tree against the device list.
CREATE TABLE IF NOT EXISTS pending_removals (
    group_id          UUID        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    device_id         UUID        NOT NULL,
    created_at_epoch  BIGINT      NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, device_id)
);

-- Backs `list_pending_removals(group_id)`. The composite primary key
-- `(group_id, device_id)` already produces an index whose leading column is
-- `group_id`, so a lookup filtered on `group_id` alone can already use it —
-- this explicit index is therefore redundant with the PK index for that
-- query shape, not an additional capability. It is added anyway to keep
-- `pending_removals` consistent with every other table in this schema that
-- is looked up by a non-leading or non-PK column (e.g. `devices_user_id_idx`,
-- `key_packages_device_id_idx`): a plan-stability safety net if the PK's
-- physical representation or lookup column order ever changes, at the cost
-- of one small extra index to maintain on a table that is write-light.
CREATE INDEX IF NOT EXISTS pending_removals_group_id_idx
    ON pending_removals(group_id);
