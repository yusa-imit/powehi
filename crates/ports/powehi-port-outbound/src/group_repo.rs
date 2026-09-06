use async_trait::async_trait;
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, Group, GroupId, GroupMember},
};

#[async_trait]
pub trait GroupRepository: Send + Sync {
    async fn save(&self, group: &Group) -> Result<(), DomainError>;
    /// Atomically advance `group_id`'s epoch by exactly 1, iff its
    /// currently-stored epoch equals `expected`.
    ///
    /// This is the only safe primitive for accepting an MLS Commit: two
    /// concurrent commits against the same epoch must result in exactly one
    /// accepted advance, never both (RFC 9420 requires exactly one Commit be
    /// applied per epoch — a home region racily accepting two would fork
    /// group state). [`GroupRepository::save`]'s blind upsert provides no
    /// such guarantee and MUST NOT be used to advance epoch.
    ///
    /// Returns `Ok(Some(new_epoch))` when the compare-and-swap succeeded.
    /// Returns `Ok(None)` when the group's stored epoch no longer equals
    /// `expected` (lost the race to a concurrent commit, or the caller's
    /// view of the epoch is stale) or when the group does not exist —
    /// callers must treat both as a rejection, not a 0-epoch success.
    async fn advance_epoch(
        &self,
        group_id: &GroupId,
        expected: Epoch,
    ) -> Result<Option<Epoch>, DomainError>;
    /// Insert a group row only if `group.id` is not already present.
    ///
    /// Returns `true` when a new row was created, `false` when the id already
    /// existed — in which case no column of the existing row is modified.
    ///
    /// This is the client-facing creation primitive. Unlike
    /// [`GroupRepository::save`] (a destructive upsert, still needed to persist
    /// an epoch advance on commit), it can never reset an existing group's
    /// `epoch`, `home_region` or `created_at`, so a caller that supplies another
    /// group's id cannot downgrade or hijack it.
    async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError>;
    /// Atomically create a group and add `creator` as its sole initial member
    /// in a single transaction.
    ///
    /// Returns `true` when a new group row was created, `false` when
    /// `group.id` already existed — in which case neither the group row nor
    /// `creator`'s membership row is touched. Unlike calling
    /// [`GroupRepository::create_if_absent`] followed by
    /// [`GroupRepository::add_member`] as two separate calls, a failure
    /// between the two (DB error, pod kill) can never leave a group row with
    /// zero members, which would otherwise be permanently unusable — every
    /// future `create_group` retry would hit the already-exists-and-not-a-
    /// member branch forever since nothing may add the first member once the
    /// group is known to exist.
    ///
    /// Implementors must bind the membership row's `group_id` to `group.id`
    /// (not to `creator.group_id`, which callers are expected but not
    /// enforced to keep equal) — this makes a caller-side mismatch between
    /// the two arguments inert instead of granting membership in whichever
    /// group `creator.group_id` happens to name.
    async fn create_with_creator(
        &self,
        group: &Group,
        creator: &GroupMember,
    ) -> Result<bool, DomainError>;
    async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError>;
    async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError>;
    async fn remove_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError>;
    async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError>;
    /// Returns all group IDs that `device_id` is a member of.
    async fn list_groups_for_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<GroupId>, DomainError>;
    /// Atomically upsert a group stub and insert all members in a single transaction.
    /// Uses ON CONFLICT DO NOTHING for both the group row and each member row, so
    /// re-syncing an already-known group is idempotent and safe under concurrent calls.
    async fn upsert_members(
        &self,
        group: &Group,
        members: &[GroupMember],
    ) -> Result<(), DomainError>;
    /// Record that `group_id`'s remaining members still owe an MLS Remove for
    /// `device_id`.
    ///
    /// Idempotent: implementors must use `ON CONFLICT DO NOTHING` (or
    /// equivalent) on `(group_id, device_id)` so a retried device revocation
    /// never fails, and so a retry cannot reset how long the removal has
    /// been outstanding (the original `created_at` must survive).
    ///
    /// Implementors MUST capture the group's CURRENT epoch atomically, in the
    /// same statement that inserts the row (e.g. a single
    /// `INSERT ... SELECT ... FROM groups`), never a separate read followed by
    /// a write — a read-then-write widens the window in which a concurrent
    /// Commit advances the epoch between the two, which would let
    /// [`GroupRepository::delete_pending_removal`]'s gate be satisfied by a
    /// Commit unrelated to this reminder even sooner. Doing the read and
    /// write atomically only narrows that window (see
    /// `delete_pending_removal` below for why the gate cannot fully close it
    /// regardless — the server cannot see Commit contents at all). A
    /// `group_id` naming no existing group row records nothing and is
    /// `Ok(())` — there is no group whose members could owe the Remove.
    ///
    /// Implementors MUST NOT add a foreign key from `device_id` to
    /// `devices(id)`. This row is written as part of deleting that very
    /// device row, and it must survive that deletion — that's the entire
    /// point of the table. `group_members.device_id` already cascades on
    /// device delete, which is why the server loses its own membership
    /// record and needs this durable, independent reminder instead. This is
    /// a notification, not a security control: the actual revocation
    /// controls (KeyPackage + invite deletion, session invalidation) are
    /// enforced elsewhere and are unaffected by this table's contents.
    async fn create_pending_removal(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError>;
    /// Clear a previously-recorded pending removal, once some client has
    /// landed the corresponding MLS Remove Commit and the server's own
    /// membership metadata reflects it.
    ///
    /// Idempotent: deleting a `(group_id, device_id)` pair that does not
    /// exist is a no-op success, not an error — callers must be able to
    /// retry this call freely.
    ///
    /// EPOCH-GATED, BUT A HEURISTIC, NOT A PROOF OF THE SPECIFIC REMOVE:
    /// implementors MUST only delete the row when the group's current epoch
    /// is strictly greater than the epoch captured at creation time (see
    /// [`GroupRepository::create_pending_removal`]). `groups.epoch` only ever
    /// moves via [`GroupRepository::advance_epoch`]'s CAS (directly, or
    /// through `CommitLedger::commit_epoch_and_save`) — i.e. only when *some*
    /// Commit was accepted — but the server cannot see Commit contents (RFC
    /// 9420 §6, §12.4), so this gate cannot tell "the Remove for THIS
    /// `device_id` landed" apart from "any unrelated Add/Update/Remove
    /// Commit landed since this row was written" (an ordinary self-Update,
    /// which RFC 9420 §12.1.2/§12.4.3 recommends clients send routinely for
    /// PCS, already satisfies it). Without this gate, any current member
    /// could erase the reminder for free merely by calling `remove_member`,
    /// which only touches `group_members` (pure server routing metadata) and
    /// is no evidence whatsoever that any Commit landed. With this gate, a
    /// current member can still erase the reminder without the requested
    /// Remove ever landing, but only at the cost of sending some Commit
    /// first — a heuristic that raises the cost above zero and suppresses
    /// the common case, not a cryptographic guarantee. The only party that
    /// can actually verify a leaf was removed is a client reconciling its
    /// own ratchet tree against the device list; this table exists to give
    /// that client something to reconcile against; it is not itself the
    /// enforcement.
    ///
    /// Consequently this call is a SILENT NO-OP (still returns `Ok(())`) when
    /// no epoch advance has happened yet. Callers MUST NOT read `Ok(())`
    /// from this method as "the reminder is gone", nor as "the Remove
    /// landed" even when it does delete the row — only
    /// [`GroupRepository::list_pending_removals`] tells you whether the row
    /// is still there.
    async fn delete_pending_removal(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError>;
    /// Returns the device ids still awaiting an MLS Remove in `group_id`, or
    /// an empty vec when none are pending.
    ///
    /// This is group-scoped metadata: callers MUST gate access on the caller
    /// currently being a member of `group_id` before exposing this list.
    async fn list_pending_removals(&self, group_id: &GroupId)
        -> Result<Vec<DeviceId>, DomainError>;
}
