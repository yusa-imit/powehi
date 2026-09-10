use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    key_package::{ConsumeResult, KeyPackage, KeyPackageId},
};

#[async_trait]
pub trait KeyPackageRepository: Send + Sync {
    async fn save(&self, kp: &KeyPackage) -> Result<(), DomainError>;
    /// Atomically fetch one unconsumed KeyPackage and mark it consumed.
    async fn fetch_one(&self, device_id: &DeviceId) -> Result<Option<KeyPackage>, DomainError>;
    async fn count_available(&self, device_id: &DeviceId) -> Result<u64, DomainError>;
    async fn delete(&self, id: &KeyPackageId) -> Result<(), DomainError>;
    /// Mark a specific KeyPackage consumed by ID (cross-region dedup).
    /// Idempotent: returns AlreadyConsumed if already consumed, NotFound if absent.
    /// Callers MUST treat `NotFound` as fail-closed (never proceed with the Add)
    /// exactly like `AlreadyConsumed` — after `delete_by_device` runs on device
    /// revocation, a previously-consumed id now also reads back as `NotFound`,
    /// not `AlreadyConsumed`. The same is true after
    /// [`delete_consumed_older_than`](Self::delete_consumed_older_than) sweeps
    /// an old consumed row: this existence check is the one remaining reader
    /// of a consumed row, and this fail-closed contract is exactly why that
    /// sweep is safe to run (see its doc).
    async fn mark_consumed(&self, id: &KeyPackageId) -> Result<ConsumeResult, DomainError>;
    /// Delete every KeyPackage (consumed or not) belonging to `device_id` from
    /// the shared pool table. Called on device revocation so a revoked
    /// device's credential can never be handed out again via a stale
    /// `fetch_one`/gRPC `ConsumeKeyPackage` on this path. Does NOT cover
    /// invite-pinned KeyPackage copies (`InviteUseCase::revoke_invites_for_device`
    /// closes that separate path). Idempotent: a device with zero KeyPackages
    /// returns `Ok(0)`, not an error.
    async fn delete_by_device(&self, device_id: &DeviceId) -> Result<u64, DomainError>;

    /// Delete consumed KeyPackage rows uploaded before `older_than`, up to
    /// `limit` rows per call — the retention sweep for a long-carried Tiger
    /// Style "put a limit on everything" gap (see
    /// `bin/powehi-server/src/main.rs`'s background-job section for the
    /// caller): once `fetch_one`/`mark_consumed` flips `consumed = TRUE`, a
    /// KeyPackage is single-use and can never be handed out again (RFC 9420
    /// §10). The one remaining reader of a consumed row is
    /// [`mark_consumed`](Self::mark_consumed)'s own existence check, whose
    /// contract already requires callers to treat a row's absence
    /// (`NotFound`) exactly like `AlreadyConsumed` — so this sweep only ever
    /// turns one fail-closed outcome into another, never a new one. Unlike
    /// [`GroupRepository::sweep_stale_pending_removals`](crate::group_repo::GroupRepository::sweep_stale_pending_removals),
    /// there is no liveness/epoch gate here: `consumed = TRUE` alone is
    /// definitional proof the row is done, so age is the only predicate that
    /// matters.
    ///
    /// `older_than` is compared against `uploaded_at`, not against the moment
    /// a row became consumed (there is no `consumed_at` column) — a
    /// KeyPackage consumed the instant before its grace period elapses is
    /// swept immediately rather than held for a further grace window past
    /// consumption. Harmless per the fail-closed argument above.
    ///
    /// MUST NOT touch unconsumed rows regardless of age — an unconsumed
    /// KeyPackage is still available inventory for `fetch_one`/cross-region
    /// `ConsumeKeyPackage`, and deleting one out from under a device would
    /// silently shrink its replenishment pool.
    ///
    /// `limit` bounds a single call's blast radius the same way
    /// `sweep_stale_pending_removals`'s does; a truncated run is harmless and
    /// simply resumes on the next call (the caller in `main.rs` loops calling
    /// this until a short return signals the eligible set is exhausted, so
    /// throughput isn't capped at one batch per tick). Returns the number of
    /// rows deleted.
    async fn delete_consumed_older_than(
        &self,
        older_than: DateTime<Utc>,
        limit: u32,
    ) -> Result<u64, DomainError>;
}
