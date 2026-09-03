-- Per-environment ownership marker for `sweep_orphaned_storage_objects`'s
-- `region_prefix` (`media/{region_id}/`), NARROWING (not closing) the
-- residual same-bucket-same-region_id gap left open by cycle 424's review
-- (threat-model-checker RED, fixed via `AppConfig::validate()`'s
-- dev-bucket-default guard — but that guard only catches "forgot to set
-- r2_bucket," not "two environments deliberately or mistakenly share the
-- same real bucket AND region_id"). This mechanism eliminates *mutual*
-- destruction between two colliding environments and gives the losing side
-- a loud, permanent detection signal (`gc_orphan_owner_mismatch`) instead
-- of silent data loss — but the WINNING side's sweep can still delete the
-- other, still-live environment's media as "orphans" indefinitely, since
-- its own Postgres genuinely has no row for them. Distinct real buckets per
-- environment remain a hard requirement; see prd.md §9.4.3 for the full
-- guarantee scope and `R2MediaAdapter::verify_region_ownership`'s doc
-- comment for the mechanism.
--
-- One row per region_id, generated once and never updated: the owner_id is
-- this environment's random claim over its region_prefix, persisted in
-- *this environment's own* Postgres — a different database per environment
-- by construction, so the value can never collide even when the bucket and
-- region_id do. `R2MediaAdapter::verify_region_ownership` races to claim
-- `{region_prefix}.owner` in R2 with a conditional (`If-None-Match: *`)
-- write the first time it runs, then re-checks the R2 copy against this row
-- on every subsequent sweep; a mismatch means some other environment
-- already won the claim, and the sweep refuses to delete anything that run.
--
-- The atomic `INSERT ... ON CONFLICT (region_id) DO UPDATE ... RETURNING`
-- in the adapter resolves the benign race of multiple replicas of the
-- *same* environment booting concurrently: `RETURNING` always yields the
-- one persisted value regardless of which replica's insert actually won,
-- so every replica agrees before any of them races for the R2 write.
CREATE TABLE IF NOT EXISTS media_region_owner (
    region_id  TEXT NOT NULL PRIMARY KEY,
    owner_id   UUID NOT NULL,
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
