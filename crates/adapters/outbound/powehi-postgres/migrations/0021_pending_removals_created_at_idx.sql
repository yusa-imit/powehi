-- Backs `GroupRepository::sweep_stale_pending_removals`'s
-- `WHERE created_at < $1` bound-scan (paired with the `ctid IN (SELECT ...
-- LIMIT $2)` per-tick cap — see the adapter impl), invoked by a daily
-- background sweep job. Without this index every tick degrades to a full
-- sequential scan of a table whose whole purpose (see 0020_pending_removals.sql)
-- is to accumulate rows until a group's members act — i.e. a table that is
-- expected to grow, not shrink, absent this sweep, so the scan only gets
-- more expensive over time if left unindexed.
--
-- Neither existing index can serve this predicate: `pending_removals_group_id_idx`
-- and the primary key `(group_id, device_id)` both lead with `group_id`, not
-- `created_at`, so a `WHERE created_at < $1` scan cannot use either as an
-- index scan on its own leading column.
CREATE INDEX IF NOT EXISTS pending_removals_created_at_idx
    ON pending_removals(created_at);
