-- Automates the manual runbook step from 0011's OPERATIONAL NOTE (deferred
-- there as a next-cycle candidate, cycle 353). If 0011's `CREATE INDEX
-- CONCURRENTLY` was interrupted (deploy cancelled, connection dropped,
-- deadlock), Postgres leaves an INVALID index under that name; `IF NOT
-- EXISTS` then makes a migration retry no-op without rebuilding it. Without
-- this guard, 0013 would go on to drop the only good (two-column) index,
-- leaving every poll to seq-scan `envelopes`.
--
-- This runs as an ordinary transactional migration (a `DO` block requires a
-- transaction, and `CREATE INDEX CONCURRENTLY` forbids one — the two can't
-- share a file, which is why 0011 couldn't self-check). Placed strictly
-- between 0011 (create) and 0013 (drop) so a bad build aborts the whole
-- migration run here, before 0013 ever executes.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_index
        WHERE indexrelid = 'envelopes_recipient_created_id_idx'::regclass
          AND indisvalid = false
    ) THEN
        RAISE EXCEPTION
            'envelopes_recipient_created_id_idx is INVALID (0011''s CREATE INDEX CONCURRENTLY was likely interrupted) -- run `DROP INDEX CONCURRENTLY envelopes_recipient_created_id_idx` manually, then re-run migrations, before 0013 drops the fallback index';
    END IF;
END $$;
