-- no-transaction
-- Drops the now-superseded two-column index once the three-column
-- envelopes_recipient_created_id_idx (0011) is built and serving queries.
-- CONCURRENTLY for the same reason as 0011: avoid an ACCESS EXCLUSIVE lock
-- on envelopes for the drop's duration (a plain DROP INDEX takes one too,
-- if briefly — CONCURRENTLY avoids blocking concurrent polls even for that).
DROP INDEX CONCURRENTLY IF EXISTS envelopes_recipient_created_idx;
