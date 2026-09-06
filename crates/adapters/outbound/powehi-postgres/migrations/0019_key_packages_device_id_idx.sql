-- no-transaction
-- Backs the new `KeyPackageRepository::delete_by_device` cleanup
-- (`DELETE FROM key_packages WHERE device_id = $1`, cycle 447's device-
-- revocation fix). The table's only existing index —
-- `key_packages_device_unconsumed_idx ON key_packages(device_id) WHERE NOT
-- consumed` — is partial and cannot back this DELETE, since it must also
-- match already-consumed rows. Without a non-partial index, every device
-- revocation forces a full `key_packages` sequential scan (crypto-reviewer/
-- security-auditor finding, cycle 447): the table has no GC for consumed
-- rows, so it only grows over time.
--
-- CREATE INDEX CONCURRENTLY cannot run inside sqlx's default migration
-- transaction (Postgres forbids CONCURRENTLY in a transaction block
-- outright), hence `-- no-transaction` above, matching the 0011/0014/0016/
-- 0017 precedent. OPERATIONAL NOTE: if this build is interrupted, `IF NOT
-- EXISTS` makes a migration retry no-op past a resulting INVALID index —
-- run `DROP INDEX CONCURRENTLY key_packages_device_id_idx` manually, then
-- re-run migrations, to actually rebuild it.
CREATE INDEX CONCURRENTLY IF NOT EXISTS key_packages_device_id_idx
    ON key_packages(device_id);
