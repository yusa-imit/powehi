-- Rollback for 0004_push_subscriptions.sql.
-- Verified by the rollback integration test (tests/push_subscription_repo_it.rs).
-- Kept outside migrations/ so sqlx's simple-migration scanner does not treat it
-- as a forward migration (the workspace uses up-only simple migrations).
DROP TABLE IF EXISTS push_subscriptions;
