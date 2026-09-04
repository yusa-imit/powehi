use async_trait::async_trait;
use chrono::{DateTime, Utc};
use powehi_domain::{
    device::DeviceId,
    error::DomainError,
    group::{Epoch, Group, GroupId, GroupMember},
    region::RegionId,
};
use powehi_port_outbound::group_repo::GroupRepository;
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::map_err;

#[derive(sqlx::FromRow)]
struct GroupRow {
    id: Uuid,
    home_region: String,
    epoch: i64,
    created_at: DateTime<Utc>,
}

#[derive(sqlx::FromRow)]
struct GroupMemberRow {
    group_id: Uuid,
    device_id: Uuid,
    joined_at_epoch: i64,
}

impl From<GroupRow> for Group {
    fn from(r: GroupRow) -> Self {
        Group {
            id: GroupId::from(r.id),
            home_region: RegionId::new(r.home_region),
            epoch: Epoch(r.epoch as u64),
            created_at: r.created_at,
        }
    }
}

impl From<GroupMemberRow> for GroupMember {
    fn from(r: GroupMemberRow) -> Self {
        GroupMember {
            group_id: GroupId::from(r.group_id),
            device_id: DeviceId::from(r.device_id),
            joined_at_epoch: Epoch(r.joined_at_epoch as u64),
        }
    }
}

pub struct PgGroupRepository {
    pool: PgPool,
}

impl PgGroupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl GroupRepository for PgGroupRepository {
    async fn save(&self, group: &Group) -> Result<(), DomainError> {
        // Same range guard as `advance_epoch`: an out-of-range epoch must
        // fail loudly here rather than silently wrap negative via `as i64`,
        // which `advance_epoch`'s own `i64::try_from` would then reject on
        // every future call for this group.
        let epoch_i64 = i64::try_from(group.epoch.0)
            .map_err(|_| DomainError::Internal("epoch exceeds representable range".into()))?;
        sqlx::query(
            "INSERT INTO groups (id, home_region, epoch, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE
               SET home_region = EXCLUDED.home_region,
                   epoch       = EXCLUDED.epoch",
        )
        .bind(group.id.as_uuid())
        .bind(group.home_region.as_str())
        .bind(epoch_i64)
        .bind(group.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn advance_epoch(
        &self,
        group_id: &GroupId,
        expected: Epoch,
    ) -> Result<Option<Epoch>, DomainError> {
        // Reject out-of-range input before it ever reaches the WHERE clause —
        // silently truncating via `as i64` here would let a caller's stale/
        // corrupt u64 match an unrelated stored value. `expected_epoch`
        // arrives directly from a client (REST) or peer region (gRPC), so an
        // out-of-range value is bad *input*, not a server fault — map it to
        // `InvalidInput` (400/InvalidArgument), not `Internal` (500).
        let expected_i64 = i64::try_from(expected.0)
            .map_err(|_| DomainError::InvalidInput("epoch exceeds representable range".into()))?;
        // `epoch = epoch + 1 WHERE epoch = $2` is the compare-and-swap: only
        // the caller whose `expected` matches the row currently in the
        // database moves it, and Postgres's bigint `+` raises on overflow
        // rather than wrapping (see the port doc comment on why a blind
        // Rust-side `+ 1` must never be used for this).
        let row: Option<(i64,)> = sqlx::query_as(
            "UPDATE groups SET epoch = epoch + 1 WHERE id = $1 AND epoch = $2 RETURNING epoch",
        )
        .bind(group_id.as_uuid())
        .bind(expected_i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(|(e,)| Epoch(e as u64)))
    }

    async fn create_if_absent(&self, group: &Group) -> Result<bool, DomainError> {
        // DO NOTHING, not DO UPDATE: an id that already exists must keep its
        // epoch, home_region and created_at untouched, so a client-supplied
        // group_id colliding with an existing group cannot reset it. Same shape
        // as the group-stub insert in `upsert_members`.
        let epoch_i64 = i64::try_from(group.epoch.0)
            .map_err(|_| DomainError::Internal("epoch exceeds representable range".into()))?;
        let res = sqlx::query(
            "INSERT INTO groups (id, home_region, epoch, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(group.id.as_uuid())
        .bind(group.home_region.as_str())
        .bind(epoch_i64)
        .bind(group.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(res.rows_affected() == 1)
    }

    async fn create_with_creator(
        &self,
        group: &Group,
        creator: &GroupMember,
    ) -> Result<bool, DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;

        let res = sqlx::query(
            "INSERT INTO groups (id, home_region, epoch, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(group.id.as_uuid())
        .bind(group.home_region.as_str())
        .bind(group.epoch.0 as i64)
        .bind(group.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

        if res.rows_affected() == 0 {
            // The id already existed. Drop the transaction (rolls back on
            // drop) without touching membership — the caller decides whether
            // this is a legitimate retry or a hijack attempt.
            return Ok(false);
        }

        // Bind group.id here, not creator.group_id: the two are supposed to
        // always match, but binding the value this method already verified
        // the group row for (rather than trusting the caller's copy on
        // `creator`) makes it impossible for a caller-side mismatch to grant
        // membership in a different, unrelated group than the one just
        // created.
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, joined_at_epoch)
             VALUES ($1, $2, $3)
             ON CONFLICT (group_id, device_id) DO NOTHING",
        )
        .bind(group.id.as_uuid())
        .bind(creator.device_id.as_uuid())
        .bind(creator.joined_at_epoch.0 as i64)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

        tx.commit().await.map_err(map_err)?;
        Ok(true)
    }

    async fn find_by_id(&self, id: &GroupId) -> Result<Option<Group>, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(
            "SELECT id, home_region, epoch, created_at FROM groups WHERE id = $1",
        )
        .bind(id.as_uuid())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(row.map(Group::from))
    }

    async fn add_member(&self, member: &GroupMember) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO group_members (group_id, device_id, joined_at_epoch)
             VALUES ($1, $2, $3)
             ON CONFLICT (group_id, device_id) DO NOTHING",
        )
        .bind(member.group_id.as_uuid())
        .bind(member.device_id.as_uuid())
        .bind(member.joined_at_epoch.0 as i64)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
    }

    async fn remove_member(
        &self,
        group_id: &GroupId,
        device_id: &DeviceId,
    ) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM group_members WHERE group_id = $1 AND device_id = $2")
            .bind(group_id.as_uuid())
            .bind(device_id.as_uuid())
            .execute(&self.pool)
            .await
            .map_err(map_err)?;
        Ok(())
    }

    async fn list_members(&self, group_id: &GroupId) -> Result<Vec<GroupMember>, DomainError> {
        let rows = sqlx::query_as::<_, GroupMemberRow>(
            "SELECT group_id, device_id, joined_at_epoch
             FROM group_members WHERE group_id = $1 ORDER BY joined_at_epoch ASC",
        )
        .bind(group_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(GroupMember::from).collect())
    }

    async fn list_groups_for_device(
        &self,
        device_id: &DeviceId,
    ) -> Result<Vec<GroupId>, DomainError> {
        let rows = sqlx::query_scalar::<_, Uuid>(
            "SELECT group_id FROM group_members WHERE device_id = $1",
        )
        .bind(device_id.as_uuid())
        .fetch_all(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(rows.into_iter().map(GroupId::from).collect())
    }

    async fn upsert_members(
        &self,
        group: &Group,
        members: &[GroupMember],
    ) -> Result<(), DomainError> {
        let mut tx = self.pool.begin().await.map_err(map_err)?;

        // Insert group stub. DO NOTHING on conflict preserves an existing epoch so
        // a remote peer cannot downgrade a locally-tracked epoch by re-syncing.
        sqlx::query(
            "INSERT INTO groups (id, home_region, epoch, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(group.id.as_uuid())
        .bind(group.home_region.as_str())
        .bind(group.epoch.0 as i64)
        .bind(group.created_at)
        .execute(&mut *tx)
        .await
        .map_err(map_err)?;

        for member in members {
            sqlx::query(
                "INSERT INTO group_members (group_id, device_id, joined_at_epoch)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (group_id, device_id) DO NOTHING",
            )
            .bind(member.group_id.as_uuid())
            .bind(member.device_id.as_uuid())
            .bind(member.joined_at_epoch.0 as i64)
            .execute(&mut *tx)
            .await
            .map_err(map_err)?;
        }

        tx.commit().await.map_err(map_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_impl<T: GroupRepository>() {}

    #[test]
    fn pg_group_repo_impl_trait() {
        assert_impl::<PgGroupRepository>();
    }
}
