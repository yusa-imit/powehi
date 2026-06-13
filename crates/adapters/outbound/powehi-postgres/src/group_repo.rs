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
        sqlx::query(
            "INSERT INTO groups (id, home_region, epoch, created_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE
               SET home_region = EXCLUDED.home_region,
                   epoch       = EXCLUDED.epoch",
        )
        .bind(group.id.as_uuid())
        .bind(group.home_region.as_str())
        .bind(group.epoch.0 as i64)
        .bind(group.created_at)
        .execute(&self.pool)
        .await
        .map_err(map_err)?;
        Ok(())
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
