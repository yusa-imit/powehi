-- The PRIMARY KEY (group_id, device_id) does NOT help when filtering by
-- device_id alone, as the leading column is group_id.  This index makes the
-- find_pending broadcast subquery (SELECT group_id FROM group_members WHERE
-- device_id = $1) efficient.
CREATE INDEX IF NOT EXISTS group_members_device_idx ON group_members(device_id);
