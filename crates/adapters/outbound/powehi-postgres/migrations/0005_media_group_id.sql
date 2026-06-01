-- Add group_id to media_blobs so group members can download blobs shared to their group.
-- NULL = blob was not associated with a group (uploader-only access).
-- ON DELETE SET NULL: deleting a group does not cascade-delete media metadata.
ALTER TABLE media_blobs
    ADD COLUMN group_id UUID NULL REFERENCES groups(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS media_blobs_group_id_idx
    ON media_blobs(group_id) WHERE group_id IS NOT NULL;
