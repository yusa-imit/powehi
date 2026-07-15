-- Media download acknowledgements: an opaque per-device signal ("device D has
-- obtained a download URL for blob M") used only for GC eligibility (prd.md
-- §9.4.3, §3.3). Existence of the row is the signal — no timestamp column,
-- since the GC algorithm only needs set membership (prd.md §2.2 P5:
-- minimalism-is-security — don't persist data the algorithm doesn't use).
CREATE TABLE IF NOT EXISTS media_acks (
    media_id    UUID NOT NULL REFERENCES media_blobs(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (media_id, device_id)
);
