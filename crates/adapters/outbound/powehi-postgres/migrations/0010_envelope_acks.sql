-- Per-device broadcast envelope acknowledgements. Closes a broken-access-control
-- gap: broadcast envelopes (recipient_device_id IS NULL — group Application/Commit
-- messages) used to be hard-deleted by the *first* device of *any* group to ack,
-- with no membership check. That let a malicious or buggy group member delete a
-- message (or a Commit, desyncing the whole group's MLS epoch) before other
-- members had a chance to poll it. Mirrors the media_acks pattern (0008): a
-- broadcast envelope is now only deleted once every *current* group member has
-- acked it (see PgEnvelopeRepository::ack_broadcast). Existence of the row is the
-- signal — no timestamp column needed.
CREATE TABLE IF NOT EXISTS envelope_acks (
    envelope_id UUID NOT NULL REFERENCES envelopes(id) ON DELETE CASCADE,
    device_id   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (envelope_id, device_id)
);
