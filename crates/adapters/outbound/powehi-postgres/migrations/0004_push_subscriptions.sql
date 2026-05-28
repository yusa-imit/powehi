-- Push subscriptions: stores browser endpoint + ECDH keys for RFC 8291 push.
-- p256dh and auth_secret are browser-generated public material (not secret server-side).
-- One subscription per device (upsert replaces on conflict).
CREATE TABLE IF NOT EXISTS push_subscriptions (
    device_id    UUID        PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    endpoint     TEXT        NOT NULL,
    p256dh       BYTEA       NOT NULL,
    auth_secret  BYTEA       NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
