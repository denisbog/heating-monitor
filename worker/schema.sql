-- Cloudflare D1 schema for the monitoring collector.
-- Apply with: wrangler d1 execute monitoring --file=schema.sql --remote

PRAGMA foreign_keys = ON;

-- Devices discovered from both clouds.
CREATE TABLE IF NOT EXISTS devices (
    id           TEXT PRIMARY KEY,   -- e.g. "iletcomfort:<appliance-code>" / "came:<keycode>"
    provider     TEXT NOT NULL,      -- 'iletcomfort' | 'cameconnect'
    external_id  TEXT NOT NULL,      -- applianceCode / keycode (or sn for energy calls)
    name         TEXT,
    model        TEXT,               -- sn8 for iLetComfort, ProductTypeName for CAME
    kind         TEXT,               -- 'heatpump' | 'thermostat'
    meta         TEXT,               -- JSON blob (extras)
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    UNIQUE (provider, external_id)
);

-- One row per (device, metric, timestamp). Timestamps are UTC epoch seconds.
CREATE TABLE IF NOT EXISTS readings (
    device_id  TEXT NOT NULL,
    metric     TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    value      REAL,
    unit       TEXT,
    PRIMARY KEY (device_id, metric, ts)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_readings_ts     ON readings (ts);
CREATE INDEX IF NOT EXISTS idx_readings_metric ON readings (metric, ts);

-- Every collector run, so gaps and failures are visible in the UI.
-- `id` is a surrogate key on purpose: `started_at` cannot be the primary key,
-- because a manual /api/collect landing in the same second as a cron run would
-- collide and fail the whole run.
CREATE TABLE IF NOT EXISTS runs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at       INTEGER NOT NULL,
    finished_at      INTEGER,
    status           TEXT NOT NULL,      -- 'ok' | 'partial' | 'error'
    devices_seen     INTEGER DEFAULT 0,
    readings_written INTEGER DEFAULT 0,
    error            TEXT
);

CREATE INDEX IF NOT EXISTS idx_runs_started ON runs (started_at DESC);

-- Cached session tokens (both clouds only allow one session per account, so we
-- reuse a token until the API rejects it instead of logging in every run).
CREATE TABLE IF NOT EXISTS tokens (
    provider    TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER,
    extra       TEXT
);
