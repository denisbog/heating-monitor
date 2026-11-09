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

-- Newest sample per (device, metric), maintained by the collector.
--
-- `/api/latest` used to answer this by scanning `readings` twice (a self-join
-- over the whole table, ~2x rows_read because each row costs an index entry plus
-- a WITHOUT ROWID b-tree lookup), so one page load could cost as much as the
-- table. Maintaining the answer at ingest turns it into a ~84-row read.
CREATE TABLE IF NOT EXISTS latest (
    device_id  TEXT NOT NULL,
    metric     TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    value      REAL,
    unit       TEXT,
    PRIMARY KEY (device_id, metric)
) WITHOUT ROWID;

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

-- Small key/value store for UI state (currently the dashboard chart layout,
-- key 'dashboard'). Keeping it server-side means every client — and every
-- browser — shows the same admin-configured page.
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

-- Daily rollup of `readings`, used by `/api/daily`.
--
-- Computing MIN/AVG/MAX straight from the 15-minute rows cost 48-166k rows read
-- per request (CAME keeps no room-temperature history, so those aggregates are
-- ours). The collector rebuilds the last 48 h of this table once an hour, which
-- is bounded by the samples of two days instead of by the whole table.
--
-- `vsum` + `n` give AVG at read time (`vsum / n`), so no information is lost.
-- Older days are frozen: applying schema.sql backfills them once from
-- `readings` (see the tail of this file).
CREATE TABLE IF NOT EXISTS daily (
    device_id  TEXT NOT NULL,
    metric     TEXT NOT NULL,
    unit       TEXT NOT NULL DEFAULT '',
    day        TEXT NOT NULL,       -- 'YYYY-MM-DD' (UTC), like date(ts,'unixepoch')
    vmin       REAL,
    vmax       REAL,
    vsum       REAL,
    n          INTEGER NOT NULL,
    PRIMARY KEY (device_id, metric, unit, day)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_daily_day ON daily (day);

-- ---------------------------------------------------------------------------
-- Device ingest (POST /v1/samples) — see `src/ingest.rs`
-- ---------------------------------------------------------------------------
-- eink-x sensor devices push firmware samples here. These are a different kind
-- of device from the cloud-discovered rows in `devices`, hence the separate
-- table (`ingest_devices`), which also avoids changing that table's contract.
--
-- `key_enc` is the 32-byte per-device HMAC key as lowercase hex. The ingest
-- requirements allow storing it unencrypted if the decision is documented; see
-- README → "Device ingest".
--
-- `rate_start` / `rate_count` implement the fixed one-hour window of §5.3
-- (60 accepted batches per device per hour).
CREATE TABLE IF NOT EXISTS ingest_devices (
    id             TEXT PRIMARY KEY,      -- 12 uppercase hex of the BLE address
    name           TEXT,
    role           TEXT,                  -- 'server' (hub) | 'client' | 'direct'
    node_id        INTEGER,               -- last known own node id
    period_min     INTEGER,
    key_enc        TEXT NOT NULL,         -- device key, lowercase hex
    last_boot_id   INTEGER,
    last_batch     INTEGER,
    last_seen      INTEGER,               -- Unix seconds of the last accepted batch
    last_ip        TEXT,                  -- informational, never exported
    firmware       TEXT,                  -- X-Firmware / User-Agent
    disabled       INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    rate_start     INTEGER NOT NULL DEFAULT 0,
    rate_count     INTEGER NOT NULL DEFAULT 0,
    -- v2 telemetry, so the admin page stays an O(devices) read instead of
    -- scanning `samples`: accepted counts, the newest *device* timestamps
    -- (`last_sample_at` is a `collected_at`, `last_sent_at` a `sent_at`).
    samples_total  INTEGER NOT NULL DEFAULT 0,
    batches_total  INTEGER NOT NULL DEFAULT 0,
    rejected_total INTEGER NOT NULL DEFAULT 0,
    last_sample_at INTEGER,
    last_sent_at   INTEGER
);

-- One row per sample. `received_at` is the server clock and is identical for
-- every sample of a batch; `device_min` is the node's own minute counter.
-- PRIMARY KEY (device_id, node_id, received_at, seq) is the B-tree, so it is
-- WITHOUT ROWID like `readings`.
CREATE TABLE IF NOT EXISTS samples (
    device_id           TEXT    NOT NULL,
    node_id             INTEGER NOT NULL,
    seq                 INTEGER NOT NULL,
    device_min          INTEGER NOT NULL,
    received_at         INTEGER NOT NULL,   -- server clock; the canonical time
    t_x10               INTEGER NOT NULL,
    h_x10               INTEGER NOT NULL,
    batt_mv             INTEGER NOT NULL,
    boot_id             INTEGER NOT NULL,
    batch               INTEGER NOT NULL,
    -- v2 HR-202/203: untrusted device clock when the sample was queued,
    -- NULL when the device had no clock. Never used for windows or dedupe.
    device_collected_at INTEGER,
    PRIMARY KEY (device_id, node_id, received_at, seq)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS samples_by_time ON samples (received_at DESC);
CREATE INDEX IF NOT EXISTS samples_by_node ON samples (device_id, node_id, received_at DESC);
CREATE INDEX IF NOT EXISTS samples_by_device_time ON samples (device_id, received_at DESC);
-- Dashboards can plot either stored clock (see `/api/ingest/series`): the
-- `received_at` indexes above cover upload time, these two cover the device's
-- own `device_collected_at`. Without them the device-time view scans `samples`.
CREATE INDEX IF NOT EXISTS samples_by_clock         ON samples (device_collected_at);
CREATE INDEX IF NOT EXISTS samples_by_device_clock  ON samples (device_id, device_collected_at);

-- v2 §5: one row per accepted batch. `(device_id, boot_id, batch)` is the dedupe
-- key of HR-222, so a replay is recognised even after later batches arrived.
CREATE TABLE IF NOT EXISTS batches_meta (
    device_id   TEXT    NOT NULL,
    boot_id     INTEGER NOT NULL,
    batch       INTEGER NOT NULL,
    received_at INTEGER NOT NULL,           -- server clock
    sent_at     INTEGER,                    -- device clock, NULL = unknown
    samples     INTEGER NOT NULL,
    rejected    INTEGER NOT NULL,
    PRIMARY KEY (device_id, boot_id, batch)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS batches_by_time ON batches_meta (received_at DESC);
CREATE INDEX IF NOT EXISTS batches_by_device_time ON batches_meta (device_id, received_at DESC);
-- ---------------------------------------------------------------------------
-- Backfill (idempotent, safe to re-run)
-- ---------------------------------------------------------------------------
-- `latest` and `daily` are maintained by the collector from now on, but a
-- database that already holds `readings` needs its existing history copied in
-- once. Both statements only ever move forward: re-running them rewrites the
-- same rows, and the collector's own writes are newer or equal.
--
-- Run as part of the normal `wrangler d1 execute --file=schema.sql --remote`.

INSERT INTO latest (device_id, metric, ts, value, unit)
SELECT r.device_id, r.metric, r.ts, r.value, r.unit
  FROM readings r
  JOIN (SELECT device_id,
               metric,
               MAX(ts) AS ts
          FROM readings
         GROUP BY device_id, metric) m
    ON m.device_id = r.device_id AND m.metric = r.metric AND m.ts = r.ts
ON CONFLICT(device_id, metric) DO UPDATE SET
  ts    = excluded.ts,
  value = excluded.value,
  unit  = excluded.unit;

INSERT INTO daily (device_id, metric, unit, day, vmin, vmax, vsum, n)
SELECT device_id,
       metric,
       COALESCE(unit, ''),
       date(ts, 'unixepoch'),
       MIN(value),
       MAX(value),
       SUM(value),
       COUNT(*)
  FROM readings
 GROUP BY device_id, metric, COALESCE(unit, ''), date(ts, 'unixepoch')
ON CONFLICT(device_id, metric, unit, day) DO UPDATE SET
  vmin = excluded.vmin,
  vmax = excluded.vmax,
  vsum = excluded.vsum,
  n    = excluded.n;
