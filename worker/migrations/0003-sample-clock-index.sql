-- Indexes for `/api/ingest/series` (the ingest-chart data endpoint).
--
-- A chart can plot either stored clock: `received_at` (server clock, already
-- indexed by `samples_by_time`) or the device's own `device_collected_at`
-- (the untrusted firmware clock, HR-202). Without these the device-time view
-- scans the whole `samples` table.
--
-- `samples_by_device_time` is included because the endpoint names its index in
-- an `INDEXED BY` hint when a single device is requested; a database provisioned
-- before that index existed must get it before the endpoint can serve a
-- per-device upload-time chart.
--
-- `schema.sql` carries the same statements, so a fresh database needs only that
-- file; this delta exists so `wrangler d1 migrations apply` also brings an
-- existing database up to date.
CREATE INDEX IF NOT EXISTS samples_by_device_time   ON samples (device_id, received_at DESC);
CREATE INDEX IF NOT EXISTS samples_by_clock         ON samples (device_collected_at);
CREATE INDEX IF NOT EXISTS samples_by_device_clock  ON samples (device_id, device_collected_at);
