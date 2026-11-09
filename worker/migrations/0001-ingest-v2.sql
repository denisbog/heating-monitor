-- Ingest endpoint, requirements v2
-- (`../mesh-deepseek/docs/http-endpoint-requirements-v2.md`).
--
-- Adds the device-supplied timestamps (HR-200…204), one row per accepted batch
-- (`batches_meta`, the HR-222 dedupe key) and the per-device telemetry the admin
-- page reads. `schema.sql` already carries the final shape for fresh databases;
-- this file is the delta for a database created before v2.
--
-- Apply with:
--   wrangler d1 migrations apply monitoring --remote
--
-- SQLite has no `ADD COLUMN IF NOT EXISTS`, so this file is one-shot — which is
-- exactly what `d1 migrations apply` guarantees.

-- HR-202/203: untrusted device time per sample; NULL means "device had no clock".
ALTER TABLE samples ADD COLUMN device_collected_at INTEGER;

-- HR-222: (device_id, boot_id, batch) decides duplicates; one row per accepted
-- batch, so a replay is recognised even after later batches moved the counter.
CREATE TABLE IF NOT EXISTS batches_meta (
    device_id   TEXT    NOT NULL,
    boot_id     INTEGER NOT NULL,
    batch       INTEGER NOT NULL,
    received_at INTEGER NOT NULL,
    sent_at     INTEGER,
    samples     INTEGER NOT NULL,
    rejected    INTEGER NOT NULL,
    PRIMARY KEY (device_id, boot_id, batch)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS batches_by_time ON batches_meta (received_at DESC);
CREATE INDEX IF NOT EXISTS batches_by_device_time ON batches_meta (device_id, received_at DESC);

-- HR-223: "last upload" vs "last sample" per device, without scanning `samples`.
ALTER TABLE ingest_devices ADD COLUMN samples_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_devices ADD COLUMN batches_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_devices ADD COLUMN rejected_total INTEGER NOT NULL DEFAULT 0;
ALTER TABLE ingest_devices ADD COLUMN last_sample_at INTEGER;
ALTER TABLE ingest_devices ADD COLUMN last_sent_at INTEGER;

-- Backfill the counters from what is already stored, so the admin page shows real
-- numbers for batches accepted before this migration.
UPDATE ingest_devices
   SET samples_total  = COALESCE((SELECT COUNT(*) FROM samples s
                                   WHERE s.device_id = ingest_devices.id), 0),
       last_sample_at = (SELECT MAX(s.device_collected_at) FROM samples s
                          WHERE s.device_id = ingest_devices.id)
 WHERE TRUE;

UPDATE ingest_devices
   SET batches_total = COALESCE((SELECT COUNT(*) FROM batches_meta b
                                  WHERE b.device_id = ingest_devices.id), 0)
 WHERE TRUE;
