-- Rebuild `batches_meta` from the samples that were stored before v2.
--
-- `batches_meta` is written by the ingest handler from v2 onwards, so batches
-- accepted earlier have samples but no batch row — which makes the admin page
-- show "0 batches" next to a non-zero sample count, and would let a very old
-- replay fall through to the ordering check instead of being answered as a
-- duplicate (v2 HR-222).
--
-- Every sample carries `boot_id`/`batch`, and all samples of a batch share one
-- `received_at`, so the batch rows can be reconstructed exactly. `sent_at` and
-- `rejected` were never recorded and stay `NULL` / `0`.
--
-- Idempotent: `DO NOTHING` keeps the rows the handler wrote after v2.
--
-- Apply with:
--   wrangler d1 migrations apply monitoring --remote

INSERT INTO batches_meta (device_id, boot_id, batch, received_at, sent_at, samples, rejected)
SELECT device_id,
       boot_id,
       batch,
       MIN(received_at),
       NULL,
       COUNT(*),
       0
  FROM samples
 GROUP BY device_id, boot_id, batch
ON CONFLICT(device_id, boot_id, batch) DO NOTHING;

UPDATE ingest_devices
   SET batches_total = (SELECT COUNT(*) FROM batches_meta b
                         WHERE b.device_id = ingest_devices.id)
 WHERE TRUE;
