//! D1 persistence and read queries.
//!
//! Schema lives in `schema.sql`. Binding uses `JsValue` because D1 statements
//! are variadic JS arrays; `batch` is chunked to stay well inside D1's per-call
//! statement limit.

use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;
use worker::*;

use crate::model::{day_str, now_secs, Device, Reading};

/// D1 accepts a bounded number of statements per batch; 50 is comfortably safe.
const BATCH: usize = 50;

fn s(v: &str) -> JsValue {
    JsValue::from_str(v)
}

fn n(v: f64) -> JsValue {
    JsValue::from_f64(v)
}

// ---------------------------------------------------------------------------
// Writes
// ---------------------------------------------------------------------------

/// Insert or refresh device rows.
pub async fn upsert_devices(db: &D1Database, devices: &[Device]) -> Result<()> {
    if devices.is_empty() {
        return Ok(());
    }
    let now = now_secs();
    let mut stmts = Vec::with_capacity(devices.len());
    for d in devices {
        let stmt = db
            .prepare(
                "INSERT INTO devices
                   (id, provider, external_id, name, model, kind, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(id) DO UPDATE SET
                   name      = excluded.name,
                   model     = excluded.model,
                   last_seen = excluded.last_seen",
            )
            .bind(&[
                s(&d.id),
                s(d.provider),
                s(&d.external_id),
                s(&d.name),
                s(&d.model),
                s(d.kind),
                n(now as f64),
                n(now as f64),
            ])?;
        stmts.push(stmt);
    }
    drain_batch(db, stmts).await
}

/// Insert readings. `(device_id, metric, ts)` is the primary key, so re-polling
/// the same instant just refreshes the value.
///
/// **Already-stored timestamps are not written again.** The `WHERE` on the
/// `DO UPDATE` makes a re-poll that carries the same value a no-op: D1 reports
/// 0 rows written for it instead of 1 (measured: `WHERE`-guarded upsert on an
/// unchanged row is `rows_read: 0, rows_written: 0`; a changed value still
/// writes 1). This matters because the collector re-sends the same provider
/// buckets — CAME's month history and iLetComfort's hourly energy — on every
/// run, which used to cost ~280 writes per hourly run for a handful of new
/// samples.
///
/// The same call also refreshes the `latest` row of every touched series, which
/// is what keeps `/api/latest` and `/api/metrics` a ~84-row read instead of a
/// scan of this whole table.
///
/// Returns the number of samples handed in (what the run produced), not the
/// number of rows that were new — the run log reports collector yield.
pub async fn insert_readings(db: &D1Database, readings: &[Reading]) -> Result<usize> {
    if readings.is_empty() {
        return Ok(0);
    }
    let mut stmts = Vec::with_capacity(readings.len());
    for r in readings {
        let stmt = db
            .prepare(
                "INSERT INTO readings (device_id, metric, ts, value, unit)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, metric, ts) DO UPDATE SET
                   value = excluded.value,
                   unit  = excluded.unit
                 WHERE value IS NOT excluded.value
                    OR unit  IS NOT excluded.unit",
            )
            .bind(&[
                s(&r.device_id),
                s(&r.metric),
                n(r.ts as f64),
                n(r.value),
                s(&r.unit),
            ])?;
        stmts.push(stmt);
    }
    let count = readings.len();
    drain_batch(db, stmts).await?;
    upsert_latest(db, readings).await?;
    Ok(count)
}

/// Keep one `latest` row per series, pointing at its newest sample.
///
/// The `WHERE` spells out when the row would actually change — a strictly newer
/// sample, or the same timestamp with a different value — so a re-polled
/// provider bucket writes nothing at all (`rows_written: 0`). An out-of-order
/// (backfilled) sample is a no-op, which is exactly what `/api/latest` used to
/// return for `MAX(ts)`.
async fn upsert_latest(db: &D1Database, readings: &[Reading]) -> Result<()> {
    let mut stmts = Vec::with_capacity(readings.len());
    for r in readings {
        let stmt = db
            .prepare(
                "INSERT INTO latest (device_id, metric, ts, value, unit)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT(device_id, metric) DO UPDATE SET
                   ts    = excluded.ts,
                   value = excluded.value,
                   unit  = excluded.unit
                 WHERE excluded.ts > latest.ts
                    OR (excluded.ts = latest.ts
                        AND (excluded.value IS NOT latest.value
                             OR excluded.unit IS NOT latest.unit))",
            )
            .bind(&[
                s(&r.device_id),
                s(&r.metric),
                n(r.ts as f64),
                n(r.value),
                s(&r.unit),
            ])?;
        stmts.push(stmt);
    }
    drain_batch(db, stmts).await
}

/// Rebuild the `daily` rollup for every day from `since_day` (inclusive) up to
/// today.
///
/// Idempotent by construction — the range is deleted and re-aggregated, so
/// re-polled history cannot double-count the way an accumulating upsert would.
/// The routine call covers the last two days: that cost is bounded by two days of
/// samples instead of by the whole table, which is what `/api/daily` used to pay
/// on every request.
pub async fn refresh_daily(db: &D1Database, since_day: &str) -> Result<()> {
    db.batch(vec![
        // Deletes future-dated rows too (some provider history buckets are
        // stamped with the end of their period), so the insert below recreates
        // them from the same source of truth.
        db.prepare("DELETE FROM daily WHERE day >= ?")
            .bind(&[s(since_day)])?,
        // `INDEXED BY` is deliberate: without statistics the planner falls back
        // to scanning the whole `readings` table, and this runs every hour.
        db.prepare(
            "INSERT INTO daily (device_id, metric, unit, day, vmin, vmax, vsum, n)
             SELECT device_id,
                    metric,
                    COALESCE(unit, ''),
                    date(ts, 'unixepoch'),
                    MIN(value),
                    MAX(value),
                    SUM(value),
                    COUNT(*)
               FROM readings INDEXED BY idx_readings_ts
              WHERE ts >= CAST(strftime('%s', ?) AS INTEGER)
              GROUP BY device_id, metric, COALESCE(unit, ''), date(ts, 'unixepoch')
             ON CONFLICT(device_id, metric, unit, day) DO UPDATE SET
               vmin = excluded.vmin,
               vmax = excluded.vmax,
               vsum = excluded.vsum,
               n    = excluded.n",
        )
        .bind(&[s(since_day)])?,
    ])
    .await?;
    Ok(())
}

/// The oldest day in this batch that has no `daily` row yet, if any.
///
/// A day that already has a rollup row only changes when new samples land in it,
/// and the routine trailing window covers those. This catches the other case:
/// history pulled after an outage lands in days older than that window, and
/// without this check those days would never reach `/api/daily`.
pub async fn oldest_unrolled_day(db: &D1Database, readings: &[Reading]) -> Result<Option<String>> {
    let mut pairs: Vec<(&str, &str, String)> = readings
        .iter()
        .map(|r| (r.device_id.as_str(), r.metric.as_str(), day_str(r.ts)))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    if pairs.is_empty() {
        return Ok(None);
    }

    #[derive(Debug, Deserialize)]
    struct Row {
        day: String,
    }

    let mut oldest: Option<String> = None;
    // D1 allows 100 bound parameters per query and this binds three per row.
    for chunk in pairs.chunks(30) {
        let values = vec!["(?, ?, ?)"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT column1 AS device_id, column2 AS metric, column3 AS day
               FROM (VALUES {values}) AS v
              WHERE NOT EXISTS (SELECT 1
                                  FROM daily d
                                 WHERE d.device_id = v.column1
                                   AND d.metric    = v.column2
                                   AND d.day       = v.column3)"
        );
        let mut binds = Vec::with_capacity(chunk.len() * 3);
        for (device, metric, day) in chunk {
            binds.push(s(device));
            binds.push(s(metric));
            binds.push(s(day));
        }
        let rows = db
            .prepare(sql)
            .bind(&binds)?
            .all()
            .await?
            .results::<Row>()?;
        for row in rows {
            if oldest.as_ref().is_none_or(|o| row.day < *o) {
                oldest = Some(row.day);
            }
        }
    }
    Ok(oldest)
}

async fn drain_batch(db: &D1Database, mut stmts: Vec<D1PreparedStatement>) -> Result<()> {
    while !stmts.is_empty() {
        let take = BATCH.min(stmts.len());
        let batch: Vec<D1PreparedStatement> = stmts.drain(..take).collect();
        db.batch(batch).await?;
    }
    Ok(())
}

/// Open a run row and return its surrogate id.
pub async fn start_run(db: &D1Database) -> Result<i64> {
    let res = db
        .prepare("INSERT INTO runs (started_at, status) VALUES (?, 'running')")
        .bind(&[n(now_secs() as f64)])?
        .run()
        .await?;
    res.meta()?
        .and_then(|m| m.last_row_id)
        .ok_or_else(|| Error::RustError("start_run: D1 returned no last_row_id".into()))
}

/// Close a run row.
pub async fn finish_run(
    db: &D1Database,
    id: i64,
    status: &str,
    devices: usize,
    readings: usize,
    error: Option<&str>,
) -> Result<()> {
    db.prepare(
        "UPDATE runs
            SET finished_at = ?, status = ?, devices_seen = ?, readings_written = ?, error = ?
          WHERE id = ?",
    )
    .bind(&[
        n(now_secs() as f64),
        s(status),
        n(devices as f64),
        n(readings as f64),
        error.map(s).unwrap_or(JsValue::NULL),
        n(id as f64),
    ])?
    .run()
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Session token cache
// ---------------------------------------------------------------------------
//
// Both clouds only allow one session per account, so a fresh login evicts the
// other client (e.g. the phone app). Caching the token turns 96 logins/day into
// one per token lifetime. Tokens are refreshed a few minutes early.

/// How long before real expiry we treat a token as stale.
const TOKEN_SKEW: i64 = 300;

#[derive(Debug, Deserialize)]
struct TokenRow {
    value: String,
    expires_at: Option<i64>,
}

/// Return a still-valid cached token for `provider`, if any.
pub async fn load_token(db: &D1Database, provider: &str) -> Result<Option<String>> {
    let row = db
        .prepare("SELECT value, expires_at FROM tokens WHERE provider = ?")
        .bind(&[s(provider)])?
        .first::<TokenRow>(None)
        .await?;

    Ok(match row {
        Some(t) if t.expires_at.is_none_or(|e| e > now_secs() + TOKEN_SKEW) => Some(t.value),
        _ => None,
    })
}

/// Store (or replace) the token for `provider`.
pub async fn save_token(
    db: &D1Database,
    provider: &str,
    value: &str,
    expires_at: Option<i64>,
    extra: Option<&str>,
) -> Result<()> {
    db.prepare(
        "INSERT INTO tokens (provider, value, issued_at, expires_at, extra)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(provider) DO UPDATE SET
           value      = excluded.value,
           issued_at  = excluded.issued_at,
           expires_at = excluded.expires_at,
           extra      = excluded.extra",
    )
    .bind(&[
        s(provider),
        s(value),
        n(now_secs() as f64),
        expires_at.map(|e| n(e as f64)).unwrap_or(JsValue::NULL),
        extra.map(s).unwrap_or(JsValue::NULL),
    ])?
    .run()
    .await?;
    Ok(())
}

/// Drop a cached token so the next run logs in again.
pub async fn clear_token(db: &D1Database, provider: &str) -> Result<()> {
    db.prepare("DELETE FROM tokens WHERE provider = ?")
        .bind(&[s(provider)])?
        .run()
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Settings (dashboard layout)
// ---------------------------------------------------------------------------

/// Read a settings value, `None` when the key was never written.
pub async fn load_setting(db: &D1Database, key: &str) -> Result<Option<String>> {
    #[derive(Debug, Deserialize)]
    struct Row {
        value: String,
    }
    let row = db
        .prepare("SELECT value FROM settings WHERE key = ?")
        .bind(&[s(key)])?
        .first::<Row>(None)
        .await?;
    Ok(row.map(|r| r.value))
}

/// Insert or replace a settings value.
pub async fn save_setting(db: &D1Database, key: &str, value: &str) -> Result<()> {
    db.prepare(
        "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET
           value      = excluded.value,
           updated_at = excluded.updated_at",
    )
    .bind(&[s(key), s(value), n(now_secs() as f64)])?
    .run()
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub id: String,
    pub provider: String,
    pub external_id: String,
    pub name: Option<String>,
    pub model: Option<String>,
    pub kind: Option<String>,
    pub first_seen: i64,
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadingRow {
    pub device_id: String,
    pub metric: String,
    pub ts: i64,
    pub value: Option<f64>,
    pub unit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DailyRow {
    pub device_id: String,
    pub metric: String,
    pub unit: Option<String>,
    pub day: String,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub n: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRow {
    pub id: i64,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    pub status: String,
    pub devices_seen: Option<i64>,
    pub readings_written: Option<i64>,
    pub error: Option<String>,
}

/// One (device, metric, unit) series that exists in `readings`. Feeds the admin
/// page's metric picker, so it shows real metrics rather than a hard-coded list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricRow {
    pub device_id: String,
    pub metric: String,
    pub unit: Option<String>,
    pub n: i64,
    pub last_ts: i64,
}

/// One long-format point built from the `samples` table, shaped like
/// [`ReadingRow`] so the chart page renders ingest data with the same code as
/// the provider readings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamplePointRow {
    pub device_id: String,
    /// Registry name when the device is still registered; `None` after an
    /// unregister, because stored samples are kept on purpose.
    pub device_name: Option<String>,
    pub node_id: i64,
    /// `temperature` (°C), `humidity` (%) or `battery` (V).
    pub metric: String,
    /// Bucket start, unix seconds, on the clock the caller selected.
    pub ts: i64,
    pub value: Option<f64>,
    pub unit: String,
}

/// Row shape of the wide per-bucket query, pivoted into [`SamplePointRow`].
#[derive(Debug, Deserialize)]
struct SampleBucketRow {
    device_id: String,
    device_name: Option<String>,
    node_id: i64,
    ts: i64,
    t_x10: Option<f64>,
    h_x10: Option<f64>,
    batt_mv: Option<f64>,
}

/// Points the chart page aims for across one window. More would overlap on a
/// ~700 px-wide card; fewer would make a line look angular.
const SAMPLE_BUCKETS: i64 = 720;

/// Upper bound on buckets per request when the caller asks for an explicit
/// `bucket` finer than the window warrants (3 metrics per bucket, so this is
/// still 6,000 rows).
const SAMPLE_MAX_POINTS: i64 = 2_000;

/// A "nice" bucket width in seconds for a window: the smallest listed step that
/// keeps the series at or below [`SAMPLE_BUCKETS`] points.
///
/// The steps are the usual clock divisors (…15 min, 30 min, 1 h, 6 h, 1 day),
/// so bucket starts land on round wall-clock times rather than on arbitrary
/// offsets from the request's `from`.
pub fn pick_bucket(from: i64, to: i64) -> i64 {
    const STEPS: [i64; 14] = [
        1, 5, 10, 15, 30, 60, 300, 900, 1800, 3600, 10_800, 21_600, 43_200, 86_400,
    ];
    let span = (to - from).max(1);
    let want = span / SAMPLE_BUCKETS + 1;
    STEPS
        .into_iter()
        .find(|step| *step >= want)
        .unwrap_or(86_400)
}

/// Device samples in a window, aggregated into buckets and pivoted to one long
/// row per metric.
///
/// `device_clock` selects which of the two stored timestamps is the timeline:
/// `received_at` (server clock at upload, the canonical one) or
/// `device_collected_at` (the untrusted clock the firmware reported). Samples
/// with no value on the chosen clock are skipped, so a device that only ever
/// uploaded without a clock shows nothing in the device-time view — which is the
/// honest answer.
///
/// One scan of `samples` feeds all three metrics (the wide query averages them
/// together), instead of a three-way `UNION ALL` that would read every row three
/// times. The index hint is chosen from a fixed set, never from user input.
///
/// An explicit `bucket` is clamped so one request cannot return an unbounded
/// answer: at most [`SAMPLE_MAX_POINTS`] buckets are ever produced.
pub async fn sample_series(
    db: &D1Database,
    device: &str,
    from: i64,
    to: i64,
    device_clock: bool,
    bucket: i64,
) -> Result<Vec<SamplePointRow>> {
    // Never return more than SAMPLE_MAX_POINTS buckets, even if the caller
    // asked for a finer step than the window justifies.
    let bucket = bucket.max((to - from) / SAMPLE_MAX_POINTS + 1).max(1);
    let (column, index) = if device_clock {
        (
            "device_collected_at",
            if device.is_empty() {
                "samples_by_clock"
            } else {
                "samples_by_device_clock"
            },
        )
    } else {
        (
            "received_at",
            if device.is_empty() {
                "samples_by_time"
            } else {
                "samples_by_device_time"
            },
        )
    };
    let device_filter = if device.is_empty() {
        ""
    } else {
        " AND s.device_id = ?"
    };
    let sql = format!(
        "SELECT s.device_id,
                MAX(d.name) AS device_name,
                s.node_id,
                -- The bucket binds arrive as JS numbers, i.e. REALs, so
                -- without the CAST `col / ?` would be float division and
                -- `(x / 300.0) * 300` would return x unchanged — every sample
                -- its own bucket. CAST makes it integer division.
                (s.{column} / CAST(? AS INTEGER)) * CAST(? AS INTEGER) AS ts,
                AVG(s.t_x10)   AS t_x10,
                AVG(s.h_x10)   AS h_x10,
                AVG(s.batt_mv) AS batt_mv
           FROM samples s INDEXED BY {index}
           LEFT JOIN ingest_devices d ON d.id = s.device_id
          WHERE s.{column} IS NOT NULL
            AND s.{column} >= ? AND s.{column} <= ?{device_filter}
          GROUP BY s.device_id, s.node_id, ts
          ORDER BY ts ASC, s.device_id ASC, s.node_id ASC"
    );

    let mut binds = vec![
        n(bucket as f64),
        n(bucket as f64),
        n(from as f64),
        n(to as f64),
    ];
    if !device.is_empty() {
        binds.push(s(device));
    }
    let rows = db
        .prepare(&sql)
        .bind(&binds)?
        .all()
        .await?
        .results::<SampleBucketRow>()?;

    // Pivot the three sensor columns into one row per metric: the chart page
    // already speaks `{device_id, metric, ts, value, unit}`.
    let mut out = Vec::with_capacity(rows.len() * 3);
    for row in rows {
        for (metric, unit, value) in [
            ("temperature", "°C", row.t_x10.map(|v| v / 10.0)),
            ("humidity", "%", row.h_x10.map(|v| v / 10.0)),
            ("battery", "V", row.batt_mv.map(|v| v / 1000.0)),
        ] {
            let Some(value) = value else { continue };
            out.push(SamplePointRow {
                device_id: row.device_id.clone(),
                device_name: row.device_name.clone(),
                node_id: row.node_id,
                metric: metric.to_string(),
                ts: row.ts,
                value: Some(value),
                unit: unit.to_string(),
            });
        }
    }
    Ok(out)
}

pub async fn devices(db: &D1Database) -> Result<Vec<DeviceRow>> {
    let res = db
        .prepare("SELECT id, provider, external_id, name, model, kind, first_seen, last_seen FROM devices ORDER BY provider, name")
        .all()
        .await?;
    res.results::<DeviceRow>()
}

/// Raw (15-minute) readings in a time window.
pub async fn readings(
    db: &D1Database,
    device: &str,
    metric: &str,
    from: i64,
    to: i64,
    limit: i64,
) -> Result<Vec<ReadingRow>> {
    let sql = "SELECT device_id, metric, ts, value, unit FROM readings
               WHERE ts >= ? AND ts <= ?
                 AND (? = '' OR device_id = ?)
                 AND (? = '' OR metric = ?)
               ORDER BY ts DESC LIMIT ?";
    let res = db
        .prepare(sql)
        .bind(&[
            n(from as f64),
            n(to as f64),
            s(device),
            s(device),
            s(metric),
            s(metric),
            n(limit as f64),
        ])?
        .all()
        .await?;
    res.results::<ReadingRow>()
}

/// Daily min/avg/max per metric, read from the `daily` rollup.
///
/// This matters because CAME keeps no server-side room-temperature history, so
/// the aggregates are built entirely from our own 15-minute samples. They used to
/// be recomputed from `readings` on every request (48-166k rows read); the
/// collector now maintains `daily` and this is a ~1k-row read.
///
/// `avg` is `vsum / n` because a rollup row carries a sum, not an average —
/// identical to `AVG(value)` for every value SQLite actually saw.
pub async fn daily(db: &D1Database, device: &str, from: i64, to: i64) -> Result<Vec<DailyRow>> {
    let mut sql = String::from(
        "SELECT device_id,
                metric,
                unit,
                day,
                vmin AS min,
                vsum / n AS avg,
                vmax AS max,
                n
           FROM daily
          WHERE day >= date(?, 'unixepoch')
            AND day <= date(?, 'unixepoch')",
    );
    // Build the predicate instead of `(? = '' OR device_id = ?)`: the OR form
    // defeats the primary key and falls back to a full scan.
    if !device.is_empty() {
        sql.push_str(" AND device_id = ?");
    }
    sql.push_str(" ORDER BY day ASC, metric ASC");

    let stmt = db.prepare(sql);
    let stmt = if device.is_empty() {
        stmt.bind(&[n(from as f64), n(to as f64)])?
    } else {
        stmt.bind(&[n(from as f64), n(to as f64), s(device)])?
    };

    let res = stmt.all().await?;
    res.results::<DailyRow>()
}

/// The latest value for every metric of every device.
///
/// Reads the maintained `latest` table — the equivalent self-join over
/// `readings` scanned the whole table twice on every call.
pub async fn latest(db: &D1Database) -> Result<Vec<ReadingRow>> {
    let res = db
        .prepare(
            "SELECT device_id, metric, ts, value, unit
               FROM latest
              ORDER BY device_id, metric",
        )
        .all()
        .await?;
    res.results::<ReadingRow>()
}

pub async fn runs(db: &D1Database, limit: i64) -> Result<Vec<RunRow>> {
    let res = db
        .prepare("SELECT id, started_at, finished_at, status, devices_seen, readings_written, error FROM runs ORDER BY started_at DESC LIMIT ?")
        .bind(&[n(limit as f64)])?
        .all()
        .await?;
    res.results::<RunRow>()
}

/// Every metric we have ever stored, per device. Feeds the admin page's metric
/// picker, so it shows real metrics rather than a hard-coded list.
///
/// `n` is the sample count (`SUM` of the rollup's per-day counts, i.e. the same
/// `COUNT(*)` the old query computed) and `last_ts` comes from `latest`. Both
/// used to require a `GROUP BY` over the whole `readings` table.
pub async fn metrics(db: &D1Database) -> Result<Vec<MetricRow>> {
    let res = db
        .prepare(
            "SELECT d.device_id,
                    d.metric,
                    d.unit,
                    SUM(d.n) AS n,
                    l.ts     AS last_ts
               FROM daily d
               JOIN latest l
                 ON l.device_id = d.device_id
                AND l.metric    = d.metric
              GROUP BY d.device_id, d.metric, d.unit
              ORDER BY d.device_id, d.metric",
        )
        .all()
        .await?;
    res.results::<MetricRow>()
}

#[cfg(test)]
mod tests {
    use super::pick_bucket;

    #[test]
    fn bucket_keeps_the_series_bounded() {
        for days in [1, 7, 30, 90, 365] {
            let span = days * 86_400;
            let bucket = pick_bucket(0, span);
            assert!(
                span / bucket <= super::SAMPLE_BUCKETS,
                "{days}d: {bucket}s bucket gives more than {} points",
                super::SAMPLE_BUCKETS
            );
            assert!(bucket >= 1);
        }
    }

    #[test]
    fn bucket_uses_round_steps() {
        assert_eq!(pick_bucket(0, 3600), 10);
        assert_eq!(pick_bucket(0, 86_400), 300);
        assert_eq!(pick_bucket(0, 7 * 86_400), 900);
        assert_eq!(pick_bucket(0, 365 * 86_400), 86_400);
    }
}
