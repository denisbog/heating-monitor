//! D1 persistence and read queries.
//!
//! Schema lives in `schema.sql`. Binding uses `JsValue` because D1 statements
//! are variadic JS arrays; `batch` is chunked to stay well inside D1's per-call
//! statement limit.

use serde::{Deserialize, Serialize};
use worker::wasm_bindgen::JsValue;
use worker::*;

use crate::model::{now_secs, Device, Reading};

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
                   unit  = excluded.unit",
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
    Ok(count)
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

/// Daily min/avg/max per metric — computed in SQLite so the Worker stays cheap.
/// This matters because CAME keeps no server-side room-temperature history, so
/// the aggregates are built entirely from our own 15-minute samples.
pub async fn daily(
    db: &D1Database,
    device: &str,
    from: i64,
    to: i64,
) -> Result<Vec<DailyRow>> {
    let sql = "SELECT device_id,
                      metric,
                      unit,
                      date(ts, 'unixepoch') AS day,
                      MIN(value) AS min,
                      AVG(value) AS avg,
                      MAX(value) AS max,
                      COUNT(*)   AS n
                 FROM readings
                WHERE ts >= ? AND ts <= ?
                  AND (? = '' OR device_id = ?)
                GROUP BY device_id, metric, unit, day
                ORDER BY day ASC, metric ASC";
    let res = db
        .prepare(sql)
        .bind(&[n(from as f64), n(to as f64), s(device), s(device)])?
        .all()
        .await?;
    res.results::<DailyRow>()
}

/// The latest value for every metric of every device.
pub async fn latest(db: &D1Database) -> Result<Vec<ReadingRow>> {
    let res = db
        .prepare(
            "SELECT r.device_id, r.metric, r.ts, r.value, r.unit
               FROM readings r
               JOIN (SELECT device_id, metric, MAX(ts) AS ts
                       FROM readings GROUP BY device_id, metric) m
                 ON r.device_id = m.device_id AND r.metric = m.metric AND r.ts = m.ts",
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
