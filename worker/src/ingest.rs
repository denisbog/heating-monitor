//! Device ingest: `POST /v1/samples` and `GET /v1/health`.
//!
//! Implements the write path from
//! `../mesh-deepseek/docs/http-endpoint-requirements.md` (§4.1, §4.2, §5, §6,
//! §7, §8, M1). Devices push batches of firmware samples; the endpoint
//! authenticates each batch with a per-device HMAC-SHA256, validates the
//! samples, de-duplicates replays and stores the rest in one D1 `batch()`.
//!
//! Deliberate deviations, all allowed by the document:
//!
//! * the tables are `ingest_devices` / `samples` — the spec's `devices` name is
//!   already taken by the cloud-discovered devices in this database;
//! * `key_enc` holds the device key as lowercase hex (the document permits
//!   skipping AES-GCM with `KEY_PEPPER`, provided the decision is documented —
//!   see `README.md` → *Device ingest*);
//! * `ingest_devices` additionally carries the fixed one-hour rate window
//!   (`rate_start` / `rate_count`) required by §5.3.
//!
//! Not implemented here (later milestones): read API (§4.3), hourly rollups,
//! retention and silent-device alerts (§9), CBOR (§Appendix D), mTLS (§5.4).

use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::wasm_bindgen::JsValue;
use worker::*;

use crate::model::now_secs;

type HmacSha256 = Hmac<Sha256>;

/// `Content-Type` is always JSON in v1.
const CONTENT_TYPE: &str = "application/json";
/// §6 `body_too_large` (413 in practice).
const MAX_BODY: usize = 4096;
/// §6 `too_many_samples`; also the maximum rows one request may insert.
const MAX_SAMPLES: usize = 64;
/// §5.3: accepted batches per device per hour.
const MAX_BATCHES_PER_HOUR: i64 = 60;
/// §5.3 rate window length.
const RATE_WINDOW: i64 = 3600;
/// Canonical-string method, taken from the request itself.
const SAMPLES_PATH: &str = "/v1/samples";

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// `POST /v1/samples` body (§4.1). Unknown top-level fields are ignored for
/// forward compatibility, so every field is optional here and validated by
/// `validate_envelope` — serde must not be the one rejecting a request, since
/// the error code has to follow the document's taxonomy.
#[derive(Debug, Deserialize)]
struct Upload {
    #[serde(default)]
    v: Option<i64>,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    boot_id: Option<i64>,
    #[serde(default)]
    batch: Option<i64>,
    #[serde(default)]
    period_min: Option<i64>,
    #[serde(default)]
    samples: Option<Vec<Value>>,
    /// v2 HR-200: device wall clock when the batch was built; absent or `0`
    /// means "unknown", never a fake value.
    #[serde(default)]
    sent_at: Option<Value>,
    /// v2 HR-201: one entry per sample, device wall clock when it was queued.
    #[serde(default)]
    collected_at: Option<Vec<Value>>,
}

/// `ingest_devices` row as needed by the ingest path.
#[derive(Debug, Deserialize)]
struct DeviceRow {
    id: String,
    key_enc: String,
    disabled: i64,
    last_boot_id: Option<i64>,
    last_batch: Option<i64>,
    rate_start: i64,
    rate_count: i64,
    last_sample_at: Option<i64>,
}

/// What the structured log line reports (§9.1).
#[derive(Default)]
struct LogCtx {
    device: String,
    batch: i64,
    boot_id: i64,
    samples: usize,
    stored: usize,
    duplicate: usize,
    rejected: usize,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /v1/samples` — accept one batch of device samples.
pub async fn samples(mut req: Request, env: Env) -> Result<Response> {
    let started = Date::now().as_millis();

    let (status, body, ctx) = match ingest(&mut req, &env).await {
        Ok(outcome) => outcome,
        Err(e) => {
            // Storage failures are the only errors that escape `ingest`; D1 has
            // not committed anything in that case (§8).
            console_error!("ingest: {e}");
            (
                503,
                error_body("storage_unavailable", "storage unavailable; retry"),
                LogCtx::default(),
            )
        }
    };

    log_request(&req, status, Date::now().as_millis() - started, &ctx);
    respond(status, body)
}

/// `SELECT 1` into a named column (§4.2's "can reach D1" check).
#[derive(Debug, Deserialize)]
struct HealthProbe {
    ok: i64,
}

/// `GET /v1/health` — no auth, no side effects (§4.2).
pub async fn health(env: &Env) -> Result<Response> {
    let storage_ok = match env.d1("DB") {
        Ok(db) => matches!(
            db.prepare("SELECT 1 AS ok").first::<HealthProbe>(None).await,
            Ok(Some(probe)) if probe.ok == 1
        ),
        Err(_) => false,
    };

    if storage_ok {
        respond(
            200,
            json!({
                "ok": true,
                "time": now_secs(),
                "version": env!("CARGO_PKG_VERSION"),
                "storage": "ok",
            }),
        )
    } else {
        respond(503, json!({ "ok": false, "storage": "error" }))
    }
}

// ---------------------------------------------------------------------------
// Request pipeline
// ---------------------------------------------------------------------------

async fn ingest(req: &mut Request, env: &Env) -> Result<(u16, Value, LogCtx)> {
    // §5.5 — never redirect a plain-HTTP request, reject it instead.
    if plain_http(req) {
        return Ok(rejected(
            400,
            "https_required",
            "this endpoint requires https",
        ));
    }

    let content_type = header(req, "content-type").unwrap_or_default();
    if !content_type
        .trim()
        .to_ascii_lowercase()
        .starts_with(CONTENT_TYPE)
    {
        // v1 speaks JSON only; a CBOR body lands here too (§Appendix D).
        return Ok(rejected(
            400,
            "bad_json",
            "Content-Type must be application/json",
        ));
    }

    // Reject on the declared length before buffering the body (NFR-5).
    if let Some(len) = header(req, "content-length").and_then(|v| v.parse::<usize>().ok()) {
        if len > MAX_BODY {
            return Ok(rejected(413, "body_too_large", "body exceeds 4096 bytes"));
        }
    }

    let raw = req.bytes().await?;
    if raw.len() > MAX_BODY {
        return Ok(rejected(413, "body_too_large", "body exceeds 4096 bytes"));
    }

    let upload: Upload = match serde_json::from_slice(&raw) {
        Ok(u) => u,
        Err(_) => return Ok(rejected(400, "bad_json", "body is not valid JSON")),
    };

    // One clock reading for the whole request: it is the canonical timestamp
    // (v1 §3) and the reference the v2 device-time checks use.
    let now = now_secs();
    let envelope = match validate_envelope(&upload, now) {
        Ok(e) => e,
        Err((code, message)) => {
            let mut out = rejected(400, code, message);
            out.2 = LogCtx {
                device: upload.device.clone().unwrap_or_default(),
                batch: upload.batch.unwrap_or(0),
                boot_id: upload.boot_id.unwrap_or(0),
                samples: upload.samples.as_ref().map_or(0, Vec::len),
                ..Default::default()
            };
            return Ok(out);
        }
    };
    let device = envelope.device.clone();
    let (boot_id, batch) = (envelope.boot_id, envelope.batch);
    let samples = &envelope.samples;

    let db = env.d1("DB")?;

    // The key comes from the database, so the device row is loaded before the
    // signature can be checked. An unknown device and a bad signature answer
    // identically (§5.2), which is why this returns the same body.
    let row = load_device(&db, &device).await?;
    let Some(row) = row else {
        return Ok(rejected(401, "signature_invalid", "signature invalid"));
    };
    if !signature_ok(req, &row, boot_id, batch, &raw) {
        return Ok(rejected(401, "signature_invalid", "signature invalid"));
    }

    if row.disabled != 0 {
        return Ok(rejected(403, "device_disabled", "device is disabled"));
    }

    // v2 HR-222: `(device, boot_id, batch)` decides duplicates, so a replay is
    // recognised even after later batches moved the counter. Answering
    // `duplicate` makes the firmware drain its queue, so this must only fire for
    // a batch we really did store (v2 §3).
    if batch_stored(&db, &row.id, boot_id, batch).await? {
        let n = samples.len();
        return Ok((
            200,
            json!({
                "ok": true,
                "batch": batch,
                "stored": 0,
                "duplicate": n,
                "rejected": 0,
                "server_time": now,
                "time_source": "server",
            }),
            LogCtx {
                device: row.id.clone(),
                batch,
                boot_id,
                samples: n,
                duplicate: n,
                ..Default::default()
            },
        ));
    }

    // §5.3 ordering, only for a batch we have *not* seen: a counter that went
    // backwards is a firmware bug, not a duplicate.
    if row.last_boot_id == Some(boot_id) {
        if let Some(last) = row.last_batch {
            if batch < last {
                return Ok((
                    409,
                    json!({
                        "ok": false,
                        "code": "batch_out_of_order",
                        "message": "batch counter went backwards",
                        "expected_min_batch": last + 1,
                    }),
                    LogCtx {
                        device: row.id.clone(),
                        batch,
                        boot_id,
                        ..Default::default()
                    },
                ));
            }
        }
    }

    // §5.3 rate limit — counted only for accepted batches, checked before the
    // write so a runaway retry loop never reaches D1 (NFR-5).
    let window_open = row.rate_start > 0 && now.saturating_sub(row.rate_start) < RATE_WINDOW;
    let (rate_start, rate_count) = if window_open {
        (row.rate_start, row.rate_count + 1)
    } else {
        (now, 1)
    };
    if rate_count > MAX_BATCHES_PER_HOUR {
        let retry_after = (row.rate_start + RATE_WINDOW - now).max(1);
        let mut body = error_body("rate_limited", "too many batches; retry later");
        body["retry_after"] = json!(retry_after);
        return Ok((
            429,
            body,
            LogCtx {
                device: row.id.clone(),
                batch,
                boot_id,
                ..Default::default()
            },
        ));
    }

    // §6 per-sample validation: bad samples are dropped, the rest is stored.
    // The device-supplied collection time travels with its sample, so a dropped
    // sample cannot shift the times of the ones after it.
    let mut accepted: Vec<Accepted> = Vec::with_capacity(samples.len());
    let mut problems: Vec<Value> = Vec::new();
    for (index, sample) in samples.iter().enumerate() {
        match check_sample(sample) {
            Ok(sample) => accepted.push(Accepted {
                sample,
                collected_at: envelope.collected_at[index],
            }),
            Err(reason) => problems.push(json!({ "index": index, "reason": reason })),
        }
    }

    // Newest device clock seen in this batch, for the admin "last sample" pair.
    let batch_last_sample = accepted.iter().filter_map(|a| a.collected_at).max();
    let last_sample_at = match (row.last_sample_at, batch_last_sample) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (a, b) => a.or(b),
    };

    let received_at = now;
    let written = store(
        &db,
        &row.id,
        &accepted,
        received_at,
        boot_id,
        batch,
        rate_start,
        rate_count,
        req,
        upload.period_min,
        envelope.sent_at,
        last_sample_at,
        problems.len(),
    )
    .await?;

    let duplicate = accepted.len() - written;
    let rejected = problems.len();
    let mut body = json!({
        "ok": true,
        "batch": batch,
        "stored": written,
        "duplicate": duplicate,
        "rejected": rejected,
        "server_time": received_at,
        "time_source": "server",
    });
    if !problems.is_empty() {
        body["problems"] = Value::Array(problems);
    }

    Ok((
        200,
        body,
        LogCtx {
            device: row.id.clone(),
            batch,
            boot_id,
            samples: upload.samples.as_ref().map_or(0, Vec::len),
            stored: written,
            duplicate,
            rejected,
        },
    ))
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// One sample that passed validation, with its device-supplied time.
struct Accepted {
    sample: [i64; 6],
    /// v2 HR-202: `None` when the device had no clock for this sample.
    collected_at: Option<i64>,
}

/// Everything the write path needs from a validated body.
struct Envelope {
    device: String,
    boot_id: i64,
    batch: i64,
    samples: Vec<Value>,
    /// HR-203: untrusted, already range-checked; `None` when absent or `0`.
    sent_at: Option<i64>,
    /// HR-202: one entry per sample, `None` where the device had no clock.
    collected_at: Vec<Option<i64>>,
}

/// Request-level checks of §6 plus the v2 additions (HR-201, HR-204), in the
/// documented order. `Err` is the error `code` of §7 with a human message.
fn validate_envelope(
    u: &Upload,
    now: i64,
) -> std::result::Result<Envelope, (&'static str, &'static str)> {
    if u.v != Some(1) {
        return Err(("unknown_version", "v must be 1"));
    }
    let Some(device) = u.device.as_deref() else {
        return Err(("bad_device", "device must be 12 uppercase hex characters"));
    };
    if !is_device_id(device) {
        return Err(("bad_device", "device must be 12 uppercase hex characters"));
    }
    let Some(boot_id) = u.boot_id.filter(|v| (0..=u16::MAX as i64).contains(v)) else {
        return Err(("bad_batch", "boot_id must be a u16"));
    };
    let Some(batch) = u.batch.filter(|v| (0..=u32::MAX as i64).contains(v)) else {
        return Err(("bad_batch", "batch must be a u32"));
    };
    let Some(samples) = u.samples.as_ref() else {
        return Err(("too_many_samples", "samples must hold 1..=64 entries"));
    };
    if samples.is_empty() || samples.len() > MAX_SAMPLES {
        return Err(("too_many_samples", "samples must hold 1..=64 entries"));
    }

    // HR-201: one entry per sample, or it is a firmware bug.
    let collected_at = match u.collected_at.as_ref() {
        None => vec![None; samples.len()],
        Some(list) if list.len() == samples.len() => list
            .iter()
            .map(|v| clamp_device_time(v.as_i64(), now))
            .collect(),
        Some(_) => {
            return Err((
                "bad_collected_at",
                "collected_at must have one entry per sample",
            ))
        }
    };

    // HR-204: an implausible *batch* time is a wrong clock and is rejected; the
    // per-sample times are never a reason to drop the samples themselves.
    let sent_at = match u.sent_at.as_ref().and_then(Value::as_i64) {
        None | Some(0) => None,
        Some(t) if plausible_device_time(t, now) => Some(t),
        Some(_) => {
            return Err((
                "implausible_device_time",
                "sent_at must be within 400 days of now and at most 24 h ahead",
            ))
        }
    };

    Ok(Envelope {
        device: device.to_string(),
        boot_id,
        batch,
        samples: samples.clone(),
        sent_at,
        collected_at,
    })
}

/// HR-204 window: not more than 24 h ahead, not more than 400 days behind.
fn plausible_device_time(t: i64, now: i64) -> bool {
    t <= now + 86_400 && t >= now - 400 * 86_400
}

/// HR-202/204: `0`, a missing value and an implausible one all mean "unknown".
fn clamp_device_time(t: Option<i64>, now: i64) -> Option<i64> {
    match t {
        Some(t) if plausible_device_time(t, now) => Some(t),
        _ => None,
    }
}

/// One sample is `[node, seq, t_x10, h_x10, batt_mv, minutes]` (§Appendix B).
fn check_sample(sample: &Value) -> std::result::Result<[i64; 6], &'static str> {
    let arr = sample.as_array().ok_or("minutes_range")?;
    // §6: a wrong number of entries is reported as `minutes_range`.
    if arr.len() != 6 {
        return Err("minutes_range");
    }
    let mut out = [0_i64; 6];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = arr[i].as_i64().ok_or(match i {
            0 => "node_range",
            1 => "seq_range",
            2 => "temperature_range",
            3 => "humidity_range",
            4 => "battery_range",
            _ => "minutes_range",
        })?;
    }
    let [node, seq, t, h, batt, minutes] = out;
    if !(1..=254).contains(&node) {
        return Err("node_range");
    }
    if !(0..=255).contains(&seq) {
        return Err("seq_range");
    }
    if !(-1000..=1000).contains(&t) {
        return Err("temperature_range");
    }
    if !(0..=1000).contains(&h) {
        return Err("humidity_range");
    }
    // 0 = not measured; 1..=2000 mV is implausible for a battery.
    if !(0..=5000).contains(&batt) || (1..=2000).contains(&batt) {
        return Err("battery_range");
    }
    if !(0..=65_535).contains(&minutes) {
        return Err("minutes_range");
    }
    Ok(out)
}

/// §3: 12 uppercase hex characters of the BLE address.
pub(crate) fn is_device_id(s: &str) -> bool {
    s.len() == 12
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('A'..='F').contains(&c))
}

// ---------------------------------------------------------------------------
// Authentication (§5.2)
// ---------------------------------------------------------------------------

async fn load_device(db: &D1Database, id: &str) -> Result<Option<DeviceRow>> {
    db.prepare(
        "SELECT id, key_enc, disabled, last_boot_id, last_batch, rate_start, rate_count,
                last_sample_at
           FROM ingest_devices
          WHERE id = ?",
    )
    .bind(&[JsValue::from_str(id)])?
    .first::<DeviceRow>(None)
    .await
}

/// Verify `X-Signature: v1=<hmac>` over the canonical string.
///
/// Every failure — missing header, wrong prefix, malformed hex, wrong digest —
/// is one boolean, so the caller cannot leak which one it was.
fn signature_ok(req: &Request, row: &DeviceRow, boot_id: i64, batch: i64, raw: &[u8]) -> bool {
    let Ok(Some(header)) = req.headers().get("x-signature") else {
        return false;
    };
    let Some(hex_sig) = header.trim().strip_prefix("v1=") else {
        return false;
    };
    let Ok(sig) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(key) = hex::decode(&row.key_enc) else {
        return false;
    };
    let Ok(path) = req.url().map(|u| u.path().to_string()) else {
        return false;
    };

    let body_hash = hex::encode(Sha256::digest(raw));
    let canonical = format!(
        "v1\nPOST\n{path}\n{}\n{boot_id}\n{batch}\n{body_hash}",
        row.id
    );

    let Ok(mut mac) = HmacSha256::new_from_slice(&key) else {
        return false;
    };
    mac.update(canonical.as_bytes());
    // `verify_slice` compares in constant time.
    mac.verify_slice(&sig).is_ok()
}

/// §5.5: a request the edge received over plain HTTP, i.e. `CF-Visitor`.
///
/// `wrangler dev` serves plain HTTP on a loopback/LAN address and is the
/// documented development exception, so those hosts are not rejected.
fn plain_http(req: &Request) -> bool {
    if let Ok(Some(visitor)) = req.headers().get("cf-visitor") {
        if visitor.contains("\"http\"") {
            return true;
        }
        if visitor.contains("\"https\"") {
            return false;
        }
    }
    match req.url() {
        Ok(url) if url.scheme() == "http" => !is_dev_host(url.host_str().unwrap_or("")),
        _ => false,
    }
}

/// Loopback, RFC 1918 or `.local` — the `wrangler dev` exception of §11.
fn is_dev_host(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let host = host.split(':').next().unwrap_or(host);
    if host == "localhost" || host == "0.0.0.0" || host.ends_with(".local") {
        return true;
    }
    let mut parts = host.split('.');
    match (parts.next(), parts.next()) {
        (Some("127"), _) | (Some("10"), _) => true,
        (Some("192"), Some("168")) => true,
        (Some("172"), Some(second)) => second.parse::<u8>().is_ok_and(|n| (16..=31).contains(&n)),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Storage (§8)
// ---------------------------------------------------------------------------

/// Insert the accepted samples and advance the device row in one `batch()`, so
/// a failure commits nothing. Returns how many sample rows were actually
/// inserted (the rest were row-level duplicates).
#[allow(clippy::too_many_arguments)]
async fn store(
    db: &D1Database,
    device: &str,
    accepted: &[Accepted],
    received_at: i64,
    boot_id: i64,
    batch: i64,
    rate_start: i64,
    rate_count: i64,
    req: &Request,
    period_min: Option<i64>,
    sent_at: Option<i64>,
    last_sample_at: Option<i64>,
    rejected: usize,
) -> Result<usize> {
    let mut stmts = Vec::with_capacity(accepted.len() + 2);
    for a in accepted {
        let s = &a.sample;
        stmts.push(
            db.prepare(
                "INSERT OR IGNORE INTO samples
                   (device_id, node_id, seq, device_min, received_at,
                    t_x10, h_x10, batt_mv, boot_id, batch, device_collected_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&[
                JsValue::from_str(device),
                JsValue::from_f64(s[0] as f64),
                JsValue::from_f64(s[1] as f64),
                JsValue::from_f64(s[5] as f64),
                JsValue::from_f64(received_at as f64),
                JsValue::from_f64(s[2] as f64),
                JsValue::from_f64(s[3] as f64),
                JsValue::from_f64(s[4] as f64),
                JsValue::from_f64(boot_id as f64),
                JsValue::from_f64(batch as f64),
                opt_int(a.collected_at),
            ])?,
        );
    }

    // v2 §5: one row per accepted batch — the HR-222 dedupe key and the admin
    // page's "last upload" record.
    stmts.push(
        db.prepare(
            "INSERT INTO batches_meta
               (device_id, boot_id, batch, received_at, sent_at, samples, rejected)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(device_id, boot_id, batch) DO UPDATE SET
               received_at = excluded.received_at,
               sent_at     = COALESCE(excluded.sent_at, batches_meta.sent_at),
               samples     = excluded.samples,
               rejected    = excluded.rejected",
        )
        .bind(&[
            JsValue::from_str(device),
            JsValue::from_f64(boot_id as f64),
            JsValue::from_f64(batch as f64),
            JsValue::from_f64(received_at as f64),
            opt_int(sent_at),
            JsValue::from_f64(accepted.len() as f64),
            JsValue::from_f64(rejected as f64),
        ])?,
    );

    let ip = header(req, "cf-connecting-ip").unwrap_or_default();
    let firmware = header(req, "x-firmware")
        .filter(|v| !v.is_empty())
        .or_else(|| header(req, "user-agent"))
        .unwrap_or_default();
    // §6: stored for alerting but clamped to one day.
    let period = period_min.map(|p| p.clamp(1, 1440)).unwrap_or(0);

    // Device row last: counters are cumulative so the admin page never has to
    // scan `samples` or `batches_meta` (v2 HR-223).
    stmts.push(
        db.prepare(
            "UPDATE ingest_devices
                SET last_boot_id    = ?,
                    last_batch      = ?,
                    last_seen       = ?,
                    last_ip         = ?,
                    firmware        = ?,
                    period_min      = CASE WHEN ? > 0 THEN ? ELSE period_min END,
                    rate_start      = ?,
                    rate_count      = ?,
                    samples_total   = samples_total + ?,
                    batches_total   = batches_total + 1,
                    rejected_total  = rejected_total + ?,
                    last_sample_at  = ?,
                    last_sent_at    = COALESCE(?, last_sent_at)
              WHERE id = ?",
        )
        .bind(&[
            JsValue::from_f64(boot_id as f64),
            JsValue::from_f64(batch as f64),
            JsValue::from_f64(received_at as f64),
            JsValue::from_str(&ip),
            JsValue::from_str(&firmware),
            JsValue::from_f64(period as f64),
            JsValue::from_f64(period as f64),
            JsValue::from_f64(rate_start as f64),
            JsValue::from_f64(rate_count as f64),
            JsValue::from_f64(accepted.len() as f64),
            JsValue::from_f64(rejected as f64),
            opt_int(last_sample_at),
            opt_int(sent_at),
            JsValue::from_str(device),
        ])?,
    );

    let results = db.batch(stmts).await?;
    let stored = results
        .iter()
        .take(accepted.len())
        .filter_map(|r| r.meta().ok().flatten().and_then(|m| m.changes))
        .sum();
    Ok(stored)
}

/// Has this `(device, boot_id, batch)` already been accepted? (v2 HR-222)
async fn batch_stored(db: &D1Database, device: &str, boot_id: i64, batch: i64) -> Result<bool> {
    #[derive(Debug, Deserialize)]
    struct Row {
        #[allow(dead_code)]
        batch: i64,
    }
    let row = db
        .prepare("SELECT batch FROM batches_meta WHERE device_id = ? AND boot_id = ? AND batch = ?")
        .bind(&[
            JsValue::from_str(device),
            JsValue::from_f64(boot_id as f64),
            JsValue::from_f64(batch as f64),
        ])?
        .first::<Row>(None)
        .await?;
    Ok(row.is_some())
}

/// `Option<i64>` → a bound number or SQL NULL.
fn opt_int(value: Option<i64>) -> JsValue {
    value
        .map(|v| JsValue::from_f64(v as f64))
        .unwrap_or(JsValue::NULL)
}

// ---------------------------------------------------------------------------
// Responses, logging
// ---------------------------------------------------------------------------

fn header(req: &Request, name: &str) -> Option<String> {
    req.headers().get(name).ok().flatten()
}

fn error_body(code: &str, message: &str) -> Value {
    json!({ "ok": false, "code": code, "message": message })
}

/// `(status, body, empty log ctx)` for a rejection.
fn rejected(status: u16, code: &str, message: &str) -> (u16, Value, LogCtx) {
    (status, error_body(code, message), LogCtx::default())
}

/// Common response headers: never cached, always HSTS (§5.5).
fn respond(status: u16, body: Value) -> Result<Response> {
    let headers = Headers::new();
    // `with_headers` replaces the set that `from_json` produced, so restate it.
    headers.set("content-type", "application/json; charset=utf-8")?;
    headers.set("cache-control", "no-store")?;
    headers.set(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    )?;
    headers.set("x-content-type-options", "nosniff")?;
    Ok(Response::from_json(&body)?
        .with_status(status)
        .with_headers(headers))
}

/// One structured line per request (§9.1). Never keys, signatures or bodies.
fn log_request(req: &Request, status: u16, ms: u64, ctx: &LogCtx) {
    // `cf-ray` carries the request id and the colo suffix; reading it as a
    // header also works under `wrangler dev`, where `request.cf` may be empty.
    console_log!(
        "{}",
        json!({
            "ts": now_secs(),
            "device": ctx.device,
            "batch": ctx.batch,
            "boot_id": ctx.boot_id,
            "samples": ctx.samples,
            "stored": ctx.stored,
            "duplicate": ctx.duplicate,
            "rejected": ctx.rejected,
            "status": status,
            "ms": ms,
            "ray": header(req, "cf-ray").unwrap_or_default(),
            "path": SAMPLES_PATH,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §Appendix A vector 1 — the canonical string and HMAC are fixed there.
    #[test]
    fn appendix_a_vector_1() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let body = br#"{"v":1,"device":"F29E9E3C98E5","boot_id":4660,"batch":42,"period_min":30,"samples":[[7,12,234,649,4000,1230]]}"#;
        let hash = hex::encode(Sha256::digest(body));
        assert_eq!(
            hash,
            "5bde61973898e7ecc083084a36c326aef587423a9a851b07fd9626144e309fd5"
        );
        let canonical = format!("v1\nPOST\n/v1/samples\nF29E9E3C98E5\n4660\n42\n{hash}");
        let mut mac = HmacSha256::new_from_slice(&key).unwrap();
        mac.update(canonical.as_bytes());
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "56b73dfadec798fe453e12e3fe9c422d8f211c4a1d18c18e57c38eea65b1da64"
        );
    }

    #[test]
    fn sample_ranges() {
        assert!(check_sample(&json!([7, 12, 234, 649, 4000, 1230])).is_ok());
        assert_eq!(
            check_sample(&json!([7, 12, 234, 1200, 4000, 1230])),
            Err("humidity_range")
        );
        assert_eq!(
            check_sample(&json!([0, 12, 234, 649, 4000, 1230])),
            Err("node_range")
        );
        assert_eq!(
            check_sample(&json!([7, 12, 234, 649, 1000, 1230])),
            Err("battery_range")
        );
        assert_eq!(check_sample(&json!([7, 12])), Err("minutes_range"));
        assert_eq!(
            check_sample(&json!([7, 12, -1001, 649, 4000, 1])),
            Err("temperature_range")
        );
    }

    #[test]
    fn device_ids() {
        assert!(is_device_id("F29E9E3C98E5"));
        assert!(!is_device_id("f29e9e3c98e5"));
        assert!(!is_device_id("F29E9E3C98E"));
        assert!(!is_device_id("F29E9E3C98EG"));
    }

    #[test]
    fn dev_hosts() {
        assert!(is_dev_host("localhost:8787"));
        assert!(is_dev_host("127.0.0.1"));
        assert!(is_dev_host("192.168.1.10:8787"));
        assert!(is_dev_host("printer.local"));
        assert!(!is_dev_host("ingest.example.com"));
    }
}
