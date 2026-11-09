//! Operator API for the ingest device registry (`/api/ingest/devices`).
//!
//! The device-facing write path is `ingest.rs`; this is the admin page's side of
//! the same table. Everything here requires the admin token (`API_TOKEN`) — the
//! shareable read token must not see device ids, IPs or firmware versions.
//!
//! Keys are never listed and never read back: a key is returned exactly once,
//! from the call that created or rotated it, because the server cannot show a
//! device's key later without handing out credentials on every page load.

use serde::{Deserialize, Serialize};
use serde_json::json;
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::*;

use crate::ingest::is_device_id;

/// `role` values of the ingest requirements (§2/§8).
const ROLES: [&str; 3] = ["server", "client", "direct"];

/// One registry row, without the key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: Option<String>,
    pub role: Option<String>,
    pub node_id: Option<i64>,
    pub period_min: Option<i64>,
    pub last_boot_id: Option<i64>,
    pub last_batch: Option<i64>,
    pub last_seen: Option<i64>,
    pub last_ip: Option<String>,
    pub firmware: Option<String>,
    pub disabled: i64,
    pub created_at: i64,
    /// v2 HR-223: "last upload" is `last_seen` (server clock), "last sample" is
    /// `last_sample_at` (device clock). They differ when a queue was drained.
    pub samples_total: i64,
    pub batches_total: i64,
    pub rejected_total: i64,
    pub last_sample_at: Option<i64>,
    pub last_sent_at: Option<i64>,
}

const COLUMNS: &str = "id, name, role, node_id, period_min, last_boot_id, last_batch,
                       last_seen, last_ip, firmware, disabled, created_at,
                       samples_total, batches_total, rejected_total,
                       last_sample_at, last_sent_at";

/// One stored sample, for the admin page's recent-samples table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SampleRow {
    pub device_id: String,
    pub node_id: i64,
    pub seq: i64,
    pub device_min: i64,
    pub received_at: i64,
    /// v2 HR-202: the device clock when it was queued, `None` = unknown.
    pub device_collected_at: Option<i64>,
    pub t_x10: i64,
    pub h_x10: i64,
    pub batt_mv: i64,
    pub boot_id: i64,
    pub batch: i64,
}

/// Upper bound for one admin read; the page only ever shows a screenful.
const MAX_LIMIT: i64 = 200;

#[derive(Debug, Deserialize)]
struct CreateBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    node_id: Option<i64>,
    #[serde(default)]
    period_min: Option<i64>,
    #[serde(default)]
    key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateBody {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    node_id: Option<i64>,
    #[serde(default)]
    period_min: Option<i64>,
    #[serde(default)]
    disabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RotateBody {
    #[serde(default)]
    key: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/ingest/devices` — every registered device, key excluded.
pub async fn list(env: &Env) -> Result<Response> {
    let db = env.d1("DB")?;
    let rows = db
        .prepare(format!("SELECT {COLUMNS} FROM ingest_devices ORDER BY id").as_str())
        .all()
        .await?
        .results::<DeviceRow>()?;
    Response::from_json(&rows)
}

/// `GET /api/ingest/samples?device=&limit=` — the newest stored samples.
///
/// `limit` is capped at 200. Without `device` the query walks `samples_by_time`,
/// with it `samples_by_device_time`; both are index-ordered, so this stays a
/// bounded read no matter how much history the table holds.
pub async fn samples(req: Request, env: &Env) -> Result<Response> {
    let params: std::collections::HashMap<String, String> = req
        .url()
        .map(|u| u.query_pairs().into_owned().collect())
        .unwrap_or_default();
    let device = params
        .get("device")
        .map(|d| d.trim().to_ascii_uppercase())
        .filter(|d| is_device_id(d));
    let limit = params
        .get("limit")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(50)
        .clamp(1, MAX_LIMIT);

    let db = env.d1("DB")?;
    let sql = match device {
        Some(_) => {
            "SELECT device_id, node_id, seq, device_min, received_at, device_collected_at,
                    t_x10, h_x10, batt_mv, boot_id, batch
               FROM samples
              WHERE device_id = ?
              ORDER BY received_at DESC
              LIMIT ?"
        }
        None => {
            "SELECT device_id, node_id, seq, device_min, received_at, device_collected_at,
                    t_x10, h_x10, batt_mv, boot_id, batch
               FROM samples
              ORDER BY received_at DESC
              LIMIT ?"
        }
    };
    let stmt = db.prepare(sql);
    let stmt = match &device {
        Some(d) => stmt.bind(&[JsValue::from_str(d), JsValue::from_f64(limit as f64)])?,
        None => stmt.bind(&[JsValue::from_f64(limit as f64)])?,
    };
    let rows = stmt.all().await?.results::<SampleRow>()?;
    Response::from_json(&rows)
}

/// `POST /api/ingest/devices` — register a device and return its key once.
///
/// A `key` may be supplied (it must be 64 hex characters, the same bytes the
/// firmware stores); otherwise 32 random bytes are generated here.
pub async fn create(mut req: Request, env: &Env) -> Result<Response> {
    let body: CreateBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("invalid JSON body", 400),
    };

    let Some(id) = body
        .id
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_uppercase)
        .filter(|id| is_device_id(id))
    else {
        return Response::error(
            "id must be 12 uppercase hex characters (the BLE address)",
            400,
        );
    };

    let role = match clean_role(body.role.as_deref()) {
        Ok(r) => r,
        Err(e) => return Response::error(e, 400),
    };
    let node_id = match clean_node_id(body.node_id) {
        Ok(v) => v,
        Err(e) => return Response::error(e, 400),
    };
    let period_min = match clean_period(body.period_min) {
        Ok(v) => v,
        Err(e) => return Response::error(e, 400),
    };

    let key = match body.key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => match clean_key(k) {
            Ok(k) => k,
            Err(e) => return Response::error(e, 400),
        },
        None => random_key()?,
    };

    let db = env.d1("DB")?;
    let name = body
        .name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty());

    // A re-registered device keeps its history and its optional fields; it gets a
    // new key and is re-enabled. An empty field in the body means "leave alone".
    db.prepare(
        "INSERT INTO ingest_devices (id, name, role, node_id, period_min, key_enc, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           name       = COALESCE(excluded.name, ingest_devices.name),
           role       = COALESCE(excluded.role, ingest_devices.role),
           node_id    = COALESCE(excluded.node_id, ingest_devices.node_id),
           period_min = COALESCE(excluded.period_min, ingest_devices.period_min),
           key_enc    = excluded.key_enc,
           disabled   = 0",
    )
    .bind(&[
        JsValue::from_str(&id),
        name.map(JsValue::from_str).unwrap_or(JsValue::NULL),
        opt_str(&role),
        int(node_id),
        int(period_min),
        JsValue::from_str(&key),
        f64_of(now_secs()),
    ])?
    .run()
    .await?;

    let device = fetch(&db, &id).await?;
    Response::from_json(&json!({ "ok": true, "device": device, "key": key }))
}

/// `PUT /api/ingest/devices/:id` — update the editable fields.
///
/// Missing fields are left alone; an empty `name`/`role` clears it, and a
/// `node_id`/`period_min` of 0 clears that too (the UI sends 0 for "not set").
pub async fn update(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    let Some(id) = ctx.param("id").map(|s| s.to_ascii_uppercase()) else {
        return Response::error("missing device id", 400);
    };
    if !is_device_id(&id) {
        return Response::error("id must be 12 uppercase hex characters", 400);
    }

    let body: UpdateBody = match req.json().await {
        Ok(b) => b,
        Err(_) => return Response::error("invalid JSON body", 400),
    };

    let db = ctx.env.d1("DB")?;
    let Some(current) = fetch(&db, &id).await? else {
        return Response::error("unknown device", 404);
    };

    let name = match body.name.as_deref() {
        Some(raw) => {
            let t = raw.trim();
            if t.is_empty() {
                None
            } else {
                Some(t.chars().take(120).collect::<String>())
            }
        }
        None => current.name.clone(),
    };
    let role = match body.role.as_deref() {
        Some(raw) => match clean_role(Some(raw)) {
            Ok(r) => r,
            Err(e) => return Response::error(e, 400),
        },
        None => current.role.clone(),
    };
    let node_id = match body.node_id {
        Some(v) => match clean_node_id(Some(v)) {
            Ok(v) => v,
            Err(e) => return Response::error(e, 400),
        },
        None => current.node_id,
    };
    let period_min = match body.period_min {
        Some(v) => match clean_period(Some(v)) {
            Ok(v) => v,
            Err(e) => return Response::error(e, 400),
        },
        None => current.period_min,
    };
    let disabled = body.disabled.map_or(current.disabled, i64::from);

    db.prepare(
        "UPDATE ingest_devices
            SET name = ?, role = ?, node_id = ?, period_min = ?, disabled = ?
          WHERE id = ?",
    )
    .bind(&[
        opt_str(&name),
        opt_str(&role),
        int(node_id),
        int(period_min),
        f64_of(disabled as f64),
        JsValue::from_str(&id),
    ])?
    .run()
    .await?;

    let device = fetch(&db, &id).await?;
    Response::from_json(&json!({ "ok": true, "device": device }))
}

/// `DELETE /api/ingest/devices/:id` — unregister. Samples are kept.
pub async fn remove(ctx: &RouteContext<()>) -> Result<Response> {
    let Some(id) = ctx.param("id").map(|s| s.to_ascii_uppercase()) else {
        return Response::error("missing device id", 400);
    };
    let db = ctx.env.d1("DB")?;
    let deleted = db
        .prepare("DELETE FROM ingest_devices WHERE id = ?")
        .bind(&[JsValue::from_str(&id)])?
        .run()
        .await?
        .meta()?
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if deleted == 0 {
        return Response::error("unknown device", 404);
    }
    Response::from_json(&json!({ "ok": true }))
}

/// `POST /api/ingest/devices/:id/key` — set or rotate the device key.
///
/// Body may carry `{"key": "<64 hex>"}`; otherwise a fresh key is generated.
/// The key is returned once and never again.
pub async fn rotate(mut req: Request, ctx: &RouteContext<()>) -> Result<Response> {
    let Some(id) = ctx.param("id").map(|s| s.to_ascii_uppercase()) else {
        return Response::error("missing device id", 400);
    };
    let body: RotateBody = match req.text().await {
        Ok(text) if !text.trim().is_empty() => match serde_json::from_str(&text) {
            Ok(b) => b,
            Err(_) => return Response::error("invalid JSON body", 400),
        },
        _ => RotateBody { key: None },
    };

    let key = match body.key.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
        Some(k) => match clean_key(k) {
            Ok(k) => k,
            Err(e) => return Response::error(e, 400),
        },
        None => random_key()?,
    };

    let db = ctx.env.d1("DB")?;
    let updated = db
        .prepare("UPDATE ingest_devices SET key_enc = ? WHERE id = ?")
        .bind(&[JsValue::from_str(&key), JsValue::from_str(&id)])?
        .run()
        .await?
        .meta()?
        .and_then(|m| m.changes)
        .unwrap_or(0);
    if updated == 0 {
        return Response::error("unknown device", 404);
    }
    Response::from_json(&json!({ "ok": true, "id": id, "key": key }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn fetch(db: &D1Database, id: &str) -> Result<Option<DeviceRow>> {
    db.prepare(format!("SELECT {COLUMNS} FROM ingest_devices WHERE id = ?").as_str())
        .bind(&[JsValue::from_str(id)])?
        .first::<DeviceRow>(None)
        .await
}

fn clean_role(raw: Option<&str>) -> std::result::Result<Option<String>, &'static str> {
    match raw.map(str::trim) {
        None => Ok(None),
        Some("") => Ok(None),
        Some(r) if ROLES.contains(&r) => Ok(Some(r.to_string())),
        Some(_) => Err("role must be server, client or direct"),
    }
}

fn clean_node_id(raw: Option<i64>) -> std::result::Result<Option<i64>, &'static str> {
    match raw {
        None | Some(0) => Ok(None),
        Some(n) if (1..=254).contains(&n) => Ok(Some(n)),
        Some(_) => Err("node_id must be 1..254"),
    }
}

fn clean_period(raw: Option<i64>) -> std::result::Result<Option<i64>, &'static str> {
    match raw {
        None | Some(0) => Ok(None),
        Some(p) if (1..=1440).contains(&p) => Ok(Some(p)),
        Some(_) => Err("period_min must be 1..1440"),
    }
}

/// Keys travel as 64 lowercase hex characters: the 32 bytes the firmware stores.
fn clean_key(raw: &str) -> std::result::Result<String, &'static str> {
    let key = raw.trim().to_ascii_lowercase();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("key must be 64 hex characters (32 bytes)");
    }
    Ok(key)
}

/// 32 random bytes from `crypto.getRandomValues`, hex encoded.
fn random_key() -> Result<String> {
    let crypto = js_sys::Reflect::get(&js_sys::global(), &JsValue::from_str("crypto"))
        .map_err(|_| Error::RustError("crypto unavailable".into()))?;
    let getter = js_sys::Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .map_err(|_| Error::RustError("crypto.getRandomValues unavailable".into()))?;
    let func = getter
        .dyn_into::<js_sys::Function>()
        .map_err(|_| Error::RustError("crypto.getRandomValues is not callable".into()))?;
    let buf = js_sys::Uint8Array::new_with_length(32);
    func.call1(&crypto, &buf)
        .map_err(|_| Error::RustError("crypto.getRandomValues failed".into()))?;
    Ok(hex::encode(buf.to_vec()))
}

/// `Option<String>` → a bound string or SQL NULL.
fn opt_str(value: &Option<String>) -> JsValue {
    value
        .as_deref()
        .map(JsValue::from_str)
        .unwrap_or(JsValue::NULL)
}

fn int(value: Option<i64>) -> JsValue {
    value.map(|v| f64_of(v as f64)).unwrap_or(JsValue::NULL)
}

fn f64_of(value: f64) -> JsValue {
    JsValue::from_f64(value)
}

fn now_secs() -> f64 {
    (Date::now().as_millis() / 1000) as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles() {
        assert_eq!(clean_role(Some("server")), Ok(Some("server".into())));
        assert_eq!(clean_role(Some("")), Ok(None));
        assert_eq!(clean_role(None), Ok(None));
        assert!(clean_role(Some("hub")).is_err());
    }

    #[test]
    fn ranges() {
        assert_eq!(clean_node_id(Some(0)), Ok(None));
        assert_eq!(clean_node_id(Some(254)), Ok(Some(254)));
        assert!(clean_node_id(Some(255)).is_err());
        assert_eq!(clean_period(Some(30)), Ok(Some(30)));
        assert!(clean_period(Some(1441)).is_err());
    }

    #[test]
    fn keys() {
        let k = "759E1F15FC8465C123A6F35A59C287A6AC3CDB53B2C984A88682E9FF2473F5D7";
        assert_eq!(
            clean_key(k),
            Ok("759e1f15fc8465c123a6f35a59c287a6ac3cdb53b2c984a88682e9ff2473f5d7".into())
        );
        assert!(clean_key("abc").is_err());
        assert!(clean_key(&"z".repeat(64)).is_err());
    }
}
