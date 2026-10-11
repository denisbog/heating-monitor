//! iLetComfort (ITS/BTRI heat pump, Midea Dollin cloud) + energy statistics.
//!
//! Everything here was verified against the live EU account on 2026-10-11.
//! Protocol notes: `docs/api-research.md`.
//!
//! Two clouds are involved:
//!   * `{region}.dollin.net`        — auth, appliance list, raw C3 hex frames
//!   * `{region}.ibuildinghvac.com/api/apps-oem` — energy statistics (kWh, heat, COP)
//!
//! The C3 status frame for our unit (sn8 `171H120F`) is the ATW / Italtherm
//! 25-byte layout; the sensor frame is a known placeholder with no telemetry.

use aes::cipher::generic_array::GenericArray;
use aes::Aes128;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use worker::*;

use crate::http::post_json;
use crate::model::{now_secs, Device, AUTH_EXPIRED};

/// Measurements are stored through the shared model type.
pub use crate::model::Reading;

type HmacSha256 = Hmac<Sha256>;
type Aes128CbcEnc = cbc::Encryptor<Aes128>;

// ---------------------------------------------------------------------------
// App constants (universal — extracted from the iLetComfort iOS binary)
// ---------------------------------------------------------------------------
pub const APP_SECRET: &str = "SIT_4VjZdg19laDoIrut";
pub const APP_KEY: &str = "btri";
pub const IOT_KEY: &str = "meicloud";
pub const CLIENT_ID: &str = "d056337d77334ecc95aca4bff6025533";
pub const CLIENT_SECRET: &str = "35b965531383ce9f37f829a19712bf3a";
pub const ENCRYPT_KEY: &str = "4dbc9ff6c15944d78eebb581c2b23de3";
pub const APP_ID: &str = "8010";
pub const APPNUM: &str = "1.6.4";

/// Subtype 0x01 status query (frame: aa 0c c3 00*6 03 01 2c).
pub const STATUS_QUERY: &str = "aa0cc30000000000000301012c";
/// Subtype 0x02 sensor query (frame: aa 0c c3 00*6 03 02 2b).
pub const SENSOR_QUERY: &str = "aa0cc30000000000000302012b";

fn api_base(region: &str) -> &'static str {
    if region == "us" {
        "https://us.dollin.net"
    } else {
        "https://eu.dollin.net"
    }
}

fn energy_base(region: &str) -> &'static str {
    if region == "us" {
        "https://us.ibuildinghvac.com"
    } else {
        "https://eu.ibuildinghvac.com"
    }
}

// ---------------------------------------------------------------------------
// Crypto / signing
// ---------------------------------------------------------------------------

fn hmac_sha256_hex(key: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(msg.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_sha256_b64(key: &str, msg: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("hmac key");
    mac.update(msg.as_bytes());
    B64.encode(mac.finalize().into_bytes())
}

/// Encrypt the password for `/v1/user/login`.
///
/// 1. `sha256(password)` as lowercase hex (64 chars)
/// 2. AES-128-CBC where key/IV are the **ASCII characters** of
///    `sha256(ENCRYPT_KEY)`'s hex digest, chars 0..16 and 16..32
/// 3. PKCS7 padding, output as lowercase hex
pub fn encrypt_password(password: &str) -> String {
    let digest = hex::encode(Sha256::digest(password.as_bytes()));
    let km = hex::encode(Sha256::digest(ENCRYPT_KEY.as_bytes()));
    let kb = km.as_bytes();
    let key = GenericArray::from_slice(&kb[0..16]);
    let iv = GenericArray::from_slice(&kb[16..32]);
    let ct = Aes128CbcEnc::new(key, iv).encrypt_padded_vec_mut::<Pkcs7>(digest.as_bytes());
    hex::encode(ct)
}

/// v1 signing: `hex(hmac_sha256(APP_SECRET, prefix + body + random))`.
/// Login uses the `meicloud` prefix, every other v1 endpoint uses `btri`.
fn sign_v1(body: &str, use_iot_key: bool) -> (String, String) {
    let now = now_secs();
    let random = format!("{}{}", ymdhms(now), rand_u32(65536));
    let prefix = if use_iot_key { IOT_KEY } else { APP_KEY };
    let sig = hmac_sha256_hex(APP_SECRET, &format!("{prefix}{body}{random}"));
    (sig, random)
}

/// v2.0 signing for `/midea/open/business/v1/...`:
/// `base64(hmac_sha256(CLIENT_SECRET, METHOD + PATH + BODY))`.
fn sign_v2(method: &str, path: &str, body: &str) -> String {
    hmac_sha256_b64(CLIENT_SECRET, &format!("{method}{path}{body}"))
}

fn rand_u32(max: u32) -> u32 {
    (worker::js_sys::Math::random() * max as f64) as u32
}

fn reqid() -> String {
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"reqid").expect("hmac");
    mac.update(format!("{}-{}", Date::now(), rand_u32(u32::MAX)).as_bytes());
    let d = mac.finalize().into_bytes();
    hex::encode(&d[0..16])
}


/// UTC `YYYYMMDDHHMMSS` from a unix timestamp, without pulling in a date crate.
pub fn ymdhms(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}",
        y,
        m,
        d,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Howard Hinnant's `civil_from_days` (days since 1970-01-01 -> y/m/d).
pub(crate) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------


/// A discovered appliance.
#[derive(Debug, Clone, Serialize)]
pub struct Appliance {
    pub code: String,
    pub name: String,
    pub sn: String,
    pub sn8: String,
    pub online: bool,
}

impl Device {
    /// Build a `Device` row for an iLetComfort heat pump.
    pub fn from_iletcomfort(a: &Appliance) -> Self {
        Self {
            id: format!("iletcomfort:{}", a.code),
            provider: "iletcomfort",
            external_id: a.code.clone(),
            serial: a.sn.clone(),
            name: a.name.clone(),
            model: a.sn8.clone(),
            kind: "heatpump",
        }
    }
}

pub struct Client {
    region: String,
    token: String,
    /// Epoch seconds; the Dollin token lives ~24 h.
    expires_at: Option<i64>,
}

impl Client {
    /// Reuse an already-issued token instead of logging in again.
    ///
    /// Logging in evicts whichever other client holds the account session, so
    /// this is what keeps the phone app from being signed out on every poll.
    pub fn with_token(region: &str, token: String) -> Self {
        Self {
            region: region.to_string(),
            token,
            expires_at: None,
        }
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }
}

impl Client {
    /// Log in and return a ready client.
    ///
    /// NOTE: the Dollin cloud keeps only ONE session per account — this signs
    /// the phone app out. Use a second, shared account for the collector.
    pub async fn login(region: &str, username: &str, password: &str) -> Result<Self> {
        let base = api_base(region);
        let body = serde_json::to_string(&json!({
            "loginAccount": username,
            "password": encrypt_password(password),
            "encryptVersion": "1",
        }))
        .map_err(|e| Error::RustError(e.to_string()))?;

        let (sig, random) = sign_v1(&body, true);
        let deviceid = hex::encode(&Sha256::digest(format!("ilet-{}", Date::now()).as_bytes())[0..16])
            .to_uppercase();
        // Bind these first — temporaries cannot be borrowed into the header slice.
        let stamp = ymdhms(now_secs());
        let rid = reqid();
        let headers = [
            ("random", random.as_str()),
            ("src", "20"),
            ("appid", APP_ID),
            ("language", "en_US"),
            ("clienttype", "2"),
            ("appvnum", APPNUM),
            ("stamp", stamp.as_str()),
            ("deviceid", deviceid.as_str()),
            ("sign", sig.as_str()),
            ("reqid", rid.as_str()),
        ];

        let (status, text) = post_json(&format!("{base}/v1/user/login"), &headers, &body).await?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| Error::RustError(format!("login {status}: bad json: {e}")))?;
        if v["code"].as_i64() != Some(0) {
            return Err(Error::RustError(format!(
                "login failed: code={} msg={}",
                v["code"], v["msg"]
            )));
        }
        let token = v["data"]["accessToken"]
            .as_str()
            .ok_or_else(|| Error::RustError("login: no accessToken".into()))?
            .to_string();
        // `expiredDate` is epoch milliseconds.
        let expires_at = v["data"]["expiredDate"].as_i64().map(|ms| ms / 1000);

        Ok(Self {
            region: region.to_string(),
            token,
            expires_at,
        })
    }

    /// POST to the v2.0 business API (`/midea/open/business/v1/...`).
    async fn v2(&self, path: &str, body: &Value) -> Result<Value> {
        let json_body = serde_json::to_string(body).map_err(|e| Error::RustError(e.to_string()))?;
        let signature = sign_v2("POST", path, &json_body);
        let auth = format!("Bearer {}", self.token);
        let rid = reqid();
        let headers = [
            ("authorization", auth.as_str()),
            ("clientId", CLIENT_ID),
            ("signature", signature.as_str()),
            ("signatureversion", "2.0"),
            ("reqid", rid.as_str()),
            ("language", "en_US"),
        ];
        let (status, text) =
            post_json(&format!("{}{path}", api_base(&self.region)), &headers, &json_body).await?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| Error::RustError(format!("{path} {status}: bad json: {e}")))?;
        if v["code"].as_i64() == Some(14005) {
            return Err(Error::RustError(format!("{AUTH_EXPIRED}: token rejected (14005)")));
        }
        Ok(v)
    }

    /// POST to the energy statistics API on the iBUILDING platform.
    async fn energy(&self, path: &str, mut body: Value) -> Result<Value> {
        let auth = format!("Bearer {}", self.token);
        // The app always tags requests with its own name and the device id.
        if let Value::Object(ref mut m) = body {
            m.insert("app".into(), json!("iLetComfort"));
        }
        let json_body = serde_json::to_string(&body).map_err(|e| Error::RustError(e.to_string()))?;
        let headers = [
            ("authorization", auth.as_str()),
            ("language", "en_US"),
        ];
        let url = format!("{}/api/apps-oem{path}", energy_base(&self.region));
        let (status, text) = post_json(&url, &headers, &json_body).await?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| Error::RustError(format!("energy {path} {status}: bad json: {e}")))?;
        Ok(v)
    }

    /// Discover appliances; `sn8` selects the C3 decode profile.
    pub async fn appliances(&self) -> Result<Vec<Appliance>> {
        let v = self
            .v2("/midea/open/business/v1/appliance/list", &json!({"queryAuth": true}))
            .await?;
        let arr = v["data"].as_array().cloned().unwrap_or_default();
        Ok(arr
            .iter()
            .map(|a| Appliance {
                code: a["applianceCode"].as_str().unwrap_or_default().to_string(),
                name: a["name"].as_str().unwrap_or_default().to_string(),
                sn: a["sn"].as_str().unwrap_or_default().to_string(),
                sn8: a["sn8"].as_str().unwrap_or_default().to_string(),
                online: a["online"].as_i64() == Some(1),
            })
            .collect())
    }

    /// Send a raw C3 hex frame; returns the decoded response bytes.
    pub async fn hex_command(&self, appliance_code: &str, command: &str) -> Result<Vec<u8>> {
        let v = self
            .v2(
                "/midea/open/business/v1/appliance/control/hexadecimal",
                &json!({"applianceCode": appliance_code, "command": command}),
            )
            .await?;
        if v["code"].as_i64() != Some(0) {
            return Err(Error::RustError(format!("hex command failed: {v}")));
        }
        let data = v["data"]
            .as_str()
            .ok_or_else(|| Error::RustError("hex command: no data".into()))?;
        hex::decode(data.replace(',', ""))
            .map_err(|e| Error::RustError(format!("hex decode: {e}")))
    }

    /// Energy statistics. `path` is e.g. `/v3/energy/getTotalDetail`.
    pub async fn energy_stats(&self, path: &str, sn: &str) -> Result<Value> {
        self.energy(path, json!({"sn": sn, "nid": sn})).await
    }

    /// Collect every reading we can get for one appliance.
    pub async fn collect(&self, app: &Appliance) -> Result<(Vec<Reading>, Vec<Reading>)> {
        let now = now_secs();
        let id = format!("iletcomfort:{}", app.code);
        let mut live = Vec::new();
        let mut stats = Vec::new();

        // --- live state from the C3 status frame -------------------------------
        let frame = self.hex_command(&app.code, STATUS_QUERY).await?;
        for (metric, unit, value) in decode_status(&frame, &app.sn8)? {
            live.push(Reading::new(&id, metric, now, value, unit));
        }

        // --- sensor frame (placeholder on this model) -------------------------
        if let Ok(sf) = self.hex_command(&app.code, SENSOR_QUERY).await {
            if !is_placeholder_sensors(&sf) {
                for (metric, unit, value) in decode_sensors(&sf)? {
                    live.push(Reading::new(&id, metric, now, value, unit));
                }
            }
        }

        // --- energy statistics -------------------------------------------------
        if let Ok(v) = self.energy_stats("/v3/energy/getTotalDetail", &app.sn).await {
            if let Some(d) = v["data"].as_object() {
                // cumulative totals carry their own period in statisticalTime
                let ts_start = parse_day(&d["startTime"]);
                let ts = ts_start.unwrap_or(now);
                for (metric, unit, val) in totals(d) {
                    stats.push(Reading::new(&id, metric, ts, val, unit));
                }
            }
        }
        if let Ok(v) = self.energy_stats("/v3/energy/getEnergyLatest", &app.sn).await {
            if let Some(d) = v["data"].as_object() {
                for (metric, unit, val) in latest(d) {
                    live.push(Reading::new(&id, metric, now, val, unit));
                }
            }
        }

        // --- today's hourly detail: ambient T4, per-type electricity/heat/COP ---
        // Only the current day is served, so this must run during the day.
        let day = ymd(now);
        match self.hourly(&id, &app.sn, &day).await {
            Ok(mut r) => live.append(&mut r),
            Err(e) => console_log!("hourly {day}: {e}"),
        }

        // --- cost / savings ----------------------------------------------------
        if let Ok(mut r) = self.charge(&id, &app.sn).await {
            live.append(&mut r);
        }

        // --- year/day/week/month rollups ---------------------------------------
        if let Ok(mut r) = self.summary(&id, &app.sn).await {
            stats.append(&mut r);
        }

        Ok((live, stats))
    }
    /// Energy call with extra params merged in alongside `sn`/`nid`.
    pub async fn energy_call(&self, path: &str, mut params: Value, sn: &str) -> Result<Value> {
        if let Value::Object(ref mut m) = params {
            m.insert("sn".into(), json!(sn));
            m.insert("nid".into(), json!(sn));
        }
        self.energy(path, params).await
    }

    /// Today's hourly detail — the richest iLetComfort source.
    ///
    /// `GET /v3/energy/getHourInfoList` with `{sn, day}` returns four arrays:
    /// `electricityInfoDTOS` and `energyInfoListDTOS` / `copInfoListDTOS` (each
    /// grouped by usage `type`), and a flat `temp4InfoListDTOS` holding the
    /// **T4 outdoor ambient temperature** that the app shows as "Ambient T".
    ///
    /// Only the current day is served — older days answer `data: null`.
    pub async fn hourly(&self, id: &str, sn: &str, day: &str) -> Result<Vec<Reading>> {
        let v = self
            .energy_call("/v3/energy/getHourInfoList", json!({ "day": day }), sn)
            .await?;
        let d = v["data"]
            .as_object()
            .ok_or_else(|| Error::RustError("hourly: no data for that day".into()))?;

        let mut out = Vec::new();

        // Flat: outdoor ambient (T4).
        if let Some(arr) = d.get("temp4InfoListDTOS").and_then(|x| x.as_array()) {
            push_samples(&mut out, id, "ambient_t4", "", arr, "°C");
        }
        // Grouped by usage type.
        if let Some(arr) = d.get("electricityInfoDTOS").and_then(|x| x.as_array()) {
            push_grouped(&mut out, id, "elec_hourly", "electricityInfoListDTOS", arr, "kWh");
        }
        if let Some(arr) = d.get("energyInfoListDTOS").and_then(|x| x.as_array()) {
            push_grouped(&mut out, id, "heat_produced_hourly", "energyInfoListDTOS", arr, "kWh");
        }
        if let Some(arr) = d.get("copInfoListDTOS").and_then(|x| x.as_array()) {
            push_grouped(&mut out, id, "cop_hourly", "copInfoListDTOS", arr, "");
        }
        Ok(out)
    }

    /// Electricity totals and cost/savings (`energyAndChargeLast`).
    pub async fn charge(&self, id: &str, sn: &str) -> Result<Vec<Reading>> {
        let v = self
            .energy_call("/v3/energy/energyAndChargeLast", json!({}), sn)
            .await?;
        let d = v["data"]
            .as_object()
            .ok_or_else(|| Error::RustError("charge: no data".into()))?;
        let unit = d.get("unit").and_then(|x| x.as_str()).unwrap_or("EUR");
        let now = now_secs();
        let mut out = Vec::new();
        // `powerAll`/`powerLastDay` are kWh despite the shared `unit` field.
        for (key, metric, u) in [
            ("powerAll", "charge_power_all", "kWh"),
            ("powerLastDay", "charge_power_last_day", "kWh"),
            ("saveChargeAll", "charge_saved_all", unit),
            ("saveChargeLastDay", "charge_saved_last_day", unit),
        ] {
            if let Some(v) = fnum(&d[key]) {
                out.push(Reading::new(id, metric, now, v, u));
            }
        }
        Ok(out)
    }

    /// Year/day/week/month rollups (`getSummaryDetail`).
    pub async fn summary(&self, id: &str, sn: &str) -> Result<Vec<Reading>> {
        let v = self
            .energy_call("/v3/energy/getSummaryDetail", json!({}), sn)
            .await?;
        let arr = v["data"].as_array().cloned().unwrap_or_default();
        let now = now_secs();
        let mut out = Vec::new();
        for e in &arr {
            let scope = e["key"].as_str().unwrap_or("?").to_lowercase();
            for (path, metric) in [
                ("electricityDTO.value", "summary_electricity"),
                ("energyDTO.allEnergyProduce", "summary_heat_produced"),
                ("copDTO.total", "summary_cop"),
            ] {
                let mut cur = e;
                for k in path.split('.') {
                    cur = &cur[k];
                }
                if let Some(val) = fnum(cur) {
                    out.push(Reading::new(id, &format!("{metric}_{scope}"), now, val, ""));
                }
            }
        }
        Ok(out)
    }
}

/// Parse the API's timestamps: `2026-10-11 09:00:00`, `2026-10-11`, `2026-10`, `2026`.
fn parse_stamp(s: &str) -> Option<i64> {
    let s = s.trim();
    let (date, time) = match s.split_once(' ') {
        Some((d, t)) => (d, t),
        None => (s, "00:00:00"),
    };
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let mo: i64 = dp.next().and_then(|x| x.parse().ok()).unwrap_or(1);
    let da: i64 = dp.next().and_then(|x| x.parse().ok()).unwrap_or(1);
    let mut tp = time.split(':');
    let hh: i64 = tp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let mi: i64 = tp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    let ss: i64 = tp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
    Some(days_from_civil(y, mo, da) * 86_400 + hh * 3600 + mi * 60 + ss)
}

/// `YYYY-MM-DD` (UTC) for a unix timestamp — the `day` the hourly API wants.
pub fn ymd(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

/// Push a flat `[{statisticalTime, value, unit}]` array as readings.
fn push_samples(
    out: &mut Vec<Reading>,
    id: &str,
    prefix: &str,
    suffix: &str,
    arr: &[Value],
    unit: &str,
) {
    for it in arr {
        let Some(ts) = it
            .get("statisticalTime")
            .and_then(|s| s.as_str())
            .and_then(parse_stamp)
        else {
            continue;
        };
        let Some(val) = it.get("value").and_then(fnum) else {
            continue;
        };
        let u = it.get("unit").and_then(|x| x.as_str()).unwrap_or(unit);
        let metric = if suffix.is_empty() {
            prefix.to_string()
        } else {
            format!("{prefix}_{suffix}")
        };
        out.push(Reading::new(id, &metric, ts, val, u));
    }
}

/// Push a `[{type, <inner>:[samples]}]` array, naming metrics `prefix_<type>`.
fn push_grouped(
    out: &mut Vec<Reading>,
    id: &str,
    prefix: &str,
    inner: &str,
    arr: &[Value],
    unit: &str,
) {
    for grp in arr {
        let ty = grp.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if let Some(list) = grp.get(inner).and_then(|x| x.as_array()) {
            push_samples(out, id, prefix, ty, list, unit);
        }
    }
}

// ---------------------------------------------------------------------------
// C3 frame decoding
// ---------------------------------------------------------------------------

/// `body = frame[10..len-1]`; data offsets in the docs are relative to `body[1]`.
fn body_of(frame: &[u8]) -> Result<&[u8]> {
    if frame.len() < 12 {
        return Err(Error::RustError(format!("frame too short: {}", frame.len())));
    }
    Ok(&frame[10..frame.len() - 1])
}

fn decode_status(frame: &[u8], sn8: &str) -> Result<Vec<(&'static str, &'static str, f64)>> {
    let b = body_of(frame)?;

    if sn8 == "171H120F" {
        // ATW / Italtherm 25-byte layout (validated against real captures).
        if b.len() <= 22 {
            return Err(Error::RustError(format!("ATW body too short: {}", b.len())));
        }
        return Ok(vec![
            ("heat_demand", "", (b[1] & 0x01) as f64),
            ("dhw_setpoint", "°C", b[8] as f64),
            ("zone1_setpoint", "°C", b[9] as f64 / 2.0),
            ("dhw_tank_temp", "°C", b[22] as f64),
        ]);
    }

    // STANDARD C3 layout: offsets are d+N = body[1+N].
    let d = |i: usize| b.get(1 + i).copied().unwrap_or(0) as i64;
    let d35 = |i: usize| (d(i) - 35) as f64;
    let d16 = |i: usize| ((d(i) << 8) | d(i + 1)) as f64;
    Ok(vec![
        ("mode", "", d(1) as f64),
        ("setpoint_active", "°C", d35(2)),
        ("dhw_setpoint", "°C", d(4) as f64),
        ("return_temp", "°C", d35(18)),
        ("box_bottom_temp", "°C", d35(16)),
        ("error_code", "", d(23) as f64),
        ("compressor_running", "", (d(13) & 1) as f64),
        ("total_kwh", "kWh", d16(43)),
    ])
}

/// The cloud answers subtype 0x02 with repeated `03 1e 00 00 00 00` blocks on
/// models that have no live sensor telemetry (ha-iletcomfort issue #38).
/// These must never be reported as measurements.
fn is_placeholder_sensors(frame: &[u8]) -> bool {
    let Ok(b) = body_of(frame) else { return true };
    if b.len() < 8 || b[0] != 0x02 {
        return false;
    }
    let rest = &b[2..];
    if rest.len() % 6 != 0 {
        return false;
    }
    rest.chunks(6).all(|c| c[0] == 0x03 && c[1] == 0x1E)
}

fn decode_sensors(frame: &[u8]) -> Result<Vec<(&'static str, &'static str, f64)>> {
    let b = body_of(frame)?;
    let d = |i: usize| b.get(1 + i).copied().unwrap_or(0) as i64;
    let d35 = |i: usize| (d(i) - 35) as f64;
    Ok(vec![
        ("tf_refrigerant", "°C", d(14) as f64),
        ("tp_plate_hx", "°C", d(15) as f64),
        ("th_dhw_tank", "°C", d(16) as f64),
        ("t3_condenser", "°C", d35(20)),
        ("t4_outdoor_ambient", "°C", d35(21)),
        ("t2_evaporator", "°C", d35(22)),
        ("twin_water_inlet", "°C", d35(24)),
        ("twout_water_outlet", "°C", d35(25)),
        ("t1_suction", "°C", d35(26)),
    ])
}

// ---------------------------------------------------------------------------
// Energy DTO extraction
// ---------------------------------------------------------------------------

fn fnum(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse::<f64>().ok(),
        _ => None,
    }
}

fn parse_day(v: &Value) -> Option<i64> {
    // "2026-01-07" -> unix midnight UTC
    let s = v.as_str()?;
    let mut it = s.split('-');
    let y: i64 = it.next()?.parse().ok()?;
    let m: i64 = it.next()?.parse().ok()?;
    let d: i64 = it.next()?.parse().ok()?;
    Some(days_from_civil(y, m, d) * 86_400)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Cumulative totals: electricity, produced heat, COP.
fn totals(d: &serde_json::Map<String, Value>) -> Vec<(&'static str, &'static str, f64)> {
    let mut out = Vec::new();
    if let Some(v) = fnum(&d["electricityDTO"]["value"]) {
        out.push(("energy_electricity_total", "kWh", v));
    }
    if let Some(v) = fnum(&d["energyDTO"]["allEnergyProduce"]) {
        out.push(("energy_heat_produced_total", "kWh", v));
    }
    if let Some(v) = fnum(&d["copDTO"]["total"]) {
        out.push(("cop_total", "", v));
    }
    if let Some(v) = fnum(&d["copDTO"]["heat"]) {
        out.push(("cop_heat", "", v));
    }
    out
}

/// Instantaneous values from getEnergyLatest.
fn latest(d: &serde_json::Map<String, Value>) -> Vec<(&'static str, &'static str, f64)> {
    let mut out = Vec::new();
    if let Some(v) = fnum(&d["electricityDTO"]["value"]) {
        out.push(("power_instant", "kW", v));
    }
    if let Some(v) = fnum(&d["energyDTO"]["allEnergyProduce"]) {
        out.push(("heat_produce_instant", "kW", v));
    }
    if let Some(v) = fnum(&d["copDTO"]["total"]) {
        out.push(("cop_instant", "", v));
    }
    if let Some(v) = fnum(&d["runTime"]) {
        out.push(("runtime_instant", "", v));
    }
    out
}
