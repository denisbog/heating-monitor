//! CAME Connect — THermo Wi-Fi thermostats (TH/500, TH/550, TH/700).
//!
//! Two hosts are involved, which is the main gotcha:
//!   * `app.cameconnect.net/api`         — OAuth2 (authorization-code + PKCE)
//!   * `thermo.cameconnect.net`          — the thermostats themselves
//!
//! Verified live on 2026-10-11 against a normal (non-technician) user account with
//! two TH/700 units. See `../../docs/api-research.md`.
//!
//! Important: these thermostats do **not** provide a usable server-side
//! room-temperature history (only `ExternalTemperature` and `PowerOnTime` are
//! populated at day/week/month granularity). The 15-minute poll is therefore the
//! data source for daily aggregates.

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use worker::*;

use crate::http::{get_bearer, post_form};
use crate::model::{now_secs, Device, Reading, AUTH_EXPIRED};

/// Client credentials baked into the CAME web app bundle
/// (`https://www.cameconnect.net/main.<hash>.js`). These are NOT personal
/// secrets — they are shared by every CAME Connect user and rotate only if CAME
/// changes their frontend.
pub const CLIENT_ID: &str = "58FnU0A4KqLYo3zJO1GMuYpTu74RyfnL";
pub const CLIENT_SECRET: &str = "T23FhzVZCXUD87TwP21L3ALdJYcPGCCPSqQTjMrnwG5SwQY6w6xFa9hnidS9KkZb8MMUBJJC8U2UdpFqdUVjbXtzdNqUk9eDu72VF6YdKTq8Z8ULzmbcAvgEiNwzZq2x6RLxF7ewCqAMUcUBPEAXhJwqv7j6f3bxJZNZZmLpWn5b8MqVxwk6CNq0C6uVTrRJuwTEkY23Vpq5Atwyq0QatdMwcFDT7CFJgJs1DiBR3MmHX0fXE4gnvLiJEFG0LXfR";
pub const REDIRECT_URI: &str = "https://app.cameconnect.net/role";

const AUTH_BASE: &str = "https://app.cameconnect.net/api";
const THERMO_BASE: &str = "https://thermo.cameconnect.net";

/// A thermostat discovered from `GET /v2/groups`.
#[derive(Debug, Clone, Serialize)]
pub struct Thermostat {
    pub keycode: String,
    pub name: String,
    pub model: String,
}

// ---------------------------------------------------------------------------
// OAuth2 + PKCE
// ---------------------------------------------------------------------------

fn form_encode(pairs: &[(&str, &str)]) -> String {
    fn enc(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// PKCE pair: a high-entropy verifier and its S256 challenge (base64url, no pad).
fn pkce() -> (String, String) {
    let mut raw = [0u8; 48];
    for b in raw.iter_mut() {
        *b = (worker::js_sys::Math::random() * 256.0) as u8;
    }
    let verifier = B64URL.encode(raw);
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    (verifier, challenge)
}

fn rand_str(len: usize) -> String {
    (0..len)
        .map(|_| {
            let n = (worker::js_sys::Math::random() * 62.0) as usize;
            const CS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            CS[n.min(61)] as char
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

pub struct Client {
    token: String,
    /// Epoch seconds, from the token response's `expires_in`.
    expires_at: Option<i64>,
}

impl Client {
    /// Reuse an already-issued token instead of running the OAuth flow again.
    pub fn with_token(token: String) -> Self {
        Self {
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
    /// Full OAuth2 authorization-code + PKCE flow, performed headlessly.
    pub async fn login(username: &str, password: &str) -> Result<Self> {
        let (verifier, challenge) = pkce();
        let auth = format!(
            "Basic {}",
            B64.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
        );
        let state = rand_str(16);
        let nonce = rand_str(16);

        // Step 1: exchange credentials for an authorization code.
        let query = form_encode(&[
            ("client_id", CLIENT_ID),
            ("response_type", "code"),
            ("redirect_uri", REDIRECT_URI),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &challenge),
            ("code_challenge_method", "S256"),
        ]);
        let body = form_encode(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("username", username),
            ("password", password),
        ]);
        let (status, text) = post_form(
            &format!("{AUTH_BASE}/oauth/auth-code?{query}"),
            &[("authorization", auth.as_str())],
            &body,
        )
        .await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            Error::RustError(format!("came auth-code {status}: bad json: {e}: {text}"))
        })?;
        let code = v["code"]
            .as_str()
            .ok_or_else(|| {
                Error::RustError(format!("came auth-code failed ({status}): {v}"))
            })?
            .to_string();

        // Step 2: exchange the code for a bearer token.
        let body = form_encode(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", REDIRECT_URI),
            ("code_verifier", &verifier),
        ]);
        let (status, text) = post_form(
            &format!("{AUTH_BASE}/oauth/token"),
            &[("authorization", auth.as_str())],
            &body,
        )
        .await?;
        let v: Value = serde_json::from_str(&text).map_err(|e| {
            Error::RustError(format!("came token {status}: bad json: {e}: {text}"))
        })?;
        let token = v["access_token"]
            .as_str()
            .ok_or_else(|| Error::RustError(format!("came token failed ({status}): {v}")))?
            .to_string();
        // `expires_in` is a number of seconds from now.
        let expires_at = v["expires_in"].as_i64().map(|s| now_secs() + s);

        Ok(Self { token, expires_at })
    }

    async fn get(&self, url: &str) -> Result<Value> {
        let (status, text) = get_bearer(url, &self.token).await?;
        if status == 401 {
            return Err(Error::RustError(format!("{AUTH_EXPIRED}: token rejected (401)")));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::RustError(format!("GET {url} {status}: bad json: {e}: {text}")))
    }

    /// All thermostats on the account (`GET /v2/groups`).
    pub async fn thermostats(&self) -> Result<Vec<Thermostat>> {
        let v = self.get(&format!("{THERMO_BASE}/v2/groups")).await?;
        let mut out = Vec::new();
        collect_thermostats(&v, &mut out);
        // de-duplicate by keycode (the payload nests groups and devices)
        let mut seen = std::collections::HashSet::new();
        out.retain(|t| seen.insert(t.keycode.clone()));
        Ok(out)
    }

    /// Live thermostat state (`GET /v2/devices/{keycode}`).
    pub async fn device(&self, keycode: &str) -> Result<Value> {
        self.get(&format!("{THERMO_BASE}/v2/devices/{keycode}")).await
    }

    /// History. `intervaltype` is one of `day` | `week` | `month` | `year`.
    ///
    /// `from` MUST carry milliseconds, e.g. `2026-10-09T00:00:00.000Z`, or the
    /// API answers `ErrorCode 53` ("Invalid datetime format").
    pub async fn statistics(&self, keycode: &str, from_iso: &str, intervaltype: &str) -> Result<Value> {
        let url = format!(
            "{THERMO_BASE}/api/v1/statistics/{keycode}?from={}&intervaltype={intervaltype}",
            from_iso
        );
        self.get(&url).await
    }

    /// Instantaneous snapshot as readings.
    /// Live state as a `Device` plus readings.
    ///
    /// `GET /v2/devices/{keycode}` is the only place the display name and product
    /// type appear — `/v2/groups` returns bare keycodes — so the device row is
    /// built from this payload rather than from the group listing.
    pub async fn snapshot(&self, keycode: &str) -> Result<(Device, Vec<Reading>)> {
        let d = self.device(keycode).await?;
        let cc = &d["cameconnect"];

        let pick = |a: &str, b: &str| -> String {
            cc[a].as_str()
                .or_else(|| d[b].as_str())
                .unwrap_or("")
                .to_string()
        };
        let device = Device {
            id: format!("came:{keycode}"),
            provider: "cameconnect",
            external_id: keycode.to_string(),
            serial: keycode.to_string(),
            name: pick("Name", "Description"),
            model: pick("ProductTypeName", "productTypeName"),
            kind: "thermostat",
        };

        let id = device.id.clone();
        let now = now_secs();
        let mut out = Vec::new();
        {
            let mut num = |metric: &str, key: &str, unit: &str| {
                if let Some(v) = value_f64(&d[key]) {
                    out.push(Reading::new(&id, metric, now, v, unit));
                }
            };
            num("room_temp", "temp_loc", "°C");
            num("humidity", "hum_loc", "%");
            num("setpoint", "set_point_temp", "°C");
            num("outdoor_temp_cloud", "temp_ext", "°C");
            num("relay_heating", "relay_status", "");
            num("online", "on_line", "");
            num("comfort_state", "comfort_state", "");
            num("boost_remaining_min", "boost_rem_minutes", "min");
            num("holiday_remaining_days", "holiday_rem_days", "d");
            num("alarm_temp_high", "alarm_t_high", "");
            num("alarm_temp_low", "alarm_t_low", "");
        }

        Ok((device, out))
    }

    /// Daily outdoor-temperature history (the only series populated on TH/700).
    /// History for one interval: `day` | `week` | `month` | `year`.
    ///
    /// Every series in the response is an object with `Average` / `Total` plus a
    /// `List` of `{Timestamp, Value}` buckets. On TH/700 only `ExternalTemperature`
    /// and `PowerOnTime` carry data at day/week/month granularity;
    /// `InternalTemperature`, `Humidity` and `SetPoint` only appear at `year`.
    pub async fn history(
        &self,
        t: &Thermostat,
        from_iso: &str,
        intervaltype: &str,
    ) -> Result<Vec<Reading>> {
        let v = self.statistics(&t.keycode, from_iso, intervaltype).await?;
        let id = format!("came:{}", t.keycode);
        let mut out = Vec::new();

        for (key, metric, unit) in [
            ("ExternalTemperature", "outdoor_temp", "°C"),
            ("InternalTemperature", "internal_temp", "°C"),
            ("Humidity", "humidity_avg", "%"),
            ("SetPoint", "setpoint_avg", "°C"),
        ] {
            let node = &v[key];
            if let Some(list) = node["List"].as_array() {
                for item in list {
                    let ts = item["Timestamp"].as_i64().unwrap_or(0);
                    if ts <= 0 {
                        continue;
                    }
                    if let Some(val) = value_f64(&item["Value"]) {
                        out.push(Reading::new(&id, metric, ts, val, unit));
                    }
                }
            }
            // The window average, anchored at the window start.
            if let (Some(avg), Some(from)) = (value_f64(&node["Average"]), v["From"].as_i64()) {
                out.push(Reading::new(
                    &id,
                    &format!("{metric}_{intervaltype}_avg"),
                    from,
                    avg,
                    unit,
                ));
            }
        }

        let from = v["From"].as_i64();
        // PowerOnTime: total minutes in the window.
        if let (Some(total), Some(from)) = (value_f64(&v["PowerOnTime"]["Total"]), from) {
            out.push(Reading::new(&id, "power_on_total", from, total, "min"));
        }
        // ConnectionEvents: number of link events in the window.
        if let Some(n) = v["ConnectionEvents"]["List"].as_array().map(|l| l.len()) {
            if let Some(from) = from {
                out.push(Reading::new(&id, "connection_events", from, n as f64, ""));
            }
        }
        Ok(out)
    }
}


fn value_f64(v: &Value) -> Option<f64> {
    v.as_f64()
}

/// Walk the `/v2/groups` payload for anything carrying a `keycode`.
fn collect_thermostats(v: &Value, out: &mut Vec<Thermostat>) {
    match v {
        Value::Object(map) => {
            if let Some(kc) = map.get("keycode").and_then(|k| k.as_str()) {
                let name = ["Name", "name", "Description", "description"]
                    .iter()
                    .find_map(|k| map.get(*k).and_then(|x| x.as_str()))
                    .unwrap_or("")
                    .to_string();
                let model = ["ProductTypeName", "productTypeName", "ProductType", "model"]
                    .iter()
                    .find_map(|k| map.get(*k).and_then(|x| x.as_str()))
                    .unwrap_or("")
                    .to_string();
                out.push(Thermostat {
                    keycode: kc.to_string(),
                    name,
                    model,
                });
                return;
            }
            for v in map.values() {
                collect_thermostats(v, out);
            }
        }
        Value::Array(items) => {
            for v in items {
                collect_thermostats(v, out);
            }
        }
        _ => {}
    }
}
