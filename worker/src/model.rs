//! Shared data model used by every provider.

use serde::Serialize;
use worker::{Date, Error};

/// One stored measurement.
#[derive(Debug, Clone, Serialize)]
pub struct Reading {
    pub device_id: String,
    pub metric: String,
    pub ts: i64,
    pub value: f64,
    pub unit: String,
}

impl Reading {
    pub fn new(device_id: &str, metric: &str, ts: i64, value: f64, unit: &str) -> Self {
        Self {
            device_id: device_id.to_string(),
            metric: metric.to_string(),
            ts,
            value,
            unit: unit.to_string(),
        }
    }

    /// A reading taken right now.
    pub fn now(device_id: &str, metric: &str, value: f64, unit: &str) -> Self {
        Self::new(device_id, metric, now_secs(), value, unit)
    }
}

/// A device as discovered from a provider.
#[derive(Debug, Clone, Serialize)]
pub struct Device {
    /// Stable key, e.g. `iletcomfort:<appliance-code>` or `came:<keycode>`.
    pub id: String,
    pub provider: &'static str,
    /// Provider-native identifier (applianceCode / keycode).
    pub external_id: String,
    /// Serial used by the provider's statistics endpoints (may equal `external_id`).
    pub serial: String,
    pub name: String,
    pub model: String,
    pub kind: &'static str,
}

/// Current time as unix seconds (`Date::now()` returns a `Date`, not a number).
pub fn now_secs() -> i64 {
    (Date::now().as_millis() / 1000) as i64
}

/// ISO-8601 UTC timestamp with milliseconds, `days` days before now.
///
/// The CAME statistics endpoint rejects a `from` without milliseconds
/// (`ErrorCode 53: Invalid datetime format`), so the exact shape matters.
pub fn iso_days_ago(days: i64) -> String {
    let unix = now_secs() - days * 86_400;
    let day = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (y, m, d) = crate::iletcomfort::civil_from_days(day);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

/// Marker embedded in errors meaning "the cached session was rejected".
///
/// Both clouds keep only one session per account, so a rejected token is a
/// normal event (the phone app logged in) rather than a failure: the caller
/// clears the cache and logs in again.
pub const AUTH_EXPIRED: &str = "E_AUTH_EXPIRED";

pub fn auth_expired(e: &Error) -> bool {
    e.to_string().contains(AUTH_EXPIRED)
}
