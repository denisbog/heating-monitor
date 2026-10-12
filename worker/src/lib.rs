//! Cloudflare Worker: collector + JSON API + static chart page.
//!
//! * `#[event(scheduled)]`  every 15 min — poll both clouds into D1
//! * `#[event(fetch)]`      `/api/*` — read endpoints for the desktop app and page
//!
//! Secrets (wrangler secret / .dev.vars):
//!   ILETCOMFORT_USERNAME, ILETCOMFORT_PASSWORD
//!   CAMECONNECT_USERNAME, CAMECONNECT_PASSWORD,
//!   CAMECONNECT_CLIENT_ID, CAMECONNECT_CLIENT_SECRET
//!   API_TOKEN

pub mod cameconnect;
pub mod config;
pub mod db;
pub mod http;
pub mod iletcomfort;
pub mod model;

use worker::*;

/// Cron entry point (see `triggers.crons` in wrangler.toml).
#[event(scheduled)]
pub async fn scheduled(_event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    // The daily history is heavier than a plain snapshot, so refresh it only near
    // the top of the hour. Cron fires at :00/:15/:30/:45, and a skipped hour is
    // harmless because the underlying data is daily.
    let with_history = ((model::now_secs() / 60) % 60) < 3;
    match collect_all(&env, with_history).await {
        Ok((devices, readings)) => {
            console_log!("collector ok: {devices} devices, {readings} readings");
        }
        Err(e) => console_error!("collector failed: {e}"),
    }
}

/// Poll every provider once, persist the result, and record the run.
/// A failure in one cloud is logged and does not stop the other.
async fn collect_all(env: &Env, with_history: bool) -> Result<(usize, usize)> {
    let db = env.d1("DB")?;
    let run_id = db::start_run(&db).await?;

    let mut devices: Vec<model::Device> = Vec::new();
    let mut readings: Vec<model::Reading> = Vec::new();
    let mut errors: Vec<String> = Vec::new();

    match collect_iletcomfort(env, &db).await {
        Ok((mut d, mut r)) => {
            devices.append(&mut d);
            readings.append(&mut r);
        }
        Err(e) => {
            console_error!("iletcomfort: {e}");
            errors.push(format!("iletcomfort: {e}"));
        }
    }

    match collect_came(env, &db, with_history).await {
        Ok((mut d, mut r)) => {
            devices.append(&mut d);
            readings.append(&mut r);
        }
        Err(e) => {
            console_error!("cameconnect: {e}");
            errors.push(format!("cameconnect: {e}"));
        }
    }

    db::upsert_devices(&db, &devices).await?;
    let written = db::insert_readings(&db, &readings).await?;

    let status = if errors.is_empty() {
        "ok"
    } else if devices.is_empty() {
        "error"
    } else {
        "partial"
    };
    let err = if errors.is_empty() {
        None
    } else {
        Some(errors.join("; "))
    };
    db::finish_run(&db, run_id, status, devices.len(), written, err.as_deref()).await?;

    Ok((devices.len(), written))
}

/// iLetComfort: live C3 frames + iBUILDING energy statistics.
async fn collect_iletcomfort(
    env: &Env,
    db: &D1Database,
) -> Result<(Vec<model::Device>, Vec<model::Reading>)> {
    let region = env
        .var("ILETCOMFORT_REGION")
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "eu".to_string());

    // Reuse the cached session when possible. The Dollin cloud allows only one
    // session per account, so every login signs the phone app out — caching turns
    // 96 logins/day into one per token lifetime.
    let mut client = match db::load_token(db, "iletcomfort").await? {
        Some(token) => {
            console_log!("iletcomfort: reusing cached token");
            iletcomfort::Client::with_token(&region, token)
        }
        None => {
            let username = env.secret("ILETCOMFORT_USERNAME")?.to_string();
            let password = env.secret("ILETCOMFORT_PASSWORD")?.to_string();
            let c = iletcomfort::Client::login(&region, &username, &password).await?;
            db::save_token(db, "iletcomfort", c.token(), c.expires_at(), None).await?;
            console_log!("iletcomfort: logged in, token cached");
            c
        }
    };

    let appliances = match client.appliances().await {
        Ok(a) => a,
        // The phone app (or token rotation) took the session: log in once and retry.
        Err(e) if model::auth_expired(&e) => {
            console_warn!("iletcomfort: cached token rejected, re-authenticating");
            db::clear_token(db, "iletcomfort").await?;
            let username = env.secret("ILETCOMFORT_USERNAME")?.to_string();
            let password = env.secret("ILETCOMFORT_PASSWORD")?.to_string();
            client = iletcomfort::Client::login(&region, &username, &password).await?;
            db::save_token(db, "iletcomfort", client.token(), client.expires_at(), None).await?;
            client.appliances().await?
        }
        Err(e) => return Err(e),
    };

    let mut devices = Vec::with_capacity(appliances.len());
    let mut out = Vec::new();
    for app in &appliances {
        devices.push(model::Device::from_iletcomfort(app));
        match client.collect(app).await {
            Ok((mut live, mut stats)) => {
                out.append(&mut live);
                out.append(&mut stats);
            }
            Err(e) => console_error!("{}: {e}", app.code),
        }
    }
    Ok((devices, out))
}

/// CAME Connect: OAuth login, then a snapshot of every thermostat.
async fn collect_came(
    env: &Env,
    db: &D1Database,
    with_history: bool,
) -> Result<(Vec<model::Device>, Vec<model::Reading>)> {
    let mut client = match db::load_token(db, "cameconnect").await? {
        Some(token) => {
            console_log!("cameconnect: reusing cached token");
            cameconnect::Client::with_token(token)
        }
        None => {
            let username = env.secret("CAMECONNECT_USERNAME")?.to_string();
            let password = env.secret("CAMECONNECT_PASSWORD")?.to_string();
            let c = cameconnect::Client::login(&username, &password).await?;
            db::save_token(db, "cameconnect", c.token(), c.expires_at(), None).await?;
            console_log!("cameconnect: logged in, token cached");
            c
        }
    };

    let stats = match client.thermostats().await {
        Ok(s) => s,
        Err(e) if model::auth_expired(&e) => {
            console_warn!("cameconnect: cached token rejected, re-authenticating");
            db::clear_token(db, "cameconnect").await?;
            let username = env.secret("CAMECONNECT_USERNAME")?.to_string();
            let password = env.secret("CAMECONNECT_PASSWORD")?.to_string();
            client = cameconnect::Client::login(&username, &password).await?;
            db::save_token(db, "cameconnect", client.token(), client.expires_at(), None).await?;
            client.thermostats().await?
        }
        Err(e) => return Err(e),
    };

    let mut devices = Vec::with_capacity(stats.len());
    let mut out = Vec::new();
    for t in &stats {
        match client.snapshot(&t.keycode).await {
            Ok((device, mut r)) => {
                devices.push(device);
                out.append(&mut r);
            }
            Err(e) => console_error!("{}: {e}", t.keycode),
        }
    }

    // The daily history is heavier than a snapshot, so refresh it once an hour.
    // Cron fires at :00/:15/:30/:45, and a skipped hour is harmless because the
    // underlying data is daily.
    if with_history {
        // Quirk: `intervaltype=month` returns the *calendar month containing*
        // `from`, not a rolling 30-day window. So ask for the current month
        // (offset 0) and the previous one (~35 days back) to cover recent days.
        for (interval, days_ago) in [("month", 0_i64), ("month", 35), ("year", 0)] {
            let from_iso = model::iso_days_ago(days_ago);
            for t in &stats {
                match client.history(t, &from_iso, interval).await {
                    Ok(mut r) => out.append(&mut r),
                    Err(e) => console_error!("history {interval} {}: {e}", t.keycode),
                }
            }
        }
    }

    Ok((devices, out))
}

/// HTTP entry point. Everything under `/api/` is handled here; the chart page
/// itself is served from the static assets binding.
#[event(fetch)]
pub async fn main(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get_async("/api/health", |_req, _ctx| async move {
            Response::from_json(&serde_json::json!({"ok": true}))
        })
        .get_async("/api/devices", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let db = ctx.env.d1("DB")?;
            Response::from_json(&db::devices(&db).await?)
        })
        .get_async("/api/latest", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let db = ctx.env.d1("DB")?;
            Response::from_json(&db::latest(&db).await?)
        })
        .get_async("/api/readings", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let q = query_params(&req);
            let db = ctx.env.d1("DB")?;
            let rows = db::readings(
                &db,
                q.get("device").map(String::as_str).unwrap_or(""),
                q.get("metric").map(String::as_str).unwrap_or(""),
                q.get("from").and_then(|v| v.parse().ok()).unwrap_or(0),
                q.get("to")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(model::now_secs),
                q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(500),
            )
            .await?;
            Response::from_json(&rows)
        })
        .get_async("/api/daily", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let q = query_params(&req);
            let db = ctx.env.d1("DB")?;
            let rows = db::daily(
                &db,
                q.get("device").map(String::as_str).unwrap_or(""),
                q.get("from")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| model::now_secs() - 30 * 86_400),
                q.get("to")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(model::now_secs),
            )
            .await?;
            Response::from_json(&rows)
        })
        .get_async("/api/runs", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let q = query_params(&req);
            let db = ctx.env.d1("DB")?;
            let rows = db::runs(
                &db,
                q.get("limit").and_then(|v| v.parse().ok()).unwrap_or(50),
            )
            .await?;
            Response::from_json(&rows)
        })
        // Dashboard layout: readable by any token (the chart page renders it),
        // writable by the admin token only.
        .get_async("/api/config", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let db = ctx.env.d1("DB")?;
            let cfg = db::load_setting(&db, config::SETTINGS_KEY)
                .await?
                .and_then(|raw| serde_json::from_str::<config::Dashboard>(&raw).ok())
                .unwrap_or_default();
            Response::from_json(&cfg)
        })
        .put_async("/api/config", |req, ctx| async move {
            if !authorized_admin(&req, &ctx.env) {
                return Response::error("read-only token: admin access required", 403);
            }
            let mut req = req;
            let cfg = match req.json::<config::Dashboard>().await {
                Ok(c) => c.sanitize(),
                Err(e) => return Response::error(format!("invalid config: {e}"), 400),
            };
            let db = ctx.env.d1("DB")?;
            let json = serde_json::to_string(&cfg).map_err(|e| Error::RustError(e.to_string()))?;
            db::save_setting(&db, config::SETTINGS_KEY, &json).await?;
            Response::from_json(&serde_json::json!({"ok": true, "charts": cfg.charts.len()}))
        })
        // Every (device, metric, unit) that exists — feeds the admin picker.
        .get_async("/api/metrics", |req, ctx| async move {
            if !authorized(&req, &ctx.env) {
                return Response::error("unauthorized", 401);
            }
            let db = ctx.env.d1("DB")?;
            Response::from_json(&db::metrics(&db).await?)
        })
        // Lets the admin page tell "admin token" from "read-only token".
        .get_async("/api/whoami", |req, ctx| async move {
            Response::from_json(&serde_json::json!({
                "read": authorized(&req, &ctx.env),
                "admin": authorized_admin(&req, &ctx.env),
            }))
        })
        // Manual trigger: run a collection now instead of waiting for cron.
        .post_async("/api/collect", |req, ctx| async move {
            if !authorized_admin(&req, &ctx.env) {
                return Response::error("read-only token: collection not permitted", 403);
            }
            let (devices, readings) = collect_all(&ctx.env, true).await?;
            Response::from_json(&serde_json::json!({
                "devices": devices,
                "readings": readings,
            }))
        })
        .run(req, env)
        .await
}

/// Pull the bearer token out of a request's Authorization header.
fn bearer(req: &Request) -> String {
    let raw = req
        .headers()
        .get("authorization")
        .ok()
        .flatten()
        .unwrap_or_default();
    raw.strip_prefix("Bearer ").unwrap_or(&raw).to_string()
}

/// Read a secret, treating an empty value as absent.
fn secret_str(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .ok()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
}

/// Read access — every GET endpoint. Accepts either `API_TOKEN` (full) or
/// `READ_TOKEN`, the deliberately simple token meant to be shareable.
fn authorized(req: &Request, env: &Env) -> bool {
    let got = bearer(req);
    if got.is_empty() {
        return false;
    }
    // A plain comparison is fine: the read token is deliberately short and low
    // value, so there is no meaningful timing oracle to protect.
    secret_str(env, "API_TOKEN").is_some_and(|t| t == got)
        || secret_str(env, "READ_TOKEN").is_some_and(|t| t == got)
}

/// Full access — may trigger a collection. `API_TOKEN` only.
fn authorized_admin(req: &Request, env: &Env) -> bool {
    match secret_str(env, "API_TOKEN") {
        Some(expected) => bearer(req) == expected,
        None => false,
    }
}

fn query_params(req: &Request) -> std::collections::HashMap<String, String> {
    req.url()
        .map(|u| u.query_pairs().into_owned().collect())
        .unwrap_or_default()
}
