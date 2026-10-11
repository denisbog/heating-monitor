//! Minimal outbound HTTP helpers for `workers-rs`.
//!
//! The 0.8 API builds outbound POSTs as `Request::new_with_init(url, &RequestInit)`
//! then `Fetch::Request(req).send()`.

use worker::wasm_bindgen::JsValue;
use worker::*;

/// POST a JSON body with extra headers; returns (status, raw body text).
pub async fn post_json(url: &str, headers: &[(&str, &str)], body: &str) -> Result<(u16, String)> {
    let h = Headers::new();
    h.set("content-type", "application/json")?;
    h.set("accept", "application/json")?;
    for (k, v) in headers {
        h.set(k, v)?;
    }

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(h)
        .with_body(Some(JsValue::from_str(body)));
    let req = Request::new_with_init(url, &init)?;

    let mut resp = Fetch::Request(req).send().await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

/// POST an `application/x-www-form-urlencoded` body (OAuth2 token endpoints).
pub async fn post_form(url: &str, headers: &[(&str, &str)], body: &str) -> Result<(u16, String)> {
    let h = Headers::new();
    h.set(
        "content-type",
        "application/x-www-form-urlencoded; charset=utf-8",
    )?;
    h.set("accept", "application/json")?;
    for (k, v) in headers {
        h.set(k, v)?;
    }

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(h)
        .with_body(Some(JsValue::from_str(body)));
    let req = Request::new_with_init(url, &init)?;

    let mut resp = Fetch::Request(req).send().await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}

/// GET with a Bearer token.
pub async fn get_bearer(url: &str, token: &str) -> Result<(u16, String)> {
    let mut req = Request::new(url, Method::Get)?;
    {
        let h = req.headers_mut()?;
        h.set("authorization", &format!("Bearer {token}"))?;
        h.set("accept", "application/json")?;
    }

    let mut resp = Fetch::Request(req).send().await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    Ok((status, text))
}
