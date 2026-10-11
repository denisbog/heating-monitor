#!/usr/bin/env python3
"""mitmproxy addon: capture iLetComfort energy calls (and CAME if needed).

Goal: find the missing parameters for the per-day/per-hour energy endpoints and
the "Ambient T average" reading.

Credentials are NEVER written to disk: Authorization / accessToken / cookie
headers are redacted, and presigned URLs are trimmed.

Run:
    mitmweb -s tools/mitm_energy.py --listen-port 8080 --set web_port=8081
or headless:
    mitmdump -s tools/mitm_energy.py --listen-port 8080

Then configure the phone/emulator proxy to <this-machine-ip>:8080 and open the
iLetComfort energy page.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from mitmproxy import http

HOSTS = ("ibuildinghvac.com", "mideaibp.com", "dollin.net", "cameconnect.net")
ENERGY_HINT = ("energy", "statistics", "searchRange", "ambient")
OUT = Path("data/capture.log")
MAX = 4000

SECRET_HEADERS = {"authorization", "accesstoken", "cookie", "set-cookie", "sign", "signature"}


def _redact(headers) -> dict:
    return {
        k: ("<redacted>" if k.lower() in SECRET_HEADERS else v)
        for k, v in headers.items()
    }


def _log(line: str) -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def request(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if not any(h in host for h in HOSTS):
        return
    url = flow.request.pretty_url
    interesting = any(h in url.lower() for h in ENERGY_HINT)
    body = flow.request.get_text() or ""
    # never persist an access token that happens to sit in a body/url
    safe_url = url.split("?")[0] + ("?<query redacted>" if "?" in url else "")
    rec = [
        f"\n=== {time.strftime('%H:%M:%S')} REQUEST {'[ENERGY] ' if interesting else ''}"
        f"{flow.request.method} {safe_url}",
        f"    headers: {json.dumps(_redact(flow.request.headers), ensure_ascii=False)}",
    ]
    if body:
        rec.append(f"    body: {body[:MAX]}")
    _log("\n".join(rec))


def response(flow: http.HTTPFlow) -> None:
    host = flow.request.pretty_host
    if not any(h in host for h in HOSTS):
        return
    url = flow.request.pretty_url.lower()
    if not any(h in url for h in ENERGY_HINT):
        return
    text = flow.response.get_text() or ""
    _log(
        f"    -> {flow.response.status_code}  {text[:MAX]}"
        + ("  ...[truncated]" if len(text) > MAX else "")
    )
