#!/usr/bin/env python3
"""Fetch the vendor's per-model plugin bundle for the iLetComfort heat pump.

Uses the documented version-downgrade trick: report version "0.0.0" and the Dollin
cloud answers with a presigned download URL for the current bundle. The bundle is
the vendor's own schema (Weex/JS, one file per app screen) and is the source of
truth for which fields the app can show — including energy/consumption.

The presigned URL embeds AWS credentials, so it is never printed.

Usage:
    python3 tools/iletcomfort_plugin.py 171H120F
    python3 tools/iletcomfort_plugin.py 171H120F --grep energy,consumption,kwh
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random as rnd
import re
import sys
import time
import tomllib
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import iletcomfort_probe as ip  # noqa: E402

PLUGIN_PATH = "/v1/product/upgrade/plugin/get/latest"
SDK_VERSION = 20230725
OUT = Path("data/plugins")


def headers(body_json: str, token: str) -> dict:
    sig, rv = ip.sign_v1(body_json, use_iot_key=True)
    return {
        "Content-Type": "application/json",
        "random": rv,
        "src": "20",
        "appid": ip.APP_ID,
        "language": "en_US",
        "clienttype": "2",
        "appvnum": ip.APPNUM,
        "stamp": time.strftime("%Y%m%d%H%M%S"),
        "deviceid": hashlib.sha256(f"probe-{int(time.time())}".encode()).hexdigest()[:32].upper(),
        "sign": sig,
        "reqid": hashlib.md5(f"{time.time()}-{rnd.random()}".encode()).hexdigest(),
        "accessToken": token,          # NOT Authorization: Bearer
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("model", help="sn8 model code, e.g. 171H120F")
    ap.add_argument("--creds", default="~/.config/monitoring/credentials.toml")
    ap.add_argument("--grep", default="energy,consumption,kwh,power,electric")
    ap.add_argument("--out", default=str(OUT))
    args = ap.parse_args()

    s = tomllib.load(open(os.path.expanduser(args.creds), "rb")).get("iletcomfort") or {}
    c = ip.Client(ip.REGION_URLS[(s.get("region") or "us").lower()])
    c.login(s["username"], s["password"])

    body = json.dumps({
        "language": "en_US",
        "model": args.model,
        "sdkVersion": SDK_VERSION,
        "firmwareVersion": "000000000000",
        "type": "0xC3",
        "version": "0.0.0",
    }, separators=(",", ":"))

    status, text = ip.http("POST", c.base + PLUGIN_PATH, headers(body, c.token), body.encode())
    print(f"plugin lookup -> HTTP {status}")
    r = json.loads(text)
    if r.get("code") != 0:
        sys.exit(f"plugin not available: code={r.get('code')} msg={r.get('msg')}")

    data = r.get("data") or {}
    url = data.get("packageUrl")
    # print metadata minus the credential-bearing URL
    safe = {k: v for k, v in data.items() if k not in ("packageUrl", "previewUrl")}
    print("metadata:", json.dumps(safe, ensure_ascii=False)[:600])
    if not url:
        sys.exit("no packageUrl (server thinks we are current)")

    outdir = Path(os.path.expanduser(args.out)) / args.model
    outdir.mkdir(parents=True, exist_ok=True)
    zpath = outdir / "bundle.zip"
    with urllib.request.urlopen(url, timeout=60) as resp, open(zpath, "wb") as f:
        f.write(resp.read())
    print(f"downloaded {zpath.stat().st_size} bytes -> {zpath}")

    if zipfile.is_zipfile(zpath):
        with zipfile.ZipFile(zpath) as z:
            names = z.namelist()
            z.extractall(outdir / "unpacked")
        print(f"unpacked {len(names)} files into {outdir/'unpacked'}")
        for n in names[:40]:
            print("   ", n)

    terms = [t.strip().lower() for t in args.grep.split(",") if t.strip()]
    print(f"\n=== searching unpacked bundle for {terms} ===")
    hits = 0
    for p in sorted((outdir / "unpacked").rglob("*")):
        if not p.is_file():
            continue
        try:
            txt = p.read_text(errors="replace")
        except Exception:
            continue
        for i, line in enumerate(txt.splitlines(), 1):
            low = line.lower()
            if any(t in low for t in terms):
                hits += 1
                if hits <= 60:
                    print(f"{p.relative_to(outdir/'unpacked')}:{i}: {line.strip()[:150]}")
    print(f"\ntotal matching lines: {hits}")


if __name__ == "__main__":
    main()
