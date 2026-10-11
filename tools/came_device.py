#!/usr/bin/env python3
"""Dump one CAME thermostat's state and probe its history endpoint.

Usage:
    python3 tools/came_device.py <keycode>
    python3 tools/came_device.py <keycode> --raw          # don't truncate JSON
    python3 tools/came_device.py --stats-probe <keycode>  # try intervaltype values
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import came_probe as cp  # noqa: E402


def load_token(creds_path):
    path = os.path.expanduser(creds_path)
    with open(path, "rb") as f:
        creds = __import__("tomllib").load(f)
    cid = cp.find_key(creds, "client_id", "clientid", default=cp.FALLBACK_CLIENT_ID)
    sec = cp.find_key(creds, "client_secret", "clientsecret", default=cp.FALLBACK_CLIENT_SECRET)
    user = cp.find_key(creds, "username", "user", "email")
    pwd = cp.find_key(creds, "password", "pass")
    if not user or not pwd:
        sys.exit(f"could not find username/password in {path}")
    return cp.login(cid, sec, user, pwd)


def dump(label, token, url, raw, limit=6000):
    status, text = cp.get(token, url)
    print(f"\n=== {label}\n    {url}\n    -> HTTP {status}")
    if status != 200:
        print("   ", text[:500])
        return None
    try:
        js = json.loads(text)
    except Exception:
        print("   ", text[:1000])
        return None
    body = json.dumps(js, indent=2, ensure_ascii=False)
    print(body if raw else body[:limit] + ("\n... [truncated, use --raw]" if len(body) > limit else ""))
    return js


def flatten(node, prefix=""):
    """Yield (path, value) for scalars only."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from flatten(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(node, list):
        for i, v in enumerate(node[:3]):
            yield from flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, node


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("keycode", nargs="?")
    ap.add_argument("--creds", default="~/.config/monitoring/credentials.toml")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--stats-probe", action="store_true",
                    help="try several intervaltype values on /api/v1/statistics")
    args = ap.parse_args()
    if not args.keycode:
        sys.exit(__doc__)

    kc = args.keycode
    token = load_token(args.creds)

    dump("device status  /devices/{keycode}", token, f"{cp.THERMO}/devices/{kc}", args.raw)
    dump("device status v2 /v2/devices/{keycode}", token, f"{cp.THERMO}/v2/devices/{kc}", args.raw)

    if args.stats_probe:
        print("\n\n########## intervaltype probe ##########")
        for it in ("hour", "day", "week", "month", "hourly", "daily", "1", "0"):
            url = f"{cp.THERMO}/api/v1/statistics/{kc}?from=2024-01-01T00:00:00&intervaltype={it}"
            status, text = cp.get(token, url)
            head = text[:200].replace("\n", " ")
            print(f"  intervaltype={it:<8} HTTP {status}  {head}")
            if status == 200 and text.strip() not in ("{}", "[]"):
                try:
                    js = json.loads(text)
                    print("      keys:", list(js)[:12] if isinstance(js, dict) else f"list[{len(js)}]")
                    for p, v in list(flatten(js))[:25]:
                        print(f"        {p} = {v}")
                except Exception:
                    pass
                break


if __name__ == "__main__":
    main()
