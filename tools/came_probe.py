#!/usr/bin/env python3
"""CAME Connect probe: OAuth login + list thermostats (keycodes).

Reads credentials from ~/.config/monitoring/credentials.toml (override with
--creds). Never prints the password, client secret, or the access token.

Usage:
    python3 tools/came_probe.py            # login, list thermostats
    python3 tools/came_probe.py --raw      # also dump the raw JSON of /v2/groups
"""
from __future__ import annotations

import argparse
import base64
import json
import secrets
import sys
import tomllib
import urllib.parse
import urllib.request
from hashlib import sha256

API = "https://app.cameconnect.net/api"
THERMO = "https://thermo.cameconnect.net"
REDIRECT_URI = "https://app.cameconnect.net/role"

# Public values shared by every CAME Connect user (from cameconnect.net/main.<hash>.js).
# Only used as a fallback if the credentials file does not carry them.
FALLBACK_CLIENT_ID = "58FnU0A4KqLYo3zJO1GMuYpTu74RyfnL"
FALLBACK_CLIENT_SECRET = (
    "T23FhzVZCXUD87TwP21L3ALdJYcPGCCPSqQTjMrnwG5SwQY6w6xFa9hnidS9KkZb8MMUBJJC8U2UdpFqdUVjbXtzdNqUk9eDu72VF6YdKTq8Z8ULzmbcAvgEiNwzZq2x6RLxF7ewCqAMUcUBPEAXhJwqv7j6f3bxJZNZZmLpWn5b8MqVxwk6CNq0C6uVTrRJuwTEkY23Vpq5Atwyq0QatdMwcFDT7CFJgJs1DiBR3MmHX0fXE4gnvLiJEFG0LXfR"
)


def find_key(obj, *names, default=None):
    """Find a key anywhere in a nested dict, case/underscore-insensitively."""
    wanted = {n.replace("_", "").lower() for n in names}
    stack = [obj]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.replace("_", "").lower() in wanted and isinstance(v, str):
                    return v
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur)
    return default


def http(method, url, *, headers=None, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
            return r.status, body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def login(client_id, client_secret, username, password) -> str:
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    # OAuth2 authorization-code + PKCE, exactly like the web app (no browser needed).
    verifier = secrets.token_urlsafe(64)
    challenge = (
        base64.urlsafe_b64encode(sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    q = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": REDIRECT_URI,
            "state": secrets.token_urlsafe(16),
            "nonce": secrets.token_urlsafe(16),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "username": username,
            "password": password,
        }
    ).encode()
    hdrs = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
        "Accept": "application/json",
    }
    status, text = http("POST", f"{API}/oauth/auth-code?{q}", headers=hdrs, data=body)
    if status != 200:
        sys.exit(f"auth-code failed: HTTP {status}: {text[:400]}")
    code = json.loads(text).get("code")
    if not code:
        sys.exit(f"no code in response: {text[:400]}")

    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        }
    ).encode()
    status, text = http("POST", f"{API}/oauth/token", headers=hdrs, data=body)
    if status != 200:
        sys.exit(f"token failed: HTTP {status}: {text[:400]}")
    token = json.loads(text).get("access_token")
    if not token:
        sys.exit(f"no access_token: {text[:400]}")
    print("login OK (access token acquired, not shown)")
    return token


def get(token, url):
    status, text = http(
        "GET", url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"}
    )
    return status, text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", default="~/.config/monitoring/credentials.toml")
    ap.add_argument("--raw", action="store_true", help="dump raw /v2/groups JSON")
    args = ap.parse_args()

    path = __import__("os").path.expanduser(args.creds)
    with open(path, "rb") as f:
        creds = tomllib.load(f)

    client_id = find_key(creds, "client_id", "clientid", default=FALLBACK_CLIENT_ID)
    client_secret = find_key(
        creds, "client_secret", "clientsecret", default=FALLBACK_CLIENT_SECRET
    )
    username = find_key(creds, "username", "user", "email")
    password = find_key(creds, "password", "pass")
    if not username or not password:
        sys.exit(f"could not find username/password in {path}")

    token = login(client_id, client_secret, username, password)

    for label, url in (
        ("/groups/get   (legacy)", f"{THERMO}/groups/get"),
        ("/v2/groups    (current)", f"{THERMO}/v2/groups"),
    ):
        status, text = get(token, url)
        print(f"\n=== {label} -> HTTP {status}")
        if status != 200:
            print(text[:500])
            continue
        if args.raw:
            print(text[:4000])
            continue
        try:
            js = json.loads(text)
        except Exception:
            print(text[:800])
            continue
        # Walk the payload and print anything that looks like a thermostat.
        found = []

        def walk(node):
            if isinstance(node, dict):
                keys = {k.lower() for k in node}
                if "keycode" in keys:
                    found.append(node)
                    return
                for v in node.values():
                    walk(v)
            elif isinstance(node, list):
                for v in node:
                    walk(v)

        walk(js)
        if not found:
            print("(no objects containing 'keycode' — rerun with --raw)")
        for i, d in enumerate(found, 1):
            interesting = {
                k: v
                for k, v in d.items()
                if any(
                    s in k.lower()
                    for s in ("keycode", "name", "model", "type", "group", "site", "online")
                )
            }
            print(f"[{i}] {json.dumps(interesting, ensure_ascii=False)}")


if __name__ == "__main__":
    main()
