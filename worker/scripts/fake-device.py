#!/usr/bin/env python3
"""Fake eink-x device: signs a batch exactly as the firmware must and posts it.

Implements the signature of the ingest requirements
(`../mesh-deepseek/docs/http-endpoint-requirements.md`, §5.2 / Appendix A):

    canonical = "v1\\nPOST\\n/v1/samples\\n<device>\\n<boot_id>\\n<batch>\\n<sha256(rawBody)>"
    signature = "v1=" + hmac_sha256(key, canonical).hex()

Usage:

    # one batch (Appendix A vector 1)
    ./fake-device.py --url http://127.0.0.1:8787 --key <hex> post

    # run the acceptance tests (AT-1…AT-14) against a deployment
    ./fake-device.py --url http://127.0.0.1:8787 --key <hex> test

    # print the SQL that registers a device with this key
    ./fake-device.py --key <hex> provision

`--url` defaults to $INGEST_URL or http://127.0.0.1:8787 (the `wrangler dev`
exception of §11: plain HTTP on a loopback/LAN address is allowed).

No third-party dependencies; needs Python 3.8+.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import random
import sys
import time
import urllib.error
import urllib.request

# Appendix A test key — test only, never use in production.
TEST_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
DEVICE = "F29E9E3C98E5"

# Appendix A vector 1 / 2 (exact bytes; the signature covers these bytes).
VECTOR_1 = b'{"v":1,"device":"F29E9E3C98E5","boot_id":4660,"batch":42,"period_min":30,"samples":[[7,12,234,649,4000,1230]]}'
VECTOR_2 = b'{"v":1,"device":"F29E9E3C98E5","boot_id":4660,"batch":43,"period_min":30,"samples":[[7,13,-52,812,3990,1260],[9,4,215,640,4020,15]]}'
VECTOR_1_SIGNATURE = "v1=56b73dfadec798fe453e12e3fe9c422d8f211c4a1d18c18e57c38eea65b1da64"
VECTOR_2_SIGNATURE = "v1=bc5fb08f1c6adf0e725932fcfc7436cafe1c58bdd8317dc7f6c55a9f1f40ff47"

PATH = "/v1/samples"


def sign(key_hex: str, device: str, boot_id: int, batch: int, body: bytes) -> str:
    canonical = "\n".join(
        ["v1", "POST", PATH, device, str(boot_id), str(batch), hashlib.sha256(body).hexdigest()]
    ).encode()
    return "v1=" + hmac.new(bytes.fromhex(key_hex), canonical, hashlib.sha256).hexdigest()


def body(device: str, boot_id: int, batch: int, samples, period_min: int = 30,
         sent_at: int | None = None, collected_at=None, **extra) -> bytes:
    doc = {
        "v": 1,
        "device": device,
        "boot_id": boot_id,
        "batch": batch,
        "period_min": period_min,
        "samples": samples,
    }
    # v2 §1.1: both fields are optional and must be omitted when unknown.
    if sent_at is not None:
        doc["sent_at"] = sent_at
    if collected_at is not None:
        doc["collected_at"] = collected_at
    doc.update(extra)
    # Compact separators: the firmware must sign exactly what it sends.
    return json.dumps(doc, separators=(",", ":")).encode()


def post(url: str, raw: bytes, signature: str | None, content_type="application/json",
         headers: dict | None = None) -> tuple[int, dict | str]:
    req = urllib.request.Request(url + PATH, data=raw, method="POST")
    req.add_header("Content-Type", content_type)
    req.add_header("User-Agent", "eink-x/0.2.0")
    if signature is not None:
        req.add_header("X-Signature", signature)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    return _send(req)


def get(url: str, path: str, token: str | None = None) -> tuple[int, dict | str]:
    req = urllib.request.Request(url + path, method="GET")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    return _send(req)


def _send(req) -> tuple[int, dict | str]:
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = resp.read().decode("utf-8", "replace")
            status = resp.status
    except urllib.error.HTTPError as e:  # 4xx/5xx
        payload = e.read().decode("utf-8", "replace")
        status = e.code
    except urllib.error.URLError as e:
        return 0, str(e.reason)
    try:
        return status, json.loads(payload)
    except ValueError:
        return status, payload


# ---------------------------------------------------------------------------
# Acceptance tests (the AT table of §12)
# ---------------------------------------------------------------------------

class T:
    passed = 0
    failed = 0

    @classmethod
    def check(cls, name: str, ok: bool, detail: str = "") -> None:
        if ok:
            cls.passed += 1
            print(f"PASS {name}")
        else:
            cls.failed += 1
            print(f"FAIL {name}" + (f"  {detail}" if detail else ""))


def run_tests(base: str, key: str, device: str, token: str | None = None) -> int:
    # The suite is re-runnable against the same device: a fresh boot_id and a
    # batch base drawn from the clock keep the ordering/rate state independent
    # of earlier runs.
    boot = random.randrange(1, 65000)
    batch0 = random.randrange(1000, 40000)

    hint = (
        "  (if this is 429, the one-hour rate window of this device is full: "
        "run `./fake-device.py reset` and apply that SQL)"
    )
    # AT-1: a valid batch (same shape as the Appendix A vector)
    raw = body(device, boot, batch0, [[7, 12, 234, 649, 4000, 1230]])
    sig = sign(key, device, boot, batch0, raw)
    status, body_ = post(base, raw, sig)
    T.check("AT-1 valid batch", status == 200 and body_.get("stored") == 1
            and body_.get("duplicate") == 0 and "server_time" in body_, f"{status} {body_}")
    if status == 429:
        print(hint)

    # AT-2: exact replay
    status, body_ = post(base, raw, sig)
    T.check("AT-2 replay is a duplicate", status == 200 and body_.get("stored") == 0
            and body_.get("duplicate") == 1, f"{status} {body_}")

    # AT-3: one hex character changed
    bad = sig[:-1] + ("0" if sig[-1] != "0" else "1")
    status, body_ = post(base, raw, bad)
    T.check("AT-3 bad signature", status == 401 and body_.get("code") == "signature_invalid",
            f"{status} {body_}")

    # AT-4: no signature at all
    status, body_ = post(base, raw, None)
    T.check("AT-4 missing signature", status == 401 and body_.get("code") == "signature_invalid",
            f"{status} {body_}")

    # AT-5: unknown device (signed with the same key, so only the id is wrong)
    unknown = "AAAAAAAAAAAA"
    ub = body(unknown, boot, batch0, [[7, 12, 234, 649, 4000, 1230]])
    status, body_ = post(base, ub, sign(key, unknown, boot, batch0, ub))
    T.check("AT-5 unknown device is not enumerated",
            status == 401 and body_.get("code") == "signature_invalid", f"{status} {body_}")

    # AT-6: 65 samples
    many = [[7, i % 200, 234, 649, 4000, 1230] for i in range(65)]
    bb = body(device, boot, batch0 + 10, many)
    status, body_ = post(base, bb, sign(key, device, boot, batch0 + 10, bb))
    T.check("AT-6 too many samples", status == 400 and body_.get("code") == "too_many_samples",
            f"{status} {body_}")

    # AT-7: 5 KiB body
    big = body(device, boot, batch0 + 11, [[7, 1, 234, 649, 4000, 1230]], pad="x" * 5000)
    status, body_ = post(base, big, sign(key, device, boot, batch0 + 11, big))
    T.check("AT-7 body too large", status == 413 and body_.get("code") == "body_too_large",
            f"{status} {body_}")

    # AT-8: a lower batch number, same boot_id
    ob = body(device, boot, batch0 - 1, [[7, 12, 234, 649, 4000, 1230]])
    status, body_ = post(base, ob, sign(key, device, boot, batch0 - 1, ob))
    T.check("AT-8 out of order",
            status == 409 and body_.get("code") == "batch_out_of_order"
            and body_.get("expected_min_batch") == batch0 + 1, f"{status} {body_}")

    # AT-9: a new boot_id restarts the counter.
    # Distinct `seq` per batch: `received_at` has one-second resolution and the
    # primary key is (device_id, node_id, received_at, seq), so two different
    # batches sharing a node+seq inside the same second are one row by design.
    boot2 = (boot + 1) % 65000 or 1
    rb = body(device, boot2, 1, [[7, 20, 234, 649, 4000, 1230]])
    status, body_ = post(base, rb, sign(key, device, boot2, 1, rb))
    T.check("AT-9 reboot restarts the counter", status == 200 and body_.get("stored") == 1,
            f"{status} {body_}")

    # AT-10: one invalid sample, one valid
    mb = body(device, boot2, 2, [[7, 21, 234, 649, 4000, 1230], [9, 4, 215, 1200, 4020, 15]])
    status, body_ = post(base, mb, sign(key, device, boot2, 2, mb))
    problems = body_.get("problems") if isinstance(body_, dict) else None
    T.check("AT-10 bad sample is rejected, good one stored",
            status == 200 and body_.get("stored") == 1 and body_.get("rejected") == 1
            and problems and problems[0]["reason"] == "humidity_range"
            and problems[0]["index"] == 1, f"{status} {body_}")

    # AT-11: health
    status, body_ = get(base, "/v1/health")
    T.check("AT-11 health", status == 200 and body_.get("storage") == "ok", f"{status} {body_}")

    # AT-12: https_required — only meaningful when the edge reports the scheme.
    # Locally (wrangler dev on a LAN address) plain HTTP is the documented
    # exception, so this drives the CF-Visitor override instead.
    status, body_ = post(base, raw, sig, headers={"CF-Visitor": '{"scheme":"http"}'})
    T.check("AT-12 plain http rejected", status == 400 and body_.get("code") == "https_required",
            f"{status} {body_}")

    # ---- v2 (http-endpoint-requirements-v2.md §4) ------------------------
    now = int(time.time())
    boot3 = (boot2 + 100) % 65000 or 1

    # AT-30: sent_at + a matching collected_at array
    v2b = body(device, boot3, 1, [[7, 41, 208, 502, 4000, 12], [9, 42, 204, 492, 4000, 3900]],
               sent_at=now - 5, collected_at=[now - 300, now - 60])
    status, body_ = post(base, v2b, sign(key, device, boot3, 1, v2b))
    T.check("AT-30 sent_at + collected_at accepted",
            status == 200 and body_.get("stored") == 2 and body_.get("time_source") == "server",
            f"{status} {body_}")

    # AT-31: the v1 shape still works
    v1b = body(device, boot3, 2, [[7, 43, 210, 500, 4000, 20]])
    status, body_ = post(base, v1b, sign(key, device, boot3, 2, v1b))
    T.check("AT-31 v1 shape still accepted", status == 200 and body_.get("stored") == 1,
            f"{status} {body_}")

    # AT-32: collected_at length mismatch
    bad = body(device, boot3, 3, [[7, 44, 210, 500, 4000, 20]], collected_at=[now, now])
    status, body_ = post(base, bad, sign(key, device, boot3, 3, bad))
    T.check("AT-32 collected_at length mismatch",
            status == 400 and body_.get("code") == "bad_collected_at", f"{status} {body_}")

    # AT-33: a zero entry means "unknown", the batch still stores
    zb = body(device, boot3, 4, [[7, 45, 210, 500, 4000, 20], [9, 46, 211, 501, 4000, 21]],
              collected_at=[0, now - 10])
    status, body_ = post(base, zb, sign(key, device, boot3, 4, zb))
    T.check("AT-33 zero collected_at is unknown, not 1970",
            status == 200 and body_.get("stored") == 2, f"{status} {body_}")

    # AT-34: a device clock two days ahead is implausible
    fb = body(device, boot3, 5, [[7, 47, 210, 500, 4000, 20]], sent_at=now + 2 * 86400)
    status, body_ = post(base, fb, sign(key, device, boot3, 5, fb))
    T.check("AT-34 sent_at two days ahead is rejected",
            status == 400 and body_.get("code") == "implausible_device_time", f"{status} {body_}")

    # AT-35: a burst of 16 samples spanning hours, one received_at
    burst = [[7, 50 + i, 200 + i, 500, 4000, 10 * i] for i in range(16)]
    times = [now - 3600 * (15 - i) for i in range(16)]
    bb2 = body(device, boot3, 6, burst, sent_at=now - 30, collected_at=times)
    status, body_ = post(base, bb2, sign(key, device, boot3, 6, bb2))
    T.check("AT-35 16-sample burst across hours", status == 200 and body_.get("stored") == 16,
            f"{status} {body_}")

    # AT-36: same batch number, new boot_id -> accepted
    rb2 = body(device, (boot3 + 1) % 65000 or 1, 6, [[7, 80, 210, 500, 4000, 20]])
    status, body_ = post(base, rb2, sign(key, device, (boot3 + 1) % 65000 or 1, 6, rb2))
    T.check("AT-36 new boot_id accepts a reused batch number",
            status == 200 and body_.get("stored") == 1, f"{status} {body_}")

    # AT-37: read API — last upload vs last sample (needs an admin token)
    status, devices_ = get(base, "/api/ingest/devices", token=token)
    row = None
    if isinstance(devices_, list):
        row = next((d for d in devices_ if d.get("id") == device), None)
    T.check("AT-37 last upload vs last sample per device",
            status == 200 and row is not None
            and row.get("last_seen") is not None and row.get("last_sample_at") is not None,
            f"{status} {row}")

    # AT-13: rate limit — a fresh boot_id per batch keeps ordering out of the way.
    status, body_ = 0, {}
    accepted = 0
    for i in range(80):
        b = 1000 + i
        rb = body(device, boot2 + 1 + i, b, [[7, 30 + i, 234, 649, 4000, 1230]])
        status, body_ = post(base, rb, sign(key, device, boot2 + 1 + i, b, rb))
        if status == 429:
            break
        accepted += 1
    T.check("AT-13 rate limited within the hour",
            status == 429 and body_.get("code") == "rate_limited"
            and body_.get("retry_after", 0) > 0,
            f"accepted {accepted} then {status} {body_}")

    # AT-14: unknown path is a 404, never a redirect
    wrong = urllib.request.Request(base + "/v1/nope", data=b"{}", method="POST")
    wrong.add_header("Content-Type", "application/json")
    status, _ = _send_noexcept(wrong)
    T.check("AT-14 unknown path is 404", status == 404, str(status))

    print(f"\n{T.passed} passed, {T.failed} failed")
    return 0 if T.failed == 0 else 1


def _send_noexcept(req) -> tuple[int, object]:
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read()[:200]
    except urllib.error.URLError as e:
        return 0, str(e.reason)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument(
        "mode",
        choices=["post", "test", "provision", "reset", "vector"],
        nargs="?",
        default="vector",
    )
    ap.add_argument("--url", default=os.environ.get("INGEST_URL", "http://127.0.0.1:8787"))
    ap.add_argument("--key", default=TEST_KEY, help="32-byte device key, hex")
    ap.add_argument("--device", default=DEVICE)
    ap.add_argument("--token", help="admin API_TOKEN, enables the read-API checks")
    ap.add_argument("--boot-id", type=int, default=4660)
    ap.add_argument("--batch", type=int, default=42)
    args = ap.parse_args()

    if args.mode == "provision":
        now = int(time.time())
        print(
            "INSERT INTO ingest_devices (id, name, role, key_enc, created_at)\n"
            f"VALUES ('{args.device}', 'fake device', 'server', '{args.key}', {now})\n"
            "ON CONFLICT(id) DO UPDATE SET key_enc = excluded.key_enc, disabled = 0;"
        )
        return 0

    if args.mode == "reset":
        # Development only: clears the ordering state and the one-hour rate
        # window so the acceptance suite can run again against the same device.
        print(
            "UPDATE ingest_devices\n"
            "   SET last_boot_id = NULL, last_batch = NULL,\n"
            "       rate_start = 0, rate_count = 0\n"
            f" WHERE id = '{args.device}';"
        )
        return 0

    if args.mode == "vector":
        # AT-16: canonical string + HMAC for the two Appendix A vectors.
        for label, raw, expected in (
            ("vector 1 (batch 42)", VECTOR_1, VECTOR_1_SIGNATURE),
            ("vector 2 (batch 43)", VECTOR_2, VECTOR_2_SIGNATURE),
        ):
            batch = json.loads(raw)["batch"]
            sig = sign(args.key, args.device, args.boot_id, batch, raw)
            print(f"{label}: {sig}")
            print(f"  expected: {expected}")
            print(f"  match:    {sig == expected}")
        return 0

    if args.mode == "test":
        print(f"# acceptance tests against {args.url}\n")
        return run_tests(args.url, args.key, args.device, args.token)

    raw = body(args.device, args.boot_id, args.batch, [[7, 12, 234, 649, 4000, 1230]])
    sig = sign(args.key, args.device, args.boot_id, args.batch, raw)
    status, payload = post(args.url, raw, sig)
    print(status, json.dumps(payload, ensure_ascii=False) if isinstance(payload, dict) else payload)
    return 0 if status == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
