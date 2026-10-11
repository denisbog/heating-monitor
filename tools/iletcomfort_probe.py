#!/usr/bin/env python3
"""iLetComfort (ITS/BTRI heat pump) probe: login, list appliances, read status.

Reads credentials from ~/.config/monitoring/credentials.toml ([iletcomfort] section).
Never prints the password, tokens, or signing keys.

!! WARNING !! The Dollin cloud allows only ONE active session per account. Running
this logs the iLetComfort phone app out (and using the phone app logs this out).
Use a second, shared account for automation if you want both at once.

Usage:
    python3 tools/iletcomfort_probe.py                 # login + list + status + sensors
    python3 tools/iletcomfort_probe.py --raw           # dump raw hex frames + full JSON
    python3 tools/iletcomfort_probe.py --list-only     # no device traffic
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import random as rnd
import sys
import time
import tomllib
import urllib.error
import urllib.request

# --- app constants (universal, extracted from the iLetComfort iOS binary) ---
APP_SECRET = "SIT_4VjZdg19laDoIrut"
APP_KEY = "btri"
IOT_KEY = "meicloud"
CLIENT_ID = "d056337d77334ecc95aca4bff6025533"
CLIENT_SECRET = "35b965531383ce9f37f829a19712bf3a"
ENCRYPT_KEY = "4dbc9ff6c15944d78eebb581c2b23de3"
APP_ID = "8010"
APPNUM = "1.6.4"
REGION_URLS = {"us": "https://us.dollin.net", "eu": "https://eu.dollin.net"}

STATUS_QUERY = "aa0cc30000000000000301012c"  # subtype 0x01
SENSOR_QUERY = "aa0cc30000000000000302012b"  # subtype 0x02


def encrypt_password(plaintext: str) -> str:
    """SHA256(pw) hex -> AES-128-CBC with key/IV = ASCII of SHA256(ENCRYPT_KEY)[0:32]."""
    from cryptography.hazmat.primitives import padding as cp
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    hexdigest = hashlib.sha256(plaintext.encode()).hexdigest()
    km = hashlib.sha256(ENCRYPT_KEY.encode()).hexdigest()
    key, iv = km[0:16].encode("ascii"), km[16:32].encode("ascii")
    padder = cp.PKCS7(128).padder()
    data = padder.update(hexdigest.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return (enc.update(data) + enc.finalize()).hex()


def sign_v1(body: str, use_iot_key: bool) -> tuple[str, str]:
    ts = time.strftime("%Y%m%d%H%M%S") + str(rnd.randint(0, 65535))
    msg = (IOT_KEY if use_iot_key else APP_KEY) + body + ts
    sig = hmac.new(APP_SECRET.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return sig, ts


def sign_v2(method: str, path: str, body: str) -> str:
    sig = hmac.new(CLIENT_SECRET.encode(), (method + path + body).encode(), hashlib.sha256).digest()
    return base64.b64encode(sig).decode()


def http(method, url, headers, data=None, timeout=30):
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


class Client:
    def __init__(self, base: str):
        self.base = base
        self.token: str | None = None

    def _v1(self, path: str, body: dict, use_iot_key: bool) -> dict:
        js = json.dumps(body, separators=(",", ":"))
        sig, rv = sign_v1(js, use_iot_key)
        hdrs = {
            "random": rv,
            "src": "20",
            "appid": APP_ID,
            "language": "en_US",
            "clienttype": "2",
            "appvnum": APPNUM,
            "stamp": time.strftime("%Y%m%d%H%M%S"),
            "deviceid": hashlib.sha256(f"ilet-{int(time.time())}".encode()).hexdigest()[:32].upper(),
            "sign": sig,
            "reqid": hashlib.md5(f"{time.time()}-{rnd.random()}".encode()).hexdigest(),
            "Content-Type": "application/json",
            "User-Agent": f"iLetComfort/{APPNUM} (com.btri.OEMPlus; build:308; iOS) Alamofire/5.5.0",
        }
        return json.loads(http("POST", self.base + path, hdrs, js.encode())[1])

    def _v2(self, path: str, body: dict) -> dict:
        js = json.dumps(body, separators=(",", ":"))
        hdrs = {
            "authorization": f"Bearer {self.token}",
            "clientId": CLIENT_ID,
            "signature": sign_v2("POST", path, js),
            "signatureversion": "2.0",
            "reqid": hashlib.md5(f"{time.time()}-{rnd.random()}".encode()).hexdigest(),
            "language": "en_US",
            "Content-Type": "application/json",
            "User-Agent": f"iLetComfort/{APPNUM} (com.btri.OEMPlus; build:308; iOS) Alamofire/5.5.0",
        }
        return json.loads(http("POST", self.base + path, hdrs, js.encode())[1])

    def login(self, user: str, pw: str) -> dict:
        r = self._v1(
            "/v1/user/login",
            {"loginAccount": user, "password": encrypt_password(pw), "encryptVersion": "1"},
            use_iot_key=True,
        )
        if r.get("code") != 0:
            sys.exit(f"LOGIN FAILED: code={r.get('code')} msg={r.get('msg')}")
        d = r["data"]
        self.token = d["accessToken"]
        print(f"login OK  uid={d.get('uid')}  region={d.get('registerRegion')} "
              f"country={d.get('countryName')}")
        srv = d.get("requestServer", {}).get("mqttServer") or {}
        if srv.get("host"):
            print(f"          mqtt -> {srv['host']}:{srv.get('port')}")
        return d

    def appliances(self) -> list:
        r = self._v2("/midea/open/business/v1/appliance/list", {"queryAuth": True})
        if r.get("code") != 0:
            sys.exit(f"appliance/list failed: {r}")
        return r.get("data") or []

    def hex_command(self, appliance_code: str, command: str) -> dict:
        return self._v2(
            "/midea/open/business/v1/appliance/control/hexadecimal",
            {"applianceCode": appliance_code, "command": command},
        )


# --------------------------------------------------------------------------
# C3 frame decoding (offsets from API_FINDINGS.md sections 5 & 6)
# --------------------------------------------------------------------------
def frame_bytes(api_response: dict) -> bytes:
    data = api_response.get("data")
    if not isinstance(data, str):
        raise ValueError(f"no hex data in response: {api_response}")
    return bytes.fromhex(data.replace(",", "").strip())


def body_of(frame: bytes) -> bytes:
    return frame[10:-1]


# ATW profile (sn8 171H120F, Italtherm air-to-water) — 25-byte status body.
# Validated against the 5 real captures in ha-iletcomfort tests/test_model_profiles.py.
ATW_DHW_SETPOINT_INDEX = 8
ATW_ZONE1_SETPOINT_X2_INDEX = 9
ATW_DHW_TANK_TEMP_INDEX = 22
ATW_FLAGS_INDEX = 1
ATW_SPACE_HEAT_DEMAND_BIT = 0x01
ATW_SN8 = "171H120F"

# The cloud sometimes answers subtype 0x02 with a repeated "03 1e 00 00 00 00"
# template instead of live telemetry — it must NOT be reported as measurements.
def is_atw_placeholder_sensors(body: bytes) -> bool:
    if len(body) < 8 or body[0] != 0x02:
        return False
    rest = body[2:]
    if len(rest) % 6:
        return False
    return all(rest[i] == 0x03 and rest[i + 1] == 0x1E for i in range(0, len(rest), 6))


def decode_atw_status(frame: bytes) -> dict:
    """Decode the ATW (Italtherm, sn8 171H120F) 25-byte status body."""
    body = body_of(frame)
    if len(body) <= ATW_DHW_TANK_TEMP_INDEX:
        raise ValueError(f"ATW body too short: {len(body)} bytes")
    flags = body[ATW_FLAGS_INDEX]
    return {
        "profile": "ATW / Italtherm 25-byte",
        "space_heat_demand": bool(flags & ATW_SPACE_HEAT_DEMAND_BIT),
        "flags_raw": flags,
        "dhw_setpoint_c": body[ATW_DHW_SETPOINT_INDEX],
        "zone1_setpoint_c": body[ATW_ZONE1_SETPOINT_X2_INDEX] / 2,
        "dhw_tank_temp_c": body[ATW_DHW_TANK_TEMP_INDEX],
    }


MODE_NAMES = {0: "Off", 1: "Heat", 2: "Cool", 3: "Auto", 4: "WaterPump"}


def decode_status(frame: bytes) -> dict:
    b = body_of(frame)
    d = lambda i: b[1 + i]
    f16 = lambda i: (b[1 + i] << 8) | b[1 + i + 1]
    r35 = lambda i: d(i) - 35
    flags = d(13)
    return {
        "mode": MODE_NAMES.get(d(1), f"unknown({d(1)})"),
        "pump_flags": d(0),
        "setpoint_active": r35(2),
        "dhw_setpoint": d(4),
        "td_max": r35(6),
        "td_min": r35(7),
        "box_bottom_temp": r35(16),
        "ptc_temp": r35(17),
        "return_temp": r35(18),
        "error_code": d(23),
        "compressor_running": bool(flags & 1),
        "ibh_running": bool(flags & 2),
        "sterilize_running": bool(flags & 4),
        "exv_opening_deg": f16(35),
        "pressure_high": f16(37),
        "pressure_low": f16(39),
        "compressor_freq": f16(41),
        "total_kwh": f16(43),
        "compressor_hours": f16(45),
        "fan_hours": f16(47),
    }


def decode_sensors(frame: bytes) -> dict:
    b = body_of(frame)
    d = lambda i: b[1 + i]
    f16 = lambda i: (b[1 + i] << 8) | b[1 + i + 1]
    r35 = lambda i: d(i) - 35
    ctrl = d(41)
    return {
        "online_units": d(11),
        "tf_refrigerant": d(14),
        "tp_plate_hx": d(15),
        "th_dhw_tank": d(16),
        "water_pressure": d(17),
        "water_flow_switch": d(18),
        "capacity_hp": d(19),
        "t3_condenser": r35(20),
        "t4_outdoor_ambient": r35(21),
        "t2_evaporator": r35(22),
        "t2b_evap_secondary": r35(23),
        "twin_water_inlet": r35(24),
        "twout_water_outlet": r35(25),
        "t1_suction": r35(26),
        "odu_current": f16(27),
        "odu_voltage": d(29),
        "mute_level": d(40),
        "control_flag": {0: "normal", 1: "mute", 2: "boost"}.get(ctrl, ctrl),
    }


def show(title, obj):
    print(f"\n=== {title}")
    for k, v in obj.items():
        print(f"    {k:24} {v}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--creds", default="~/.config/monitoring/credentials.toml")
    ap.add_argument("--raw", action="store_true")
    ap.add_argument("--list-only", action="store_true")
    args = ap.parse_args()

    path = os.path.expanduser(args.creds)
    with open(path, "rb") as f:
        section = tomllib.load(f).get("iletcomfort") or {}
    user, pw = section.get("username"), section.get("password")
    region = (section.get("region") or "us").lower()
    if not user or not pw:
        sys.exit(f"no [iletcomfort] username/password in {path}")

    c = Client(REGION_URLS.get(region, REGION_URLS["us"]))
    print(f"region={region} -> {c.base}")
    c.login(user, pw)

    appliances = c.appliances()
    print(f"\n=== appliances ({len(appliances)})")
    for a in appliances:
        print("   ", json.dumps({
            k: a.get(k) for k in
            ("applianceCode", "name", "applianceType", "online", "activeStatus", "sn", "sn8", "owner")
        }, ensure_ascii=False))

    if args.list_only or not appliances:
        return

    for a in appliances:
        code = a.get("applianceCode")
        name = a.get("name")
        sn8 = (a.get("sn8") or "").strip()
        is_atw = sn8 == ATW_SN8
        print(f"\n########## {name}  applianceCode={code}  sn8={sn8}"
              f"{'  [ATW profile]' if is_atw else ''} ##########")

        for label, query in (("STATUS (subtype 0x01)", STATUS_QUERY),
                             ("SENSORS (subtype 0x02)", SENSOR_QUERY)):
            r = c.hex_command(code, query)
            if r.get("code") != 0:
                print(f"\n=== {label} -> FAILED {r}")
                continue
            frame = frame_bytes(r)
            if args.raw:
                print(f"\n=== {label} raw ({len(frame)} bytes)")
                print("   ", r["data"])
            try:
                if label.startswith("SENSORS") and is_atw:
                    if is_atw_placeholder_sensors(body_of(frame)):
                        print("\n=== SENSORS -> cloud placeholder template, "
                              "no live telemetry on this model")
                        continue
                    show(f"{label} decoded", decode_sensors(frame))
                elif is_atw:
                    show(f"{label} decoded", decode_atw_status(frame))
                else:
                    dec = decode_status if label.startswith("STATUS") else decode_sensors
                    show(f"{label} decoded", dec(frame))
            except Exception as e:
                print(f"\n=== {label} decode error: {e} (use --raw)")


if __name__ == "__main__":
    main()
