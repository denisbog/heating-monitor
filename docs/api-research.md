# Monitoring research: iLetComfort + CAME THermo Wi-Fi

Goal: fetch daily readings from both systems, store them, chart them in a Rust
`iced` desktop app. This file records what the two clouds are and how to talk to
them. Credentials are **not** stored here.

---

## 1. iLetComfort (ITS / BTRI — heat pump)

| | |
|---|---|
| Android package | `com.mbt.iletcomfort` (also iOS `com.btri.OEMPlus`) |
| Vendor | Shanghai KONG Intelligent Building / ITS brand |
| Platform | Midea **Dollin** OEM cloud (proprietary C3 variant) |
| Web UI | **none consumer-facing** — cloud REST API only |
| Region | US `us.dollin.net`, EU `eu.dollin.net` |

### Cloud endpoints
```
# Auth (signing scheme v1, headers: random/src/appid/language/clienttype/appvnum/stamp/deviceid/sign/reqid)
POST https://us.dollin.net/v1/user/login

# Business API (signing scheme v2.0, header: signature)
GET  https://us.dollin.net/midea/open/business/v1/appliance/list
GET  https://us.dollin.net/midea/open/business/v1/appliance/info
POST https://us.dollin.net/midea/open/business/v1/appliance/control/hexadecimal   <- main data/control channel
GET  https://us.dollin.net/midea/open/business/v1/ads
GET  https://us.dollin.net/midea/open/business/v1/country/channel/retrieve

# SDK API (signing scheme v2.1) - returns MQTT client certificate
POST https://us.dollin.net/v2/open/sdk/appliance/privateKey

# Realtime push (mutual-TLS MQTT, AWS IoT Core)
mqtts://a39t91kk7ictzi-ats.iot.us-west-2.amazonaws.com:8883

# Server-side hex decode helper
POST https://us.ibuildinghvac.com/api/mibp-connector-mo-parser/mibp/sys/mg_iot/decode
```

### Key mechanics
- **Password encryption**: `SHA256(password)` hex -> AES-128-CBC where key/IV are the
  *ASCII characters* of the first 32 hex digits of `SHA256(ENCRYPT_KEY)`.
- **Signing** differs per API generation (v1 HMAC-SHA256 with `meicloud`/`btri` prefix;
  v2.0 `signature`; v2.1 SDK). See `API_FINDINGS.md` in the reference repo.
- Appliance data comes back as **raw hex C3 frames**; decode locally or via the
  server-side decode endpoint.
  - status query = subtype `0x01`, sensor query = subtype `0x02`, control = SET frame.
  - Temps: most fields `raw_byte - 35`; `tf/tp/th` direct.
- **Query mode numbering != SET mode numbering** (easy bug source).
- **Only one active session per account**: logging in here kicks the phone app out
  (and vice versa). Best practice from the HA integration: create a *second* cloud
  account and share the device to it, or use the MQTT cert read-only mode.

### Reference implementations (read these first)
- `tgenov/iletcomfort-cli` — Python client + `API_FINDINGS.md` (best protocol doc).
- `tgenov/ha-iletcomfort` — complete HA integration; `custom_components/iletcomfort/api.py`
  has the full cloud client (auth, signing, MQTT, sensors).

### ✅ VERIFIED against the live account (2026-10-11)

- `region = "eu"` → **`https://eu.dollin.net`** (not `us`). Login OK, country <redacted>.
- MQTT broker for EU: `a39t91kk7ictzi-ats.iot.**eu-central-1**.amazonaws.com:8883`
  (the reverse-engineering doc only lists the US broker).
- 1 appliance: `applianceCode = <appliance-code>`, name "ATW heat pump",
  `applianceType = 0xC3`, **`sn8 = 171H120F`**, `sn = <device-serial>`.
- Both subtypes work through `/midea/open/business/v1/appliance/control/hexadecimal`.

**Status frame is 36 bytes** (the reference doc describes 62) → 25-byte body. This is the
known **ATW / Italtherm air-to-water profile** (`171H120F`), already validated in
ha-iletcomfort against five real captures:
```
body: 01 01 17 a0 03 03 19 1e 14 30 37 19 19 05 37 19 19 05 3c 22 3c 14 10 00 80
```
| field | offset | decoded |
|---|---|---|
| space heat demand | `body[1]` bit 0 | **true** |
| DHW setpoint | `body[8]`, direct °C | **20 °C** |
| Zone-1 setpoint | `body[9] / 2` | **24.0 °C** |
| DHW tank temp | `body[22]`, direct °C | **16 °C** |

**Sensors frame is 49 bytes** of repeating `03 1e 00 00 00 00` blocks = the known
**placeholder template** (ha-iletcomfort issue #38). **This model exposes no live sensor
telemetry** — no water inlet/outlet, no outdoor ambient, no compressor frequency via this path.

⚠️ **To validate with the user:** `dhw_tank_temp = 16 °C` and `dhw_setpoint = 20 °C` look
unusual for a DHW tank (normally >= 40 °C). Either DHW is genuinely off on this unit, or this
frame variant (`body[2] = 0x17` vs Italtherm `0x07` / Galmet `0x15`) shifts the mapping.
Confirm against the official app's current screen.

⚠️ **Single active session:** every login invalidates the previous token *and* silently signs
the phone app out. Polling every 15 min would log the app out ~96x/day.
→ Use a **second iLetComfort account** with the heat pump shared to it, as
`docs/TROUBLESHOOTING.md` in ha-iletcomfort recommends.

### ✅ Electric consumption, produced heat and COP — all available

The app's energy screens do **not** use dollin.net. The vendor's own plugin bundle
(`MthermalEnergy.js`, `MthermalNewEnergyStatistics.js`) calls the **iBUILDING HVAC** platform:

```
Base (EU): https://eu.ibuildinghvac.com/api/apps-oem        <- works
           https://hbtapp-prod.mideaibp.com/api/apps-oem    <- also works (not EU)
           https://eu.mideaibp.com  -> 404                   <- do not use

Auth: same `Authorization: Bearer <accessToken>` from the dollin.net login. No extra signing.
Body: {"sn": "<device serial>"}
      sn = <device-serial>   (NOT applianceCode)
```

Verified live:

| endpoint | response |
|---|---|
| `POST /v3/energy/getEnergyLatest` | `{"key":"INSTANT","electricityDTO":{"statisticalTime":"2026-10-11 17:47:51","value":"0.00","unit":"kW"},"energyDTO":{"allEnergyProduce":"0.00","energyProduce":"0.00","energyReProduce":"0.00"},"copDTO":{"total":"0.00","heat":"0.00","cool":"0.00","dhw":"0.00"},"runTime":"0.0"}` |
| `POST /v3/energy/getTotalDetail` | `{"key":"TOTAL","electricityDTO":{"statisticalTime":"2026-01-07~2026-10-10","value":"1999.00","unit":"kWh"},"energyDTO":{"allEnergyProduce":"8732.00","energyProduce":"8732.00","energyReProduce":"0.00"},"copDTO":{"total":"4.37","heat":"4.38","cool":"0.00","dhw":"0.00"},"startTime":"2026-01-07"}` |
| `POST /energyStatistics/getStartDateForSn` | `"2026-01-07"` — first day of recorded history |

So we get **cumulative electricity kWh, produced heat kWh, and COP**, with history back to
2026-01-07. This is separate from the C3 hex frames — a completely different, much richer source.

Still to pin down (my first parameter guesses returned `null`):
```
/v3/energy/getAllInfoList      per-day list   (params TBD)
/v3/energy/getHourInfoList     per-hour list  (params TBD)
/v3/energy/getSummaryDetail
/v3/energy/getCostSavingList
/v3/energy/energyAndChargeLast
/v3/energy/power/price/detail + /save     (tariff config)
/energyStatistics/accessEnergyData
/energyStatistics/searchRangeData
```
Next step: read the exact request bodies from `MthermalNewEnergyStatistics.js`
(minified; call sites wrap `{sn: ...}` plus date fields).
Webpack module IDs inside `MthermalEnergy.js` (already downloaded to `data/plugins/`):
`getAllInfoList` = **591**, `getHourInfoList` = **603**, `getSummaryDetail` = 579,
`getCostSavingList` = 588, `energyAndChargeLast` = 597, `getTotalDetail` = 585.
Extract those module bodies to read the exact request payloads.

### ✅ RESOLVED — `getHourInfoList` returns ambient temp + full energy breakdown

Extracted from the vendor plugin bundle (`MthermalEnergy.js`, the `fetchData` method; the
literal `getAllInfoList err---\>` is a reliable grep anchor). Exact call shapes:

```js
// hourly detail
getHourInfoList.request({ host: oemRequestHost, params: { sn, day: "YYYY-MM-DD" } })
                                              // ^^^ `day`, NOT `date` — that was the bug

// day/week/month/year detail
getAllInfoList.request({ host: oemRequestHost, params: { sn, type, startTime, endTime } })
                                              // type = DAY | WEEK | MONTH | YEAR | TOTAL | HOUR
```
- `startTime` is normalised by `formatStartTime`: `MONTH` → `yyyy-MM-01`, `YEAR` → `yyyy-01-01`,
  otherwise the raw `YYYY-MM-DD`. `endTime` is always `YYYY-MM-DD`.
- Host comes from `oemRequestHost` = `OEM_EU_PROD_URL` (EU accounts) / `OEM_US_PROD_URL` (`us`) /
  `OEM_SIT_URL` (SIT) → `https://eu.ibuildinghvac.com`, the host we already use.

`getHourInfoList` response `data` carries **four** arrays:

| array | shape | meaning |
|---|---|---|
| `electricityInfoDTOS` | grouped by `type`, each `{type, electricityInfoListDTOS:[{statisticalTime,value,unit,type}]}` | **electric consumption per hour (kWh)** — the app's "Electric Comsumption" screen |
| `energyInfoListDTOS` | grouped by `type`, `{statisticalTime,allEnergyProduce,energyProduce,energyReProduce,type,unit}` | heat produced per hour |
| `copInfoListDTOS` | grouped by `type`, `{statisticalTime,value,type}` | COP per hour |
| **`temp4InfoListDTOS`** | **flat** list of `{statisticalTime,value,unit}` | **T4 = outdoor ambient temperature** |

Group `type` values seen: `heat`, `cool`, `tbh`, `ibh`, `others`.

Verified live for 2026-10-11 (10 hourly samples 09:00–19:00):
```
T4 outdoor ambient: 24, 26, 29, 30, 25, 23, 20, 19, 16, 16  °C   ->  average 22.8 °C
```
So the app's "Ambient T average" is the mean of `temp4InfoListDTOS`, and the newest sample is
the "last reading". **This is the ambient temperature that was missing** — and it is far richer
than the C3 sensor frame, which is a placeholder on this model.

`getAllInfoList` still returned `data: null` for `type=DAY|WEEK|MONTH|YEAR`; `getHourInfoList`
works and is strictly more detailed, so prefer it.

### iLetComfort statistics inventory (all probed live, 2026-10-11)

Every call is `POST https://eu.ibuildinghvac.com/api/apps-oem<path>` with
`Authorization: Bearer <dollin accessToken>` and body `{...params, app:"iLetComfort", nid:<sn>}`.

| endpoint | params | returns | usable |
|---|---|---|---|
| `/v3/energy/getHourInfoList` | `{sn, day}` | 4 arrays (electricity/energy/cop by type + `temp4InfoListDTOS`) | ✅ **today only** |
| `/v3/energy/getAllInfoList` | `{sn, type, startTime, endTime}` | 3 arrays | ⚠️ only `type=YEAR` (1 annual bucket per usage type) |
| `/v3/energy/getTotalDetail` | `{sn}` | cumulative | ✅ |
| `/v3/energy/getEnergyLatest` | `{sn}` | instant | ✅ |
| `/v3/energy/getSummaryDetail` | `{sn}` | `[YEAR, DAY, WEEK, MONTH]` | ✅ |
| `/v3/energy/energyAndChargeLast` | `{sn}` | `powerAll`, `powerLastDay`, `saveChargeAll`, `saveChargeLastDay`, `unit` | ✅ cost/savings (EUR) |
| `/energyStatistics/getStartDateForSn` | `{sn}` | `"2026-01-07"` | ✅ history start |
| `/energyStatistics/searchRangeData` | `{sn, startTime, endTime, type}` | `searchList[4]` = capacity / quantityOfHeat / powerConsumption / COP | ⚠️ range aggregate, all zeros here |
| `/v3/energy/getCostSavingList` | `{sn}` | `null` | ❌ |
| `/v3/energy/power/price/{detail,getUnitCoinMaster}` | | `null` | ❌ tariff not configured |
| `/energyStatistics/check/*` | | `null` | ❌ never worked |

`type` is one of `TOTAL, INSTANT, HOUR, DAY, WEEK, MONTH, YEAR`
(`modeTabs` in `MthermalEnergy.js`). `TOTAL` → `getTotalDetail`, `INSTANT` → `getEnergyLatest`,
`HOUR` → `getHourInfoList`; the rest go to `getAllInfoList`.

**Key constraint: hourly data exists only for the current day.** The 15-minute poll is
therefore what builds history — nothing can be backfilled later.

### What the collector stores per poll
- iLetComfort: 40+ metrics — `ambient_t4`, `elec_hourly_{all,heat,cool,dhw,tbh,ibh,others}`,
  `cop_hourly_*`, `heat_produced_hourly_*`, `charge_*` (EUR/kWh), `summary_*_{day,week,month,year}`,
  plus the C3 status fields and the cumulative totals.
- CAME (per thermostat): 20 metrics — `room_temp`, `humidity`, `setpoint`, `relay_heating`,
  `outdoor_temp_cloud`, `online`, `comfort`, boost/holiday, `outdoor_temp` + `internal_temp` +
  `humidity_avg` + `setpoint_avg` (daily buckets), window averages, `power_on_total`,
  `connection_events`.

Measured: **324 readings per run** (was 112).

### Confirmed by decompiling the APK (2026-10-11)
`/api/mibp-connector-mo-parser/mibp/sys/mg_iot/`**`encode`** exists alongside `decode`
(server-side C3 frame encode/decode). Midea OEM SDK: `com.midea.oem.iot.sdk.{account,device,message}`.
The APK ships **no** per-model plugin bundles and has **zero** references to `v3/energy` — the
energy logic lives entirely in the runtime-downloaded Weex plugin, so the APK is not the place
to look for it.

### The vendor plugin route (useful technique)
`POST /v1/product/upgrade/plugin/get/latest` (v1 signing with the **iot-key** prefix, token in
an `accessToken` header — *not* `Authorization: Bearer`), body:
```json
{"language":"en_US","model":"<sn8>","sdkVersion":20230725,
 "firmwareVersion":"000000000000","type":"0xC3","version":"0.0.0"}
```
Sending `version: "0.0.0"` forces the server to hand back a presigned bundle URL.
- `17100007` → plugin **v1.0.65** (12.6 MB, 126 files) — this is where the energy endpoints came from.
- `171H120F` (ours) → `code 2200004`, **no plugin registered in the EU region**.
- `171000AU` → `code 2200007`, not in this region's catalogue.

So our model has no plugin, but the `0xC3` plugin is the vendor's own schema and is the
authoritative reference for what the app can do with any C3 heat pump.

---

## 2. CAME THermo Wi-Fi (thermostats TH/500, TH/550, TH/700, TH/One)

| | |
|---|---|
| Android package | `com.came.thermosg` (THermo Wi-Fi); older `com.came.thermo` |
| Vendor | CAME S.p.A. |
| Cloud | **CAMEConnect Cloud** (app uses MQTT ports 8883/1883) |

### Web version (this is the answer to "web version")
- Login portal: **https://www.cameconnect.net** (redirects to the web app)
- Web app: **https://app.cameconnect.net**  (e.g. `app.cameconnect.net/home/devices/<id>`)
- OAuth: **https://app.cameconnect.net/api/oauth/token** (`auth.cameconnect.net` does *not*
  resolve — the older HA README is wrong). The app also knows a second backend,
  **`https://thermo.cameconnect.net`**, which serves the thermostats.

### Auth API (base `https://app.cameconnect.net/api`)
```
POST /oauth/auth-code   query : client_id, response_type=code, redirect_uri,
                               state, nonce, code_challenge, code_challenge_method=S256
                        body  : grant_type=authorization_code, client_id, username, password
                        header: Authorization: Basic base64(clientId:clientSecret)
POST /oauth/token       body  : grant_type=authorization_code, code, redirect_uri, code_verifier
                        header: Authorization: Basic base64(clientId:clientSecret)
```
`redirect_uri` is built from `location` as `<scheme>://<host>/role`, so when logging in
at app.cameconnect.net it is `https://app.cameconnect.net/role`.

### Automation / site API (gates, intercoms, board I/O)
```
GET  /api/evo/v1/sites
GET  /api/evo/v1/sites/{site_id}/devices
GET  /api/devicestatus?devices=[<device_id>]
POST /api/automations/{device_id}/commands/{command_id}
WS   wss://app.cameconnect.net/api/events-real-time   (Origin: https://www.cameconnect.net)
```

### Thermostat API  <-- **THermo Wi-Fi data lives here, NOT on app.cameconnect.net**
```
Base: https://thermo.cameconnect.net        (same Bearer token as above)

GET  /groups/get                                   thermostat list (legacy)
GET  /v2/groups[?userId=...]                       thermostat list (used by current UI)
GET  /devices/{keycode}                            current thermostat status
GET  /v2/devices/{keycode}[?userId=...]            thermostat status v2
GET  /api/v1/statistics/{keycode}                  HISTORY / GRAPH DATA
       ?from=<ISO8601>&intervaltype=<...>&location=<...>
GET  /api/v1/statistics/{keycode}/download         LOG EXPORT -> returns {Url, FileType}
       ?from=<ISO8601>&to=<ISO8601>&metrics=<csv>
POST /control/{keycode}/{keycode}   body = thermostat object      (control)
WS   wss://thermo.cameconnect.net:8443/WebSocket/{keycode}/{...}
       subprotocol: ["bearer", <access_token>]
```
The thermostat identifier is called **`Keycode`** throughout the web app (`device_id`
is the gate/automation API concept). Extract the same way as in `sdeagh/came_connect`.
- `redirect_uri` must be exactly `https://app.cameconnect.net/role`
  (beta clients: `https://beta.cameconnect.net/role`).
- Tokens are Bearer; refresh by re-running the auth-code flow.

### Client id / secret — already extracted (public values, shared by all users)

Read straight out of `https://www.cameconnect.net/main.<hash>.js` (config object):

| key | value |
|---|---|
| `clientId` | `58FnU0A4KqLYo3zJO1GMuYpTu74RyfnL` |
| `clientSecret` | `T23FhzVZCXUD87TwP21L3ALdJYcPGCCPSqQTjMrnwG5SwQY6w6xFa9hnidS9KkZb8MMUBJJC8U2UdpFqdUVjbXtzdNqUk9eDu72VF6YdKTq8Z8ULzmbcAvgEiNwzZq2x6RLxF7ewCqAMUcUBPEAXhJwqv7j6f3bxJZNZZmLpWn5b8MqVxwk6CNq0C6uVTrRJuwTEkY23Vpq5Atwyq0QatdMwcFDT7CFJgJs1DiBR3MmHX0fXE4gnvLiJEFG0LXfR` |
| `redirect_uri` | `https://app.cameconnect.net/role` (or `.../beta.cameconnect.net/role`) |

Full config seen in the bundle:
```js
apiUrl:            "https://app.cameconnect.net/api",
apiUrlThermo:      "https://thermo.cameconnect.net",
websocketUrl:      "wss://app.cameconnect.net/api/events-real-time",
websocketUrlThermo:"wss://thermo.cameconnect.net:8443/WebSocket",
frontEnd:          "https://cameconnect.net",
clientId:          "58FnU0A4KqLYo3zJO1GMuYpTu74RyfnL",
clientSecret:      "T23FhzVZCXUD87TwP21L3ALdJYcPGCCPSqQTjMrnwG5..."
```

To re-extract if CAME ever rotates them:
```bash
curl -s https://www.cameconnect.net/ | grep -oE 'src="main\.[a-f0-9]+\.js"'      # find bundle
curl -s https://www.cameconnect.net/main.<hash>.js -o main.js
grep -oE 'clientId:"[^"]*"|clientSecret:"[^"]*"' main.js
```
Alternative: DevTools -> Network on login -> the `oauth/token` request's
`Authorization: Basic <b64>` header -> `base64 -d` -> `clientId:clientSecret`.

### `device_id` / `keycode`
- **Thermostats**: use `Keycode`. Get the list with
  `GET https://thermo.cameconnect.net/v2/groups` (Bearer token) — it returns the
  user's groups and their thermostats. `Keycode` is the id used in every
  `/devices/...`, `/api/v1/statistics/...` and `/control/...` URL.
- **Gates/automations**: `device_id` is the trailing number in the web-app URL
  `https://app.cameconnect.net/home/devices/XXXXXX`, or from
  `GET /api/evo/v1/sites` + `/api/evo/v1/sites/{id}/devices`.

### ✅ VERIFIED against the live account (2026-10-11)

Normal **user** account, headless OAuth2 authorization-code + PKCE works with no browser
(`tools/came_probe.py`). One Bearer token is valid for both `app.` and `thermo.` hosts.

Two thermostats, both `ProductTypeName: "TH/700"` (`ProductTypeId: 20`):

| Name | Keycode |
|---|---|
| et1 | `<keycode-a>` |
| (2nd) | `<keycode-b>` |

**Current state** — `GET {thermo}/devices/{keycode}` (or `/v2/devices/{keycode}`):
```jsonc
{
  "keycode": "<keycode-a>",
  "cameconnect": { "Id": <id>, "SiteId": <site-id>, "Name": "et1",
                   "ProductTypeId": 20, "ProductTypeName": "TH/700", "AclRole": 1 },
  "on_line": 1, "updatedAt": "...",
  "temp_loc": 20.2,          // measured room temperature      <-- main reading
  "hum_loc": 55,             // measured relative humidity
  "set_point_temp": 18, "manual_temp": 18,
  "mode": "manual", "current_season": "winter",
  "relay_status": 0,         // boiler relay: 0 = no heating demand
  "comfort_state": true, "stdby_mode": "proximity",
  "temp_ext": 20, "weather": "sunny", "request_type": "weather",   // cloud weather, not a sensor
  "alarm_t_high": false, "alarm_t_low": false, "alarm_h_high": false, "alarm_h_low": false,
  "offset_temp": 0, "min_temp": 3, "max_temp": 35,
  "t_threshold_enable": false, "t_threshold_high": 26, "t_threshold_low": 20,
  "h_threshold_enable": false, "h_threshold_high": 70, "h_threshold_low": 30,
  "boost_level": 4, "boost_rem_minutes": 0,
  "holiday_days": 4, "holiday_rem_days": 0,
  "keyboard_lock": false, "buzzer": true, "light_skin": false, "automatic_hour_change": true,
  "Global FW Version": "1.10.000", "WiFi FW Version": "1.10.000",
  "winter": { "T0": 3, "T1": 16, "T2": 18, "T3": 20, "day1".."day7": "<hex>" },
  "summer": { "T1": 24, "T2": 26, "T3": 28, "day1".."day7": "<hex>" },
  "algo": { "type": "diff", "PI_band": 1.5, "T_cycle": 10, "t_diff": 0.2, ... }
}
```
Schedules are hex nibbles, one per hourly slot: `5`=T1, `F`=T2 (or off), `A`=T3.

**History** — `GET {thermo}/api/v1/statistics/{keycode}`:
- Valid `intervaltype`: **`day` | `week` | `month` | `year`** only
  (`hour`, `daily`, `15min`, `D`… → `ErrorCode 55`).
- `from` **must** be `YYYY-MM-DDTHH:MM:SS.000Z` — the milliseconds are required,
  otherwise `ErrorCode 53` "Invalid datetime format". `to` is accepted but ignored.
- `day` = one day, ~20 samples (~70 min apart) · `week` = 7 daily
  · **`month` = 30 daily aggregates, exactly 24 h apart** ← use for daily readings
  · `year` = 12 monthly.
- Response:
```jsonc
{ "Keycode": "...", "IntervalType": "month", "From": 1788213600, "To": 1790719200,
  "PowerOnTime":         { "Total": 0, "List": [ {"Timestamp":0,"Value":0} x30 ] },
  "Humidity":            { "Average": 0, "List": [] },
  "SetPoint":            { "Average": 0, "List": [] },
  "InternalTemperature": { "Average": 0, "List": [] },
  "ExternalTemperature": { "Average": 18.43,
                           "List": [ {"Timestamp":..., "Value":19.005}, ... ] },
  "ConnectionEvents": null }
```

**Two important limitations found:**
1. At day/week/month granularity only `ExternalTemperature` and `PowerOnTime` carry data.
   `InternalTemperature` / `Humidity` / `SetPoint` come back empty (they only appear at
   `year` granularity, 6 points). There is **no usable server-side daily room-temperature
   history** — yet `temp_loc` is available live in `/devices/{keycode}`.
   → The daily job must poll `/v2/devices/{keycode}` periodically and roll its own
     min/avg/max per day into SQLite; history only supplements `ExternalTemperature`.
2. `.../statistics/{keycode}/download` always returns HTTP 500 "Error generating file"
   (`ErrorCode 70`) on this account → unusable, use `/statistics` instead.
   The `location` query param on `/statistics` returns 502 → ignore.

### Reference implementations
- `sdeagh/came_connect` — modern HA integration (OAuth PKCE + WebSocket), best code to mirror.
- `jasonmadigan/came-connect` — older Python lib/CLI + REST proxy (unmaintained).
- `yashijoe/hassio-cameconnect` — HA add-on REST proxy for gates.

---

## Open questions / verification needed once credentials exist

1. **Resolved** — THermo thermostats are *not* on the gate API; they live on
   `https://thermo.cameconnect.net` (`/groups/get`, `/v2/groups`, `/devices/{keycode}`).
2. **Resolved** — history is `GET {thermo}/api/v1/statistics/{keycode}` plus
   `.../download` for a full file export. Best daily-ingestion path.
3. **Still open:** the exact `intervaltype` values for `/api/v1/statistics` are not in
   the JS bundle (they come from UI state). Probe `hour` / `day` / `week` / `month`.
4. **iLetComfort region** (us vs eu) and which sensor fields the unit actually reports
   (some models return 0/unavailable) — confirm against the real app values.
5. Confirm whether the CAME account is a "user" or "installer/technician" role;
   the web app branches on `technician`, so permissions may differ.
6. Check for a *local* LAN fallback:
   - CAME TH/700 etc. serve a config UI at `http://<thermostat-ip>` (installer mode).
   - iLetComfort/Midea C3 devices can often be reached on the LAN via the Midea
     local protocol (but this variant is proprietary and midea-local mis-decodes it).

---

## Cloudflare deployment — cost options

Polling every 15 min = 96 runs/day. Per run: 1 iLetComfort login + status + sensors
(1 device) and 1 CAME OAuth + 2 device fetches (2 thermostats) ≈ **700 HTTP requests/day**.
Storage ≈ **600 rows/day** (6 values × 96 runs + both devices).


> **CAME history quirk (verified live):** `intervaltype=month` returns the
> **calendar month containing `from`**, not a rolling 30-day window. To collect
> recent days you must request the current month *and* the previous one
> (e.g. `from` = now, then `from` = now − 35 d). Likewise `week` is the week
> containing `from`.
Architecture:
```
Cron Trigger */15  ->  Worker "collector"
                         |- iLetComfort client  (eu.dollin.net, v1+v2 signing, C3 decode)
                         |- CAME client         (oauth + thermo.cameconnect.net)
                         `- D1 batch INSERT readings
Worker "api"       ->  D1 SELECT -> JSON  ->  iced desktop app (charts)
```

| Resource | Free plan | Paid ($5/mo base) |
|---|---|---|
| Workers requests | 100k/day | 10M included, then $0.30/M |
| Worker CPU | **10 ms per invocation** | 30M CPU-ms included, then $0.02/M |
| Cron Triggers | 1 min min interval, **3 per Worker**, 10 ms CPU, **no retries/alerts** | 5 per Worker, 30 s CPU (>hourly: 15 min) |
| D1 | 5 GB, **5M rows read/day**, **100k rows written/day** | $0.75/GB-mo, $1/M rows written |
| KV / R2 | 1 GB / 10 GB | cheap |

**Verdict: Workers Free is comfortably enough** — ~700 req/day of 100k, ~600 rows/day of 100k,
1 cron trigger of 3. Expected cost **$0/month**.

Constraints to design around:
1. **10 ms CPU per cron run on free.** Waiting on `fetch` is *not* billed, but JSON parsing,
   HMAC/AES and D1 round-trips are. WebCrypto is native, so the iLetComfort AES + double
   HMAC and the CAME PKCE are cheap. Keep decoding tight and batch the D1 insert into one
   statement. If we ever exceed 10 ms, $5/mo Paid lifts it to 30 s.
2. **No cron retries and no failure alerts.** Add a `runs` table and treat a missing 15-min
   slot as an incident (the desktop app can show gaps). Consider Cloudflare Queues for
   retry/DLQ if gaps become a problem.
3. **D1 free limits are hard-enforced since 2026-09-01** — exceeding them makes queries fail
   until midnight UTC, not just bill you.
4. Secrets via `wrangler secret put` (encrypted at rest); nothing in the repo or in the
   Worker's plain-text vars.
5. Cron changes take up to 15 min to propagate.

Alternatives considered and rejected:
- **$5-15/mo VPS** — more CPU headroom, but we would own patch/uptime/backups; not cheaper
  than free for this workload.
- **GitHub Actions scheduled workflow** — free but scheduling is unreliable and min 5 min;
  fine as a break-glass backfill, not as the primary 15-min poller.
- **Cloudflare Workflows / Durable Object alarms** — more machinery than a fixed 15-min fetch
  needs; revisit only if we later want MQTT push instead of polling.
- **MQTT instead of polling** — Cloudflare Workers *can* do TLS sockets (`cloudflare:sockets`),
  and the iLetComfort MQTT cert is session-independent (no login war). More work; only worth it
  if the single-session problem cannot be solved with a second account.

### Rust on Workers (workers-rs) — confirmed viable
- Cloudflare officially supports Rust via the `workers-rs` crate: `fetch`, KV, R2, Queues,
  Durable Objects, routing, and **D1 via the `d1` feature**.
- Cron = `#[event(scheduled)]` + `triggers.crons` in `wrangler.toml`.
- **Bundle size is no longer a constraint**: the old 3 MiB (free) / 10 MiB (paid) *compressed*
  caps were removed in Sept 2026 — it is now **64 MiB uncompressed on all plans**. Still run
  `wasm-opt` and keep the binary under ~1 MiB gzipped for clean cold starts.
- Cold starts are sub-5 ms; WASM is ~2-5% slower than native, irrelevant for this workload.
- **Chart webpage**: Workers Static Assets (`assets.directory` + `assets.binding`) are
  **unmetered even on Free**. Use `run_worker_first: ["/api/*"]` so only API routes invoke the
  Worker; the page is static HTML + a small chart library fed by our Rust JSON API.
- Remaining risk: the **10 ms CPU cap** per cron run on Free. Rust/WASM crypto is fast, but if a
  live run exceeds it, $5/mo Paid raises it to 30 s.

### Open decision: the iLetComfort "login war"
Polling every 15 min re-logs in 96x/day, each time evicting the phone app session. Two fixes:
1. **Second account + device sharing** (simplest, recommended) — the poller gets its own session.
2. **MQTT + cached client certificate** — session-independent, but needs longer-lived TLS on the
   Worker and the v2.1 `privateKey` call, whose signing key is *not* cracked (cert must be
   captured once out-of-band and stored as a secret).

## Suggested Rust architecture (later)

```
Collector — Cloudflare Worker (TypeScript). Only the cloud sees credentials.
worker/
  src/index.ts        # scheduled(): fan out to both providers, batch-insert into D1
  src/iletcomfort.ts  # v1 HMAC login + AES password + v2.0 business signing + C3/ATW decode
  src/cameconnect.ts  # OAuth PKCE + /v2/devices/{keycode} + /api/v1/statistics
  src/api.ts          # fetch(): /readings?from&to&device -> JSON
  schema.sql          # devices, readings, runs
  wrangler.toml

Desktop app — Rust + iced (read-only, holds no vendor credentials)
src/
  main.rs             # iced entry point
  api.rs              # reqwest client for the Worker API
  model.rs            # Reading { ts, device, metric, value, unit }
  cache.rs            # local sqlite mirror so charts work offline
  ui/                 # date-range picker, device picker, line charts
```
- Desktop crates: `iced`, `reqwest`, `serde`, `rusqlite`, `chrono`, `tokio`,
  charts via `iced_plot` (or `plotters-iced` for more control).
- The desktop app authenticates to *our* Worker with a bearer token; it never talks to
  dollin.net or cameconnect.net directly.

### Sources
- https://github.com/tgenov/iletcomfort-cli
- https://github.com/tgenov/ha-iletcomfort
- https://github.com/sdeagh/came_connect
- https://github.com/jasonmadigan/came-connect
- https://community.home-assistant.io/t/came-bpt-thermostat-integration/329301
- CAME TH/700 manual (confirms CAMEConnect Cloud usage)
