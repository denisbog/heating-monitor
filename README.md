# heating-monitor

A Cloudflare Worker that polls an **iLetComfort** (ITS/BTRI) heat pump and **CAME THermo
Wi-Fi** thermostats every 15 minutes, stores the readings in D1, and serves a JSON API
plus an installable chart PWA.

```
Cron */15 ──► Worker (Rust / workers-rs)
                ├─ iLetComfort  →  Dollin cloud + iBUILDING energy statistics
                ├─ CAME Connect →  OAuth2 + PKCE
                └─ D1 (SQLite)
Worker /api/* ──► JSON ──► PWA charts, or any other client
```

## Layout

| path | what |
|---|---|
| `worker/` | the Worker: Rust source, D1 schema, chart PWA, deploy scripts |
| `docs/api-research.md` | protocol reference for both clouds, incl. endpoint inventories |
| `tools/` | Python probes used during the reverse engineering |

## What it collects

**iLetComfort heat pump** — C3 hex frames (mode, setpoints, DHW tank temperature) plus the
iBUILDING energy API: hourly electricity and COP split by usage type, produced heat,
T4 outdoor ambient temperature, and cost/savings.

**CAME THermo Wi-Fi thermostats** — room temperature, humidity, setpoint, relay state,
boost/holiday countdowns, plus day/week/month/year history for outdoor and internal
temperature.

## Quick start

Full walkthrough in [`worker/README.md`](worker/README.md). In short:

```bash
cd worker
./make-dev-vars.sh                          # build .dev.vars from your credentials
./set-secrets.sh                            # push them as encrypted Worker secrets
wrangler d1 create monitoring
wrangler d1 execute monitoring --file=schema.sql --remote
wrangler deploy
```

Then open the Worker URL and paste the read token. It is installable as a PWA.

### Two access levels

| token | secret | can |
|---|---|---|
| `API_TOKEN` | long random | read **and** `POST /api/collect` |
| `READ_TOKEN` | short and shareable | read only |

## Notes and caveats

- **Both clouds allow one session per account.** Logging in evicts the vendor app, so use
  a second account with the device shared to it. Token caching cuts logins to one per
  token lifetime but does not remove the conflict.
- **CAME keeps no usable room-temperature history** — the 15-minute poll *is* the data
  source, and daily aggregates are computed in SQLite.
- **iLetComfort serves hourly detail only for the current day**, so it cannot be
  backfilled. The poll has to run during the day.
- **CAME's `intervaltype=month` means "the calendar month containing `from`"**, not a
  rolling 30 days — ask for the current month *and* the previous one.

## Provenance

The API details here were obtained by studying the vendor applications for
interoperability with hardware we own. This project is not affiliated with, endorsed by,
or supported by ITS, BTRI, Midea or CAME. Private APIs change without notice.

## License

No license has been chosen yet, so all rights are reserved by default. Open an issue if
you want to use this and we'll sort something out.
