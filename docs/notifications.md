# Notifications, API and metrics

egress-autopilot has no built-in Telegram, e-mail or Home Assistant code — on
purpose. It produces **one JSON event** for everything worth knowing and gives
you generic ways to take it. Pick what fits your stack:

| Way | Direction | Good for |
|---|---|---|
| `notify.webhook` | push, HTTP POST | anything with an HTTP endpoint: automation tools, notification gateways, your own bot |
| `notify.exec` | push, command + stdin | a small shell/python script mounted into the container |
| `notify.file` | pull, `/data/events.jsonl` | log shippers, cron scripts, `tail -F` |
| `GET /events` | pull, HTTP | polling from a bot or dashboard |
| `GET /state`, `/series` | pull, HTTP | dashboards, status pages |
| `GET /metrics` | pull, Prometheus | Grafana, Alertmanager |
| `POST /action` | control | buttons: find a better node, speed test, pin, pause |

## Event

```json
{
  "id": "4f0c3b7e1d2a4c19a8f6e0b1c2d3e4f5",
  "time": "2026-10-26T14:03:11+0000",
  "kind": "switch",
  "key": "switch",
  "severity": "critical",
  "title": "Fell back main → backup",
  "message": "🇩🇪 Frankfurt 2 · 87 ms · 143.2 Mbit/s · DE · active node does not answer",
  "actions": ["find_best", "speedtest"],
  "data": {
    "from_sub": "main", "from_node": "🇳🇱 Amsterdam 1",
    "sub": "backup", "node": "🇩🇪 Frankfurt 2",
    "reason": "active node does not answer",
    "latency_ms": 87, "mbps": 143.2, "country": "DE", "verified": true
  }
}
```

| Field | Meaning |
|---|---|
| `id` | unique per event — use it to de-duplicate retries |
| `time` | local time of the container (`TZ`), ISO 8601 |
| `kind` | `alert`, `resolved`, `switch`, `quarantine`, `action`, `survey` |
| `key` | stable identifier of the condition; an `alert` and its `resolved` share it (`dead`, `fetch-main`, …) — use it to replace/close a previous notification |
| `severity` | `critical` or `info` |
| `title`, `message` | human-readable English text; ignore them and build your own from `data` if you prefer another language |
| `actions` | suggested `POST /action` values to offer as buttons (may be empty) |
| `data` | structured details; for `switch` as above, for `resolved` — `duration_s`, for `quarantine` and `speedtest` — `sub`, `node`, `mbps` |

The list of conditions is in [how-it-works.md](how-it-works.md#alerts).

## Sinks

All sinks respect `notify.min_severity`; webhook and exec also have their own
`min_severity`. Delivery runs in a background thread and never delays
switching.

### Webhook

```toml
[[notify.webhook]]
url = "http://192.168.1.10:8080/hooks/egress"
headers = { Authorization = "Bearer ${HOOK_TOKEN}" }
min_severity = "info"
timeout_s = 10
```

`POST` with `Content-Type: application/json` and the event as the body. Any
2xx is success; otherwise three attempts with 5 s / 10 s / 15 s pauses, then
the failure is logged (with the host only — URLs often contain tokens).
Several `[[notify.webhook]]` blocks may coexist, e.g. everything to one
receiver and critical-only to another.

The receiver just has to accept a JSON POST. If yours needs another body
shape, put a tiny translator in between or use `exec`.

### Exec

```toml
[[notify.exec]]
command = ["/config/hooks/notify.sh"]
min_severity = "critical"
timeout_s = 30
```

The command gets the event JSON on stdin. A non-zero exit or a timeout is
logged. The image ships `sh`, `curl` and `python3`; `./config` is mounted at
`/config`, so a script there is available without changing the compose file
(make it executable). Skeleton:

```sh
#!/bin/sh
event=$(cat)                       # the JSON event
# extract what you need and forward it anywhere
echo "$event" >> /data/my-hook.log
```

### File

`/data/events.jsonl`, one event per line, appended under an exclusive `flock`.
At `file_max_mb` it is renamed to `events.jsonl.1` (one generation kept). A
consumer may truncate the file after reading it.

## HTTP API

Listens on `:8765` in the container; the compose file publishes it on
`127.0.0.1` only. Every path except `/health` needs

```
Authorization: Bearer <token>
```

The token comes from `api.token`, else `$API_TOKEN`, else it is generated once
into `/data/api-token`:

```sh
TOKEN=$(sudo cat data/api-token)
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/state
```

| Request | Returns |
|---|---|
| `GET /health` | `{"ok": true}`, no auth |
| `GET /state` | current snapshot (below) |
| `GET /series` | time series for charts: `uptime_vpn`, `uptime_direct` (hourly, 7 d), `latency`, `probe_fails` (10 min, 24 h), `vpn_speed`, `home_speed` (7 d), `ping` (per target, 24 h), `ping_loss`, `switches` (7 d), `heatmap` (latency by weekday × hour, 4 weeks), `traffic_daily` (bytes, 30 d). Points are `[unix_ms, value]` |
| `GET /events?limit=50` | latest manager events from the database (`time`, `kind`, `sub`, `text`); up to 1000 |
| `GET /metrics` | Prometheus text format; no token if `api.metrics_public = true` |
| `POST /action` | queue a command, `202 {"queued": "<action>"}` |

`/state` (abridged):

```json
{
  "mode": "ok",
  "active": {"sub": "main", "name": "🇳🇱 Amsterdam 1", "proto": "vless", "since": "2026-10-26T09:12:40+0000",
             "country": "NL", "city": "Amsterdam", "latitude": 52.37, "longitude": 4.89,
             "flag_emoji": "🇳🇱", "backups": ["🇳🇱 Amsterdam 2", "🇩🇪 Frankfurt 1"]},
  "latency_ms": 64, "probe_ok": true, "vpn_mbps": 212.4, "home_mbps": 480.1,
  "pings": {"1.1.1.1": {"ms": 4.1, "loss_pct": 0.0, "at": "…"}},
  "uptime": {"vpn_24h": 100.0, "vpn_7d": 99.71, "vpn_30d": 99.52, "direct_24h": 100.0, "direct_7d": 99.98, "direct_30d": 99.9},
  "traffic_today_bytes": 734003200, "traffic_month_bytes": 41875931136,
  "subs": [{"prio": 1, "name": "main", "status": "active", "nodes": 50, "checked": 49, "alive": 41,
            "fetched": "…", "expire": "…", "used_pct": 37, "flags": []}],
  "events": [{"time": "…", "kind": "switch", "sub": "main", "text": "…"}],
  "alerts": {"fetch-backup": {"title": "Subscription backup cannot be fetched", "since": "…"}},
  "pin": null, "paused": false, "survey_running": false, "next_scheduled": "…", "updated": "…"
}
```

`mode` is `ok`, `degraded`, `dead` or `unknown` (before the first cycle).
`subs[].status`: `active`, `green` (> 80 % of checked nodes good), `yellow`
(> 30 %), `red` (at least one), `none`, `unknown` (not checked within 7 h).

### Actions

| `action` | Does |
|---|---|
| `find_best` | full top-down search now; switches if it finds a node other than the current |
| `speedtest` | speed test of the active node; result as an `action` event |
| `survey` | probe every node of every subscription in the background (minutes to an hour); summary as a `survey` event and in `/state.survey` |
| `pin` + `"sub"` | prefer that subscription for `pin_hours`; switches to it now if it works |
| `unpin` | drop the pin |
| `pause` | no automatic switching for `pause_hours` (failures still raise alerts) |
| `resume` | end the pause |

```sh
curl -s -X POST -H "Authorization: Bearer $TOKEN" -d '{"action":"pin","sub":"backup"}' http://127.0.0.1:8765/action
```

Commands run in the manager's main loop between checks, so a command may wait
up to a few minutes behind a running search.

## Prometheus metrics

All gauges, prefix `egress_`:

| Metric | Labels |
|---|---|
| `mode` | `mode` = ok / degraded / dead (1 for the current) |
| `active_info` | `sub`, `node`, `proto`, `country` |
| `probe_ok`, `latency_ms`, `vpn_speed_mbps`, `home_speed_mbps` | — |
| `ping_ms`, `ping_loss_pct` | `target` |
| `uptime_pct` | `scope` = vpn / direct, `window` = 24h / 7d / 30d |
| `traffic_today_bytes`, `traffic_month_bytes` | — |
| `sub_nodes`, `sub_alive`, `sub_last_fetch_timestamp`, `sub_expire_timestamp`, `sub_used_pct` | `sub`, `prio` |
| `alert` | `key`, `title` (1 per active alert) |
| `paused`, `switches_24h` | — |

```yaml
# prometheus.yml
scrape_configs:
  - job_name: egress
    scrape_interval: 60s
    authorization:
      credentials_file: /etc/prometheus/egress-token
    static_configs:
      - targets: ["egress-manager:8765"]
```

Values come from the same database as `/state`, so scraping more often than
the quick cycle (2–4 min) adds nothing.
