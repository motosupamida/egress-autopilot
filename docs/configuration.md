# Configuration

One file: `./config/config.toml` (mounted read-only at `/config`). Start from
[`examples/config.toml`](../examples/config.toml) — it lists every key with its
default. Only `[[subscription]]` is required.

- Subscriptions are re-read on every scheduled cycle (6 h): adding or removing
  one needs no restart. Everything else is read at start —
  `docker compose restart manager`.
- Any string can reference an environment variable as `${NAME}`; an unset
  variable becomes an empty string (and an empty subscription URL is an error).
  Keep tokens in `.env` and pass them through `environment:` in compose.
- Validate without starting: `docker compose run --rm manager check`.
- See what your subscriptions contain: `docker compose exec manager python3 /app/manager.py subs`.

## Reference

### `[[subscription]]`

| Key | Default | |
|---|---|---|
| `name` | — | 1–40 chars `A-Z a-z 0-9 _ . -`; shown in logs, API, metrics, events |
| `url` | — | http(s); usually `${VAR}` |
| `priority` | position | 1 = most preferred |
| `flags` | `[]` | `noexpiry` — ignore expiry/traffic headers; `free` — critical alert while on it |

Renaming a subscription starts its history from scratch (history is keyed by name).

### `[selection]`

| Key | Default | |
|---|---|---|
| `max_latency_ms` | `800` | warm latency limit of a good node |
| `min_speed_mbps` | `10` | below → quarantine |
| `blocked_countries` | `[]` | ISO codes of exits never accepted; nodes with that flag emoji in the name are not even probed |
| `quarantine_hours` | `24` | |
| `big_subscription` | `100` | node count above which a subscription is "big" |
| `big_good_enough` | `10` | big: stop searching after this many good nodes |
| `dead_days` | `30` | big: sleep time of a node that failed twice… |
| `dead_gap_hours` | `6` | …at least this far apart |
| `light_sample` | `10` | nodes of the last subscription probed per scheduled cycle |
| `probe_targets` | Cloudflare, Google, ipinfo | table `name = "url"`; replaces the default set as a whole. Exit country is read from a Cloudflare `trace` body (`loc=`) or JSON `"country"` |

### `[schedule]`

| Key | Default | |
|---|---|---|
| `fast_interval_s` | `[120, 240]` | random pause between quick checks |
| `scheduled_every_h` | `6` | refresh, return-up attempt, light check |
| `vpn_speed_every_h` | `6` | active node speed test |
| `return_min_gap_min` | `60` | |
| `return_confirm` | `3` | good checks needed before going back up |
| `return_confirm_pause_s` | `100` | |
| `retry_bad_min` | `15` | search period while degraded/dead |
| `pin_hours`, `pause_hours` | `24`, `24` | lifetime of `pin` / `pause` actions |

### `[speedtest]` — through the VPN

| Key | Default | |
|---|---|---|
| `duration_s` | `20` | |
| `max_bytes` | `25000000` | byte range for targets with `range = true` |
| `min_bytes` | `2097152` | less → the target is considered broken, next one |
| `targets` | Cloudflare, OVH, Hetzner | array of `{name, url, range}`; replaces the default list |

### `[home]` — direct internet

| Key | Default | |
|---|---|---|
| `enabled` | `true` | pings and speed tests; the `direct_check` gate stays regardless |
| `ping_targets` | `1.1.1.1`, `8.8.8.8`, `9.9.9.9` | graphed; add your router |
| `direct_check` | same | uplink is up if any answers ping |
| `direct_http` | gstatic 204 | fallback check when ICMP is filtered |
| `speed_every_h` | `[2.5, 3.5]` | random interval |
| `speed_streams` | `4` | parallel downloads of the same URL |
| `speed_duration_s` | `10` | |
| `speed_min_bytes` | `20971520` | |
| `speed_targets` | Cloudflare, OVH | array of `{name, url}` |

### `[alerts]`

| Key | Default |
|---|---|
| `expire_warn_days` | `3` |
| `traffic_warn_pct` | `90` |
| `fetch_alert_h` | `24` |
| `internet_alert_min` | `10` |

### `[notify]`

| Key | Default | |
|---|---|---|
| `min_severity` | `"info"` | global filter: `info` or `critical` |
| `file` | `true` | `/data/events.jsonl` |
| `file_max_mb` | `5` | |
| `webhook` | `[]` | `[[notify.webhook]]`: `url`, `headers`, `min_severity`, `timeout_s` |
| `exec` | `[]` | `[[notify.exec]]`: `command` (array), `min_severity`, `timeout_s` |

Details and the event schema: [notifications.md](notifications.md).

### `[api]`

| Key | Default | |
|---|---|---|
| `port` | `8765` | inside the container |
| `token` | `""` | empty → `$API_TOKEN` → generated `/data/api-token` |
| `metrics_public` | `false` | serve `/metrics` without a token |

### `[storage]`

| Key | Default |
|---|---|
| `retention_days` | `365` |
| `max_db_mb` | `800` |
| `node_forget_days` | `30` |

### Environment (compose)

| Variable | Default | |
|---|---|---|
| `TZ` | `UTC` | timestamps in logs, events and daily traffic buckets |
| `CONFIG` | `/config/config.toml` | |
| `XRAY_API` | `10.79.0.2:10085` | change together with the `control` subnet |
| `PROD_PROXY` | `http://10.79.0.2:1080` | |
| `API_TOKEN` | — | used when `api.token` is empty |

## Recipes

### One paid subscription

```toml
[[subscription]]
name = "vpn"
url = "${SUB_URL}"
```

Failover then means "another node of the same provider"; you still get alerts,
speed tests and uptime.

### Paid main, second provider as backup, public list as last resort

```toml
[[subscription]]
name = "main"
url = "${SUB_MAIN}"
priority = 1

[[subscription]]
name = "reserve"
url = "${SUB_RESERVE}"
priority = 2

[[subscription]]
name = "public"
url = "https://raw.githubusercontent.com/<owner>/<repo>/main/list.txt"
priority = 3
flags = ["noexpiry", "free"]
```

The manager falls back down the list and climbs back up on its own (after 3
confirmations, at most hourly). On `public` a critical alert stays up: unknown
operators see your traffic.

### Exit must never be in your own country

Typical when providers mix domestic relays into the list or the network
filters foreign probes.

```toml
[selection]
blocked_countries = ["RU"]

[home]
# domestic hosts: "uplink is up" must not depend on foreign reachability
direct_check = ["77.88.8.8", "ya.ru", "vk.com"]
ping_targets = ["192.168.1.1", "77.88.8.8", "1.1.1.1"]
direct_http = "https://ya.ru/"

[[home.speed_targets]]
name = "selectel"
url = "https://speedtest.selectel.ru/1GB"
```

### Slow uplink or metered connection

```toml
[selection]
min_speed_mbps = 3

[schedule]
vpn_speed_every_h = 24

[speedtest]
max_bytes = 5000000
min_bytes = 524288

[home]
enabled = false
```

### Quiet: only what needs action

```toml
[notify]
min_severity = "critical"
```

### Everything to one receiver, critical also to a second one

```toml
[[notify.webhook]]
url = "http://automation.lan:5678/webhook/egress"

[[notify.webhook]]
url = "${PAGER_WEBHOOK_URL}"
min_severity = "critical"
```

### Prometheus on the same Docker host

```toml
[api]
metrics_public = true
```

Attach Prometheus to the manager's network (or publish the port) and scrape
`egress-manager:8765/metrics`. Keep `metrics_public = false` if anything
untrusted shares that network — `/metrics` reveals node names.

### Use the proxy from other stacks

The compose file creates the Docker network `egress`. In another stack:

```yaml
services:
  app:
    environment:
      - HTTP_PROXY=http://egress-xray:1080
      - HTTPS_PROXY=http://egress-xray:1080
      - NO_PROXY=localhost,127.0.0.1,.lan
    networks: [default, egress]

networks:
  egress:
    external: true
```

SOCKS5 (with UDP) is `egress-xray:1081`. The proxy has no authentication:
never publish 1080/1081 beyond hosts you trust.
