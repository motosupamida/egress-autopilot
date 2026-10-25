# egress-autopilot

**Self-healing outbound VPN for your homelab.** One xray proxy for all your
containers, and a manager that keeps it on a working node: it watches the
active node every few minutes, fails over in seconds, prefers your best
subscription and climbs back to it when it recovers — and reports everything
as JSON you can send anywhere.

[Русская версия](README.ru.md)

```
 your apps ──HTTP :1080 / SOCKS :1081──▶ egress-xray ──▶ best node ──▶ internet
                                             ▲
                                       egress-manager ── webhook / exec / file / API / Prometheus
```

## Why

You have a VPN subscription (or three) with dozens of vless/vmess/trojan/ss/hysteria2
nodes, and a server full of things that need a reliable way out: automations,
bots, downloaders, AI clients. Nodes die, slow down, get blocked, providers
rotate parameters, subscriptions expire. Picking a node by hand in a desktop
client does not scale to a headless box.

## Features

- **Subscriptions with priorities** — base64/plain link lists and JSON xray
  configs (including `dialerProxy` chains); `vless`, `vmess`, `trojan`, `ss`,
  `hysteria2`; REALITY, TLS, ws, grpc, httpupgrade, xhttp.
- **Real checks** — latency over a warm connection, exit country, time-bound
  speed test; thresholds are yours.
- **Fast failover** — a quick check every 2–4 min, an instant hop to a
  pre-checked backup, then a top-down search over subscriptions.
- **Comes back** — returns to a higher-priority subscription after repeated
  confirmations, not on the first lucky probe.
- **Doesn't panic** — no switching while your own uplink is down; a working
  node that vanished from the subscription stays in use; a degraded mode
  instead of "no internet at all".
- **Handles messy providers** — stable node identity even when SNI/shortId
  rotate on every fetch; huge public lists probed in parallel with early stop;
  "dead for a month" tracking for nodes that never answer.
- **Zero-downtime switching** through the xray API — no restarts, existing
  clients keep their proxy address.
- **Direct internet monitoring** (optional) — ping, multi-stream speed test,
  uptime.
- **Bring your own notifications** — webhook, exec hook, JSONL file, REST API,
  Prometheus metrics. No vendor lock-in, no built-in Telegram/e-mail code to
  maintain: [notifications.md](docs/notifications.md).
- **Small** — Python stdlib + xray + curl in an Alpine image; SQLite history
  with retention; `amd64`, `arm64`, `armv7`.

## Quick start

Requirements: Docker with Compose v2.

```sh
git clone https://github.com/motosupamida/egress-autopilot.git
cd egress-autopilot
mkdir -p config
cp examples/config.toml config/config.toml
$EDITOR config/config.toml          # your subscriptions; secrets via ${VARS}
echo 'SUB_MAIN_URL=https://provider.example/sub/your-token' > .env
chmod 600 .env config/config.toml
```

Pass the variable through to the manager — uncomment it in `compose.yaml`:

```yaml
    environment:
      - SUB_MAIN_URL=${SUB_MAIN_URL}
```

Start:

```sh
docker compose run --rm manager check   # validate the config
docker compose up -d --build
docker compose logs -f manager
```

The first cycle fetches subscriptions, probes nodes and selects one (a minute
or two; traffic through the proxy is dropped until then). Then:

```sh
docker compose exec manager python3 /app/manager.py status
curl -s -H "Authorization: Bearer $(sudo cat data/api-token)" http://127.0.0.1:8765/state
```

Point your apps at the proxy (`HTTP_PROXY=http://egress-xray:1080` on the
`egress` Docker network, or SOCKS5 `egress-xray:1081`) —
[example](docs/configuration.md#use-the-proxy-from-other-stacks).

## Documentation

| | |
|---|---|
| [Configuration](docs/configuration.md) | every key, defaults, ready-made recipes |
| [Notifications, API, metrics](docs/notifications.md) | event schema, webhook/exec/file, REST API, actions, Prometheus |
| [How it works](docs/how-it-works.md) | exact selection, failover and alert rules |

## Files

| Path | |
|---|---|
| `config/config.toml` | your configuration (secret: contains subscription URLs or `${VARS}`) |
| `data/metrics.db` | SQLite history: probes, speeds, pings, events, traffic |
| `data/state.json` | current state (active node, alerts, timers) |
| `data/events.jsonl` | emitted events |
| `data/subs/` | last good copy of each subscription (secret) |
| `data/api-token` | generated API token (secret) |
| `xray/config.json` | production xray config, written only by the manager |

Back up `config/` and `data/`; `xray/` is regenerated.

## Commands

```sh
docker compose exec manager python3 /app/manager.py status   # short state
docker compose exec manager python3 /app/manager.py subs     # fetch subscriptions, show node counts
docker compose exec manager python3 /app/survey.py           # probe every node now, no switching
```

Or through the API: `POST /action` with `find_best`, `speedtest`, `survey`,
`pin`, `unpin`, `pause`, `resume` ([details](docs/notifications.md#actions)).

## Security notes

- The proxy (1080/1081) has **no authentication**. It is only on the `egress`
  Docker network; do not publish it to your LAN unless you mean to.
- The API is published on `127.0.0.1` only and requires a bearer token; it has
  no TLS of its own.
- The xray API is reachable only on an internal network between the two
  containers.
- The manager runs with all capabilities dropped except `NET_RAW` (for ping)
  and `no-new-privileges`.
- `config/`, `.env` and `data/` contain secrets — keep them `0600`, out of git
  (already in `.gitignore`).

## FAQ

**Does it route the whole host or LAN?** No. It is an explicit HTTP/SOCKS
proxy for things you point at it. Transparent routing (tun, tproxy) is out of
scope.

**Can I use my own xray settings (routing rules, DNS, sniffing)?** Not yet:
the manager owns the production config. Issues and PRs welcome.

**Which protocols are not supported?** ss with plugins, hysteria2 with obfs,
tuic, wireguard links. They are counted in `subs` output and skipped.

**Where do the defaults come from?** Months of running this against several
commercial providers and public lists on a home server. They are deliberately
conservative: no flapping, no false alarms.

## License

[MIT](LICENSE). The image contains the [Xray-core](https://github.com/XTLS/Xray-core)
binary, licensed under MPL-2.0.

Use it only where using a VPN is legal for you.
