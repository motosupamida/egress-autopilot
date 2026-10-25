# How it works

The exact rules the manager follows. Numbers in **bold** are defaults; every one
of them is a key in [configuration](configuration.md).

## Containers

```
 your apps ──HTTP :1080 / SOCKS :1081──▶  egress-xray  ──▶  selected node  ──▶  internet
                                              ▲
                          xray API (control net, internal)
                                              │
                                        egress-manager  ── direct internet: subscriptions, probes, home checks
                                              │
                         HTTP API :8765 · events (file / webhook / exec) · /metrics
```

- **egress-xray** is stock xray. It only routes: inbounds `http` (1080) and
  `socks` (1081) go through the balancer `egress` to outbound `a-<id>` (the
  active node); two backups `a-<id>` stay loaded too.
- **egress-manager** owns `xray/config.json`. A switch is done live through the
  xray API (`ado` → `bo -b egress` → `rmo`), and the file is rewritten
  atomically, so an xray restart keeps the selection. The xray directory is
  mounted, not the file: an atomic replace creates a new inode that a
  single-file bind mount would not see.
- Candidates are probed by a throwaway xray *inside* the manager container, one
  local port per node, so probing never touches production traffic.
- On the very first start there is no config: the manager writes a placeholder
  (traffic is dropped), and the first cycle selects a node.

## Subscriptions

Listed in `config.toml` with a priority, **1** being the most preferred.
Formats: base64 or plain lists of `vless://`, `vmess://`, `trojan://`, `ss://`,
`hysteria2://` links, or JSON xray configs (`remarks` + `outbounds`, including
`dialerProxy` chains). Unsupported entries (e.g. ss plugins, tuic) are counted
and skipped.

Fetch order: direct → through production xray → through a recently healthy node
of another subscription. If everything fails, the cached copy is used.

Flags:

| Flag | Effect |
|---|---|
| `noexpiry` | ignore the `subscription-userinfo` header (no expiry/traffic alerts) |
| `free` | a critical alert stays raised while the active node is from this subscription |

## Node identity

Many providers rotate SNI/shortId on every fetch, so a hash of all parameters
would "create" new nodes every time. Therefore:

- a node whose name is **unique** in its subscription gets an id from
  name + protocol + address + port;
- repeated names (typical for public lists) fall back to a hash of all
  parameters.

Quarantine, the 30-day "dead" mark and the whole history are bound to that id.

## Checks

- **Probe**: three HTTP requests over one connection through the node to one of
  the probe targets (Cloudflare trace, Google 204, ipinfo), random order, next
  target on failure. A target failing 5 times in a row while others work is
  disabled for an hour. Latency is the median of the two warm requests; the
  exit country comes from Cloudflare `loc=` or ipinfo.
- **Good node**: answered, warm latency ≤ **800 ms**, exit country not in
  `blocked_countries`. Nodes whose name carries a blocked country's flag emoji
  are not probed at all.
- **Speed test**: one stream, time-bound (**20 s**), targets in order with two
  attempts each. Below **10 Mbit/s** → quarantine for **24 h**. Run for search
  finalists and for the active node every **6 h**.
- **Dead for a month**: only in subscriptions with more than **100** nodes — a
  node that failed in two cycles at least **6 h** apart is skipped for **30**
  days.

## Cycles

1. **Quick** — every **120–240 s** (random): direct internet check, then a probe
   of the active node through production xray. One failure → failover.
2. **Failover** — first, direct internet must be up (any of `direct_check`
   answers, or `direct_http` responds): with a dead uplink nothing is switched.
   Then an instant hop to a good backup, then a top-down search: the first
   subscription with a node passing probe *and* speed test wins; inside it, the
   lowest latency. Big subscriptions are probed 20 at a time, best history
   first, stopping at **10** good nodes.
3. **Scheduled** — every **6 h**: refresh subscriptions; search the
   higher-priority subscriptions and go back up after **3** good checks
   **100 s** apart, no more than once per **60 min**; refresh backups; probe
   (no speed test) every node of every subscription except the last, which
   gets a sample of **10**.
4. **Degraded** — nobody passed every check: take the lowest-latency node that
   passes traffic at all (still respecting `blocked_countries`), raise a
   critical alert. Nobody passes traffic: stay where we are, alert, retry the
   search every **15 min**. There is never a direct exit without VPN.
5. A working active node that disappeared from its subscription is not a
   failure: the manager keeps using it from the live xray config.
6. **Pin** a subscription and **pause** auto-switching (API only) expire by
   themselves after **24 h**. If a pinned subscription dies, normal failover runs.

## Direct internet

Every quick cycle pings `ping_targets` and `direct_check`. Every **2.5–3.5 h**
a direct speed test runs: **4** parallel streams for **10 s** (a single stream
rarely saturates a fast line). Disable with `home.enabled = false`; the
`direct_check` gate before switching stays.

## Alerts

`critical` — something needs you; `info` — FYI. Alerts are de-duplicated: an
`alert` event fires once when the condition appears, a `resolved` event when it
clears (with its duration).

| Key | Severity | When |
|---|---|---|
| `switch` (kind `switch`) | critical | fell back to a lower-priority subscription |
| `switch` (kind `switch`) | info | another node in the same subscription; back to a higher one |
| `free` | critical | running on a `free` subscription |
| `degraded` | critical | no node passes every check |
| `dead` | critical | no node passes traffic |
| `paused-fail` | critical | the active node failed while auto-switching is paused |
| `fetch-<sub>` | critical | subscription not fetched for **24 h** |
| `expire-<sub>` | critical | expires within **3** days or traffic > **90 %** |
| `q-<node>` (kind `quarantine`) | info | a node went to quarantine |
| `internet` | info | no direct internet for **10 min** |
| `speedtest`, `survey`, `find_best`, `pin` (kind `action`) | info | result of an API action |

Critical events about a failure carry `actions: ["find_best", "speedtest"]` —
ready-made buttons for whatever UI you build (each maps to `POST /action`).

## Uptime

- VPN — share of successful probes of the active node through production xray.
- Direct internet — share of minutes in which at least one `direct_check` host
  answered.

## Storage

SQLite in `/data/metrics.db`: records older than **365** days are deleted; above
**800 MB** the oldest are dropped. Nodes absent from every subscription for
**30** days are forgotten (their probe history stays).
