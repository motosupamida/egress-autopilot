"""HTTP API: build any dashboard, bot or automation on top of it.

Everything except /health needs `Authorization: Bearer <token>` (token from
config, $API_TOKEN or the generated /data/api-token). /metrics can be made
public with api.metrics_public.

  GET  /health          liveness, no auth
  GET  /state           mode, active node, metrics, subscriptions, recent events
  GET  /series          time series for charts (last 24 h / 7 d / 30 d)
  GET  /events?limit=N  recent manager events (switches, failovers, actions)
  GET  /metrics         Prometheus text format
  POST /action          {"action": find_best|speedtest|survey|pin|unpin|pause|resume, "sub": "<name>"}
"""
import hmac
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import manager as M

ACTIONS = {"find_best", "speedtest", "survey", "pin", "unpin", "pause", "resume"}
WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
CHECK_WINDOW = 7 * 3600  # a scheduled cycle probes every subscription each 6 h
MODES = ("ok", "degraded", "dead")


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts)) if ts else None


def day_start(ts, month=False):
    t = time.localtime(ts)
    return int(time.mktime((t.tm_year, t.tm_mon, 1 if month else t.tm_mday, 0, 0, 0, 0, 0, -1)))


def flag_emoji(cc):
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) if cc and len(cc) == 2 and cc.isalpha() else ""


def in_list(hosts):
    return "(" + ",".join("'" + h.replace("'", "''") + "'" for h in hosts) + ")"


# VPN: share of successful checks of the active node through production xray.
# Direct internet: share of minutes in which at least one home.direct_check host answered.
VPN_UP = "SELECT {bucket}, avg(ok) * 100 FROM probes WHERE via='prod' AND ts>=? GROUP BY 1 ORDER BY 1"
DIRECT_UP = ("SELECT {bucket}, avg(up) * 100 FROM (SELECT ts/60 AS minute, min(ts) AS ts, max(ok) AS up FROM pings "
             f"WHERE target IN {in_list(M.DIRECT_CHECK)} AND ts>=? GROUP BY minute) GROUP BY 1 ORDER BY 1")
WINDOWS = (("24h", 86400), ("7d", 7 * 86400), ("30d", 30 * 86400))


def uptime(db, now):
    out = {}
    for key, sql in (("vpn", VPN_UP), ("direct", DIRECT_UP)):
        for label, span in WINDOWS:
            row = db.x(sql.format(bucket="0"), (int(now - span),))
            out[f"{key}_{label}"] = round(row[0][1], 2) if row and row[0][1] is not None else None
    return out


def state(m):
    now = time.time()
    st, db = m.st, m.db
    a = st.get("active") or {}
    node = m.active_node()
    geo = a.get("geo") or {}
    probe = db.x("SELECT ts, ok, warm_ms, loc FROM probes WHERE via='prod' ORDER BY ts DESC LIMIT 1")
    vpn = db.x("SELECT ts, mbps FROM speeds WHERE scope='vpn' AND ok=1 ORDER BY ts DESC LIMIT 1")
    home = db.x("SELECT ts, mbps FROM speeds WHERE scope='home' AND ok=1 ORDER BY ts DESC LIMIT 1")
    pings = {}
    for target in M.PING_TARGETS:
        row = db.x("SELECT avg_ms, loss_pct, ts FROM pings WHERE target=? ORDER BY ts DESC LIMIT 1", (target,))
        if row:
            pings[target] = {"ms": row[0][0] and round(row[0][0], 1), "loss_pct": row[0][1], "at": iso(row[0][2])}
    traffic = lambda since: (db.x("SELECT sum(up+down) FROM traffic WHERE ts>=?", (since,))[0][0] or 0)
    pin, paused = st.get("pin"), st.get("paused")
    survey = st.get("survey") or {}
    return {
        "mode": st.get("mode") or "unknown",
        "active": {
            "sub": a.get("sub"), "name": a.get("name"), "proto": node.proto if node else None,
            "flag": node.flag if node else None, "since": iso(a.get("since")),
            "flag_emoji": flag_emoji(geo.get("country") or (node.flag if node else "")),
            "country": geo.get("country"), "city": geo.get("city"),
            "latitude": geo.get("lat"), "longitude": geo.get("lon"),
            "backups": [b.name for b in (m.find(i) for i in st.get("backups", [])) if b],
        },
        "latency_ms": probe[0][2] if probe and probe[0][1] else None,
        "probe_ok": bool(probe and probe[0][1]),
        "probe_at": iso(probe[0][0]) if probe else None,
        "vpn_mbps": vpn[0][1] if vpn else None, "vpn_mbps_at": iso(vpn[0][0]) if vpn else None,
        "home_mbps": home[0][1] if home else None, "home_mbps_at": iso(home[0][0]) if home else None,
        "pings": pings,
        "uptime": uptime(db, now),
        "traffic_today_bytes": traffic(day_start(now)), "traffic_month_bytes": traffic(day_start(now, True)),
        "subs": subs(m, now),
        "events": events(m, 15),
        "pin": pin["sub"] if pin and pin["until"] > now else None,
        "pin_until": iso(pin["until"]) if pin and pin["until"] > now else None,
        "paused": bool(paused and paused > now), "paused_until": iso(paused) if paused and paused > now else None,
        "survey_running": bool(survey.get("running")), "survey_at": iso(survey.get("at")),
        "survey": survey.get("lines", []),
        "alerts": {k: {"title": v["title"], "since": iso(v["since"])} for k, v in st.get("alerts", {}).items()},
        "next_scheduled": iso(st.get("next_long")),
        "updated": iso(now),
    }


def events(m, limit):
    return [{"time": iso(ts), "kind": k, "sub": s, "text": d} for ts, k, s, d in
            m.db.x("SELECT ts, kind, sub, detail FROM events WHERE kind != 'action' ORDER BY ts DESC LIMIT ?", (limit,))]


def subs(m, now):
    out, active = [], (m.st.get("active") or {}).get("sub")
    for s in M.read_subs():
        name = s["name"]
        row = m.db.x("SELECT last_ok, nodes, upload, download, total, expire FROM subs WHERE name=?", (name,))
        last_ok, nodes, up, down, total, expire = row[0] if row else (None,) * 6
        # only the subscription's current nodes and only their latest check within CHECK_WINDOW
        current = {n.id for n in m.nodes.get(name, [])}
        known_loc = {r[0]: r[1] for r in m.db.x("SELECT id, loc FROM nodes WHERE sub=?", (name,))}
        latest = {}
        for nid, ok, warm, loc, ts in m.db.x("SELECT node, ok, warm_ms, loc, ts FROM probes WHERE sub=? AND ts>? ORDER BY ts",
                                             (name, int(now - CHECK_WINDOW))):
            if nid in current:
                latest[nid] = (ok, warm, loc or known_loc.get(nid), ts)
        # alive = answered, latency within the threshold, exit not in a blocked country
        checked = len(latest)
        alive = sum(1 for ok, warm, loc, _ in latest.values()
                    if ok and warm is not None and warm <= M.LAT_MAX_MS and loc not in M.STOP_COUNTRIES)
        last_check = max((ts for *_, ts in latest.values()), default=None)
        share = alive / checked if checked else 0
        if name == active:
            status = "active"
        elif not checked:
            status = "unknown"
        elif not alive:
            status = "none"
        elif share > 0.8:
            status = "green"
        elif share > 0.3:
            status = "yellow"
        else:
            status = "red"
        tracked = "noexpiry" not in s["flags"]
        out.append({
            "prio": s["prio"], "name": name, "flags": sorted(s["flags"]), "status": status,
            "nodes": len(current), "checked": checked, "alive": alive, "checked_at": iso(last_check),
            "fetched": iso(last_ok), "fetched_ts": last_ok,
            "expire": iso(expire) if expire and tracked else None, "expire_ts": expire if tracked else None,
            "used_pct": round((up + down) * 100 / total) if total and up is not None and down is not None and tracked else None,
        })
    return out


def series(m):
    now, db = int(time.time()), m.db
    day, week = now - 86400, now - 7 * 86400
    lat = db.x("SELECT ts/600*600, avg(CASE WHEN ok=1 THEN warm_ms END), sum(1-ok) FROM probes "
               "WHERE via='prod' AND ts>=? GROUP BY 1 ORDER BY 1", (day,))
    ping = {t: [[ms * 1000, round(v, 1)] for ms, v in db.x(
        "SELECT ts/600*600, avg(avg_ms) FROM pings WHERE target=? AND ts>=? AND avg_ms IS NOT NULL GROUP BY 1 ORDER BY 1",
        (t, day))] for t in M.PING_TARGETS}
    loss = db.x("SELECT ts/600*600, avg(loss_pct) FROM pings WHERE ts>=? GROUP BY 1 ORDER BY 1", (day,))
    heat = {(int(w), int(h)): v for w, h, v in db.x(
        "SELECT strftime('%w', ts, 'unixepoch', 'localtime'), strftime('%H', ts, 'unixepoch', 'localtime'), avg(warm_ms) "
        "FROM probes WHERE via='prod' AND ok=1 AND ts>=? GROUP BY 1, 2", (now - 28 * 86400,))}
    ms = lambda t: t * 1000
    hour = "ts/3600*3600"
    return {
        # every series is [[unix_ms, value], ...]
        "uptime_vpn": [[ms(t), round(v, 1)] for t, v in db.x(VPN_UP.format(bucket=hour), (week,))],
        "uptime_direct": [[ms(t), round(v, 1)] for t, v in db.x(DIRECT_UP.format(bucket=hour), (week,))],
        "latency": [[ms(t), round(v)] for t, v, _ in lat if v is not None],
        "probe_fails": [[ms(t), f] for t, _, f in lat if f],
        "vpn_speed": [[ms(t), v] for t, v in db.x(
            "SELECT ts, mbps FROM speeds WHERE scope='vpn' AND ok=1 AND ts>=? ORDER BY ts", (week,))],
        "home_speed": [[ms(t), v] for t, v in db.x(
            "SELECT ts, mbps FROM speeds WHERE scope='home' AND ok=1 AND ts>=? ORDER BY ts", (week,))],
        "ping": ping,
        "ping_loss": [[ms(t), round(v, 1)] for t, v in loss if v],
        "switches": [[ms(t), d[:80]] for t, d in db.x(
            "SELECT ts, detail FROM events WHERE kind='switch' AND ts>=? ORDER BY ts", (week,))],
        # rows — weekdays Mon…Sun, values — average latency per hour over 4 weeks
        "heatmap": [{"name": WEEKDAYS[d], "data": [[f"{h:02d}", round(heat[((d + 1) % 7, h)]) if ((d + 1) % 7, h) in heat else None]
                                                   for h in range(24)]} for d in range(7)],
        "traffic_daily": [[ms(day_start(t)), v] for t, v in db.x(
            "SELECT min(ts), sum(up+down) FROM traffic WHERE ts>=? GROUP BY date(ts, 'unixepoch', 'localtime') ORDER BY 1",
            (now - 30 * 86400,))],
        "updated": iso(now),
    }


def esc(v):
    return str(v if v is not None else "").replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def metrics(m):
    s = state(m)
    lines = []

    def g(name, value, help_=None, **labels):
        if help_:
            lines.append(f"# HELP egress_{name} {help_}\n# TYPE egress_{name} gauge")
        if value is None:
            return
        lab = ",".join(f'{k}="{esc(v)}"' for k, v in labels.items())
        num = int(value) if float(value).is_integer() else round(float(value), 3)
        lines.append(f"egress_{name}{'{' + lab + '}' if lab else ''} {num}")

    g("mode", None, "1 for the current mode (ok, degraded, dead)")
    for mode in MODES:
        g("mode", int(s["mode"] == mode), mode=mode)
    a = s["active"]
    g("active_info", 1 if a["sub"] else None, "Active node", sub=a["sub"], node=a["name"], proto=a["proto"], country=a["country"])
    g("probe_ok", int(s["probe_ok"]), "Last check of the active node through production xray succeeded")
    g("latency_ms", s["latency_ms"], "Warm latency of the active node")
    g("vpn_speed_mbps", s["vpn_mbps"], "Last speed test of the active node")
    g("home_speed_mbps", s["home_mbps"], "Last direct internet speed test")
    g("ping_ms", None, "Direct ping RTT")
    for t, p in s["pings"].items():
        g("ping_ms", p["ms"], target=t)
    g("ping_loss_pct", None, "Direct ping loss")
    for t, p in s["pings"].items():
        g("ping_loss_pct", p["loss_pct"], target=t)
    g("uptime_pct", None, "Uptime over a window")
    for k, v in s["uptime"].items():
        scope, window = k.split("_")
        g("uptime_pct", v, scope=scope, window=window)
    g("traffic_today_bytes", s["traffic_today_bytes"], "Proxy traffic since local midnight")
    g("traffic_month_bytes", s["traffic_month_bytes"], "Proxy traffic since the 1st of the month")
    for name, help_ in (("sub_nodes", "Nodes in a subscription"), ("sub_alive", "Good nodes by the latest checks"),
                        ("sub_last_fetch_timestamp", "Last successful fetch"), ("sub_expire_timestamp", "Subscription expiry"),
                        ("sub_used_pct", "Subscription traffic used")):
        g(name, None, help_)
        key = {"sub_nodes": "nodes", "sub_alive": "alive", "sub_last_fetch_timestamp": "fetched_ts",
               "sub_expire_timestamp": "expire_ts", "sub_used_pct": "used_pct"}[name]
        for sub in s["subs"]:
            g(name, sub[key], sub=sub["name"], prio=sub["prio"])
    g("alert", None, "1 for each active alert")
    for key, al in s["alerts"].items():
        g("alert", 1, key=key, title=al["title"])
    g("paused", int(s["paused"]), "Auto-switching paused")
    g("switches_24h", m.db.x("SELECT count(*) FROM events WHERE kind='switch' AND ts>=?", (int(time.time() - 86400),))[0][0],
      "Node switches in the last 24 h")
    return "\n".join(lines) + "\n"


class Handler(BaseHTTPRequestHandler):
    mgr = None
    token = ""
    metrics_public = False

    def log_message(self, fmt, *args):
        pass  # dashboards poll often — keep the log clean

    def reply(self, code, body, ctype="application/json; charset=utf-8"):
        data = body.encode() if isinstance(body, str) else json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        got = self.headers.get("Authorization", "")
        if hmac.compare_digest(got.encode(), f"Bearer {self.token}".encode()):
            return True
        self.reply(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/health":
            return self.reply(200, {"ok": True})
        if not (u.path == "/metrics" and self.metrics_public) and not self.authorized():
            return
        try:
            if u.path == "/state":
                return self.reply(200, state(self.mgr))
            if u.path == "/series":
                return self.reply(200, series(self.mgr))
            if u.path == "/events":
                limit = int((urllib.parse.parse_qs(u.query).get("limit") or ["50"])[0])
                return self.reply(200, events(self.mgr, max(1, min(limit, 1000))))
            if u.path == "/metrics":
                return self.reply(200, metrics(self.mgr), "text/plain; version=0.0.4")
        except Exception as e:
            M.log(f"api {u.path}: {type(e).__name__}: {e}")
            return self.reply(500, {"error": type(e).__name__})
        self.reply(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/action":
            return self.reply(404, {"error": "not found"})
        if not self.authorized():
            return
        try:
            body = json.loads(self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 4096)) or b"{}")
        except ValueError:
            return self.reply(400, {"error": "bad json"})
        action = str(body.get("action", "")).lower()
        if action not in ACTIONS:
            return self.reply(400, {"error": f"unknown action {action}", "actions": sorted(ACTIONS)})
        self.mgr.commands.put({"action": action, "sub": str(body.get("sub") or "")})
        self.reply(202, {"queued": action})


def serve(mgr, port, token, metrics_public=False):
    Handler.mgr, Handler.token, Handler.metrics_public = mgr, token, metrics_public
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    M.log(f"HTTP API on :{port}")
