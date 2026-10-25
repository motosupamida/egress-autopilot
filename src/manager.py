#!/usr/bin/env python3
"""egress-autopilot — picks, checks and switches the outbound node of an xray proxy.

Behaviour rules: docs/how-it-works.md. Subcommands:
  run         main loop (default)
  subs        fetch and parse all subscriptions, print what was found
  status      short state, no secrets
  check       validate the config and exit
HTTP API and Prometheus metrics: webapi.py. Event delivery: notify.py.
"""
import base64
import collections
import concurrent.futures as cf
import hashlib
import json
import os
import queue
import random
import re
import secrets
import socket
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

import config
import notify

DATA = os.environ.get("DATA", "/data")
XRAY_CONF = os.environ.get("XRAY_CONF", "/xray/config.json")
XRAY = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
API = os.environ.get("XRAY_API", "10.79.0.2:10085")
PROD_PROXY = os.environ.get("PROD_PROXY", "http://10.79.0.2:1080")
DB_PATH = f"{DATA}/metrics.db"
STATE = f"{DATA}/state.json"
EVENTS = f"{DATA}/events.jsonl"
CACHE = f"{DATA}/subs"
TOKEN_FILE = f"{DATA}/api-token"
SURVEY_PORT = 23000
TESTER_PORT = 21000
UA = "v2rayN/7.0"
PROXY_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http", "wireguard"}
# suggested reactions for alerts about a failure: values for POST /action
FAIL_ACTIONS = ["find_best", "speedtest"]

CFG = config.load()
_sel, _sch, _spd, _home, _al, _st = (CFG[k] for k in ("selection", "schedule", "speedtest", "home", "alerts", "storage"))
LAT_MAX_MS = _sel["max_latency_ms"]
SPEED_MIN_MBPS = _sel["min_speed_mbps"]
STOP_COUNTRIES = {c.upper() for c in _sel["blocked_countries"]}
QUARANTINE = int(_sel["quarantine_hours"] * 3600)
DEAD = int(_sel["dead_days"] * 86400)
DEAD_GAP = int(_sel["dead_gap_hours"] * 3600)
BIG_SUB = _sel["big_subscription"]
BIG_GOOD_ENOUGH = _sel["big_good_enough"]
LIGHT_SAMPLE = _sel["light_sample"]
PROBE_TARGETS = _sel["probe_targets"]
FAST = tuple(_sch["fast_interval_s"])
LONG_EVERY = int(_sch["scheduled_every_h"] * 3600)
VPN_SPEED_EVERY = int(_sch["vpn_speed_every_h"] * 3600)
UP_MIN_GAP = int(_sch["return_min_gap_min"] * 60)
UP_CONFIRM = (_sch["return_confirm"], _sch["return_confirm_pause_s"])
RETRY_BAD = int(_sch["retry_bad_min"] * 60)
PIN_TTL = int(_sch["pin_hours"] * 3600)
PAUSE_TTL = int(_sch["pause_hours"] * 3600)
VPN_SPEED_SECS = _spd["duration_s"]
VPN_SPEED_MIN_BYTES = _spd["min_bytes"]
VPN_SPEED = [(t["name"], t["url"], f"0-{_spd['max_bytes'] - 1}" if t.get("range") else None) for t in _spd["targets"]]
HOME = _home["enabled"]
PING_TARGETS = _home["ping_targets"] if HOME else []
DIRECT_CHECK = _home["direct_check"]
DIRECT_HTTP = _home["direct_http"]
HOME_SPEED_EVERY = tuple(h * 3600 for h in _home["speed_every_h"])
HOME_STREAMS = _home["speed_streams"]
HOME_SECS = _home["speed_duration_s"]
HOME_MIN_BYTES = _home["speed_min_bytes"]
HOME_SPEED = [(t["name"], t["url"]) for t in _home["speed_targets"]]
EXPIRE_WARN = int(_al["expire_warn_days"] * 86400)
TRAFFIC_WARN = _al["traffic_warn_pct"] / 100
FETCH_ALERT = int(_al["fetch_alert_h"] * 3600)
INTERNET_ALERT = int(_al["internet_alert_min"] * 60)
RETENTION = int(_st["retention_days"] * 86400)
DB_MAX = int(_st["max_db_mb"] * 2**20)
NODE_FORGET = int(_st["node_forget_days"] * 86400)

LOG_LOCK = threading.Lock()


def log(msg):
    with LOG_LOCK:
        print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}", flush=True)


def ago(ts):
    s = int(time.time() - ts)
    return f"{s // 3600}h {s % 3600 // 60}m" if s >= 3600 else f"{s // 60}m"


def write_private(path, data):
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    os.replace(tmp, path)


# --- subscriptions and nodes ---------------------------------------------------------

class Unsupported(ValueError):
    pass


class Node:
    __slots__ = ("id", "sub", "name", "proto", "outbounds", "flag")

    def __init__(self, sub, name, outbounds):
        self.sub, self.name, self.outbounds = sub, name, outbounds
        self.proto = outbounds[0].get("protocol", "?")
        self.flag = flag_country(name)
        self.id = node_id(outbounds)

    def label(self):
        return f"{self.sub}/{self.name[:40] or self.id}"


def flag_country(name):
    chars = [c for c in name if 0x1F1E6 <= ord(c) <= 0x1F1FF]
    return "".join(chr(ord(c) - 0x1F1E6 + 65) for c in chars[:2]) if len(chars) >= 2 else ""


def node_id(outbounds):
    """Hash of all parameters (tags normalised)."""
    tags = {o.get("tag"): f"dep{i}" for i, o in enumerate(outbounds)}
    norm = []
    for o in outbounds:
        o = json.loads(json.dumps(o))
        o.pop("tag", None)
        sock = (o.get("streamSettings") or {}).get("sockopt") or {}
        if sock.get("dialerProxy") in tags:
            sock["dialerProxy"] = tags[sock["dialerProxy"]]
        norm.append(o)
    return hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()[:12]


def name_id(name, outbounds):
    """Id from name + protocol/address/port. Many providers rotate SNI and shortId on
    every fetch (dozens of "nodes" are a handful of entry servers that differ only
    in that), so a parameter hash would "create" new nodes each time. The name is stable."""
    o = outbounds[0]
    s = o.get("settings") or {}
    srv = (s.get("vnext") or s.get("servers") or [{}])[0]
    key = [name, o.get("protocol"), srv.get("address") or s.get("address"), srv.get("port") or s.get("port")]
    return "n" + hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:11]


def retag(node, main, dep_prefix):
    tags = {o.get("tag"): (main if i == 0 else f"{dep_prefix}{i}") for i, o in enumerate(node.outbounds)}
    out = []
    for i, o in enumerate(node.outbounds):
        o = json.loads(json.dumps(o))
        o["tag"] = main if i == 0 else f"{dep_prefix}{i}"
        sock = (o.get("streamSettings") or {}).get("sockopt") or {}
        if sock.get("dialerProxy") in tags:
            sock["dialerProxy"] = tags[sock["dialerProxy"]]
        out.append(o)
    return out


def b64decode(s):
    s = "".join(s.strip().split()).replace("-", "+").replace("_", "/")
    return base64.b64decode(s + "=" * (-len(s) % 4))


def one(q, key, default=""):
    v = q.get(key) or q.get(key.lower())
    return v[0] if v else default


def stream_from_query(q, address, default_security="none"):
    net = (one(q, "type", "tcp") or "tcp").lower()
    net = {"raw": "tcp", "splithttp": "xhttp"}.get(net, net)
    sec = (one(q, "security", default_security) or default_security).lower()
    host, path = one(q, "host"), one(q, "path")
    s = {"network": net}
    if net == "tcp":
        if one(q, "headerType") == "http":
            req = {"path": [path or "/"]}
            if host:
                req["headers"] = {"Host": [host]}
            s["tcpSettings"] = {"header": {"type": "http", "request": req}}
    elif net == "ws":
        s["wsSettings"] = {"path": path or "/", **({"host": host} if host else {})}
    elif net == "httpupgrade":
        s["httpupgradeSettings"] = {"path": path or "/", **({"host": host} if host else {})}
    elif net == "grpc":
        g = {"serviceName": one(q, "serviceName") or path, "multiMode": one(q, "mode") == "multi"}
        if one(q, "authority"):
            g["authority"] = one(q, "authority")
        s["grpcSettings"] = g
    elif net == "xhttp":
        x = {"path": path or "/", "mode": one(q, "mode", "auto") or "auto"}
        if host:
            x["host"] = host
        if one(q, "extra"):
            x["extra"] = json.loads(one(q, "extra"))
        s["xhttpSettings"] = x
    else:
        raise Unsupported(f"transport {net}")
    sni, fp, alpn = one(q, "sni") or one(q, "peer"), one(q, "fp"), one(q, "alpn")
    if sec == "tls":
        t = {"serverName": sni or host or address}
        if fp:
            t["fingerprint"] = fp
        if alpn:
            t["alpn"] = [a for a in alpn.split(",") if a]
        if one(q, "allowInsecure") in ("1", "true") or one(q, "insecure") in ("1", "true"):
            t["allowInsecure"] = True
        s["security"], s["tlsSettings"] = "tls", t
    elif sec == "reality":
        if not one(q, "pbk"):
            raise Unsupported("reality without pbk")
        s["security"] = "reality"
        s["realitySettings"] = {"serverName": sni, "fingerprint": fp or "chrome", "publicKey": one(q, "pbk"),
                                "shortId": one(q, "sid"), "spiderX": one(q, "spx")}
    elif sec in ("none", ""):
        s["security"] = "none"
    else:
        raise Unsupported(f"security {sec}")
    return s


def hostport(netloc):
    u = urllib.parse.urlsplit(f"//{netloc}")
    if not u.hostname or not u.port:
        raise Unsupported("no host/port")
    return u.hostname, u.port


def parse_link(line):
    scheme = line.split("://", 1)[0].lower()
    if scheme == "vmess":
        j = json.loads(b64decode(line[8:].split("#")[0]))
        q = {k: [str(v)] for k, v in {"type": j.get("net") or "tcp", "security": j.get("tls") or "none",
                                       "host": j.get("host", ""), "path": j.get("path", ""), "sni": j.get("sni", ""),
                                       "fp": j.get("fp", ""), "alpn": j.get("alpn", ""),
                                       "headerType": j.get("type", ""), "serviceName": j.get("path", "")}.items()}
        out = {"protocol": "vmess", "settings": {"vnext": [{"address": j["add"], "port": int(j["port"]), "users": [
            {"id": j["id"], "alterId": int(j.get("aid") or 0), "security": j.get("scy") or "auto"}]}]},
               "streamSettings": stream_from_query(q, j["add"])}
        return out, j.get("ps", "")
    u = urllib.parse.urlsplit(line)
    name = urllib.parse.unquote(u.fragment)
    q = urllib.parse.parse_qs(u.query)
    if scheme == "vless":
        host, port = hostport(u.netloc.rsplit("@", 1)[-1])
        uid = urllib.parse.unquote(u.username or "")
        user = {"id": uid, "encryption": one(q, "encryption", "none") or "none"}
        if one(q, "flow"):
            user["flow"] = one(q, "flow")
        return {"protocol": "vless", "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
                "streamSettings": stream_from_query(q, host)}, name
    if scheme == "trojan":
        host, port = hostport(u.netloc.rsplit("@", 1)[-1])
        return {"protocol": "trojan", "settings": {"servers": [{"address": host, "port": port,
                                                                "password": urllib.parse.unquote(u.username or "")}]},
                "streamSettings": stream_from_query(q, host, "tls")}, name
    if scheme == "ss":
        if one(q, "plugin"):
            raise Unsupported("ss plugin")
        rest = line[5:].split("#")[0].split("?")[0].rstrip("/")
        if "@" in rest:
            userinfo, hp = rest.rsplit("@", 1)
            userinfo = urllib.parse.unquote(userinfo)
            if ":" not in userinfo:
                userinfo = b64decode(userinfo).decode()
        else:
            userinfo, hp = b64decode(rest).decode().rsplit("@", 1)
        method, password = userinfo.split(":", 1)
        host, port = hostport(hp)
        return {"protocol": "shadowsocks", "settings": {"servers": [
            {"address": host, "port": port, "method": method, "password": password}]}}, name
    if scheme in ("hysteria2", "hy2"):
        if one(q, "obfs"):
            raise Unsupported("hysteria2 obfs")
        host, port = hostport(u.netloc.rsplit("@", 1)[-1])
        auth = urllib.parse.unquote(u.netloc.rsplit("@", 1)[0]) if "@" in u.netloc else ""
        tls = {"serverName": one(q, "sni") or host, "alpn": ["h3"]}
        if one(q, "insecure") in ("1", "true"):
            tls["allowInsecure"] = True
        return {"protocol": "hysteria", "settings": {"address": host, "port": port, "version": 2},
                "streamSettings": {"network": "hysteria", "hysteriaSettings": {"version": 2, "auth": auth},
                                   "security": "tls", "tlsSettings": tls}}, name
    raise Unsupported(f"scheme {scheme}")


def json_nodes(sub, data):
    items = data if isinstance(data, list) else [data]
    for item in items:
        outs = {o.get("tag"): o for o in item.get("outbounds", []) if isinstance(o, dict)}
        proxies = [o for o in outs.values() if o.get("protocol") in PROXY_PROTOCOLS]
        for o in proxies:
            chain, cur = [o], o
            while True:
                dep = ((cur.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy")
                if not dep or dep not in outs or outs[dep] in chain:
                    break
                cur = outs[dep]
                chain.append(cur)
            name = item.get("remarks", "")
            if len(proxies) > 1:
                name = f"{name} · {o.get('tag', '')}"
            yield Node(sub, name, chain)


def parse_subscription(sub, body):
    """Returns (nodes, counter of unsupported entries)."""
    text = body.decode("utf-8-sig", errors="replace").strip()
    skipped = collections.Counter()
    if text[:1] in "[{":
        nodes = list(json_nodes(sub, json.loads(text)))
    else:
        if "://" not in text[:256]:
            text = b64decode(text).decode("utf-8-sig", errors="replace")
        nodes = []
        for line in text.splitlines():
            line = line.strip()
            if "://" not in line or line.startswith("#"):
                continue
            try:
                out, name = parse_link(line)
                nodes.append(Node(sub, name, [dict(out, tag="proxy")]))
            except Unsupported as e:
                skipped[str(e)] += 1
            except Exception:
                skipped["broken link"] += 1
    # a unique name gives a name-based id; repeated names (public lists) — parameter hash
    names = collections.Counter(n.name for n in nodes)
    unique = {}
    for n in nodes:
        if n.name and names[n.name] == 1:
            n.id = name_id(n.name, n.outbounds)
        unique.setdefault(n.id, n)
    return list(unique.values()), skipped


def read_subs():
    """Re-read on every scheduled cycle, so config edits apply without a restart."""
    return config.load(required=True)["subscription"]


# --- measurements ------------------------------------------------------------------

TARGET_LOCK = threading.Lock()
TARGET_FAILS = collections.Counter()
TARGET_DOWN = {}


def live_targets():
    now = time.time()
    names = [n for n in PROBE_TARGETS if TARGET_DOWN.get(n, 0) < now] or list(PROBE_TARGETS)
    random.shuffle(names)
    return names


def target_result(name, ok):
    with TARGET_LOCK:
        if ok:
            TARGET_FAILS[name] = 0
            return
        TARGET_FAILS[name] += 1
        if TARGET_FAILS[name] >= 5 and TARGET_DOWN.get(name, 0) < time.time():
            TARGET_DOWN[name] = time.time() + 3600
            TARGET_FAILS[name] = 0
            log(f"probe target {name} disabled for an hour: fails while the others work")


def probe(proxy, timeout=12):
    """Three requests over one connection through proxy. ok, target, cold_ms, warm_ms, loc, err."""
    failed, err = [], ""
    for name in live_targets()[:2]:
        url = PROBE_TARGETS[name]
        try:
            p = subprocess.run(["curl", "-sS", "-x", proxy, "--max-time", str(timeout), "-A", "curl/8",
                                "-w", "\n@@%{http_code} %{time_total}\n", url, url, url],
                               capture_output=True, text=True, timeout=timeout + 5)
            out, err = p.stdout, (p.stderr.strip().splitlines() or [""])[-1][:120]
        except subprocess.TimeoutExpired:
            out, err = "", "timeout"
        codes = re.findall(r"@@(\d+) ([\d.]+)", out)
        times = [float(t) * 1000 for c, t in codes if c in ("200", "204")]
        if len(codes) >= 2 and codes[0][0] in ("200", "204") and len(times) >= 2:
            for f in failed:
                target_result(f, False)
            target_result(name, True)
            loc = None
            m = re.search(r"^loc=([A-Z]{2})$", out, re.M) or re.search(r'"country":\s*"([A-Z]{2})"', out)
            if m:
                loc = m.group(1)
            return {"ok": True, "target": name, "cold_ms": round(times[0]), "warm_ms": round(statistics.median(times[1:])),
                    "loc": loc, "err": ""}
        failed.append(name)
        err = err or f"http {','.join(c for c, _ in codes) or 'none'}"
    return {"ok": False, "target": ",".join(failed), "cold_ms": None, "warm_ms": None, "loc": None, "err": err}


def download(url, proxy=None, rng=None, timeout=120):
    args = ["curl", "-sS", "-L", "-o", "/dev/null", "--max-time", str(timeout), "-w", "%{http_code} %{size_download} %{time_total}"]
    if proxy:
        args += ["-x", proxy]
    if rng:
        args += ["-r", rng]
    try:
        p = subprocess.run(args + [url], capture_output=True, text=True, timeout=timeout + 10)
        code, size, secs = p.stdout.split()
        return int(code), int(size), float(secs)
    except Exception:
        return 0, 0, 0.0


# --- storage -----------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS probes(ts INT, node TEXT, sub TEXT, via TEXT, target TEXT, ok INT, cold_ms INT, warm_ms INT, loc TEXT, err TEXT);
CREATE TABLE IF NOT EXISTS speeds(ts INT, scope TEXT, node TEXT, sub TEXT, target TEXT, ok INT, mbps REAL, bytes INT, secs REAL);
CREATE TABLE IF NOT EXISTS pings(ts INT, target TEXT, ok INT, avg_ms REAL, mdev_ms REAL, loss_pct REAL);
CREATE TABLE IF NOT EXISTS events(ts INT, kind TEXT, sub TEXT, node TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS nodes(id TEXT PRIMARY KEY, sub TEXT, name TEXT, proto TEXT, first_seen INT, last_seen INT,
  last_ok INT DEFAULT 0, fails INT DEFAULT 0, last_fail INT DEFAULT 0, quarantine_until INT DEFAULT 0,
  dead_until INT DEFAULT 0, invalid INT DEFAULT 0, loc TEXT);
CREATE TABLE IF NOT EXISTS subs(name TEXT PRIMARY KEY, last_ok INT, last_try INT, nodes INT, skipped TEXT,
  upload INT, download INT, total INT, expire INT);
CREATE TABLE IF NOT EXISTS traffic(ts INT, node TEXT, sub TEXT, up INT, down INT);
CREATE INDEX IF NOT EXISTS probes_ts ON probes(ts);
CREATE INDEX IF NOT EXISTS traffic_ts ON traffic(ts);
CREATE INDEX IF NOT EXISTS pings_ts ON pings(ts);
CREATE INDEX IF NOT EXISTS speeds_ts ON speeds(ts);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
"""


class DB:
    def __init__(self, path):
        self.lock = threading.Lock()
        self.c = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.executescript(SCHEMA)
        os.chmod(path, 0o600)

    def x(self, sql, args=()):
        with self.lock:
            return self.c.execute(sql, args).fetchall()

    def node(self, nid):
        with self.lock:
            cur = self.c.execute("SELECT * FROM nodes WHERE id=?", (nid,))
            row = cur.fetchone()
            return dict(zip([d[0] for d in cur.description], row)) if row else {}

    def maintain(self):
        cutoff = int(time.time() - RETENTION)
        for t in ("probes", "speeds", "pings", "events", "traffic"):
            self.x(f"DELETE FROM {t} WHERE ts < ?", (cutoff,))
        # nodes absent from every subscription for a while; their probe history stays
        self.x("DELETE FROM nodes WHERE last_seen < ?", (int(time.time() - NODE_FORGET),))
        while os.path.getsize(DB_PATH) > DB_MAX:
            for t in ("probes", "pings", "speeds", "events"):
                self.x(f"DELETE FROM {t} WHERE rowid IN (SELECT rowid FROM {t} ORDER BY ts LIMIT (SELECT count(*)/10 + 1 FROM {t}))")
            self.x("VACUUM")
        self.x("PRAGMA wal_checkpoint(TRUNCATE)")


# --- throwaway xray for probing -------------------------------------------------------

class Tester:
    """xray inside the manager container: one HTTP port on 127.0.0.1 per node."""

    def __init__(self, mgr, nodes, port=None):
        self.mgr, self.nodes, self.proc, self.dir = mgr, list(nodes), None, None
        self.port = port or getattr(threading.current_thread(), "tester_port", TESTER_PORT)
        self.ports = {}

    def config(self, nodes):
        inbounds, outbounds, rules = [], [], []
        for i, n in enumerate(nodes):
            inbounds.append({"tag": f"in{i}", "listen": "127.0.0.1", "port": self.port + i, "protocol": "http"})
            outbounds += retag(n, f"t{i}", f"u{i}-")
            rules.append({"inboundTag": [f"in{i}"], "outboundTag": f"t{i}"})
        return {"log": {"loglevel": "none"}, "inbounds": inbounds, "outbounds": outbounds, "routing": {"rules": rules}}

    def valid(self, nodes):
        path = f"{self.dir}/test.json"
        write_private(path, json.dumps(self.config(nodes)))
        return subprocess.run([XRAY, "run", "-test", "-c", path], capture_output=True, timeout=60).returncode == 0

    def __enter__(self):
        self.dir = tempfile.mkdtemp(prefix="tester-")
        if self.nodes and not self.valid(self.nodes):
            good = []
            for n in self.nodes:
                if self.valid([n]):
                    good.append(n)
                else:
                    self.mgr.db.x("UPDATE nodes SET invalid=1 WHERE id=?", (n.id,))
                    log(f"node {n.label()} rejected by xray -test, marked invalid")
            self.nodes = good
        if self.nodes:
            path = f"{self.dir}/run.json"
            write_private(path, json.dumps(self.config(self.nodes)))
            self.proc = subprocess.Popen([XRAY, "run", "-c", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    socket.create_connection(("127.0.0.1", self.port + len(self.nodes) - 1), 0.5).close()
                    break
                except OSError:
                    time.sleep(0.2)
            self.ports = {n.id: self.port + i for i, n in enumerate(self.nodes)}
        return self

    def proxy(self, node):
        return f"http://127.0.0.1:{self.ports[node.id]}"

    def __exit__(self, *exc):
        if self.proc:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        subprocess.run(["rm", "-rf", self.dir])


# --- manager -----------------------------------------------------------------------

class Manager:
    def __init__(self):
        os.makedirs(CACHE, mode=0o700, exist_ok=True)
        self.db = DB(DB_PATH)
        self.st = self.load_state()
        self.subs = []
        self.nodes = {}  # sub -> [Node]
        self.notifier = notify.Notifier(CFG["notify"], EVENTS, log)

    # state and alerts
    def load_state(self):
        try:
            with open(STATE) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {"alerts": {}}

    def save_state(self):
        write_private(STATE, json.dumps(self.st, ensure_ascii=False, indent=1))

    def event(self, kind, detail, node=None):
        self.db.x("INSERT INTO events VALUES(?,?,?,?,?)",
                  (int(time.time()), kind, node.sub if node else None, node.id if node else None, detail))
        log(f"[{kind}] {detail}")

    def push(self, kind, key, title, message, severity="critical", actions=None, data=None):
        self.notifier.emit(kind, key, title, message, severity, actions, data)
        log(f"notify [{severity}] {title}: {message}")

    def raise_alert(self, key, title, message, severity="critical", actions=None):
        alerts = self.st.setdefault("alerts", {})
        if alerts.get(key, {}).get("title") != title:
            self.push("alert", key, title, message, severity, actions)
        alerts[key] = {"title": title, "since": alerts.get(key, {}).get("since", time.time())}

    def clear_alert(self, key, title, message=""):
        old = self.st.setdefault("alerts", {}).pop(key, None)
        if old:
            self.push("resolved", key, title, f"{message}{' · ' if message else ''}lasted {ago(old['since'])}", "info",
                      data={"duration_s": int(time.time() - old["since"])})

    # subscriptions
    def sub(self, name):
        return next((s for s in self.subs if s["name"] == name), None)

    def fetch(self, sub, via):
        with tempfile.TemporaryDirectory() as d:
            args = ["curl", "-sS", "-L", "-A", UA, "--max-time", "40", "--max-filesize", "20000000",
                    "-D", f"{d}/h", "-o", f"{d}/b", "-w", "%{http_code}"]
            if via:
                args += ["-x", via]
            try:
                p = subprocess.run(args + [sub["url"]], capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                return None
            if p.stdout.strip() != "200" or not os.path.exists(f"{d}/b"):
                return None
            with open(f"{d}/b", "rb") as f:
                body = f.read()
            with open(f"{d}/h", errors="replace") as f:
                headers = f.read()
        info = {}
        m = re.findall(r"(?im)^subscription-userinfo:\s*(.+)$", headers)
        if m:
            for kv in m[-1].split(";"):
                k, _, v = kv.strip().partition("=")
                if v.strip().isdigit():
                    info[k.strip()] = int(v)
        return body, info

    def update_subs(self):
        self.subs = read_subs()
        now = int(time.time())
        fresh, failed = {}, []
        for s in self.subs:
            res = None
            for via in (None, PROD_PROXY):
                res = self.fetch(s, via)
                if res:
                    res = res + ("direct" if via is None else "vpn",)
                    break
            if res:
                fresh[s["name"]] = res
            else:
                failed.append(s)
        if failed:  # third attempt — through recently healthy nodes of other subscriptions
            helpers = [n for n in self.known_good(5) if n.sub not in {s["name"] for s in failed}]
            if helpers:
                with Tester(self, helpers[:3]) as t:
                    for s in list(failed):
                        for n in t.nodes:
                            res = self.fetch(s, t.proxy(n))
                            if res:
                                fresh[s["name"]] = res + (f"node {n.sub}",)
                                failed.remove(s)
                                break
        for s in self.subs:
            name = s["name"]
            self.db.x("INSERT OR IGNORE INTO subs(name) VALUES(?)", (name,))
            self.db.x("UPDATE subs SET last_try=? WHERE name=?", (now, name))
            if name in fresh:
                body, info, via = fresh[name]
                try:
                    nodes, skipped = parse_subscription(name, body)
                except Exception as e:
                    log(f"{name}: cannot parse subscription: {e}")
                    nodes, skipped = [], {}
                if nodes:
                    write_private(f"{CACHE}/{name}", body)
                    self.nodes[name] = nodes
                    self.db.x("UPDATE subs SET last_ok=?, nodes=?, skipped=?, upload=?, download=?, total=?, expire=? WHERE name=?",
                              (now, len(nodes), json.dumps(dict(skipped)), info.get("upload"), info.get("download"),
                               info.get("total"), info.get("expire"), name))
                    log(f"{name}: {len(nodes)} nodes ({via}){' · skipped ' + str(dict(skipped)) if skipped else ''}")
                    self.check_expiry(s, info)
                else:
                    log(f"{name}: fetched, but no nodes")
            if name not in self.nodes and os.path.exists(f"{CACHE}/{name}"):
                with open(f"{CACHE}/{name}", "rb") as f:
                    self.nodes[name] = parse_subscription(name, f.read())[0]
                log(f"{name}: fetch failed, using cache ({len(self.nodes[name])} nodes)")
            elif name not in fresh:
                log(f"{name}: fetch failed, no cache")
            last_ok = (self.db.x("SELECT last_ok FROM subs WHERE name=?", (name,)) or [[None]])[0][0]
            since = last_ok or self.st.setdefault("first_try", {}).setdefault(name, now)
            if now - since > FETCH_ALERT:
                self.raise_alert(f"fetch-{name}", f"Subscription {name} cannot be fetched", f"last success {ago(since)} ago")
            else:
                self.clear_alert(f"fetch-{name}", f"Subscription {name} fetches again")
        for name, nodes in self.nodes.items():
            for n in nodes:
                self.db.x("INSERT INTO nodes(id, sub, name, proto, first_seen, last_seen) VALUES(?,?,?,?,?,?) "
                          "ON CONFLICT(id) DO UPDATE SET last_seen=excluded.last_seen, sub=excluded.sub, name=excluded.name",
                          (n.id, name, n.name, n.proto, now, now))
        self.st["last_update"] = now

    def check_expiry(self, s, info):
        if "noexpiry" in s["flags"]:
            return
        problems = []
        exp = info.get("expire") or 0
        if exp and exp - time.time() < EXPIRE_WARN:
            problems.append("expired" if exp < time.time() else f"expires {time.strftime('%Y-%m-%d', time.localtime(exp))}")
        total = info.get("total") or 0
        used = (info.get("upload") or 0) + (info.get("download") or 0)
        if total and used / total > TRAFFIC_WARN:
            problems.append(f"traffic {used * 100 // total}%")
        if problems:
            self.raise_alert(f"expire-{s['name']}", f"Subscription {s['name']} needs attention", " · ".join(problems))
        else:
            self.clear_alert(f"expire-{s['name']}", f"Subscription {s['name']} is fine")

    def known_good(self, limit):
        rows = self.db.x("SELECT id FROM nodes WHERE last_ok > ? AND invalid=0 ORDER BY last_ok DESC LIMIT ?",
                         (int(time.time() - 86400), limit * 3))
        by_id = {n.id: n for nodes in self.nodes.values() for n in nodes}
        return [by_id[r[0]] for r in rows if r[0] in by_id][:limit]

    def find(self, nid):
        return next((n for nodes in self.nodes.values() for n in nodes if n.id == nid), None)

    def active_node(self):
        """The active node from its subscription, or, if it is gone from there, from the
        live xray config: a node that left the subscription but still works is no reason to fail over."""
        a = self.st.get("active") or {}
        node = self.find(a.get("id"))
        if node or not a:
            return node
        try:
            with open(XRAY_CONF) as f:
                cfg = json.load(f)
            tag = cfg["routing"]["balancers"][0]["selector"][0]
            outs = {o["tag"]: o for o in cfg["outbounds"]}
            chain, cur = [outs[tag]], outs[tag]
            while (dep := ((cur.get("streamSettings") or {}).get("sockopt") or {}).get("dialerProxy")) in outs:
                cur = outs[dep]
                chain.append(cur)
        except (OSError, ValueError, KeyError, IndexError):
            return None
        if chain[0].get("protocol") not in PROXY_PROTOCOLS:
            return None  # placeholder config written before the first selection
        ghost = Node(a.get("sub") or "?", a.get("name") or "", chain)
        # the same node under a new id: by name or by parameters
        for nid in ((name_id(ghost.name, chain) if ghost.name else None), ghost.id):
            same = self.find(nid)
            if same and same.sub == ghost.sub:
                a["id"] = same.id
                return same
        a["id"] = ghost.id
        return ghost

    # node checks
    def record_probe(self, node, via, r):
        now = int(time.time())
        self.db.x("INSERT INTO probes VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (now, node.id, node.sub, via, r["target"], int(r["ok"]), r["cold_ms"], r["warm_ms"], r["loc"], r["err"]))
        if r["ok"]:
            self.db.x("UPDATE nodes SET last_ok=?, fails=0, loc=coalesce(?, loc) WHERE id=?", (now, r["loc"], node.id))
            return
        if len(self.nodes.get(node.sub, [])) <= BIG_SUB:
            return
        row = self.db.node(node.id)
        if not row.get("fails"):
            self.db.x("UPDATE nodes SET fails=1, last_fail=? WHERE id=?", (now, node.id))
        elif now - row["last_fail"] >= DEAD_GAP:
            self.db.x("UPDATE nodes SET fails=2, dead_until=? WHERE id=?", (now + DEAD, node.id))

    def good(self, r, node):
        loc = r["loc"] or self.db.node(node.id).get("loc")
        return r["ok"] and r["warm_ms"] <= LAT_MAX_MS and loc not in STOP_COUNTRIES

    def candidates(self, sub, exclude=()):
        now = time.time()
        out = []
        for n in self.nodes.get(sub, []):
            row = self.db.node(n.id)
            if n.id in exclude or n.flag in STOP_COUNTRIES or row.get("invalid"):
                continue
            if row.get("quarantine_until", 0) > now or row.get("dead_until", 0) > now:
                continue
            out.append(n)
        return out

    def probe_nodes(self, nodes, stop_after=None, workers=5):
        results = {}
        for i in range(0, len(nodes), 50 if stop_after is None else 20):
            chunk = nodes[i:i + (50 if stop_after is None else 20)]
            with Tester(self, chunk) as t:
                with cf.ThreadPoolExecutor(workers) as ex:
                    for n, r in zip(t.nodes, ex.map(lambda n: probe(t.proxy(n)), t.nodes)):
                        self.record_probe(n, "tester", r)
                        results[n.id] = (n, r)
            if stop_after and sum(self.good(r, n) for n, r in results.values()) >= stop_after:
                break
        return results

    def speed(self, proxy, node, scope="vpn"):
        best = None
        for name, url, rng in VPN_SPEED:
            for _ in range(2):
                # time-bound: a slow node gets a speed from what it managed, not "none" after 2 minutes
                code, size, secs = download(url, proxy, rng, VPN_SPEED_SECS)
                ok = code in (200, 206) and size >= VPN_SPEED_MIN_BYTES and secs > 0
                mbps = round(size * 8 / secs / 1e6, 1) if ok else None
                self.db.x("INSERT INTO speeds VALUES(?,?,?,?,?,?,?,?,?)", (int(time.time()), scope, node.id if node else None,
                                                                           node.sub if node else None, name, int(ok), mbps, size, secs))
                if not ok:
                    break  # this target does not serve — next one
                best = max(best or 0, mbps)
                if mbps >= SPEED_MIN_MBPS:
                    return best
            if best is not None:
                return best
        return best

    def search(self, subs):
        """Top-down: the first subscription with a node passing probe and speed test. -> (node, backups, metrics) | None."""
        for s in subs:
            name = s["name"]
            cands = self.candidates(name)
            if not cands:
                log(f"search: {name} — no candidates")
                continue
            big = len(self.nodes.get(name, [])) > BIG_SUB
            if big:
                hist = {r[0]: r[1] for r in self.db.x("SELECT id, last_ok FROM nodes WHERE sub=?", (name,))}
                random.shuffle(cands)
                cands.sort(key=lambda n: -(hist.get(n.id) or 0))
            results = self.probe_nodes(cands, BIG_GOOD_ENOUGH if big else None, 20 if big else 5)
            good = sorted([(n, r) for n, r in results.values() if self.good(r, n)], key=lambda x: x[1]["warm_ms"])
            log(f"search: {name} — probed {len(results)}, alive {sum(r['ok'] for _, r in results.values())}, good {len(good)}")
            if not good:
                continue
            with Tester(self, [n for n, _ in good[:5]]) as t:
                for n, r in good[:5]:
                    if n.id not in t.ports:
                        continue
                    mbps = self.speed(t.proxy(n), n, "cand")
                    if mbps is not None and mbps >= SPEED_MIN_MBPS:
                        backups = [b for b, _ in good if b.id != n.id][:2]
                        return n, backups, {"warm_ms": r["warm_ms"], "mbps": mbps, "loc": r["loc"]}
                    self.db.x("UPDATE nodes SET quarantine_until=? WHERE id=?", (int(time.time() + QUARANTINE), n.id))
                    self.event("quarantine", f"{n.label()}: speed {mbps or 'none'} Mbit/s — quarantined", n)
                    self.push("quarantine", f"q-{n.id}", "Node quarantined", f"{n.label()} · {mbps or 'none'} Mbit/s", "info",
                              data={"sub": n.sub, "node": n.name, "mbps": mbps})
        return None

    def degraded_pick(self):
        """Lowest latency among nodes that pass traffic, ignoring quarantine and thresholds (except country)."""
        best = None
        for s in self.subs:
            small = len(self.nodes.get(s["name"], [])) <= BIG_SUB
            pool = self.nodes.get(s["name"], []) if small else self.candidates(s["name"])
            pool = [n for n in pool if n.flag not in STOP_COUNTRIES and not self.db.node(n.id).get("invalid")]
            for n, r in self.probe_nodes(pool, None if small else BIG_GOOD_ENOUGH, 5 if small else 20).values():
                loc = r["loc"] or self.db.node(n.id).get("loc")
                if r["ok"] and loc not in STOP_COUNTRIES and (best is None or r["warm_ms"] < best[1]["warm_ms"]):
                    best = (n, r)
        return best

    # production xray
    def prod_config(self, active, backups):
        if active:
            outs = []
            for n in [active] + backups:
                outs += retag(n, f"a-{n.id}", f"z-{n.id}-")
            selector = f"a-{active.id}"
        else:  # nothing selected yet: xray starts and drops traffic until the first switch
            outs, selector = [{"tag": "a-none", "protocol": "blackhole"}], "a-none"
        return {"log": {"loglevel": "warning"},
                "api": {"tag": "api", "listen": API, "services": ["HandlerService", "RoutingService", "StatsService"]},
                "stats": {},
                "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
                "inbounds": [{"tag": "http", "listen": "0.0.0.0", "port": 1080, "protocol": "http"},
                             {"tag": "socks", "listen": "0.0.0.0", "port": 1081, "protocol": "socks", "settings": {"udp": True}}],
                "outbounds": outs,
                "routing": {"balancers": [{"tag": "egress", "selector": [selector]}],
                            "rules": [{"inboundTag": ["http", "socks"], "balancerTag": "egress"}]}}

    def api(self, *args):
        p = subprocess.run([XRAY, "api", args[0], "-s", API, *args[1:]], capture_output=True, text=True, timeout=30)
        return p.returncode == 0, (p.stdout + p.stderr).strip()

    def write_prod(self, active, backups):
        cfg = self.prod_config(active, backups)
        if os.path.exists(XRAY_CONF):
            with open(XRAY_CONF, "rb") as f:
                write_private(f"{DATA}/xray-config.prev.json", f.read())
        write_private(XRAY_CONF, json.dumps(cfg, ensure_ascii=False, indent=1) + "\n")
        os.chmod(XRAY_CONF, 0o644)  # the xray container may run as another user
        return cfg

    def apply(self, active, backups, via_api=True):
        cfg = self.write_prod(active, backups)
        if via_api:
            ok, out = self.api("lso")
            have = set(re.findall(r'"tag":\s*"([^"]+)"', out)) if ok else None
            if have is None:
                log(f"xray API unavailable ({out[:100]}) — selection saved to the config, applies after an xray restart")
            else:
                want = [o for o in cfg["outbounds"] if o["tag"] not in have]
                if want:
                    with tempfile.NamedTemporaryFile("w", suffix=".json", dir=DATA, delete=False) as f:
                        json.dump({"outbounds": want}, f)
                    try:
                        ok, out = self.api("ado", f.name)
                    finally:
                        os.remove(f.name)
                    if not ok:
                        log(f"xray api ado: {out[:200]}")
                ok, out = self.api("bo", "-b", "egress", f"a-{active.id}")
                if not ok:
                    log(f"xray api bo: {out[:200]}")
                keep = {o["tag"] for o in cfg["outbounds"]} | {"api"}
                for tag in have - keep:
                    if tag.startswith(("a-", "z-")):
                        self.api("rmo", tag)
        prev = self.st.get("active") or {}
        same = prev.get("id") == active.id  # only backups changed — time on node and geolocation stay
        self.st["active"] = {"id": active.id, "sub": active.sub, "name": active.name,
                             "since": prev.get("since") if same else time.time(),
                             **({"geo": prev["geo"]} if same and "geo" in prev else {})}
        self.st["backups"] = [b.id for b in backups]

    def switch(self, active, backups, metrics, reason, quiet=False, prev=None):
        """prev — the node before a failure, if a quiet hop to a backup happened on the way."""
        old = prev or self.st.get("active") or {}
        self.apply(active, backups)
        r = probe(PROD_PROXY)
        self.record_probe(active, "prod", r)
        self.geo()
        m = " · ".join(x for x in (f"{metrics['warm_ms']} ms" if metrics.get("warm_ms") else "",
                                   f"{metrics['mbps']} Mbit/s" if metrics.get("mbps") else "",
                                   metrics.get("loc") or "") if x)
        detail = f"{old.get('sub', '—')}/{(old.get('name') or '')[:30]} → {active.label()} · {reason}{' · ' + m if m else ''}"
        self.event("switch", detail + ("" if r["ok"] else " · check through production xray FAILED"), active)
        if quiet or old.get("id") == active.id:
            return r["ok"]
        old_sub = self.sub(old.get("sub", ""))
        new_sub = self.sub(active.sub)
        msg = f"{active.name[:40]}{' · ' + m if m else ''} · {reason}"
        data = {"from_sub": old.get("sub"), "from_node": old.get("name"), "sub": active.sub, "node": active.name,
                "reason": reason, "latency_ms": metrics.get("warm_ms"), "mbps": metrics.get("mbps"),
                "country": metrics.get("loc"), "verified": r["ok"]}
        if not old_sub or old_sub["prio"] == new_sub["prio"]:
            self.push("switch", "switch", f"Switched node within {active.sub}", msg, "info", data=data)
        elif new_sub["prio"] > old_sub["prio"]:
            self.push("switch", "switch", f"Fell back {old_sub['name']} → {active.sub}", msg, actions=FAIL_ACTIONS, data=data)
        else:
            self.push("switch", "switch", f"Back up {old_sub['name']} → {active.sub}", msg, "info", data=data)
            self.st["last_up"] = time.time()
        if "free" in new_sub["flags"]:
            self.raise_alert("free", "Running on free nodes", f"{active.sub} — nodes of unknown operators")
        else:
            self.clear_alert("free", "Left free nodes", active.sub)
        return r["ok"]

    # scenarios
    def set_mode(self, mode, detail=""):
        prev = self.st.get("mode")
        self.st["mode"] = mode
        if mode == "ok":
            self.clear_alert("degraded", "VPN quality restored", detail)
            self.clear_alert("dead", "VPN works again", detail)
        elif mode == "degraded":
            self.clear_alert("dead", "VPN passes traffic again", detail)
            self.raise_alert("degraded", "VPN degraded", detail, actions=FAIL_ACTIONS)
        elif mode == "dead":
            self.raise_alert("dead", "All VPN nodes are down", detail, actions=FAIL_ACTIONS)
        if prev != mode:
            self.event("mode", f"{prev} → {mode} {detail}")

    def pinned(self):
        pin = self.st.get("pin")
        return pin["sub"] if pin and pin["until"] > time.time() and self.sub(pin["sub"]) else None

    def ordered_subs(self):
        """A pinned subscription goes first, the rest by priority."""
        p = self.pinned()
        return sorted(self.subs, key=lambda s: (s["name"] != p, s["prio"]))

    def geo(self):
        try:
            p = subprocess.run(["curl", "-sS", "-x", PROD_PROXY, "--max-time", "10", "https://ipinfo.io/json"],
                               capture_output=True, text=True, timeout=20)
            j = json.loads(p.stdout)
            lat, lon = (float(x) for x in j["loc"].split(","))
            self.st.setdefault("active", {})["geo"] = {"city": j.get("city"), "country": j.get("country"),
                                                       "lat": lat, "lon": lon}
        except Exception as e:
            log(f"exit geolocation unknown: {type(e).__name__}")

    def collect_traffic(self):
        ok, out = self.api("statsquery", "-pattern", "outbound>>>a-", "-reset")
        if not ok:
            return
        try:
            stats = json.loads(out).get("stat", [])
        except ValueError:
            return
        per = collections.defaultdict(lambda: [0, 0])
        for s in stats:
            parts = s.get("name", "").split(">>>")
            if len(parts) == 4 and parts[1].startswith("a-"):
                per[parts[1][2:]][parts[3] == "downlink"] += int(s.get("value") or 0)
        now = int(time.time())
        for nid, (up, down) in per.items():
            if up or down:
                n = self.find(nid)
                self.db.x("INSERT INTO traffic VALUES(?,?,?,?,?)", (now, nid, n.sub if n else None, up, down))

    def failover(self, reason):
        self.event("failover", reason)
        if self.paused():
            self.raise_alert("paused-fail", "VPN failure while auto-switching is paused", reason, actions=FAIL_ACTIONS)
            return
        orig = dict(self.st.get("active") or {})
        backups = [b for b in (self.find(i) for i in self.st.get("backups", [])) if b]
        if backups:
            res = self.probe_nodes(backups)
            ok = sorted([(n, r) for n, r in res.values() if self.good(r, n)], key=lambda x: x[1]["warm_ms"])
            if ok:
                n, r = ok[0]
                self.switch(n, [b for b, _ in ok[1:]], {"warm_ms": r["warm_ms"], "loc": r["loc"]}, "quick hop to a backup", quiet=True)
        found = self.search(self.ordered_subs())
        if found:
            n, backups, m = found
            self.switch(n, backups, m, reason, prev=orig)
            self.set_mode("ok", n.label())
            return
        pick = self.degraded_pick()
        self.st["next_retry"] = time.time() + RETRY_BAD
        if pick:
            n, r = pick
            self.switch(n, [], {"warm_ms": r["warm_ms"], "loc": r["loc"]}, "degraded", prev=orig)
            self.set_mode("degraded", f"{n.label()} · {r['warm_ms']} ms · no node passed all checks")
        else:
            self.set_mode("dead", "no node of any subscription passes traffic")

    def scheduled(self):
        self.update_subs()
        self.scheduled_switch()
        self.light_check()

    def light_check(self):
        """Every scheduled cycle, no speed test: in every subscription but the last one, each
        node (quarantined included; blocked-flag and invalid ones not) that was not probed in
        the last hour; the last (usually a big public list) — a sample of LIGHT_SAMPLE."""
        since = int(time.time() - 3600)
        last = max(s["prio"] for s in self.subs) if len(self.subs) > 1 else None
        for s in self.subs:
            name = s["name"]
            recent = {r[0] for r in self.db.x("SELECT DISTINCT node FROM probes WHERE sub=? AND ts > ?", (name, since))}
            pool = [n for n in self.nodes.get(name, []) if n.flag not in STOP_COUNTRIES
                    and not self.db.node(n.id).get("invalid")]
            if s["prio"] == last:
                if recent:
                    continue
                hist = {r[0]: r[1] or 0 for r in self.db.x("SELECT id, last_ok FROM nodes WHERE sub=?", (name,))}
                random.shuffle(pool)
                # half — nodes with the best history, half — random
                best = sorted(pool, key=lambda n: -hist.get(n.id, 0))[:LIGHT_SAMPLE // 2]
                todo = best + [n for n in pool if n not in best][:LIGHT_SAMPLE - len(best)]
            else:
                todo = [n for n in pool if n.id not in recent]
            if todo:
                res = self.probe_nodes(todo)
                log(f"check {name}: {sum(r['ok'] for _, r in res.values())} of {len(res)} answered")

    def scheduled_switch(self):
        cur = self.active_node()
        if self.st.get("mode") != "ok" or not cur:
            self.failover("scheduled search")
            return
        cur_sub = self.sub(cur.sub)
        higher = [s for s in self.subs if cur_sub and s["prio"] < cur_sub["prio"]]
        pin = self.pinned()
        if pin:  # pinned: never go above, only return to the pinned one
            higher = [self.sub(pin)] if pin != cur.sub else []
        if self.paused():
            higher = []
        if higher and time.time() - self.st.get("last_up", 0) >= UP_MIN_GAP:
            found = self.search(higher)
            if found:
                n, backups, m = found
                if self.confirm(n):
                    self.switch(n, backups, m, "higher-priority subscription works again")
                    return
        # refresh backups from the current subscription
        cands = [n for n in self.candidates(cur.sub, exclude={cur.id})][:50]
        res = self.probe_nodes(cands) if cands else {}
        ok = sorted([(n, r) for n, r in res.values() if self.good(r, n)], key=lambda x: x[1]["warm_ms"])
        new_backups = [n for n, _ in ok[:2]]
        if [b.id for b in new_backups] != self.st.get("backups"):
            self.apply(cur, new_backups)
            log(f"backups refreshed: {[b.label() for b in new_backups]}")

    def confirm(self, node):
        count, pause = UP_CONFIRM
        with Tester(self, [node]) as t:
            if node.id not in t.ports:
                return False
            for i in range(count):
                if i:
                    time.sleep(pause)
                r = probe(t.proxy(node))
                self.record_probe(node, "tester", r)
                if not self.good(r, node):
                    log(f"return to {node.label()} cancelled: check {i + 1}/{count} failed")
                    return False
        return True

    # direct (home) internet
    def home_ping(self):
        def one_ping(host):
            try:
                p = subprocess.run(["ping", "-n", "-q", "-c", "5", "-i", "0.2", "-W", "2", host],
                                   capture_output=True, text=True, timeout=25)
                out = p.stdout
            except subprocess.TimeoutExpired:
                out = ""
            loss = re.search(r"([\d.]+)% packet loss", out)
            rtt = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)(?:/([\d.]+))?", out)
            loss = float(loss.group(1)) if loss else 100.0
            row = (int(time.time()), host, int(loss < 100), float(rtt.group(2)) if rtt else None,
                   float(rtt.group(4)) if rtt and rtt.group(4) else None, loss)
            self.db.x("INSERT INTO pings VALUES(?,?,?,?,?,?)", row)
            return host, loss < 100
        hosts = list(dict.fromkeys(PING_TARGETS + DIRECT_CHECK))
        with cf.ThreadPoolExecutor(len(hosts)) as ex:
            res = dict(ex.map(one_ping, hosts))
        if any(res[h] for h in DIRECT_CHECK):
            return True
        return download(DIRECT_HTTP, timeout=10)[0] in (200, 204, 301, 302)

    def home_speed(self):
        """HOME_STREAMS parallel streams for HOME_SECS: a single stream often cannot saturate the line."""
        for name, url in HOME_SPEED:
            start = time.time()
            procs = [subprocess.Popen(["curl", "-sS", "-L", "-o", "/dev/null", "--max-time", str(HOME_SECS),
                                       "-w", "%{http_code} %{size_download}", url],
                                      stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True) for _ in range(HOME_STREAMS)]
            outs = [(p.communicate(timeout=HOME_SECS + 20)[0] or "0 0").split() for p in procs]
            secs = time.time() - start
            size = sum(int(o[1]) for o in outs if len(o) == 2)
            ok = all(o and o[0] in ("200", "206") for o in outs) and size >= HOME_MIN_BYTES
            mbps = round(size * 8 / secs / 1e6, 1) if ok else None
            self.db.x("INSERT INTO speeds VALUES(?,?,?,?,?,?,?,?,?)",
                      (int(time.time()), "home", None, None, name, int(ok), mbps, size, secs))
            if ok:
                log(f"direct internet: {mbps} Mbit/s ({name})")
                return mbps
        log("direct internet: speed test failed on every target")
        return None

    # main loop
    def tick(self):
        now = time.time()
        if not self.home_ping():
            self.st.setdefault("internet_down", now)
            if now - self.st["internet_down"] > INTERNET_ALERT:
                self.raise_alert("internet", "No direct internet", "not switching VPN, waiting", "info")
            log("no direct internet — switching frozen")
            return
        if self.st.pop("internet_down", None):
            self.clear_alert("internet", "Direct internet is back")
        pin = self.st.get("pin")
        if pin and pin["until"] <= now:
            self.st.pop("pin")
            self.event("pin", f"pin of {pin['sub']} expired")
        if self.st.get("paused") and self.st["paused"] <= now:
            self.st.pop("paused")
            self.clear_alert("paused-fail", "Auto-switching enabled again")
            self.event("pause", "pause expired")
        self.collect_traffic()
        if self.st.get("active") and "geo" not in self.st["active"]:
            self.geo()
        # while degraded or dead, a full search runs no more often than RETRY_BAD
        search_allowed = self.st.get("mode") == "ok" or now >= self.st.get("next_retry", 0)
        if now >= self.st.get("next_long", 0):
            self.st["next_long"] = now + LONG_EVERY
            self.scheduled()
        elif self.st.get("mode") != "ok" and search_allowed:
            self.failover("repeated search")
        act = self.active_node()
        if act:
            r = probe(PROD_PROXY)
            self.record_probe(act, "prod", r)
            if not r["ok"]:
                log(f"active node does not answer: {r['target']} · {r['err']}")
                if search_allowed and self.st.get("mode") == "ok":
                    self.failover("active node does not answer")
            elif now >= self.st.get("next_vpn_speed", 0):
                self.st["next_vpn_speed"] = now + VPN_SPEED_EVERY
                mbps = self.speed(PROD_PROXY, act)
                log(f"active node speed: {mbps} Mbit/s")
                if mbps is None or mbps < SPEED_MIN_MBPS:
                    self.db.x("UPDATE nodes SET quarantine_until=? WHERE id=?", (int(now + QUARANTINE), act.id))
                    self.failover(f"active node is slow: {mbps} Mbit/s")
        elif self.st.get("mode") == "ok":
            self.failover("active node is missing from subscriptions")
        if HOME and now >= self.st.get("next_home_speed", 0):
            self.st["next_home_speed"] = now + random.uniform(*HOME_SPEED_EVERY)
            self.home_speed()
        if now >= self.st.get("next_maintain", 0):
            self.st["next_maintain"] = now + 86400
            self.db.maintain()

    # commands from POST /action — run in the main thread between checks
    def paused(self):
        return bool(self.st.get("paused")) and self.st["paused"] > time.time()

    def handle(self, cmd):
        action, arg = cmd.get("action"), cmd.get("sub") or ""
        self.event("action", f"{action} {arg}".strip())
        act = self.active_node()
        if action == "find_best":
            found = self.search(self.ordered_subs())
            if found and (not act or found[0].id != act.id):
                self.switch(*found, "manual search")
            else:
                self.push("action", "find_best", "Nothing better than the current node", act.label() if act else "—", "info")
            if found:  # the current node may have just passed every check while we were degraded/dead
                self.set_mode("ok", found[0].label())
        elif action == "speedtest" and act:
            mbps = self.speed(PROD_PROXY, act)
            self.push("action", "speedtest", "Speed test", f"{act.label()} · {mbps or 'none'} Mbit/s", "info",
                      data={"sub": act.sub, "node": act.name, "mbps": mbps})
        elif action == "survey":
            self.start_survey()
        elif action == "pin" and self.sub(arg):
            self.st["pin"] = {"sub": arg, "until": time.time() + PIN_TTL}
            if not act or act.sub != arg:
                found = self.search([self.sub(arg)])
                if found:
                    self.switch(*found, f"pinned {arg}")
                    self.set_mode("ok", found[0].label())
                else:
                    self.push("action", "pin", f"{arg} does not work", "pin kept, staying on the current node")
        elif action == "unpin":
            self.st.pop("pin", None)
        elif action == "pause":
            self.st["paused"] = time.time() + PAUSE_TTL
        elif action == "resume":
            self.st.pop("paused", None)
            self.clear_alert("paused-fail", "Auto-switching enabled again")
        self.save_state()

    def start_survey(self):
        if self.st.get("survey", {}).get("running"):
            return

        def worker():
            import survey
            threading.current_thread().tester_port = SURVEY_PORT
            self.st["survey"] = {"running": True, "started": time.time()}
            try:
                lines = survey.run(self)
                self.st["survey"] = {"running": False, "at": time.time(), "lines": lines}
                self.push("survey", "survey", "Full survey finished", "\n".join(l.split("\n")[0] for l in lines), "info")
            except Exception as e:
                self.st["survey"] = {"running": False, "at": time.time(), "lines": [f"error: {e}"]}
        threading.Thread(target=worker, daemon=True).start()

    def load_cache(self):
        self.subs = read_subs()
        for s in self.subs:
            if os.path.exists(f"{CACHE}/{s['name']}"):
                with open(f"{CACHE}/{s['name']}", "rb") as f:
                    self.nodes[s["name"]] = parse_subscription(s["name"], f.read())[0]

    def run(self):
        import webapi
        log(f"egress-autopilot started: {len(read_subs())} subscriptions")
        self.load_cache()
        if not os.path.exists(XRAY_CONF):
            self.write_prod(None, [])
            log("no xray config yet — wrote a placeholder, the first cycle selects a node")
        token = CFG["api"]["token"] or os.environ.get("API_TOKEN", "")
        if not token:
            if not os.path.exists(TOKEN_FILE):
                write_private(TOKEN_FILE, secrets.token_urlsafe(32))
                log(f"API token generated: {TOKEN_FILE}")
            with open(TOKEN_FILE) as f:
                token = f.read().strip()
        self.commands = queue.Queue()
        webapi.serve(self, CFG["api"]["port"], token, CFG["api"]["metrics_public"])
        while True:
            try:
                self.tick()
            except Exception as e:
                log(f"cycle error: {type(e).__name__}: {e}")
            self.save_state()
            deadline = time.time() + random.uniform(*FAST)
            while (left := deadline - time.time()) > 0:
                try:
                    cmd = self.commands.get(timeout=left)
                except queue.Empty:
                    break
                try:
                    self.handle(cmd)
                except Exception as e:
                    log(f"command error {cmd}: {type(e).__name__}: {e}")

    def show_subs(self):
        self.update_subs()
        for s in self.subs:
            nodes = self.nodes.get(s["name"], [])
            flags = collections.Counter(n.flag or "?" for n in nodes)
            print(f"{s['prio']:>3} {s['name']}: {len(nodes)} nodes · "
                  + ", ".join(f"{c} {k}" for c, k in flags.most_common(10)))

    def status(self):
        a = self.st.get("active") or {}
        print(f"mode={self.st.get('mode')} active={a.get('sub')}/{a.get('name')} since={ago(a['since']) if a else '-'}")
        print(f"backups={len(self.st.get('backups', []))} alerts={list(self.st.get('alerts', {}))}")
        for name, last_ok, nodes, exp in self.db.x("SELECT name, last_ok, nodes, expire FROM subs ORDER BY name"):
            print(f"  {name}: nodes={nodes} last_ok={ago(last_ok) + ' ago' if last_ok else '-'} "
                  f"expire={time.strftime('%Y-%m-%d', time.localtime(exp)) if exp else '-'}")
        for row in self.db.x("SELECT datetime(ts,'unixepoch','localtime'), kind, detail FROM events ORDER BY ts DESC LIMIT 10"):
            print("  ", *row)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    try:
        subs = read_subs()
    except config.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if cmd == "check":
        print(f"config ok: {len(subs)} subscriptions: {', '.join(s['name'] for s in subs)}")
        return 0
    m = Manager()
    if cmd == "subs":
        return m.show_subs()
    if cmd == "status":
        return m.status()
    m.run()


if __name__ == "__main__":
    sys.exit(main())
