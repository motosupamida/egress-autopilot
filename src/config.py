"""Configuration: defaults merged with /config/config.toml (path from $CONFIG).

Every key is optional except at least one [[subscription]]. String values may
reference environment variables as ${NAME}, e.g. url = "${SUB_MAIN_URL}".
Reference: docs/configuration.md.
"""
import copy
import os
import re
import sys
import tomllib

PATH = os.environ.get("CONFIG", "/config/config.toml")

DEFAULTS = {
    "selection": {
        "max_latency_ms": 800,
        "min_speed_mbps": 10,
        "blocked_countries": [],
        "quarantine_hours": 24,
        "big_subscription": 100,
        "big_good_enough": 10,
        "dead_days": 30,
        "dead_gap_hours": 6,
        "light_sample": 10,
        "probe_targets": {
            "cloudflare": "https://cloudflare.com/cdn-cgi/trace",
            "google": "https://www.google.com/generate_204",
            "ipinfo": "https://ipinfo.io/json",
        },
    },
    "schedule": {
        "fast_interval_s": [120, 240],
        "scheduled_every_h": 6,
        "vpn_speed_every_h": 6,
        "return_min_gap_min": 60,
        "return_confirm": 3,
        "return_confirm_pause_s": 100,
        "retry_bad_min": 15,
        "pin_hours": 24,
        "pause_hours": 24,
    },
    "speedtest": {
        "duration_s": 20,
        "max_bytes": 25_000_000,
        "min_bytes": 2 * 2**20,
        "targets": [
            {"name": "cloudflare", "url": "https://speed.cloudflare.com/__down?bytes=25000000"},
            {"name": "ovh", "url": "https://proof.ovh.net/files/100Mb.dat", "range": True},
            {"name": "hetzner", "url": "https://hel1-speed.hetzner.com/100MB.bin", "range": True},
        ],
    },
    "home": {
        "enabled": True,
        "ping_targets": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "direct_check": ["1.1.1.1", "8.8.8.8", "9.9.9.9"],
        "direct_http": "http://connectivitycheck.gstatic.com/generate_204",
        "speed_every_h": [2.5, 3.5],
        "speed_streams": 4,
        "speed_duration_s": 10,
        "speed_min_bytes": 20 * 2**20,
        "speed_targets": [
            {"name": "cloudflare", "url": "https://speed.cloudflare.com/__down?bytes=1000000000"},
            {"name": "ovh", "url": "https://proof.ovh.net/files/1Gb.dat"},
        ],
    },
    "alerts": {
        "expire_warn_days": 3,
        "traffic_warn_pct": 90,
        "fetch_alert_h": 24,
        "internet_alert_min": 10,
    },
    "notify": {
        "min_severity": "info",
        "file": True,
        "file_max_mb": 5,
        "webhook": [],
        "exec": [],
    },
    "api": {
        "port": 8765,
        "token": "",
        "metrics_public": False,
    },
    "storage": {
        "retention_days": 365,
        "max_db_mb": 800,
        "node_forget_days": 30,
    },
    "subscription": [],
}

SUB_FLAGS = {"noexpiry", "free"}
SEVERITIES = ("info", "critical")
ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


def expand(v):
    if isinstance(v, str):
        return ENV.sub(lambda m: os.environ.get(m.group(1), ""), v)
    if isinstance(v, list):
        return [expand(x) for x in v]
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    return v


def merge(base, over, where=""):
    for k, v in over.items():
        if k not in base:
            print(f"config: unknown key {where}{k} — ignored", file=sys.stderr)
            continue
        if isinstance(base[k], dict) and k != "probe_targets":
            if not isinstance(v, dict):
                raise ConfigError(f"{where}{k} must be a table")
            merge(base[k], v, f"{where}{k}.")
        else:
            base[k] = v


def check_subs(subs):
    seen = set()
    out = []
    for i, s in enumerate(subs):
        name, url = str(s.get("name", "")), str(s.get("url", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
            raise ConfigError(f"subscription #{i + 1}: name must be 1-40 chars of A-Z a-z 0-9 _ . -")
        if name in seen:
            raise ConfigError(f"subscription {name}: duplicate name")
        if not url.startswith(("http://", "https://")):
            raise ConfigError(f"subscription {name}: url must be http(s) (empty ${{VAR}}?)")
        flags = set(s.get("flags", []))
        if flags - SUB_FLAGS:
            raise ConfigError(f"subscription {name}: unknown flags {sorted(flags - SUB_FLAGS)}")
        seen.add(name)
        out.append({"name": name, "url": url, "prio": int(s.get("priority", i + 1)), "flags": flags})
    return sorted(out, key=lambda s: s["prio"])


def load(path=PATH, required=False):
    cfg = copy.deepcopy(DEFAULTS)
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except FileNotFoundError:
        if required:
            raise ConfigError(f"{path} not found — start from examples/config.toml")
        return cfg
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: {e}") from None
    merge(cfg, expand(raw))
    for sink in cfg["notify"]["webhook"] + cfg["notify"]["exec"] + [cfg["notify"]]:
        if sink.get("min_severity", "info") not in SEVERITIES:
            raise ConfigError(f"notify: min_severity must be one of {SEVERITIES}")
    cfg["subscription"] = check_subs(cfg["subscription"])
    if required and not cfg["subscription"]:
        raise ConfigError("no [[subscription]] configured")
    return cfg
