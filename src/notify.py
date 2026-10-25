"""Event delivery. The manager never talks to Telegram, e-mail, Home Assistant
etc. directly: it emits one JSON event and hands it to generic sinks, and you
bridge them wherever you like.

  file     /data/events.jsonl, one event per line (rotated to .1)
  webhook  POST application/json to each [[notify.webhook]] url
  exec     run each [[notify.exec]] command with the event on stdin

Delivery runs in a background thread and never blocks switching. Schema:
docs/notifications.md.
"""
import fcntl
import json
import os
import queue
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid

RANK = {"info": 0, "critical": 1}


class Notifier:
    def __init__(self, cfg, path, log):
        self.cfg, self.path, self.log = cfg, path, log
        self.q = queue.Queue(1000)
        threading.Thread(target=self.worker, daemon=True).start()

    def emit(self, kind, key, title, message, severity="info", actions=None, data=None):
        ev = {"id": uuid.uuid4().hex, "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind, "key": key,
              "severity": severity, "title": title, "message": message, "actions": actions or [], "data": data or {}}
        if RANK[severity] < RANK[self.cfg["min_severity"]]:
            return ev
        if self.cfg["file"]:
            self.to_file(ev)
        try:
            self.q.put_nowait(ev)
        except queue.Full:
            self.log("notify: queue full, event dropped")
        return ev

    def to_file(self, ev):
        if os.path.exists(self.path) and os.path.getsize(self.path) > self.cfg["file_max_mb"] * 2**20:
            os.replace(self.path, f"{self.path}.1")
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")

    def worker(self):
        while True:
            ev = self.q.get()
            body = json.dumps(ev, ensure_ascii=False).encode()
            for hook in self.cfg["webhook"]:
                if RANK[ev["severity"]] >= RANK[hook.get("min_severity", "info")]:
                    self.post(hook, body)
            for hook in self.cfg["exec"]:
                if RANK[ev["severity"]] >= RANK[hook.get("min_severity", "info")]:
                    self.run(hook, body)

    def post(self, hook, body):
        headers = {"Content-Type": "application/json", "User-Agent": "egress-autopilot", **hook.get("headers", {})}
        for attempt in range(3):
            try:
                req = urllib.request.Request(hook["url"], body, headers, method="POST")
                with urllib.request.urlopen(req, timeout=hook.get("timeout_s", 10)) as r:
                    if r.status < 300:
                        return
            except Exception as e:
                err = type(e).__name__
            else:
                err = f"http {r.status}"
            time.sleep(5 * (attempt + 1))
        # the url often carries a token, so only the host goes to the log
        self.log(f"notify: webhook {urllib.parse.urlsplit(hook['url']).hostname} failed: {err}")

    def run(self, hook, body):
        try:
            p = subprocess.run(hook["command"], input=body, capture_output=True, timeout=hook.get("timeout_s", 30))
            if p.returncode:
                self.log(f"notify: exec {hook['command'][0]} exited {p.returncode}: {p.stderr[-200:].decode(errors='replace')}")
        except Exception as e:
            self.log(f"notify: exec {hook['command'][0]}: {type(e).__name__}: {e}")
