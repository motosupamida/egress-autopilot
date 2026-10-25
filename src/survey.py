#!/usr/bin/env python3
"""Diagnostics: probe every node of every subscription without touching production xray.

From the API: POST /action {"action": "survey"} (a thread inside the manager).
By hand next to the running manager:
  docker compose exec manager python3 /app/survey.py
Uses its own port range so it does not collide with the manager's checks.
Results go to the same metrics.db; nothing is quarantined.
"""
import statistics
import sys
import threading
import time

sys.path.insert(0, "/app")
import manager as M

TOP_SPEED = 3


def run(m):
    """Probe everything; return summary lines per subscription."""
    subs = M.read_subs()
    started = time.time()
    summary = []
    for s in subs:
        name = s["name"]
        nodes = m.nodes.get(name, [])
        if not nodes:
            summary.append(f"{name}: no nodes (subscription does not fetch, no cache)")
            continue
        t0 = time.time()
        pool = [n for n in nodes if n.flag not in M.STOP_COUNTRIES]
        results = m.probe_nodes(pool, None, 20 if len(nodes) > M.BIG_SUB else 5)
        alive = [(n, r) for n, r in results.values() if r["ok"]]
        good = sorted([(n, r) for n, r in alive if m.good(r, n)], key=lambda x: x[1]["warm_ms"])
        blocked = sum(1 for n, r in alive if (r["loc"] or "") in M.STOP_COUNTRIES)
        invalid = len(pool) - len(results)
        speeds = []
        with M.Tester(m, [n for n, _ in good[:TOP_SPEED]]) as t:
            for n, r in good[:TOP_SPEED]:
                if n.id in t.ports:
                    speeds.append((n, r, m.speed(t.proxy(n), n, "cand")))
        countries = {}
        for n, r in good:
            c = r["loc"] or n.flag or "?"
            countries[c] = countries.get(c, 0) + 1
        lat = statistics.median([r["warm_ms"] for _, r in good]) if good else None
        line = (f"{name}: nodes {len(nodes)} · skipped by flag {len(nodes) - len(pool)} · invalid {invalid} · "
                f"alive {len(alive)} · good {len(good)}{f' · median {lat:.0f} ms' if lat else ''}"
                f"{f' · blocked-country exit {blocked}' if blocked else ''} · {time.time() - t0:.0f} s")
        line += "\n   countries: " + (", ".join(f"{c} {k}" for c, k in sorted(countries.items(), key=lambda x: -x[1])[:12]) or "—")
        for n, r, mbps in speeds:
            line += f"\n   top: {n.name[:40]} · {r['warm_ms']} ms · {mbps if mbps is not None else 'none'} Mbit/s · {r['loc'] or n.flag or '?'}"
        M.log(line)
        summary.append(line)
    M.log(f"full survey finished in {(time.time() - started) / 60:.0f} min")
    return summary


def main():
    threading.current_thread().tester_port = M.SURVEY_PORT + 500
    m = M.Manager()
    m.load_cache()
    print("\n===== SUMMARY =====", *run(m), sep="\n", flush=True)


if __name__ == "__main__":
    main()
