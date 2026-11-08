"""Statistiques par appli : requêtes (journal JSON de Caddy) et ressources (docker stats), par minute."""
import json
import os
import time

from . import db
from . import platform as P

KEEP_DAYS = 8
_pos = {"ino": None, "off": 0}


def _p95(values):
    if not values:
        return 0.0
    v = sorted(values)
    return v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))]


def collect_requests():
    """Lit les nouvelles lignes du journal de Caddy et les agrège par appli et par minute."""
    path = P.ACCESS_LOG
    try:
        st = os.stat(path)
    except OSError:
        return 0
    saved = db.kv_get("stats_pos") or {}
    ino, off = saved.get("ino"), saved.get("off", 0)
    if ino != st.st_ino or off > st.st_size:   # fichier tourné ou recréé : on repart du début
        off = 0 if ino is not None else st.st_size   # tout premier passage : on ignore l'historique
    buckets = {}
    with open(path, "rb") as f:
        f.seek(off)
        chunk = f.read(32 * 1024 * 1024)
        end = chunk.rfind(b"\n") + 1
        for line in chunk[:end].splitlines():
            try:
                d = json.loads(line)
            except ValueError:
                continue
            app = d.get("hangar_app")
            if not app:
                continue
            t = int(d.get("ts", time.time()) // 60 * 60)
            b = buckets.setdefault((app, t), {"n": 0, "e4": 0, "e5": 0, "dur": [], "bytes": 0})
            status = int(d.get("status") or 0)
            b["n"] += 1
            b["e4"] += 400 <= status < 500
            b["e5"] += status >= 500
            b["dur"].append(float(d.get("duration") or 0))
            b["bytes"] += int(d.get("size") or 0)
    for (app, t), b in buckets.items():
        db.x("""INSERT INTO stats_req(app, t, n, e4, e5, dur_sum, p95, bytes) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(app, t) DO UPDATE SET n = n + excluded.n, e4 = e4 + excluded.e4, e5 = e5 + excluded.e5,
                dur_sum = dur_sum + excluded.dur_sum, p95 = max(p95, excluded.p95), bytes = bytes + excluded.bytes""",
             (app, t, b["n"], b["e4"], b["e5"], sum(b["dur"]), _p95(b["dur"]), b["bytes"]))
    db.kv_set("stats_pos", {"ino": st.st_ino, "off": off + end})
    return len(buckets)


def _mem_mb(text):
    """"123.4MiB / 384MiB" -> 123.4"""
    v = text.split("/")[0].strip()
    for unit, mult in (("GiB", 1024), ("MiB", 1), ("KiB", 1 / 1024), ("GB", 1000), ("MB", 1), ("kB", 1 / 1000), ("B", 1 / 1048576)):
        if v.endswith(unit):
            try:
                return float(v[:-len(unit)]) * mult
            except ValueError:
                return 0.0
    return 0.0


def collect_resources():
    rc, out = P.run(["docker", "stats", "--no-stream", "--format", "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"], timeout=30)
    if rc:
        return
    t = int(time.time() // 60 * 60)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0].startswith("app-") or not parts[0].endswith("-app-1"):
            continue
        slug = parts[0][4:-6]
        try:
            cpu = float(parts[1].rstrip("%"))
        except ValueError:
            cpu = 0.0
        db.x("INSERT OR REPLACE INTO stats_res(app, t, cpu, mem) VALUES(?, ?, ?, ?)", (slug, t, cpu, _mem_mb(parts[2])))


def purge():
    limit = time.time() - KEEP_DAYS * 86400
    db.x("DELETE FROM stats_req WHERE t < ?", (limit,))
    db.x("DELETE FROM stats_res WHERE t < ?", (limit,))


# ---------------------------------------------------------------- lecture

RANGES = {"1h": (3600, 60), "24h": (86400, 900), "7j": (7 * 86400, 3 * 3600)}


def series(slug, rng="24h"):
    """Séries alignées sur des intervalles réguliers (les trous valent 0 ou None)."""
    span, step = RANGES.get(rng, RANGES["24h"])
    now = int(time.time())
    start = (now - span) // step * step + step
    slots = list(range(start, now // step * step + step, step))
    idx = {t: i for i, t in enumerate(slots)}
    n = len(slots)
    req, e5, e4, avg, p95, mem, cpu = [0] * n, [0] * n, [0] * n, [None] * n, [None] * n, [None] * n, [None] * n
    durs = [0.0] * n
    for r in db.q(f"SELECT (t / {step}) * {step} AS s, sum(n) n, sum(e4) e4, sum(e5) e5, sum(dur_sum) d, max(p95) p "
                  "FROM stats_req WHERE app = ? AND t >= ? GROUP BY s", (slug, start)):
        i = idx.get(r["s"])
        if i is None:
            continue
        req[i], e4[i], e5[i], durs[i], p95[i] = r["n"], r["e4"], r["e5"], r["d"], r["p"] * 1000
        avg[i] = r["d"] / r["n"] * 1000 if r["n"] else None
    for r in db.q(f"SELECT (t / {step}) * {step} AS s, avg(cpu) c, max(mem) m FROM stats_res "
                  "WHERE app = ? AND t >= ? GROUP BY s", (slug, start)):
        i = idx.get(r["s"])
        if i is not None:
            cpu[i], mem[i] = round(r["c"], 1), round(r["m"], 1)
    total = sum(req)
    return {
        "range": rng, "step": step, "t": slots, "mem_limit": (db.app(slug) or {}).get("mem_mb"),
        "req": req, "e5": e5, "e4": e4, "avg": avg, "p95": p95, "mem": mem, "cpu": cpu,
        "summary": {
            "requests": total,
            "errors5": sum(e5),
            "error_rate": (sum(e5) / total * 100) if total else 0,
            "avg_ms": (sum(durs) / total * 1000) if total else None,
            "p95_ms": max([x for x in p95 if x is not None], default=None),
            "mem_max": max([x for x in mem if x is not None], default=None),
            "cpu_avg": (sum(x for x in cpu if x is not None) / max(1, len([x for x in cpu if x is not None])))
            if any(x is not None for x in cpu) else None,
        },
    }


def requests_24h():
    since = time.time() - 86400
    return {r["app"]: r for r in db.q("SELECT app, sum(n) n, sum(e5) e5 FROM stats_req WHERE t >= ? GROUP BY app", (since,))}
