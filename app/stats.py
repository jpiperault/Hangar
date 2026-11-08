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


_prev = {}


def _cpu_times():
    f = open("/proc/stat").readline().split()[1:9]   # user nice system idle iowait irq softirq steal
    v = [int(x) for x in f]
    return sum(v), v[3] + v[4]


def _net(iface="eth0"):
    for line in open("/proc/net/dev"):
        if line.strip().startswith(iface + ":"):
            f = line.split(":", 1)[1].split()
            return int(f[0]), int(f[8])
    return 0, 0


def _cg_usage():
    """Temps CPU consommé par cette machine ou ce conteneur (cgroup v2, µs). En LXC, /proc/stat reflète l'hôte."""
    try:
        for line in open("/sys/fs/cgroup/cpu.stat"):
            if line.startswith("usage_usec"):
                return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def collect_host():
    """CPU (cgroup, sinon /proc/stat), mémoire, swap, disque, charge, débit réseau d'eth0 — vus depuis le conteneur."""
    import shutil
    now = time.time()
    total, idle = _cpu_times()
    cg = _cg_usage()
    rx, tx = _net()
    prev = _prev.get("s")
    _prev["s"] = (now, total, idle, rx, tx, cg)
    if not prev:
        return
    dt = max(1.0, now - prev[0])
    if cg is not None and prev[5] is not None:
        cpu = (cg - prev[5]) / (dt * 1e6 * (os.cpu_count() or 1)) * 100
    else:
        dtot = total - prev[1]
        cpu = (1 - (idle - prev[2]) / dtot) * 100 if dtot > 0 else 0
    m = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
    du = shutil.disk_usage("/")
    load1 = float(open("/proc/loadavg").read().split()[0])
    db.x("INSERT OR REPLACE INTO stats_host(t, cpu, mem, mem_total, swap, disk, disk_total, load1, rx, tx) "
         "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
         (int(now // 60 * 60), round(max(0, min(100, cpu)), 1), (m["MemTotal"] - m["MemAvailable"]) / 1024,
          m["MemTotal"] / 1024, (m.get("SwapTotal", 0) - m.get("SwapFree", 0)) / 1024, du.used / 1e9, du.total / 1e9,
          load1, max(0, rx - prev[3]) / dt, max(0, tx - prev[4]) / dt))


def host_now():
    m = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
    import shutil
    du = shutil.disk_usage("/")
    up = float(open("/proc/uptime").read().split()[0])
    last = db.one("SELECT * FROM stats_host ORDER BY t DESC LIMIT 1") or {}
    return {"cpu": last.get("cpu"), "rx": last.get("rx"), "tx": last.get("tx"),
            "mem": (m["MemTotal"] - m["MemAvailable"]) / 1024, "mem_total": m["MemTotal"] / 1024,
            "swap": (m.get("SwapTotal", 0) - m.get("SwapFree", 0)) / 1024, "swap_total": m.get("SwapTotal", 0) / 1024,
            "disk": du.used / 1e9, "disk_total": du.total / 1e9,
            "load": [float(x) for x in open("/proc/loadavg").read().split()[:3]], "cores": os.cpu_count() or 1,
            "uptime": up}


def host_series(rng="24h"):
    span, step = RANGES.get(rng, RANGES["24h"])
    now = int(time.time())
    start = (now - span) // step * step + step
    slots = list(range(start, now // step * step + step, step))
    idx = {t: i for i, t in enumerate(slots)}
    n = len(slots)
    out = {k: [None] * n for k in ("cpu", "mem", "swap", "load1", "rx", "tx")}
    for r in db.q(f"SELECT (t / {step}) * {step} AS s, avg(cpu) cpu, max(mem) mem, max(swap) swap, avg(load1) load1, "
                  "avg(rx) rx, avg(tx) tx FROM stats_host WHERE t >= ? GROUP BY s", (start,)):
        i = idx.get(r["s"])
        if i is not None:
            for k in out:
                out[k][i] = round(r[k], 2) if r[k] is not None else None
    req, e5 = [0] * n, [0] * n
    for r in db.q(f"SELECT (t / {step}) * {step} AS s, sum(n) n, sum(e5) e5 FROM stats_req WHERE t >= ? GROUP BY s",
                  (start,)):
        i = idx.get(r["s"])
        if i is not None:
            req[i], e5[i] = r["n"], r["e5"]
    out.update(t=slots, step=step, range=rng, req=req, e5=e5)
    return out


def apps_overview():
    """Par appli sur 24 h : requêtes, 5xx, p95, temps moyen, et requêtes par heure (sparkline)."""
    since = int(time.time()) - 86400
    res = {r["app"]: r for r in db.q("SELECT app, sum(n) n, sum(e5) e5, sum(e4) e4, max(p95) p95, sum(dur_sum) d "
                                     "FROM stats_req WHERE t >= ? GROUP BY app", (since,))}
    start = since // 3600 * 3600 + 3600
    spark = {}
    for r in db.q("SELECT app, (t / 3600) * 3600 AS h, sum(n) n FROM stats_req WHERE t >= ? GROUP BY app, h", (start,)):
        spark.setdefault(r["app"], [0] * 24)
        i = (r["h"] - start) // 3600
        if 0 <= i < 24:
            spark[r["app"]][i] = r["n"]
    cpu = {r["app"]: r for r in db.q("SELECT app, avg(cpu) cpu, max(mem) mem FROM stats_res WHERE t >= ? GROUP BY app",
                                     (since,))}
    return res, spark, cpu


def spark_path(values, w=96, h=24):
    if not values or max(values) == 0:
        return f"M0,{h - 1}H{w}"
    top = max(values)
    n = len(values)
    pts = [f"{i * w / (n - 1):.1f},{h - 1 - v / top * (h - 3):.1f}" for i, v in enumerate(values)]
    return "M" + "L".join(pts)


def purge():
    limit = time.time() - KEEP_DAYS * 86400
    db.x("DELETE FROM stats_host WHERE t < ?", (limit,))
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


def _per(step):
    return f"par {step // 3600} h" if step >= 3600 else f"par {step // 60} min"


def app_charts(st, mem_mb):
    st["charts"] = [
        {"title": "Requêtes", "sub": _per(st["step"]), "unit": "", "kind": "bar", "values": st["req"],
         "marks": {"values": st["e5"], "label": "erreur(s) 5xx"}},
        {"title": "Temps de réponse", "sub": "95 % des requêtes en moins de (ms)", "unit": "ms", "kind": "line",
         "values": st["p95"], "extra": [{"label": "moyenne", "values": st["avg"], "unit": "ms"}]},
        {"title": "Mémoire", "sub": "max sur l'intervalle (Mo)", "unit": "Mo", "kind": "line", "values": st["mem"],
         "limit": mem_mb, "limitLabel": f"limite {mem_mb} Mo"},
        {"title": "Processeur", "sub": "moyenne (% d'un cœur)", "unit": "%", "kind": "line", "values": st["cpu"]},
    ]
    return st


def host_charts(hs, mem_total):
    kb = lambda v: [None if x is None else round(x / 1024, 1) for x in v]
    hs["charts"] = [
        {"title": "Processeur", "sub": "moyenne (% du cœur)", "unit": "%", "kind": "line", "values": hs["cpu"],
         "limit": 100, "limitLabel": "100 %", "extra": [{"label": "charge", "values": hs["load1"], "unit": ""}]},
        {"title": "Mémoire utilisée", "sub": "max sur l'intervalle (Mo)", "unit": "Mo", "kind": "line", "values": hs["mem"],
         "limit": round(mem_total), "limitLabel": f"total {mem_total:.0f} Mo",
         "extra": [{"label": "swap", "values": hs["swap"], "unit": "Mo"}]},
        {"title": "Requêtes, toutes applis", "sub": _per(hs["step"]), "unit": "", "kind": "bar", "values": hs["req"],
         "marks": {"values": hs["e5"], "label": "erreur(s) 5xx"}},
        {"title": "Réseau reçu", "sub": "moyenne (Ko/s)", "unit": "Ko/s", "kind": "line", "values": kb(hs["rx"])},
        {"title": "Réseau envoyé", "sub": "moyenne (Ko/s)", "unit": "Ko/s", "kind": "line", "values": kb(hs["tx"])},
    ]
    return hs
