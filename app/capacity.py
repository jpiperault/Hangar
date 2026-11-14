"""Capacité des machines : à ce rythme, quand le disque sera-t-il plein ? la mémoire réservée aux applis tient-elle ?

Mesures (stats_host pour la console, stats_node pour les nœuds) : disque en Go, mémoire en Mo, chaque minute.
- Disque : pente de l'espace utilisé sur les 7 derniers jours (moyennes par heure, moindres carrés) ; « plein » = 95 %.
  Il faut au moins 24 h de mesures. Alerte si le disque sera plein avant l'horizon choisi (14 jours par défaut),
  urgente sous 3 jours ; au plus une par machine et par jour.
- Mémoire : limites des applis de la machine (et de leurs Redis, MySQL/MariaDB ; secours et instances compris) comparées
  à sa mémoire ; alerte si elles la dépassent (elles ne peuvent pas toutes atteindre leur limite en même temps).
Réglage kv « capacity » : {"on": True, "days": 14}.
"""
import time

from . import alerts, db
from . import platform as P

DEFAULT = {"on": True, "days": 14}
FULL = 0.95


def settings():
    return {**DEFAULT, **(db.kv_get("capacity") or {})}


def save(on, days):
    db.kv_set("capacity", {"on": bool(on), "days": max(1, min(90, int(days)))})


def slope(points):
    """Pente (unités par jour) des points [(t, valeur)] ; None si trop peu de recul."""
    pts = [(t, v) for t, v in points if v is not None]
    if len(pts) < 12 or pts[-1][0] - pts[0][0] < 86400:
        return None
    n = len(pts)
    mt = sum(t for t, _ in pts) / n
    mv = sum(v for _, v in pts) / n
    den = sum((t - mt) ** 2 for t, _ in pts)
    if not den:
        return None
    return sum((t - mt) * (v - mv) for t, v in pts) / den * 86400


def _hourly(node, since):
    if node == P.LOCAL:
        rows = db.q("SELECT (t / 3600) * 3600 h, avg(disk) d, max(disk_total) dt, avg(mem) m, max(mem_total) mt "
                    "FROM stats_host WHERE t >= ? GROUP BY h ORDER BY h", (since,))
    else:
        rows = db.q("SELECT (t / 3600) * 3600 h, avg(disk) d, max(disk_total) dt, avg(mem) m, max(mem_total) mt "
                    "FROM stats_node WHERE node = ? AND t >= ? GROUP BY h ORDER BY h", (node, since))
    return rows


def _allocated(node):
    """Mo réservés aux applis sur cette machine (limites de mémoire, services compris)."""
    from . import ha, services
    total = 0
    for a in db.apps():
        h = ha.get(a["slug"])
        homes = {a["node"] or P.LOCAL} | set(h["nodes"] if h else [])
        if node not in homes or a["kind"] == "static":
            continue
        total += a["mem_mb"] or 0
        if node == (a["node"] or P.LOCAL):
            total += sum(int((s or {}).get("mem") or 0) for s in (services.redis(a["slug"]), services.mysql(a["slug"])))
    return total


def machines(now=None):
    now = now or time.time()
    out = []
    for n in db.q("SELECT id, state FROM nodes ORDER BY id"):
        rows = _hourly(n["id"], now - 7 * 86400)
        if not rows:
            out.append({"id": n["id"], "state": n["state"], "data": False})
            continue
        last = rows[-1]
        disk, total = last["d"], last["dt"]
        sl = slope([(r["h"], r["d"]) for r in rows])
        days = None
        if sl and sl > 0 and total:
            days = max(0.0, (total * FULL - disk) / sl)
        out.append({"id": n["id"], "state": n["state"], "data": True, "disk": disk, "disk_total": total,
                    "disk_pct": disk / total * 100 if total else None, "per_day": sl, "days_left": days,
                    "mem_total_mb": last["mt"] or 0, "mem_used_mb": last["m"] or 0,
                    "allocated_mb": _allocated(n["id"])})
    return out


def check(now=None):
    s = settings()
    if not s["on"]:
        return
    for m in machines(now):
        if not m.get("data"):
            continue
        de = "de la console" if m["id"] == P.LOCAL else f"du nœud {m['id']}"
        d = m["days_left"]
        if d is not None and d < s["days"]:
            urgent = d < 3
            alerts.send(f"Disque {de} plein dans {d:.0f} jour(s)" if d >= 1 else f"Disque {de} presque plein",
                        f"{m['disk_pct']:.0f} % utilisés, +{m['per_day']:.2f} Go par jour en moyenne cette semaine. "
                        "Fais de la place (nettoyage des images, anciennes sauvegardes locales, logs) ou agrandis le disque.",
                        priority=5 if urgent else 4, tags=["floppy_disk", "warning"], key=f"capacity:disk:{m['id']}",
                        cooldown=6 * 3600 if urgent else 86400)
        if m["mem_total_mb"] and m["allocated_mb"] > m["mem_total_mb"]:
            alerts.send(f"Mémoire {de} surréservée",
                        f"Les applis peuvent demander {m['allocated_mb']:.0f} Mo pour {m['mem_total_mb']:.0f} Mo de mémoire : "
                        "si plusieurs atteignent leur limite, certaines seront tuées. Baisse des limites ou déplace une appli.",
                        priority=3, tags=["warning"], key=f"capacity:mem:{m['id']}", cooldown=7 * 86400)
