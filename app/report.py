"""Rapport hebdomadaire sur ntfy (le lundi matin) et disponibilité des applis (rapport, page de statut)."""
import time

from . import alerts, backup, db, nodes, system
from . import platform as P

SEND_HOUR = 9   # le lundi, à partir de 9 h


def uptime(slug, days=7, now=None):
    """(pourcentage ou None, réussis, faits) sur les `days` derniers jours, aujourd'hui compris."""
    now = now or time.time()
    first = time.strftime("%Y-%m-%d", time.localtime(now - (days - 1) * 86400))
    r = db.one("SELECT sum(ok) ok, sum(total) total FROM uptime WHERE app = ? AND day >= ?", (slug, first))
    ok, total = (r["ok"] or 0, r["total"] or 0) if r else (0, 0)
    return (ok / total * 100 if total else None), ok, total


def uptime_days(slug, days=30, now=None):
    """[(jour, pourcentage ou None)] du plus ancien au plus récent."""
    now = now or time.time()
    rows = {r["day"]: r for r in db.q("SELECT day, ok, total FROM uptime WHERE app = ?", (slug,))}
    out = []
    for i in range(days - 1, -1, -1):
        d = time.strftime("%Y-%m-%d", time.localtime(now - i * 86400))
        r = rows.get(d)
        out.append((d, r["ok"] / r["total"] * 100 if r and r["total"] else None))
    return out


def purge(keep_days=95):
    db.x("DELETE FROM uptime WHERE day < ?", (time.strftime("%Y-%m-%d", time.localtime(time.time() - keep_days * 86400)),))


def _pct(v):
    return "—" if v is None else (f"{v:.2f} %".replace(".", ",") if v < 100 else "100 %")


def build(now=None):
    """(titre, texte) du rapport des 7 derniers jours."""
    now = now or time.time()
    since = now - 7 * 86400
    L = []
    apps = db.apps()
    req = {r["app"]: r for r in db.q("SELECT app, sum(n) n, sum(e5) e5 FROM stats_req WHERE t >= ? GROUP BY app",
                                     (int(since),))}
    worst = 100.0
    L.append("APPLIS (disponibilité 7 j · requêtes · erreurs 5xx)")
    for a in apps:
        pct, ok, total = uptime(a["slug"], 7, now)
        if pct is not None:
            worst = min(worst, pct)
        r = req.get(a["slug"]) or {}
        state = "arrêtée" if a["desired"] != "running" else ("en maintenance" if P.maintenance(a["slug"]) else "")
        L.append(f"• {a['name']} : {_pct(pct)} · {r.get('n') or 0:,} req · {r.get('e5') or 0} 5xx"
                 .replace(",", " ") + (f" ({state})" if state else ""))
    if not apps:
        L.append("• aucune appli")
    runs = db.q("SELECT ok, dest FROM backups WHERE ts >= ?", (since,))
    okb = sum(1 for r in runs if r["ok"])
    last = backup.last_ok()
    L += ["", "SAUVEGARDES",
          f"• {okb} réussie(s) sur {len(runs)} cette semaine" + (f", dernière il y a {(now - last['ts']) / 3600:.0f} h"
                                                                if last else ", aucune réussie")]
    for dest, t in (backup.restore_tests() or {}).items():
        L.append(f"• test de restauration ({dest}) : {'restaurable' if t.get('ok') else 'ÉCHEC'}"
                 + (f", il y a {(now - t['ts']) / 86400:.0f} j" if t.get("ts") else ""))
    pend = system.pending()
    names = dict(system.machines())
    L += ["", "MISES À JOUR EN ATTENTE"]
    L += [f"• {system.COMPONENTS[k]['name']} ({'console' if n == P.LOCAL else names.get(n, n)})" for n, k in pend] or ["• aucune"]
    L += ["", "MACHINES (disque · mémoire)"]
    h = nodes.local_info()
    rows = [("Console", h)] + [(n["name"], n["info"] or {}) for n in nodes.all_nodes() if n["id"] != P.LOCAL]
    for name, i in rows:
        if i.get("disk_total"):
            L.append(f"• {name} : disque {i['disk'] / i['disk_total'] * 100:.0f} %, mémoire {i['mem'] / i['mem_total'] * 100:.0f} %")
        else:
            L.append(f"• {name} : pas de mesure")
    nerr = db.one("SELECT count(*) c FROM events WHERE level = 'error' AND ts >= ?", (since,))["c"]
    L += ["", f"INCIDENTS : {nerr} erreur(s) au journal cette semaine"]
    bad = nerr or worst < 99 or (len(runs) and okb < len(runs)) or any(not t.get("ok") for t in (backup.restore_tests() or {}).values())
    title = ("Rapport de la semaine : à regarder" if bad else "Rapport de la semaine : tout va bien")
    return title, "\n".join(L)


def send(now=None, force=False):
    title, text = build(now)
    sent, err = alerts.send(title, text, priority=2, tags=["bar_chart"], force=force)
    if sent:
        P.log("info", "alertes", "rapport hebdomadaire envoyé")
    return sent, err


def maybe_send(now=None):
    """Appelée régulièrement : une fois par semaine, le lundi à partir de 9 h."""
    now = now or time.time()
    t = time.localtime(now)
    week = time.strftime("%G-W%V", t)
    if t.tm_wday != 0 or t.tm_hour < SEND_HOUR or db.kv_get("weekly_report") == week:
        return False
    db.kv_set("weekly_report", week)
    send(now)
    return True
