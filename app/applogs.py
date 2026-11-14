"""Logs des applis : lecture filtrée (période, texte, erreurs) et alertes quand un motif apparaît.

Les logs restent ceux de Docker (json-file, 3 × 10 Mo par conteneur) : la période consultable dépend du volume
écrit par l'appli. Réglage kv « log_alerts » : {slug: {"on": bool, "patterns": "un motif par ligne"}}.
Les motifs sont du texte cherché sans tenir compte de la casse ; préfixe « re: » pour une expression régulière.
"""
import re
import time

from . import alerts, db
from . import platform as P

PERIODS = {"": "300 dernières lignes", "1h": "dernière heure", "24h": "24 dernières heures", "168h": "7 derniers jours"}
ERRORS = re.compile(r"\b(error|erreur|exception|fatal|panic|traceback|critical|severe)\b|\bE/|\s5\d\d\s", re.I)
MAX_LINES = 20000
_since = {}   # slug -> horodatage du dernier passage des alertes


def read(slug, period="", q="", errors_only=False, limit=2000):
    """(lignes affichées, nombre total lu, tronqué ?)."""
    a = db.app(slug)
    d = P.app_dir(slug)
    args = ["compose", "logs", "--no-color", "--no-log-prefix", "--timestamps"]
    args += ["--since", period] if period in PERIODS and period else ["--tail", "300"]
    rc, out = P.dk(a["node"] if a else None, *args, cwd=d, timeout=60)
    lines = (out or "").splitlines()[-MAX_LINES:]
    total = len(lines)
    if q:
        m = _matcher(q)
        lines = [l for l in lines if m(l)]
    if errors_only:
        lines = [l for l in lines if ERRORS.search(l)]
    cut = len(lines) > limit
    return lines[-limit:], total, cut


def search(q="", period="24h", errors_only=False, slugs=None, limit=1000):
    """Recherche dans les logs de plusieurs applis à la fois (en parallèle, une machine lente ne bloque pas les
    autres). Retourne (résultats triés par heure : [{slug, name, ts, line}], {appli: erreur}, tronqué ?)."""
    import concurrent.futures
    apps = [a for a in db.apps() if (slugs is None or a["slug"] in slugs) and a["kind"] != "static"]

    def one(a):
        try:
            lines, _, _ = read(a["slug"], period or "24h", q, errors_only, limit=limit)
            return a, lines, None
        except Exception as e:
            return a, [], str(e)[:200]
    found, errs = [], {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(8, len(apps)))) as ex:
        for a, lines, err in ex.map(one, apps):
            if err:
                errs[a["slug"]] = err
            for l in lines:
                ts, _, rest = l.partition(" ")
                found.append({"slug": a["slug"], "name": a["name"], "ts": ts, "line": rest if ts[:2].isdigit() else l})
    found.sort(key=lambda x: x["ts"])
    cut = len(found) > limit
    return found[-limit:], errs, cut


def _matcher(p):
    p = p.strip()
    if p.startswith("re:"):
        try:
            rx = re.compile(p[3:].strip(), re.I)
            return lambda line: bool(rx.search(line))
        except re.error:
            pass
    low = p.lower()
    return lambda line: low in line.lower()


def settings(slug):
    return (db.kv_get("log_alerts") or {}).get(slug) or {"on": False, "patterns": ""}


def save(slug, on, patterns):
    pats = [p.strip() for p in (patterns or "").splitlines() if p.strip()][:20]
    for p in pats:
        if len(p) > 200:
            raise ValueError("un motif fait 200 caractères au plus")
        if p.startswith("re:"):
            try:
                re.compile(p[3:].strip())
            except re.error as e:
                raise ValueError(f"expression régulière invalide « {p[:40]} » : {e}")
    allc = db.kv_get("log_alerts") or {}
    allc[slug] = {"on": bool(on and pats), "patterns": "\n".join(pats)}
    db.kv_set("log_alerts", allc)


def scan(slug, text):
    """[(motif, [lignes])] des motifs trouvés dans `text`."""
    found = []
    for p in [x for x in settings(slug)["patterns"].splitlines() if x.strip()]:
        m = _matcher(p)
        hits = [l for l in text.splitlines() if m(l)]
        if hits:
            found.append((p, hits))
    return found


def tick(now=None):
    """Chaque minute : cherche les motifs dans les logs écrits depuis le passage précédent."""
    now = now or time.time()
    for slug, c in (db.kv_get("log_alerts") or {}).items():
        a = db.app(slug)
        if not a or not c.get("on") or a["desired"] != "running":
            _since.pop(slug, None)
            continue
        since = _since.get(slug, now - 60)
        _since[slug] = now
        rc, out = P.dk(a["node"], "logs", "--since", str(int(since)), "--until", str(int(now)),
                       f"app-{slug}-app-1", timeout=30)
        if rc:
            continue
        for p, hits in scan(slug, out):
            sample = "\n".join(h[-300:] for h in hits[-5:])
            P.log("warn", slug, f"logs : {len(hits)} ligne(s) avec « {p} »")
            alerts.send(f"{a['name']} : « {p} » dans les logs", f"{len(hits)} ligne(s) en une minute :\n{sample}",
                        priority=4, tags=["mag"], key=f"logs:{slug}:{p}", cooldown=1800)
