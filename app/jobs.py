"""Tâches planifiées par appli : une commande lancée dans le conteneur de l'appli (docker exec), sur son nœud.

Réglage kv « jobs » : {slug: [{id, name, cmd, kind, every, at, dow, on, last}]}
- kind « minutes » : toutes les `every` minutes (5 au moins) ;
- kind « daily » : chaque jour à `at` (HH:MM) ;
- kind « weekly » : chaque semaine, le jour `dow` (0 = lundi) à `at`.
Une tâche ne se chevauche jamais elle-même ; durée bornée ; sortie (fin) et code de retour gardés ; alerte en cas
d'échec (au plus une par heure et par tâche).
"""
import re
import secrets
import threading
import time

from . import alerts, db
from . import platform as P

TIMEOUT = 30 * 60
KINDS = {"minutes": "toutes les N minutes", "daily": "chaque jour", "weekly": "chaque semaine"}
DAYS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
_running = set()
_lock = threading.Lock()


def all_jobs():
    return db.kv_get("jobs") or {}


def of(slug):
    return all_jobs().get(slug, [])


def _save(slug, jobs):
    with _lock:
        allj = all_jobs()
        if jobs:
            allj[slug] = jobs
        else:
            allj.pop(slug, None)
        db.kv_set("jobs", allj)


def _update(slug, jid, **kw):
    with _lock:
        allj = all_jobs()
        for j in allj.get(slug, []):
            if j["id"] == jid:
                j.update(kw)
        db.kv_set("jobs", allj)


def validate(f):
    """Formulaire → tâche (sans id ni historique). ValueError avec un message clair."""
    name = (f.get("name") or "").strip()
    cmd = (f.get("cmd") or "").strip()
    kind = f.get("kind") or "daily"
    if not name or len(name) > 80:
        raise ValueError("nom de la tâche : 1 à 80 caractères")
    if not cmd or len(cmd) > 2000 or "\x00" in cmd:
        raise ValueError("commande : 1 à 2000 caractères")
    if kind not in KINDS:
        raise ValueError("fréquence inconnue")
    job = {"name": name, "cmd": cmd, "kind": kind, "every": 60, "at": "03:00", "dow": 0}
    if kind == "minutes":
        try:
            job["every"] = int(f.get("every") or 60)
        except ValueError:
            raise ValueError("intervalle en minutes : un nombre")
        if not 5 <= job["every"] <= 1440:
            raise ValueError("intervalle : entre 5 et 1440 minutes")
    else:
        at = (f.get("at") or "").strip()
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", at):
            raise ValueError("heure au format HH:MM")
        job["at"] = at
        if kind == "weekly":
            try:
                job["dow"] = int(f.get("dow") or 0) % 7
            except ValueError:
                raise ValueError("jour de la semaine inconnu")
    return job


def add(slug, job):
    jobs = of(slug)
    if len(jobs) >= 20:
        raise ValueError("20 tâches au plus par appli")
    jobs.append({**job, "id": secrets.token_hex(4), "on": True, "last": None, "created": time.time()})
    _save(slug, jobs)


def remove(slug, jid):
    _save(slug, [j for j in of(slug) if j["id"] != jid])


def toggle(slug, jid):
    for j in of(slug):
        if j["id"] == jid:
            _update(slug, jid, on=not j.get("on", True))


def describe(j):
    if j["kind"] == "minutes":
        return f"toutes les {j['every']} minutes"
    if j["kind"] == "daily":
        return f"chaque jour à {j['at']}"
    return f"chaque {DAYS[j['dow']]} à {j['at']}"


def _slot(j, now):
    """Début de la dernière échéance passée (ou présente) de la tâche, en secondes."""
    if j["kind"] == "minutes":
        step = j["every"] * 60
        return now // step * step
    t = time.localtime(now)
    h, m = (int(x) for x in j["at"].split(":"))
    slot = time.mktime((t.tm_year, t.tm_mon, t.tm_mday, h, m, 0, 0, 0, -1))
    if j["kind"] == "daily":
        return slot if slot <= now else slot - 86400
    back = (t.tm_wday - j["dow"]) % 7
    slot -= back * 86400
    return slot if slot <= now else slot - 7 * 86400


def due(j, now):
    """La tâche doit-elle partir ? Une échéance manquée de plus de 2 h (console arrêtée…) est sautée."""
    if not j.get("on", True):
        return False
    slot = _slot(j, now)
    last = (j.get("last") or {}).get("ts") or j.get("created") or 0
    return last < slot <= now and now - slot < 2 * 3600


def run(slug, jid, manual=False):
    """Lance la tâche (thread). Retourne False si elle tourne déjà."""
    key = f"{slug}:{jid}"
    with _lock:
        if key in _running:
            return False
        _running.add(key)
    try:
        a = db.app(slug)
        j = next((x for x in of(slug) if x["id"] == jid), None)
        if not a or not j:
            return False
        t0 = time.time()
        _update(slug, jid, last={**(j.get("last") or {}), "ts": t0, "running": True})
        rc, out = P.dk(a["node"], "exec", f"app-{slug}-app-1", "sh", "-c", j["cmd"], timeout=TIMEOUT)
        dur = time.time() - t0
        _update(slug, jid, last={"ts": t0, "rc": rc, "dur": round(dur, 1), "out": (out or "")[-4000:],
                                 "manual": manual})
        if rc == 0:
            P.log("ok", slug, f"tâche « {j['name']} » terminée en {dur:.0f} s")
        else:
            P.log("error", slug, f"tâche « {j['name']} » en échec (code {rc}) : {P.tail(out or '', 3)}")
            alerts.send(f"{a['name']} : tâche « {j['name']} » en échec", f"Code {rc}\n{P.tail(out or '', 8)}",
                        priority=4, tags=["warning"], key=f"job:{key}", cooldown=3600)
        return True
    finally:
        with _lock:
            _running.discard(key)


def is_running(slug, jid):
    return f"{slug}:{jid}" in _running


def tick(now=None):
    """Chaque minute (surveillance) : lance les tâches arrivées à échéance des applis en marche."""
    now = now or time.time()
    started = []
    for slug, jobs in all_jobs().items():
        a = db.app(slug)
        if not a:   # appli supprimée : ses tâches aussi
            _save(slug, [])
            continue
        if a["desired"] != "running" or a["state"] == "deploying":
            continue
        for j in jobs:
            if due(j, now) and not is_running(slug, j["id"]):
                P.spawn(run, slug, j["id"])
                started.append((slug, j["id"]))
    return started
